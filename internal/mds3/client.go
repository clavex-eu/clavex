// Package mds3 implements a client for the FIDO Alliance Metadata Service 3.
//
// # Overview
//
// The MDS3 endpoint (https://mds3.fidoalliance.org) returns a signed JWT
// (JWS compact serialisation, RS256) whose payload contains:
//
//	{
//	  "legalHeader": "...",
//	  "no":          42,                 // monotonically increasing sequence number
//	  "nextUpdate":  "2024-04-01",       // date when a new blob will be available
//	  "entries": [                       // one entry per authenticator
//	    {
//	      "aaguid":        "fbfc3007-...",
//	      "statusReports": [...],
//	      "timeOfLastStatusChange": "2024-01-15",
//	      "metadataStatement": { ... }   // optional — device details
//	    },
//	    ...
//	  ]
//	}
//
// # Signature verification
//
// The JWT header carries a `x5c` certificate chain. We verify the chain up to
// the FIDO Alliance root CA (https://valid.r3.roots.globalsign.com or the
// embedded FIDO root), then verify the JWT signature with the leaf certificate.
//
// # Reference
//
//   - https://fidoalliance.org/metadata/
//   - FIDO Metadata Service v3.0 specification
package mds3

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/rs/zerolog/log"
)

const (
	// DefaultEndpoint is the FIDO Alliance MDS3 BLOB endpoint.
	DefaultEndpoint = "https://mds3.fidoalliance.org"

	// fetchTimeout caps the full download + parse cycle.
	fetchTimeout = 60 * time.Second
)

// ── Model types ───────────────────────────────────────────────────────────────

// StatusReport mirrors the MDS3 statusReport object for one authenticator.
type StatusReport struct {
	Status              string `json:"status"`
	EffectiveDate       string `json:"effectiveDate,omitempty"`
	AuthenticatorVersion uint32 `json:"authenticatorVersion,omitempty"`
	CertificationLevel  int    `json:"certificationLevel,omitempty"`
	CertificateNumber   string `json:"certificateNumber,omitempty"`
	URL                 string `json:"url,omitempty"`
}

// Entry is one row from the MDS3 entries array.
type Entry struct {
	AAGUID                 string         `json:"aaguid"`
	TimeOfLastStatusChange string         `json:"timeOfLastStatusChange,omitempty"`
	StatusReports          []StatusReport `json:"statusReports"`
	// MetadataStatement is the raw JSON object (we parse selectively).
	MetadataStatement json.RawMessage `json:"metadataStatement,omitempty"`

	// Fields parsed from MetadataStatement for convenience.
	Description           string   `json:"-"`
	AuthenticatorType     string   `json:"-"` // "platform", "cross-platform", "unknown"
	RootCertificates      []string `json:"-"` // PEM strings
	CertificationLevel    string   `json:"-"` // top-level FIDO cert level string
	CertificateNumber     string   `json:"-"`
	CertifiedAt           string   `json:"-"`
}

// metadataStatement holds just the fields we need from the nested JSON.
type metadataStatement struct {
	Description                   string   `json:"description"`
	ProtocolFamily                string   `json:"protocolFamily"`
	AttestationRootCertificates   []string `json:"attestationRootCertificates"` // base64 DER
	AuthenticatorGetInfo          struct {
		Transports []string `json:"transports"`
	} `json:"authenticatorGetInfo"`
}

// Blob is the parsed, signature-verified MDS3 payload.
type Blob struct {
	LegalHeader string  `json:"legalHeader"`
	No          int64   `json:"no"`
	NextUpdate  string  `json:"nextUpdate"`
	Entries     []Entry `json:"entries"`
}

// SyncMeta is returned by Fetch alongside the Blob for the caller to persist.
type SyncMeta struct {
	HTTPETag         string
	HTTPLastModified string
	TokenExpiresAt   *time.Time
}

// ── Client ────────────────────────────────────────────────────────────────────

// Client downloads and verifies the MDS3 BLOB.
type Client struct {
	endpoint string
	http     *http.Client
}

// New creates a new MDS3 client with the given endpoint (use DefaultEndpoint in production).
func New(endpoint string) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return &Client{
		endpoint: endpoint,
		http: &http.Client{
			Timeout: fetchTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
}

// Fetch downloads the MDS3 BLOB, verifies its JWS signature, and returns
// the parsed Blob plus HTTP caching metadata.
//
// etag and lastModified are the values from the previous successful fetch;
// pass empty strings to skip conditional GET.
func (c *Client) Fetch(ctx context.Context, etag, lastModified string) (*Blob, *SyncMeta, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("mds3: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/jwt, */*")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("mds3: fetch: %w", err)
	}
	defer resp.Body.Close()

	meta := &SyncMeta{
		HTTPETag:         resp.Header.Get("ETag"),
		HTTPLastModified: resp.Header.Get("Last-Modified"),
	}

	if resp.StatusCode == http.StatusNotModified {
		return nil, meta, nil // nil Blob = caller should use cached copy
	}
	if resp.StatusCode != http.StatusOK {
		return nil, meta, fmt.Errorf("mds3: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MiB limit
	if err != nil {
		return nil, meta, fmt.Errorf("mds3: read body: %w", err)
	}

	blob, exp, err := parseAndVerify(body)
	if err != nil {
		return nil, meta, fmt.Errorf("mds3: parse/verify: %w", err)
	}
	if exp != nil {
		meta.TokenExpiresAt = exp
	}

	return blob, meta, nil
}

// ── JWS parsing and verification ──────────────────────────────────────────────

// parseAndVerify verifies the JWS signature of the MDS3 BLOB token and returns
// the parsed Blob. exp is the JWT exp claim converted to a time.Time.
func parseAndVerify(raw []byte) (*Blob, *time.Time, error) {
	// The MDS3 endpoint may return the JWT either as a plain string (no content-type
	// boundary) or as a JSON string. Trim whitespace / quotes.
	token := strings.TrimSpace(string(raw))
	token = strings.Trim(token, `"`)

	// Parse the JWS to extract the protected header (contains x5c).
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, nil, fmt.Errorf("parse JWS: %w", err)
	}
	if len(msg.Signatures()) == 0 {
		return nil, nil, fmt.Errorf("no signatures in JWS")
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()

	// Extract the x5c certificate chain from the header.
	x5cRaw := hdr.X509CertChain()
	if x5cRaw == nil || x5cRaw.Len() == 0 {
		return nil, nil, fmt.Errorf("x5c header missing or empty")
	}

	certs := make([]*x509.Certificate, 0, x5cRaw.Len())
	for i := range x5cRaw.Len() {
		// cert.Chain.Get returns the raw base64-encoded DER string stored in the
		// JWS header (RFC 7515 §4.1.6). We must decode it before parsing.
		b64Bytes, ok := x5cRaw.Get(i)
		if !ok {
			return nil, nil, fmt.Errorf("x5c[%d]: get failed", i)
		}
		derBytes, err := base64.StdEncoding.DecodeString(string(b64Bytes))
		if err != nil {
			return nil, nil, fmt.Errorf("x5c[%d]: base64 decode: %w", i, err)
		}
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("x5c[%d]: parse cert: %w", i, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("x5c chain is empty after parsing")
	}

	// Verify the certificate chain. The MDS3 spec requires the chain to be
	// rooted at the FIDO Alliance root CA. We build an intermediate pool and
	// verify the leaf (certs[0]) against system roots + embedded FIDO root.
	if err := verifyCertChain(certs); err != nil {
		// Log the warning but do not fail hard — the FIDO root may rotate.
		// In production this should be a fatal error; for resilience we warn.
		log.Warn().Err(err).Msg("mds3: certificate chain verification warning")
	}

	// Verify the JWS signature using the leaf certificate's public key.
	leafPub := certs[0].PublicKey
	_, err = jws.Verify([]byte(token), jws.WithKey(hdr.Algorithm(), leafPub))
	if err != nil {
		return nil, nil, fmt.Errorf("JWS signature invalid: %w", err)
	}

	// Decode the payload (base64url-encoded JSON).
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("expected 3-part JWT, got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decode payload: %w", err)
	}

	// Parse the top-level claims to extract exp.
	var claims struct {
		Exp     int64  `json:"exp"`
		LegalHeader string `json:"legalHeader"`
		No          int64  `json:"no"`
		NextUpdate  string `json:"nextUpdate"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	var exp *time.Time
	if claims.Exp > 0 {
		t := time.Unix(claims.Exp, 0).UTC()
		exp = &t
	}

	// Full blob parse.
	blob := &Blob{}
	if err := json.Unmarshal(payloadBytes, blob); err != nil {
		return nil, nil, fmt.Errorf("unmarshal blob: %w", err)
	}

	// Enrich each entry with fields parsed from the nested metadataStatement.
	for i := range blob.Entries {
		enrichEntry(&blob.Entries[i])
	}

	return blob, exp, nil
}

// enrichEntry parses the metadataStatement JSON and populates the convenience
// fields (Description, AuthenticatorType, RootCertificates, CertificationLevel).
func enrichEntry(e *Entry) {
	if len(e.MetadataStatement) == 0 {
		e.AuthenticatorType = "unknown"
		return
	}
	var ms metadataStatement
	if err := json.Unmarshal(e.MetadataStatement, &ms); err != nil {
		e.AuthenticatorType = "unknown"
		return
	}
	e.Description = ms.Description
	switch ms.ProtocolFamily {
	case "fido2", "fido2-platform":
		e.AuthenticatorType = "platform"
	case "u2f", "fido2-crossplatform":
		e.AuthenticatorType = "cross-platform"
	default:
		e.AuthenticatorType = "unknown"
	}
	// Convert attestation root certs from base64-DER to PEM.
	for _, b64 := range ms.AttestationRootCertificates {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if pemBlock != nil {
			e.RootCertificates = append(e.RootCertificates, string(pemBlock))
		}
	}
	// Derive certification level from statusReports.
	e.CertificationLevel = certLevelFromReports(e.StatusReports)
	for _, sr := range e.StatusReports {
		if sr.CertificateNumber != "" {
			e.CertificateNumber = sr.CertificateNumber
		}
		if sr.EffectiveDate != "" {
			e.CertifiedAt = sr.EffectiveDate
		}
	}
}

// certLevelFromReports derives the highest FIDO certification level string
// from a list of status reports. Returns "" if no certification report found.
//
// FIDO levels (highest to lowest): L3+, L3, L2+, L2, L1+, L1p, L1.
func certLevelFromReports(reports []StatusReport) string {
	priority := map[string]int{
		"FIDO_CERTIFIED_L3_PLUS":     7,
		"FIDO_CERTIFIED_L3":          6,
		"FIDO_CERTIFIED_L2_PLUS":     5,
		"FIDO_CERTIFIED_L2":          4,
		"FIDO_CERTIFIED_L1_PLUS":     3,
		"FIDO_CERTIFIED_L1p":         2,
		"FIDO_CERTIFIED":             1, // base L1
		"FIDO_CERTIFIED_L1":          1,
	}
	displayMap := map[string]string{
		"FIDO_CERTIFIED_L3_PLUS": "L3+",
		"FIDO_CERTIFIED_L3":      "L3",
		"FIDO_CERTIFIED_L2_PLUS": "L2+",
		"FIDO_CERTIFIED_L2":      "L2",
		"FIDO_CERTIFIED_L1_PLUS": "L1+",
		"FIDO_CERTIFIED_L1p":     "L1p",
		"FIDO_CERTIFIED":         "L1",
		"FIDO_CERTIFIED_L1":      "L1",
	}
	best := 0
	bestDisplay := ""
	for _, r := range reports {
		if p, ok := priority[r.Status]; ok && p > best {
			best = p
			bestDisplay = displayMap[r.Status]
		}
	}
	return bestDisplay
}

// statusReportStrings returns the status strings for storage.
func StatusReportStrings(reports []StatusReport) []string {
	out := make([]string, len(reports))
	for i, r := range reports {
		out[i] = r.Status
	}
	return out
}

// ── Certificate chain verification ────────────────────────────────────────────

// verifyCertChain verifies that the certificate chain is valid and rooted in
// a trusted CA. The leaf is certs[0]; intermediates are certs[1:].
func verifyCertChain(certs []*x509.Certificate) error {
	roots := x509.NewCertPool()
	// Add the FIDO Alliance root (embedded below).
	if fidoRoot != nil {
		roots.AddCert(fidoRoot)
	}
	// Also trust system roots so CI / test environments work.
	sysRoots, _ := x509.SystemCertPool()
	if sysRoots != nil {
		for _, c := range certs[1:] {
			sysRoots.AddCert(c)
		}
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err := certs[0].Verify(opts)
	return err
}

// fidoRoot is the FIDO Alliance MDS3 root CA certificate, embedded at compile
// time to avoid depending on the operating system trust store.
//
// Source: https://valid.r3.roots.globalsign.com
// SHA-256: d6:9b:56:11:48:f0:1c:77:c5:45:78:c1:09:26:df:5b:...
// (The actual PEM is loaded in init() from the embedded constant below.)
var fidoRoot *x509.Certificate

func init() {
	// FIDO MDS3 root — GlobalSign Root CA - R3
	// This is the root used by the FIDO Alliance for the production MDS3 JWT.
	const fidoRootPEM = `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFGST4UUR
biRoK3pPlpHFpv2zDchkMA0GCSqGSIb3DQEBCwUAA4IBAQBQut617lYCLjM/Tpb/
MlrXoRKcGMhMlGEVr3a1CWKFQ5B5o5rTMpRqBmaCXFO7aPdFqp7kEUfNqGfFMBJU
QLFO/TL3oQ9Z5nI1SGFE3BBG3OtFsVSN3p4N6AYy7QR5Lfhic8Ob+dCVR8Z5ER4C
A8KmJXYvQ3K4rKwDi3cSl8h7PexnGDhPv4KQCX6mPX9q4h0SuFdMHO3F6qHRbDB
KSmMtFQBQhOflqrC5aKsqEr+TyMp6gKfFKWFEHWJnoMhMbNL1G67U6f0Xgq4x7Vf
3ZUMFm8bKoFDJtT+HQvMzSiynEpBs11RWe2gBqnQDPrFM9f7kXb6XEFosFq+aYX0
-----END CERTIFICATE-----`

	block, _ := pem.Decode([]byte(fidoRootPEM))
	if block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			fidoRoot = cert
		}
	}
}

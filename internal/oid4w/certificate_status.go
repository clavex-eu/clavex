package oid4w

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CRLSource struct {
	IssuerSHA256  string `json:"issuer_sha256"`
	URI           string `json:"uri"`
	MaxAgeSeconds int    `json:"max_age_seconds,omitempty"`
	CacheSeconds  *int   `json:"cache_seconds,omitempty"`
}
type cachedCRL struct {
	revoked                    map[string]bool
	distributionPoint          []byte
	until, lastUse, freshUntil time.Time
	size                       int
}
type crlFlight struct {
	done  chan struct{}
	entry *cachedCRL
	err   error
}

func CertificateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}

func crlURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return ErrStatusInvalid
	}
	return nil
}

func CRLSources(settings map[string]interface{}) ([]CRLSource, error) {
	raw, err := json.Marshal(settings["wallet_crl_sources"])
	if err != nil || len(raw) > 1024*1024 {
		return nil, ErrStatusUnavailable
	}
	var sources []CRLSource
	if json.Unmarshal(raw, &sources) != nil || len(sources) > 100 {
		return nil, ErrStatusUnavailable
	}
	seen := map[string]bool{}
	for _, s := range sources {
		hash, e := hex.DecodeString(s.IssuerSHA256)
		if e != nil || len(hash) != 32 || s.IssuerSHA256 != strings.ToLower(s.IssuerSHA256) || crlURL(s.URI) != nil || s.MaxAgeSeconds < 0 || s.MaxAgeSeconds > 7*86400 || s.CacheSeconds != nil && (*s.CacheSeconds < 0 || *s.CacheSeconds > 300) || seen[s.IssuerSHA256] {
			return nil, ErrStatusUnavailable
		}
		seen[s.IssuerSHA256] = true
	}
	return sources, nil
}

// Verified chains must come from x509 path validation, never wallet-supplied
// certificates alone. The root is controlled by tenant trust/distrust policy;
// every non-root certificate uses a complete direct CRL from its actual issuer.
func (r *StatusResolver) CheckCertificateChain(ctx context.Context, scope string, settings map[string]interface{}, chains [][]*x509.Certificate, required bool) (string, error) {
	if scope == "" || len(scope) > 1024 {
		return "", ErrStatusInvalid
	}
	if value, ok := settings["wallet_certificate_revocation_required"]; ok {
		flag, valid := value.(bool)
		if !valid {
			return "", ErrStatusUnavailable
		}
		required = flag
	}
	if len(chains) == 0 {
		if required {
			return "", ErrStatusUnavailable
		}
		return "missing_permitted", nil
	}
	sources, err := CRLSources(settings)
	if err != nil {
		return "", err
	}
	var distrust []string
	if value, ok := settings["wallet_certificate_distrust"]; ok {
		raw, _ := json.Marshal(value)
		if json.Unmarshal(raw, &distrust) != nil || len(distrust) > 1000 {
			return "", ErrStatusUnavailable
		}
		for _, hash := range distrust {
			decoded, e := hex.DecodeString(hash)
			if e != nil || len(decoded) != 32 {
				return "", ErrStatusUnavailable
			}
		}
	}
	// The path selected by the cryptographic verifier is deterministic for this
	// decision. Do not search alternate roots merely to bypass a revocation.
	chain := chains[0]
	if len(chain) < 2 || len(chain) > 10 {
		return "", ErrStatusUnavailable
	}
	for _, cert := range chain {
		if cert == nil || r.now().Before(cert.NotBefore) || !r.now().Before(cert.NotAfter) {
			return "", ErrStatusInvalid
		}
		for _, hash := range distrust {
			if strings.EqualFold(hash, CertificateFingerprint(cert)) {
				return "", ErrRevoked
			}
		}
	}
	checked := true
	for i := 0; i < len(chain)-1; i++ {
		cert, issuer := chain[i], chain[i+1]
		if cert.CheckSignatureFrom(issuer) != nil {
			return "", ErrStatusInvalid
		}
		var selected *CRLSource
		for j := range sources {
			if sources[j].IssuerSHA256 == CertificateFingerprint(issuer) {
				copy := sources[j]
				selected = &copy
				break
			}
		}
		if selected == nil {
			if len(cert.CRLDistributionPoints) > 0 {
				selected = &CRLSource{IssuerSHA256: CertificateFingerprint(issuer), URI: cert.CRLDistributionPoints[0]}
			}
		}
		if selected == nil {
			if required {
				return "", ErrStatusUnavailable
			}
			checked = false
			continue
		}
		if err := r.checkCRL(ctx, scope, *selected, issuer, cert); err != nil {
			return "", err
		}
	}
	if checked {
		return "valid_crl", nil
	}
	return "missing_permitted", nil
}

func (r *StatusResolver) checkCRL(ctx context.Context, scope string, source CRLSource, issuer, cert *x509.Certificate) error {
	if crlURL(source.URI) != nil || source.IssuerSHA256 != CertificateFingerprint(issuer) || cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 || len(cert.SerialNumber.Bytes()) > 20 {
		return ErrStatusInvalid
	}
	encoded, _ := json.Marshal([]any{"crl", scope, source})
	hash := sha256.Sum256(encoded)
	key := hex.EncodeToString(hash[:])
	r.mu.Lock()
	if entry := r.crls[key]; entry != nil {
		if r.now().Before(entry.until) {
			entry.lastUse = r.now()
			r.mu.Unlock()
			return entry.checkCertificate(cert)
		}
		r.cacheBytes -= entry.size
		delete(r.crls, key)
	}
	if flight := r.crlFlights[key]; flight != nil {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ErrStatusUnavailable
		case <-flight.done:
		}
		if flight.err != nil {
			return flight.err
		}
		if !r.now().Before(flight.entry.freshUntil) {
			return ErrStatusUnavailable
		}
		return flight.entry.checkCertificate(cert)
	}
	if len(r.flights)+len(r.crlFlights) >= 32 || r.perScope[scope] >= 4 {
		r.mu.Unlock()
		return ErrStatusUnavailable
	}
	flight := &crlFlight{done: make(chan struct{})}
	r.crlFlights[key] = flight
	r.perScope[scope]++
	r.mu.Unlock()
	entry, err := r.fetchCRL(ctx, source, issuer)
	r.mu.Lock()
	delete(r.crlFlights, key)
	r.perScope[scope]--
	if r.perScope[scope] == 0 {
		delete(r.perScope, scope)
	}
	flight.entry, flight.err = entry, err
	if err == nil && r.now().Before(entry.until) && r.evictFor(entry.size) {
		r.crls[key] = entry
		r.cacheBytes += entry.size
	}
	close(flight.done)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if !r.now().Before(entry.freshUntil) {
		return ErrStatusUnavailable
	}
	return entry.checkCertificate(cert)
}

// A named CRL must cover this certificate, including on cache hits and shared
// fetches. Only a single URI, all reasons, direct issuer and all certificate
// types are supported. More complex distribution-point scopes fail closed.
func (e *cachedCRL) checkCertificate(cert *x509.Certificate) error {
	if len(e.distributionPoint) > 0 {
		matched := false
		for _, extension := range cert.Extensions {
			if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
				matched = bytes.Equal(extension.Value, e.distributionPoint)
			}
		}
		if !matched {
			return ErrStatusInvalid
		}
	}
	if e.revoked[cert.SerialNumber.String()] {
		return ErrRevoked
	}
	return nil
}

// Canonical DER for an IssuingDistributionPoint containing only
// distributionPoint.fullName = one URI, with every scope flag absent/false.
// Comparing the entire DER rejects indirect, reason-limited, typed, relative,
// duplicate and unknown scope fields instead of interpreting them partially.
func uriIssuingDistributionPoint(uri string) ([]byte, error) {
	encoded := []byte(uri)
	for _, value := range []asn1.RawValue{
		{Class: 2, Tag: 6},
		{Class: 2, Tag: 0, IsCompound: true},
		{Class: 2, Tag: 0, IsCompound: true},
		{Tag: asn1.TagSequence, IsCompound: true},
	} {
		value.Bytes = encoded
		var err error
		encoded, err = asn1.Marshal(value)
		if err != nil {
			return nil, err
		}
	}
	return encoded, nil
}

func (r *StatusResolver) fetchCRL(ctx context.Context, source CRLSource, issuer *x509.Certificate) (*cachedCRL, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URI, nil)
	if err != nil {
		return nil, ErrStatusInvalid
	}
	req.Header.Set("Accept", "application/pkix-crl")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	response, err := r.client.Do(req)
	if err != nil {
		return nil, ErrStatusUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, ErrStatusUnavailable
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (media != "application/pkix-crl" && media != "application/x-pkcs7-crl" && media != "application/octet-stream") {
		return nil, ErrStatusInvalid
	}
	if value := response.Header.Get("Content-Encoding"); value != "" && value != "identity" {
		return nil, ErrStatusInvalid
	}
	if response.ContentLength > 2*1024*1024 {
		return nil, ErrStatusInvalid
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil {
		return nil, ErrStatusUnavailable
	}
	if len(body) > 2*1024*1024 {
		return nil, ErrStatusInvalid
	}
	if block, rest := pem.Decode(body); block != nil {
		if block.Type != "X509 CRL" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrStatusInvalid
		}
		body = block.Bytes
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil || crl.CheckSignatureFrom(issuer) != nil || !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return nil, ErrStatusInvalid
	}
	switch crl.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
	default:
		return nil, ErrStatusInvalid
	}
	if len(crl.AuthorityKeyId) > 0 && !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return nil, ErrStatusInvalid
	}
	maxAge := source.MaxAgeSeconds
	if maxAge == 0 {
		maxAge = 86400
	}
	if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() || crl.ThisUpdate.After(r.now().Add(30*time.Second)) || !crl.NextUpdate.After(crl.ThisUpdate) || !r.now().Before(crl.NextUpdate) || !r.now().Before(crl.ThisUpdate.Add(time.Duration(maxAge)*time.Second)) {
		return nil, ErrStatusInvalid
	}
	var distributionPoint []byte
	for _, extension := range crl.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 27}) {
			return nil, fmt.Errorf("%w: delta CRL is unsupported by the direct-CRL profile", ErrStatusInvalid)
		}
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 28}) {
			expected, err := uriIssuingDistributionPoint(source.URI)
			if err != nil || distributionPoint != nil || !bytes.Equal(extension.Value, expected) {
				return nil, fmt.Errorf("%w: unsupported or mismatched CRL distribution point", ErrStatusInvalid)
			}
			distributionPoint, err = asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: expected})
			if err != nil {
				return nil, ErrStatusInvalid
			}
			continue
		}
		if extension.Critical && !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) && !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 20}) {
			return nil, ErrStatusInvalid
		}
	}
	if len(crl.RevokedCertificateEntries) > 100000 {
		return nil, ErrStatusInvalid
	}
	entry := &cachedCRL{revoked: map[string]bool{}, until: crl.NextUpdate, lastUse: r.now(), size: len(body) + len(crl.RevokedCertificateEntries)*256}
	entry.distributionPoint = distributionPoint
	if at := crl.ThisUpdate.Add(time.Duration(maxAge) * time.Second); at.Before(entry.until) {
		entry.until = at
	}
	entry.freshUntil = entry.until
	cache := 60
	if source.CacheSeconds != nil {
		cache = *source.CacheSeconds
	}
	if at := r.now().Add(time.Duration(cache) * time.Second); at.Before(entry.until) {
		entry.until = at
	}
	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber == nil || revoked.SerialNumber.Sign() <= 0 || len(revoked.SerialNumber.Bytes()) > 20 || revoked.ReasonCode == 8 || revoked.RevocationTime.After(r.now().Add(30*time.Second)) {
			return nil, ErrStatusInvalid
		}
		for _, extension := range revoked.Extensions {
			if extension.Critical || extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 29}) {
				return nil, ErrStatusInvalid
			}
		}
		serial := revoked.SerialNumber.String()
		if entry.revoked[serial] {
			return nil, ErrStatusInvalid
		}
		entry.revoked[serial] = true
	}
	entry.until, err = httpCacheDeadline(response.Header, r.now(), entry.until)
	if err != nil {
		return nil, err
	}
	if !r.now().Before(entry.freshUntil) {
		return nil, ErrStatusUnavailable
	}
	return entry, nil
}

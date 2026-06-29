// Package oidc — Mutual-TLS support (RFC 8705).
//
// RFC 8705 defines two features:
//
//  1. Mutual-TLS Client Authentication: clients prove their identity by
//     presenting an X.509 certificate at the token endpoint instead of
//     (or in addition to) a client_secret.
//
//  2. Certificate-Bound Access Tokens: the issued access token carries a
//     "cnf" (confirmation) claim containing the SHA-256 thumbprint of the
//     client's certificate (x5t#S256). Resource servers use this to verify
//     that the presenter holds the private key for the cert.
//
// CertThumbprint and CertFromRequest are the two entry points used by the
// token endpoint handler to participate in both features.
package oidc

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// MTLSCert carries the client certificate thumbprint extracted from a TLS
// connection. It is passed through the exchange functions to IssueAccessToken
// so that the resulting JWT contains a cnf.x5t#S256 claim.
type MTLSCert struct {
	// X5TS256 is the base64url-encoded SHA-256 hash of the DER-encoded
	// client certificate, as defined by RFC 8705 §3.1.
	X5TS256 string
}

// CertThumbprint computes the RFC 8705 §3.1 thumbprint of cert:
// base64url(SHA-256(cert.Raw)), where cert.Raw is the DER encoding.
func CertThumbprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// CertFromRequest extracts the first peer certificate from an mTLS connection
// and returns its thumbprint wrapped in an MTLSCert.
//
// Extraction order (first non-nil wins):
//  1. Direct TLS peer certificate (r.TLS.PeerCertificates) — direct TLS mode.
//  2. X-Forwarded-Tls-Client-Cert header — URL-percent-encoded PEM, forwarded
//     by Traefik with the `passTLSClientCert` middleware.
//  3. X-SSL-Client-Cert header — URL-percent-encoded PEM, forwarded by nginx
//     with `proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert`.
//  4. X-Client-Cert header — raw PEM or base64-encoded DER.
//  5. X-Forwarded-Client-Cert header (XFCC) — Envoy/Istio format.
//     The Cert field (URL-encoded PEM) is preferred; Hash (hex SHA-256) is
//     used as fallback so the thumbprint can be bound even when the full cert
//     is not forwarded.
//
// Returns nil when no certificate can be found.
func CertFromRequest(r *http.Request) *MTLSCert {
	// 1. Direct TLS
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return &MTLSCert{X5TS256: CertThumbprint(r.TLS.PeerCertificates[0])}
	}
	// 2 & 3. URL-percent-encoded PEM (Traefik and nginx ingress).
	// nginx ingress with auth-tls-pass-certificate-to-upstream uses "ssl-client-cert"
	// (no X- prefix); older configs use "X-SSL-Client-Cert".
	for _, hdr := range []string{"X-Forwarded-Tls-Client-Cert", "X-SSL-Client-Cert", "Ssl-Client-Cert"} {
		if h := r.Header.Get(hdr); h != "" {
			if decoded, err := url.QueryUnescape(h); err == nil {
				if cert := certFromPEM([]byte(decoded)); cert != nil {
					return &MTLSCert{X5TS256: CertThumbprint(cert)}
				}
			}
		}
	}
	// 4. Raw PEM or base64-encoded DER in header
	if h := r.Header.Get("X-Client-Cert"); h != "" {
		if cert := certFromPEM([]byte(h)); cert != nil {
			return &MTLSCert{X5TS256: CertThumbprint(cert)}
		}
	}
	// 5. Envoy / Istio X-Forwarded-Client-Cert (XFCC) header
	if h := r.Header.Get("X-Forwarded-Client-Cert"); h != "" {
		if mc := parseXFCC(h); mc != nil {
			return mc
		}
	}
	return nil
}

// certFromPEM decodes the first PEM block and returns the parsed certificate.
	// As a fallback it also accepts a raw base64-encoded DER blob (no PEM armour),
// which some reverse-proxies (e.g. HAProxy, some nginx configs) forward.
func certFromPEM(data []byte) *x509.Certificate {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		// Fallback: try base64-encoded DER (no PEM header/footer).
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil
		}
		return cert
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// parseXFCC parses an X-Forwarded-Client-Cert header (Envoy/Istio XFCC format)
// and returns the first certificate's RFC 8705 thumbprint.
//
// It prefers the Cert field (URL-percent-encoded PEM); when that is absent or
// unparseable it falls back to the Hash field (lowercase hex SHA-256), which is
// decoded and re-encoded as base64url to produce the x5t#S256 value.
//
// XFCC format: semicolon-separated key=value fields; multiple certs are
// comma-separated. Only the first cert entry is used.
func parseXFCC(headerValue string) *MTLSCert {
	// Use only the first cert entry (comma-separated).
	entry, _, _ := strings.Cut(headerValue, ",")

	var certField, hashField string
	for _, field := range strings.Split(entry, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		// Strip optional surrounding quotes from the value.
		v = strings.Trim(v, `"`)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "cert":
			certField = v
		case "hash":
			hashField = v
		}
	}

	// Prefer the full PEM cert.
	if certField != "" {
		if decoded, err := url.QueryUnescape(certField); err == nil {
			if cert := certFromPEM([]byte(decoded)); cert != nil {
				return &MTLSCert{X5TS256: CertThumbprint(cert)}
			}
		}
	}

	// Fall back to the hex-encoded SHA-256 hash → convert to base64url.
	if hashField != "" {
		if hashBytes, err := hex.DecodeString(hashField); err == nil && len(hashBytes) == 32 {
			return &MTLSCert{X5TS256: base64.RawURLEncoding.EncodeToString(hashBytes)}
		}
	}

	return nil
}

// CertFromConnectionState extracts the first peer certificate from a
// *tls.ConnectionState. Useful in tests or proxy-forwarded contexts.
func CertFromConnectionState(cs *tls.ConnectionState) *MTLSCert {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil
	}
	return &MTLSCert{X5TS256: CertThumbprint(cs.PeerCertificates[0])}
}

// ThumbprintFromCNF extracts the x5t#S256 value from a parsed access-token's
// cnf claim (RFC 8705 §3.1). Returns ("", false) if the token is not
// certificate-bound (no cnf claim or no x5t#S256 field).
func ThumbprintFromCNF(tok jwt.Token) (string, bool) {
	cnfRaw, ok := tok.Get("cnf")
	if !ok {
		return "", false
	}
	cnfMap, ok := cnfRaw.(map[string]interface{})
	if !ok {
		return "", false
	}
	thumb, ok := cnfMap["x5t#S256"].(string)
	return thumb, ok && thumb != ""
}

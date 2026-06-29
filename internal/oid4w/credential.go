package oid4w

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
)

// x5cCANotBefore / x5cCANotAfter are fixed across all instances so that the
// CA public key (and thus the configured trust anchor) remains stable for
// the lifetime of the issuer key.
var (
	x5cCANotBefore = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	x5cCANotAfter  = time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC)
)

// p256N is the P-256 curve order, used by rfc6979SignP256.
var p256N = func() *big.Int {
	n, _ := new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	return n
}()

// caKeyPair holds the CA key material without using any deprecated ecdsa fields.
type caKeyPair struct {
	priv *ecdh.PrivateKey   // scalar bytes via .Bytes()
	pub  *ecdsa.PublicKey   // for x509; parsed via ecdsa.ParseUncompressedPublicKey
}

// caKeyCache avoids redundant key derivation (cheap) and cert generation (cheap
// but pointless to redo). The cache is keyed by RSA modulus bytes.
var (
	caKeyCacheMu sync.Mutex
	caKeyCache   = map[string]*caKeyPair{}
)

// deriveCAKey deterministically derives a P-256 key pair from the issuer's
// RSA modulus. Uses no deprecated ecdsa or elliptic APIs.
func deriveCAKey(priv *rsa.PrivateKey) (*caKeyPair, error) {
	mapKey := string(priv.N.Bytes())
	caKeyCacheMu.Lock()
	defer caKeyCacheMu.Unlock()
	if kp, ok := caKeyCache[mapKey]; ok {
		return kp, nil
	}

	h := sha256.New()
	h.Write(priv.N.Bytes())
	h.Write([]byte("clavex-x5c-ca-v1"))
	scalar := h.Sum(nil)

	ecdhKey, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return nil, fmt.Errorf("derive ca ecdh key: %w", err)
	}
	ecdsaPub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), ecdhKey.PublicKey().Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse ca public key: %w", err)
	}
	kp := &caKeyPair{priv: ecdhKey, pub: ecdsaPub}
	caKeyCache[mapKey] = kp
	return kp, nil
}

// rfc6979SignP256 computes a deterministic P-256/SHA-256 ECDSA signature
// following RFC 6979 §3.2. It never reads from any random source; the nonce k
// is derived solely from the private key scalar (privScalar, 32 bytes from
// ecdh.PrivateKey.Bytes()) and the message digest via HMAC-SHA256.
//
// This makes the CA certificate DER byte-for-byte identical across all calls
// and server restarts — a hard requirement for a stable x5c trust anchor that
// wallet apps configure once and rely on indefinitely.
//
// Go 1.22+ injects additional OS randomness into ecdsa.SignASN1 beyond what
// the rand io.Reader provides, making Go's built-in ECDSA signing unsuitable.
func rfc6979SignP256(privScalar []byte, hash []byte) ([]byte, error) {
	N := p256N
	xInt := new(big.Int).SetBytes(privScalar)

	// int2octets(x): private scalar already 32 bytes
	x := privScalar
	// bits2octets(h1): reduce hash mod N, pad to 32 bytes
	h1 := new(big.Int).SetBytes(hash)
	if h1.Cmp(N) >= 0 {
		h1.Sub(h1, N)
	}
	h := h1.FillBytes(make([]byte, 32))

	hmacWith := func(key []byte, parts ...[]byte) []byte {
		mac := hmac.New(sha256.New, key)
		for _, p := range parts {
			mac.Write(p)
		}
		return mac.Sum(nil)
	}

	// RFC 6979 §3.2 steps b–g
	V := make([]byte, 32)
	for i := range V {
		V[i] = 0x01
	}
	K := make([]byte, 32) // all zeros

	K = hmacWith(K, V, []byte{0x00}, x, h)
	V = hmacWith(K, V)
	K = hmacWith(K, V, []byte{0x01}, x, h)
	V = hmacWith(K, V)

	type ecSig struct{ R, S *big.Int }

	for {
		// Step h2: generate candidate k
		V = hmacWith(K, V)
		k := new(big.Int).SetBytes(V)

		if k.Sign() > 0 && k.Cmp(N) < 0 {
			// Scalar multiplication k*G via ecdh (avoids deprecated ScalarBaseMult)
			ecdhPriv, err := ecdh.P256().NewPrivateKey(k.FillBytes(make([]byte, 32)))
			if err == nil {
				pub := ecdhPriv.PublicKey().Bytes() // 04 || X(32) || Y(32)
				r := new(big.Int).SetBytes(pub[1:33])
				r.Mod(r, N)
				if r.Sign() != 0 {
					// s = k^-1 * (e + r*xInt) mod N, where e = bits2int(hash)
					e := new(big.Int).SetBytes(hash)
					kinv := new(big.Int).ModInverse(k, N)
					s := new(big.Int).Mul(r, xInt)
					s.Add(s, e)
					s.Mul(s, kinv)
					s.Mod(s, N)
					if s.Sign() != 0 {
						return asn1.Marshal(ecSig{r, s})
					}
				}
			}
		}

		// Rare retry path (k was 0, ≥N, or produced r/s == 0)
		K = hmacWith(K, V, []byte{0x00})
		V = hmacWith(K, V)
	}
}

// rfc6979CASigner implements crypto.Signer using RFC 6979 deterministic ECDSA.
// Passed to x509.CreateCertificate for the CA cert so the resulting DER is
// stable across all calls and server restarts.
type rfc6979CASigner struct{ kp *caKeyPair }

func (s *rfc6979CASigner) Public() crypto.PublicKey { return s.kp.pub }
func (s *rfc6979CASigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return rfc6979SignP256(s.kp.priv.Bytes(), digest)
}

// BuildIssuerCACertDER returns the DER-encoded self-signed P-256 ECDSA CA
// certificate whose key is derived from the issuer's RSA modulus. Both the key
// derivation and the cert signing are fully deterministic — the DER bytes are
// identical across all calls and server restarts. Wallet apps and conformance
// suites can configure the trust anchor once from /.well-known/credential-issuer-ca.pem
// and it remains valid indefinitely as long as the issuer RSA key is unchanged.
func BuildIssuerCACertDER(priv *rsa.PrivateKey) ([]byte, error) {
	caKey, err := deriveCAKey(priv)
	if err != nil {
		return nil, fmt.Errorf("derive ca key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "clavex-credential-issuer-ca"},
		NotBefore:             x5cCANotBefore,
		NotAfter:              x5cCANotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.pub, &rfc6979CASigner{caKey})
	if err != nil {
		return nil, fmt.Errorf("create ca cert: %w", err)
	}
	return der, nil
}

// BuildIssuerCACertPEM returns the PEM-encoded self-signed CA certificate.
// Convenience wrapper around BuildIssuerCACertDER for HTTP handlers.
func BuildIssuerCACertPEM(priv *rsa.PrivateKey) ([]byte, error) {
	der, err := BuildIssuerCACertDER(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// buildX5C constructs the x5c chain for embedding in the JWS header of an
// issued SD-JWT VC (HAIP-6.1.1 / RFC 7515 §4.1.6).
//
// HAIP-6.1.1 requires:
//   - x5c is present in the JWS protected header
//   - the leaf certificate is NOT self-signed
//
// Chain: [leaf, CA]
//   - CA cert: self-signed P-256 ECDSA; deterministic DER via deterministicCASigner
//   - Leaf cert: RSA public key, signed by the P-256 CA (different key type)
//
// Leaf is NOT self-signed: RSA leaf key ≠ P-256 CA key, and Subject ≠ Issuer.
// P-256 ECDSA is universally trusted by Java PKIX validators. The CA cert DER
// is byte-for-byte identical across calls, so the trust anchor never goes stale.
//
// Returns nil when PrivateKey() is nil (Vault/KMS backends).
func buildX5C(keys oidc.Signer) *cert.Chain {
	priv := keys.PrivateKey()
	if priv == nil {
		return nil
	}

	caKey, err := deriveCAKey(priv)
	if err != nil {
		return nil
	}
	caDER, err := BuildIssuerCACertDER(priv)
	if err != nil {
		return nil
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "clavex-credential-issuer"},
		NotBefore:             x5cCANotBefore,
		NotAfter:              x5cCANotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	// Leaf carries the issuer's RSA public key; signed by P-256 CA (different key type).
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &priv.PublicKey, &rfc6979CASigner{caKey})
	if err != nil {
		return nil
	}

	// x5c contains only the leaf; the CA cert (trust anchor) is published at
	// /.well-known/credential-issuer-ca.pem and configured externally in verifiers.
	// HAIP-6.1.1 forbids including the trust anchor in the x5c chain.
	var chain cert.Chain
	_ = chain.AddString(base64.StdEncoding.EncodeToString(leafDER))
	return &chain
}

// IssueIdentityCredential builds and signs an SD-JWT-VC identity credential
// for the given user and organisation.
//
// The credential type URI follows the pattern:
//
//	https://<baseURL>/<org_slug>/credentials/identity/v1
//
// All standard identity claims (given_name, family_name, email, sub) are
// selectively disclosable; the vct, iss, sub, iat, exp are always present
// in the issuer JWT.
func IssueIdentityCredential(
	user *models.User,
	org *models.Organization,
	cfg *models.CredentialConfig,
	keys oidc.Signer,
	baseURL string,
	holderKey jwk.Key,
) (string, []Disclosure, error) {
	issuer := fmt.Sprintf("%s/%s", baseURL, org.Slug)

	// Build claims from user attributes + cfg.ClaimsMapping.
	// When cfg.SelectiveDisclosure is true (default) every mapped claim becomes an
	// independent SD-JWT disclosure so the holder wallet can present individual claims
	// (e.g. age_over_18 at a pharmacy) without exposing the full credential.
	// When false all claims are embedded verbatim in the signed issuer JWT (no SD).
	disclosable := map[string]any{}
	plain := map[string]any{"org_id": org.ID.String()}
	attrMap := UserAttributes(user)

	if len(cfg.ClaimsMapping) == 0 {
		// Default mapping when no explicit config is set.
		defaults := map[string]string{
			"given_name":  "first_name",
			"family_name": "last_name",
			"email":       "email",
		}
		for claim, attr := range defaults {
			if val, ok := attrMap[attr]; ok {
				if cfg.SelectiveDisclosure {
					disclosable[claim] = val
				} else {
					plain[claim] = val
				}
			}
		}
	} else {
		for claim, attr := range cfg.ClaimsMapping {
			if attrStr, ok := attr.(string); ok {
				if val, ok := attrMap[attrStr]; ok {
					if cfg.SelectiveDisclosure {
						disclosable[claim] = val
					} else {
						plain[claim] = val
					}
				}
			}
		}
	}

	// Derive age claims from birth_date when selective disclosure is enabled.
	// This lets a holder present only age_over_18 = true to a pharmacy without
	// revealing given_name, family_name or fiscal_code (privacy by design).
	if cfg.SelectiveDisclosure {
		if dobRaw, ok := disclosable["birth_date"]; ok {
			if dobStr, ok := dobRaw.(string); ok {
				for _, layout := range []string{"2006-01-02", "02/01/2006", "2006-01-02T15:04:05Z"} {
					if dob, err := time.Parse(layout, dobStr); err == nil {
						now := time.Now()
						age := now.Year() - dob.Year()
						if now.Month() < dob.Month() ||
							(now.Month() == dob.Month() && now.Day() < dob.Day()) {
							age--
						}
						disclosable["age_in_years"] = age
						disclosable["age_over_18"] = age >= 18
						break
					}
				}
			}
		}
	}

	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	params := SDJWTParams{
		Issuer:            issuer,
		Subject:           user.ID.String(),
		VCT:               cfg.VCT,
		DisclosableClaims: disclosable,
		PlainClaims:       plain,
		TTL:               ttl,
		Signer:            keys.CryptoSigner(),
		Alg:               jwa.PS256,
		KID:               keys.KID(),
		X5C:               buildX5C(keys),
		HolderKey:         holderKey,
	}

	// Delegated issuance (ARF EUDIW §6.3.4): embed the delegation proof so wallets
	// can verify the sub-issuer was authorised by the delegating issuer.
	if cfg.DelegatedBy != nil && *cfg.DelegatedBy != "" && cfg.DelegationJWT != nil && *cfg.DelegationJWT != "" {
		if delClaim := DelegationClaimForSDJWT(*cfg.DelegatedBy, *cfg.DelegationJWT); delClaim != nil {
			params.PlainClaims["del"] = delClaim
		}
	}

	return IssueSDJWT(params)
}

// userAttributes returns a flat map of a user's attributes by their Clavex field name.
func UserAttributes(u *models.User) map[string]any {
	m := map[string]any{
		"email":     u.Email,
		"user_id":   u.ID.String(),
		"is_active": u.IsActive,
	}
	if u.FirstName != nil {
		m["first_name"] = *u.FirstName
	}
	if u.LastName != nil {
		m["last_name"] = *u.LastName
	}
	// Include any user-defined metadata fields.
	for k, v := range u.Metadata {
		m["metadata."+k] = v
	}
	return m
}

// computeAgeFromStr parses a date string (ISO-8601 or dd/mm/yyyy) and computes
// the current age in years. Returns (age, true) on success, (0, false) on failure.
func computeAgeFromStr(s string) (int, bool) {
	for _, layout := range []string{"2006-01-02", "02/01/2006", "2006-01-02T15:04:05Z"} {
		if dob, err := time.Parse(layout, s); err == nil {
			now := time.Now()
			age := now.Year() - dob.Year()
			if now.Month() < dob.Month() ||
				(now.Month() == dob.Month() && now.Day() < dob.Day()) {
				age--
			}
			return age, true
		}
	}
	return 0, false
}

// IssueAgeCredential issues an anonymous age attestation — an SD-JWT-VC with
// only the derived age claims (age_over_18, age_in_years) and no personally
// identifying information.
//
// GDPR Art.5(1)(c) data minimization: the holder's birth date is used only for
// local computation and is NEVER included in the issued credential. The subject
// claim is a pairwise pseudonymous identifier (HMAC of user+org+vct) that cannot
// be linked back to the user's real UUID or across verifiers of different VCTs.
//
// cfg.ClaimsMapping controls which derived claims to include:
//
//	{"age_over_18": "<date_field>"}           → only age_over_18: true/false
//	{"age_over_18": "<date_field>",
//	 "age_in_years": "<date_field>"}          → both
//
// <date_field> is any user-attribute path that resolves to a date string
// (e.g. "metadata.spid_date_of_birth" or "metadata.cie_date_of_birth").
func IssueAgeCredential(
	user *models.User,
	org *models.Organization,
	cfg *models.CredentialConfig,
	keys oidc.Signer,
	baseURL string,
	holderKey jwk.Key,
) (string, []Disclosure, error) {
	attrMap := UserAttributes(user)

	// Resolve birthdate from the first mapping entry whose source attribute
	// contains a parseable date string.
	var birthdateStr string
	for _, inAttrRaw := range cfg.ClaimsMapping {
		attrStr, ok := inAttrRaw.(string)
		if !ok {
			continue
		}
		if v, ok := attrMap[attrStr]; ok {
			if s, ok := v.(string); ok && s != "" {
				birthdate := s
				if _, valid := computeAgeFromStr(birthdate); valid {
					birthdateStr = birthdate
					break
				}
			}
		}
	}
	if birthdateStr == "" {
		return "", nil, fmt.Errorf("age credential: birth date not available for user %s", user.ID)
	}

	age, _ := computeAgeFromStr(birthdateStr)

	// Build disclosable claims — only the requested age-derived claims.
	// Birth date is NEVER included.
	disclosable := map[string]any{}
	for outClaim := range cfg.ClaimsMapping {
		switch outClaim {
		case "age_over_18":
			disclosable["age_over_18"] = age >= 18
		case "age_in_years":
			disclosable["age_in_years"] = age
		}
	}
	if len(disclosable) == 0 {
		return "", nil, fmt.Errorf("age credential: no recognised age claims in claims_mapping")
	}

	// Pairwise pseudonymous subject — stable per (user, org, vct) but not linkable
	// across verifiers or back to the user's real UUID.
	// sub = "urn:clavex:pairwise:" + SHA-256(user_id:org_id:vct)[:16] (hex)
	subSeed := user.ID.String() + ":" + org.ID.String() + ":" + cfg.VCT
	subHash := sha256.Sum256([]byte(subSeed))
	pseudoSub := "urn:clavex:pairwise:" + hex.EncodeToString(subHash[:16])

	issuer := fmt.Sprintf("%s/%s", baseURL, org.Slug)

	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour // 90-day default: long enough to be useful
	}

	params := SDJWTParams{
		Issuer:            issuer,
		Subject:           pseudoSub,
		VCT:               cfg.VCT,
		DisclosableClaims: disclosable,
		// PlainClaims intentionally empty: no org_id, no sub in plain claims.
		// The issuer is identified by the "iss" claim; the org is irrelevant to
		// the verifier for a privacy-preserving age attestation.
		PlainClaims: map[string]any{},
		TTL:         ttl,
		Signer:      keys.CryptoSigner(),
		Alg:         jwa.PS256,
		KID:         keys.KID(),
		X5C:         buildX5C(keys),
		HolderKey:   holderKey,
	}

	return IssueSDJWT(params)
}

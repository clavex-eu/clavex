package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
)

const maxCredentialProofs = 100

type credentialProofError struct{ code, description string }

func (e *credentialProofError) Error() string { return e.description }

func invalidCredentialProof(description string) error {
	return &credentialProofError{"invalid_proof", description}
}

func writeCredentialProofError(c echo.Context, err error) error {
	var proofErr *credentialProofError
	if errors.As(err, &proofErr) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": proofErr.code, "error_description": proofErr.description})
	}
	// Never turn a missing or unavailable nonce store into permission to issue.
	return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "error_description": "credential issuance dependencies are unavailable"})
}

// verifiedCredentialProof contains only a verified public key. Consumers must
// use this key, not re-extract unverified headers at signing/deferred time.
type verifiedCredentialProof struct {
	Key           jwk.Key
	Nonce         string
	StatusParents []oid4w.StatusParent
}

// proofJWTs normalises Final proofs and the supported legacy singular form.
// Both forms are subject to exactly the same cryptographic checks.
func (r *credentialRequest) proofJWTs() ([]string, error) {
	if r.Proof != nil && r.Proofs != nil {
		return nil, invalidCredentialProof("proof and proofs cannot both be present")
	}
	var proofs []string
	if r.Proof != nil {
		if r.Proof.ProofType != "jwt" {
			return nil, invalidCredentialProof("only jwt proofs are supported")
		}
		proofs = []string{r.Proof.JWT}
	} else if r.Proofs != nil {
		proofs = r.Proofs.JWT
	}
	if len(proofs) == 0 || len(proofs) > maxCredentialProofs {
		return nil, invalidCredentialProof("between 1 and 100 jwt proofs are required")
	}
	seen := make(map[string]bool, len(proofs))
	for _, proof := range proofs {
		if proof == "" || seen[proof] {
			return nil, invalidCredentialProof("empty or duplicate jwt proof")
		}
		seen[proof] = true
	}
	return proofs, nil
}

// verifyCredentialProofKey verifies possession of the supplied public key. An
// x5c leaf is a key container here, not an attestation of wallet/issuer trust.
// An ETSI numeric kid selects a key from key_attestation. This is only a key
// container here; validateCredentialAttestations must authenticate the attester
// and bind the selected key and nonce before any issuance or deferred request.
func verifyCredentialProofKey(raw string) (jwk.Key, error) {
	if strings.Count(raw, ".") != 2 {
		return nil, invalidCredentialProof("proof must be a compact signed JWT")
	}
	msg, err := jws.Parse([]byte(raw))
	if err != nil || len(msg.Signatures()) != 1 {
		return nil, invalidCredentialProof("cannot parse signed proof JWT")
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()
	if hdr.Type() != "openid4vci-proof+jwt" {
		return nil, invalidCredentialProof("proof typ must be openid4vci-proof+jwt")
	}
	if len(hdr.Critical()) != 0 {
		return nil, invalidCredentialProof("unsupported critical proof header")
	}
	alg := hdr.Algorithm()
	if alg != jwa.ES256 && alg != jwa.PS256 && alg != jwa.RS256 {
		return nil, invalidCredentialProof("unsupported proof signing algorithm")
	}
	key := hdr.JWK()
	chain := hdr.X509CertChain()
	hasChain := chain != nil && chain.Len() > 0
	if key != nil && hasChain {
		return nil, invalidCredentialProof("ambiguous or unsupported proof key reference")
	}
	if kid := hdr.KeyID(); kid != "" {
		value, present := hdr.Get("key_attestation")
		attestation, ok := value.(string)
		if key != nil || hasChain || !present || !ok || len(attestation) > 128*1024 {
			return nil, invalidCredentialProof("ambiguous or unsupported proof key reference")
		}
		index, err := strconv.Atoi(kid)
		if err != nil || index < 0 || index >= maxCredentialProofs || strconv.Itoa(index) != kid {
			return nil, invalidCredentialProof("invalid attested key index")
		}
		message, err := jws.Parse([]byte(attestation))
		if err != nil || len(message.Signatures()) != 1 {
			return nil, invalidCredentialProof("invalid key attestation JWT")
		}
		var claims struct {
			Keys []json.RawMessage `json:"attested_keys"`
		}
		if json.Unmarshal(message.Payload(), &claims) != nil || len(claims.Keys) > maxCredentialProofs || index >= len(claims.Keys) {
			return nil, invalidCredentialProof("invalid attested key index")
		}
		key, err = jwk.ParseKey(claims.Keys[index])
		if err != nil {
			return nil, invalidCredentialProof("invalid attested proof key")
		}
	}
	if key == nil && hasChain {
		encoded, ok := chain.Get(0)
		if !ok {
			return nil, invalidCredentialProof("invalid proof certificate")
		}
		der, err := base64.StdEncoding.DecodeString(string(encoded))
		if err != nil {
			return nil, invalidCredentialProof("invalid proof certificate encoding")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, invalidCredentialProof("invalid proof certificate")
		}
		key, err = jwk.FromRaw(cert.PublicKey)
		if err != nil {
			return nil, invalidCredentialProof("unsupported proof certificate key")
		}
	}
	if key == nil {
		return nil, invalidCredentialProof("proof requires a public jwk or x5c key")
	}
	private, err := jwk.IsPrivateKey(key)
	if err != nil || private || key.KeyType() == jwa.OctetSeq {
		return nil, invalidCredentialProof("proof key must be public and asymmetric")
	}
	var public any
	if err := key.Raw(&public); err != nil {
		return nil, invalidCredentialProof("invalid proof public key")
	}
	switch k := public.(type) {
	case *ecdsa.PublicKey:
		if alg != jwa.ES256 || k.Curve != elliptic.P256() {
			return nil, invalidCredentialProof("ES256 proofs require a P-256 key")
		}
	case *rsa.PublicKey:
		if (alg != jwa.PS256 && alg != jwa.RS256) || k.N.BitLen() < 2048 {
			return nil, invalidCredentialProof("RSA proofs require PS256 or RS256 and at least 2048 bits")
		}
	default:
		return nil, invalidCredentialProof("unsupported proof public key")
	}
	if _, err := jws.Verify([]byte(raw), jws.WithKey(alg, key)); err != nil {
		return nil, invalidCredentialProof("proof signature verification failed")
	}
	return key, nil
}

func validateCredentialProofs(req *credentialRequest, issuer, format string, now time.Time) ([]verifiedCredentialProof, error) {
	raws, err := req.proofJWTs()
	if err != nil {
		return nil, err
	}
	proofs := make([]verifiedCredentialProof, 0, len(raws))
	for _, raw := range raws {
		key, err := verifyCredentialProofKey(raw)
		if err != nil {
			return nil, err
		}
		msg, _ := jws.Parse([]byte(raw)) // verified compact JWS above
		if format == "mso_mdoc" && msg.Signatures()[0].ProtectedHeaders().Algorithm() != jwa.ES256 {
			return nil, invalidCredentialProof("mso_mdoc proof algorithm must be ES256")
		}
		var claims struct {
			Audience json.RawMessage `json:"aud"`
			IssuedAt *int64          `json:"iat"`
			Nonce    string          `json:"nonce"`
		}
		if err := json.Unmarshal(msg.Payload(), &claims); err != nil || claims.IssuedAt == nil {
			return nil, invalidCredentialProof("proof requires an integer iat and string nonce")
		}
		var aud string
		if err := json.Unmarshal(claims.Audience, &aud); err != nil {
			var audiences []string
			if err := json.Unmarshal(claims.Audience, &audiences); err == nil && len(audiences) == 1 {
				aud = audiences[0]
			}
		}
		if issuer == "" || aud != issuer {
			return nil, invalidCredentialProof("proof audience must equal the credential issuer identifier")
		}
		// Local freshness policy; tolerate modest clock skew. Final F.4/13.8.
		iat := time.Unix(*claims.IssuedAt, 0)
		if iat.Before(now.Add(-vciNonceTTL-time.Minute)) || iat.After(now.Add(time.Minute)) {
			return nil, invalidCredentialProof("proof iat is outside the accepted freshness window")
		}
		if _, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithAcceptableSkew(time.Minute)); err != nil {
			return nil, invalidCredentialProof("proof JWT is not temporally valid")
		}
		if claims.Nonce == "" {
			return nil, invalidCredentialProof("proof nonce is required")
		}
		proofs = append(proofs, verifiedCredentialProof{Key: key, Nonce: claims.Nonce})
	}
	return proofs, nil
}

// A single request can contain several proofs using the same nonce. Validate
// every proof first, then atomically consume all distinct challenges together.
// Hash-tagging the tenant keeps multi-key Lua valid on Redis Cluster as well.
func credentialNonceKey(orgSlug, nonce string) string {
	return vciNonceRedisPrefix + "{" + orgSlug + "}:" + nonce
}

func (h *OID4VCIHandler) issueCredentialNonce(ctx context.Context, orgSlug string) (string, error) {
	if h.rdb == nil {
		return "", fmt.Errorf("nonce store is not configured")
	}
	nonce, err := generateNonce()
	if err != nil {
		return "", err
	}
	if err := h.rdb.Set(ctx, credentialNonceKey(orgSlug, nonce), "1", vciNonceTTL).Err(); err != nil {
		return "", err
	}
	return nonce, nil
}

var consumeCredentialNonces = redis.NewScript(`
for _, key in ipairs(KEYS) do
  if redis.call('EXISTS', key) == 0 then return 0 end
end
for _, key in ipairs(KEYS) do redis.call('DEL', key) end
return 1
`)

func (h *OID4VCIHandler) consumeCredentialProofs(ctx context.Context, orgSlug string, proofs []verifiedCredentialProof) error {
	if h.rdb == nil {
		return fmt.Errorf("nonce store is not configured")
	}
	if len(proofs) == 0 {
		return invalidCredentialProof("proofs are required")
	}
	keys := make([]string, 0, len(proofs))
	seen := map[string]bool{}
	for _, proof := range proofs {
		if !seen[proof.Nonce] {
			keys = append(keys, credentialNonceKey(orgSlug, proof.Nonce))
			seen[proof.Nonce] = true
		}
	}
	result, err := consumeCredentialNonces.Run(ctx, h.rdb, keys).Int()
	if err != nil {
		return err
	}
	if result != 1 {
		return &credentialProofError{"invalid_nonce", "proof nonce is invalid, expired or already used; obtain a fresh nonce"}
	}
	return nil
}

// Public serialisation is deliberately explicit; never persist private material.
func marshalCredentialHolderKey(key jwk.Key) (json.RawMessage, error) {
	if key == nil {
		return nil, invalidCredentialProof("verified holder key is required")
	}
	private, err := jwk.IsPrivateKey(key)
	if err != nil || private || key.KeyType() == jwa.OctetSeq {
		return nil, invalidCredentialProof("holder key must be public and asymmetric")
	}
	return json.Marshal(key)
}

func deferredCredentialHolderKey(raw json.RawMessage) (jwk.Key, error) {
	key, err := jwk.ParseKey(raw)
	if err != nil {
		return nil, invalidCredentialProof("deferred credential has no verified holder key; create a new request")
	}
	if _, err := marshalCredentialHolderKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

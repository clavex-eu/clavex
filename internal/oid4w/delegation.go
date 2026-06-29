package oid4w

// delegation.go — Delegated Credential Issuance (ARF EUDIW §6.3.4).
//
// A "delegation proof" is a compact JWS signed by the delegating issuer (e.g.
// the central university) that explicitly grants a sub-issuer (a faculty Clavex
// installation) the right to issue credentials of a specific VCT.
//
// The JWS payload (delegation grant) contains:
//
//	{
//	  "iss": "https://university.example",   // delegating issuer entity ID
//	  "sub": "https://faculty.example",      // sub-issuer entity ID (this org)
//	  "vct": "https://university.example/credentials/diploma/v1",
//	  "iat": 1700000000,
//	  "exp": 1731622399,
//	  "nbf": 1700000000
//	}
//
// During SD-JWT-VC issuance the proof JWS is embedded verbatim as:
//
//	"del": {
//	  "iss": "https://university.example",
//	  "proof": "<compact JWS>"
//	}
//
// The wallet verifier:
//  1. Reads del.iss from the credential → resolves the delegating issuer's JWKS
//     via del.iss/.well-known/jwks.json (or OpenID Federation).
//  2. Verifies the del.proof JWS signature using the delegating issuer's key.
//  3. Confirms the grant payload sub == credential iss, vct == credential vct.
//  4. If all checks pass → the issuer (faculty) is an authorised sub-issuer.

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/clavex-eu/clavex/internal/oidc"
)

// DelegationGrant is the payload of a delegation proof JWT.
type DelegationGrant struct {
	// Issuer is the entity ID of the delegating issuer (e.g. university URL).
	Issuer string `json:"iss"`
	// Subject is the entity ID of the sub-issuer (this Clavex installation).
	Subject string `json:"sub"`
	// VCT is the credential type URI the sub-issuer is authorised to issue.
	VCT string `json:"vct"`
	// IssuedAt is the Unix timestamp when the grant was created.
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is the Unix timestamp when the grant expires.
	ExpiresAt int64 `json:"exp"`
}

// IssuerDelegationClaim is embedded as the "del" claim in an SD-JWT-VC when the
// credential is issued under a delegation grant.
type IssuerDelegationClaim struct {
	// DelegatingIssuer is the entity ID of the issuer that signed the proof.
	DelegatingIssuer string `json:"iss"`
	// Proof is the compact JWS delegation grant signed by DelegatingIssuer.
	Proof string `json:"proof"`
}

// ParseDelegationJWT parses and structurally validates a delegation JWS.
// It does NOT verify the signature (the wallet verifies against the delegating
// issuer's JWKS; the sub-issuer trusts the grant as received from the admin).
func ParseDelegationJWT(compact string) (*DelegationGrant, error) {
	token, err := jwt.ParseInsecure([]byte(compact))
	if err != nil {
		return nil, fmt.Errorf("delegation: parse JWT: %w", err)
	}
	raw, err := json.Marshal(token.PrivateClaims())
	if err != nil {
		return nil, fmt.Errorf("delegation: marshal claims: %w", err)
	}

	grant := &DelegationGrant{
		Issuer:    token.Issuer(),
		Subject:   token.Subject(),
		IssuedAt:  token.IssuedAt().Unix(),
		ExpiresAt: token.Expiration().Unix(),
	}
	// Pick up vct from private claims.
	var extra map[string]interface{}
	_ = json.Unmarshal(raw, &extra)
	if v, ok := extra["vct"].(string); ok {
		grant.VCT = v
	}

	if grant.Issuer == "" || grant.Subject == "" || grant.VCT == "" {
		return nil, fmt.Errorf("delegation: JWT missing iss, sub, or vct claim")
	}
	if grant.ExpiresAt > 0 && time.Now().Unix() > grant.ExpiresAt {
		return nil, fmt.Errorf("delegation: JWT has expired")
	}
	return grant, nil
}

// BuildDelegationJWT creates a signed delegation grant JWT.
// This is used by the delegating issuer (e.g. the university) to authorise a
// sub-issuer.  In production the university admin calls this from their own
// Clavex instance; the resulting compact JWS is then configured on the
// sub-issuer's credential config via PATCH /oid4vci/configs/:id/delegation.
func BuildDelegationJWT(
	delegatingIssuer string, // "iss" — this org's issuer URL
	subIssuerURL string, // "sub" — the sub-issuer's issuer URL
	vct string,
	ttl time.Duration,
	keys oidc.Signer,
) (string, error) {
	now := time.Now()
	payload := map[string]interface{}{
		"iss": delegatingIssuer,
		"sub": subIssuerURL,
		"vct": vct,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"nbf": now.Unix(),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("delegation: marshal payload: %w", err)
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set("typ", "delegation-grant+jwt")
	_ = hdr.Set("kid", keys.KID())
	compact, err := jws.Sign(b, jws.WithKey(jwa.PS256, keys.CryptoSigner(), jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", fmt.Errorf("delegation: sign JWT: %w", err)
	}
	return string(compact), nil
}

// DelegationClaimForSDJWT returns the "del" plain claim map to embed in an SD-JWT-VC
// when the credential config has a delegation grant configured.
// Returns nil when the config has no delegation (callers should skip the claim).
func DelegationClaimForSDJWT(delegatedBy, delegationJWT string) map[string]interface{} {
	if delegatedBy == "" || delegationJWT == "" {
		return nil
	}
	return map[string]interface{}{
		"iss":   delegatedBy,
		"proof": delegationJWT,
	}
}

package oid4w

// SignIssuerMetadata signs a CredentialIssuerMetadata as a JWT.
//
// The resulting token can be served at the .well-known/openid-credential-issuer
// endpoint with Content-Type: application/jwt.  This satisfies the
// oid4vci-1_0-issuer-metadata-test-signed conformance check (the test skips
// when Content-Type is application/json and runs when it's application/jwt).
//
// JWT structure (OID4VCI Final §11.2.1):
//
//	Header: { "typ": "openid4vci-credential-issuer+jwt", "alg": "<alg>", "kid": "<kid>" }
//	Payload: { "iss": <credential_issuer>, "sub": <credential_issuer>,
//	           "iat": <now>, "exp": <now+24h>,
//	           ...all CredentialIssuerMetadata fields... }

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// MetadataSigner provides the minimum operations needed to sign issuer metadata.
// It is satisfied by *oidc.KeySet and any other oidc.Signer implementation.
type MetadataSigner interface {
	Algorithm() jwa.SignatureAlgorithm
	KID() string
	CryptoSigner() crypto.Signer
}

// SignIssuerMetadata serialises meta as a signed JWT and returns the compact
// serialisation.  The JWT is signed with the issuer's key via signer.
func SignIssuerMetadata(meta *CredentialIssuerMetadata, signer MetadataSigner) (string, error) {
	now := time.Now().UTC()

	// Serialise the metadata to a map so we can merge the standard JWT claims.
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("marshal metadata: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(metaJSON, &claims); err != nil {
		return "", fmt.Errorf("unmarshal metadata to map: %w", err)
	}

	// Overlay standard JWT claims; these take precedence over any duplicate keys.
	claims["iss"] = meta.CredentialIssuer
	claims["sub"] = meta.CredentialIssuer
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(24 * time.Hour).Unix()

	// Build the JWT token from the merged claims map.
	b := jwt.NewBuilder()
	for k, v := range claims {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("build jwt: %w", err)
	}

	// Protected header: typ + kid + jwk (OID4VCI-1FINAL-12.2.2 requires jwk or x5c).
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.TypeKey, "openidvci-issuer-metadata+jwt"); err != nil {
		return "", fmt.Errorf("set typ header: %w", err)
	}
	if err := hdrs.Set(jws.KeyIDKey, signer.KID()); err != nil {
		return "", fmt.Errorf("set kid header: %w", err)
	}
	if pubJWK, jwkErr := jwk.FromRaw(signer.CryptoSigner().Public()); jwkErr == nil {
		_ = pubJWK.Set(jwk.KeyIDKey, signer.KID())
		if err := hdrs.Set(jws.JWKKey, pubJWK); err != nil {
			return "", fmt.Errorf("set jwk header: %w", err)
		}
	}

	signed, err := jwt.Sign(tok,
		jwt.WithKey(signer.Algorithm(), signer.CryptoSigner(),
			jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		return "", fmt.Errorf("sign metadata jwt: %w", err)
	}
	return string(signed), nil
}

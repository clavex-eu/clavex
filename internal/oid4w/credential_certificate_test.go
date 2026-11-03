package oid4w

import (
	"context"
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func TestCertificateCredentialSignerUsesDedicatedKeyAcrossIssuancePaths(t *testing.T) {
	chain, keyPEM, key := metadataTestMaterial(t, nil)
	certified, err := newCertificateMetadataSigner(chain, keyPEM)
	require.NoError(t, err)
	signer := &CertificateCredentialSigner{certified}
	org := &models.Organization{ID: uuid.New(), Slug: "tenant", Name: "Example laboratory"}
	user := &models.User{ID: uuid.New(), Email: "fictional@example.invalid", Metadata: map[string]interface{}{"dob": "1990-01-01"}}
	cfg := &models.CredentialConfig{VCT: "urn:example:certificate", TTLSeconds: 86400, SelectiveDisclosure: true, ClaimsMapping: map[string]interface{}{"age_over_18": "metadata.dob"}}
	for _, path := range []string{"identity", "age", "verified"} {
		t.Run(path, func(t *testing.T) {
			var credential string
			var err error
			switch path {
			case "identity":
				credential, _, err = IssueIdentityCredential(user, org, cfg, signer, "https://issuer.example", nil)
			case "age":
				credential, _, err = IssueAgeCredential(user, org, cfg, signer, "https://issuer.example", nil)
			case "verified":
				credential, _, err = IssueVerifiedCredential(map[string]interface{}{"course": "Example"}, user.ID.String(), org, cfg, signer, "https://issuer.example", nil)
			}
			require.NoError(t, err)
			token, err := jwt.Parse([]byte(strings.Split(credential, "~")[0]), jwt.WithKey(jwa.ES256, &key.PublicKey))
			require.NoError(t, err)
			require.Equal(t, certified.certificates[0].NotAfter, token.Expiration())
			require.False(t, token.IssuedAt().Before(certified.certificates[0].NotBefore))
			require.Equal(t, "https://issuer.example/tenant", token.Issuer())
		})
	}
	// Signing must fail after certificate expiry, including direct library calls.
	certified.certificates[0].NotAfter = time.Now().Add(-time.Minute)
	_, _, err = IssueVerifiedCredential(map[string]interface{}{"course": "Example"}, user.ID.String(), org, cfg, signer, "https://issuer.example", nil)
	require.Error(t, err)
	require.Error(t, signer.Rotate())
	require.Nil(t, signer.PrivateKey(), "an EC credential signer must not expose an unrelated RSA key")
}

func TestCertificateCredentialECKeyRemainsLocalForDCQL(t *testing.T) {
	_, _, key := metadataTestMaterial(t, nil)
	p := baseParams(t)
	p.Signer, p.Alg = key, jwa.ES256
	bound := finalPresentation(t, p, finalHolder(t), jwa.ES256, "kb+jwt", "correct")
	result, err := VerifyDCQLPresentation(context.Background(), bound, finalQuery(p.VCT, nil), "session-nonce", "verifier", map[string]crypto.PublicKey{p.Issuer: &key.PublicKey}, true, &key.PublicKey)
	require.NoError(t, err)
	require.True(t, result.Identity.SignedByLocalIssuer)
	require.True(t, result.Identity.IssuerTrusted)
	require.True(t, result.Identity.HolderBound)
}

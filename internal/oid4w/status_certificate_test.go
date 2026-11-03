package oid4w

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func TestStatusListPublicKeyAndCertificateMatchActualSignature(t *testing.T) {
	chainPEM, keyPEM, key := metadataTestMaterial(t, nil)
	certified, err := newCertificateMetadataSigner(chainPEM, keyPEM)
	require.NoError(t, err)
	chain, expires, err := certified.MetadataCertificateChain("https://issuer.example/tenant")
	require.NoError(t, err)
	p := StatusListJWTParams{Issuer: "https://issuer.example/tenant", ListURI: "https://issuer.example/tenant/status/one", StatusList: NewStatusList(), TTL: 24 * time.Hour, Signer: key, Algorithm: jwa.ES256, KID: certified.KID(), X5C: chain, CertificateExpiresAt: expires}
	raw, err := IssueStatusListJWT(p)
	require.NoError(t, err)
	token, err := jwt.Parse([]byte(raw), jwt.WithKey(jwa.ES256, &key.PublicKey))
	require.NoError(t, err)
	require.Equal(t, expires, token.Expiration())
	message, err := jws.Parse([]byte(raw))
	require.NoError(t, err)
	headers := message.Signatures()[0].ProtectedHeaders()
	require.Equal(t, 1, headers.X509CertChain().Len(), "root excluded")
	embedded := headers.JWK()
	require.NotNil(t, embedded)
	encoded, err := json.Marshal(embedded)
	require.NoError(t, err)
	var public map[string]any
	require.NoError(t, json.Unmarshal(encoded, &public))
	require.NotContains(t, public, "d")
	require.NotContains(t, public, "k")
	require.Equal(t, "sig", public["use"])
	_, err = jwt.Parse([]byte(raw), jwt.WithKey(jwa.ES256, embedded))
	require.NoError(t, err)
	ref := BuildStatusClaim(p.ListURI, 0)
	_, err = ValidateStatusListToken(raw, ref, p.Issuer, &key.PublicKey, time.Now(), 24*time.Hour)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = ValidateStatusListToken(raw, ref, p.Issuer, &other.PublicKey, time.Now(), 24*time.Hour)
	require.Error(t, err, "header jwk must not replace configured trust")
	p.Signer = other
	_, err = IssueStatusListJWT(p)
	require.ErrorContains(t, err, "does not match")
	p.Signer = key
	p.CertificateExpiresAt = time.Now().Add(-time.Second)
	_, err = IssueStatusListJWT(p)
	require.Error(t, err)
	// A certificate-less profile still publishes the public verification key.
	p.X5C = nil
	p.CertificateExpiresAt = time.Time{}
	raw, err = IssueStatusListJWT(p)
	require.NoError(t, err)
	head, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[0])
	require.NoError(t, err)
	require.NotContains(t, string(head), "x5c")
}

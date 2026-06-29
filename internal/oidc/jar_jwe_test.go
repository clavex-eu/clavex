package oidc_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	jweIssuer   = "https://clavex.example.com/test-org"
	jweClientID = "fed-rp"
)

// stubDecrypter implements oidc.JWEDecrypter with a fixed RSA private key,
// mirroring what EncKeySet does at runtime.
type stubDecrypter struct{ priv *rsa.PrivateKey }

func (s stubDecrypter) DecryptJWE(compact string) (string, error) {
	pt, err := jwe.Decrypt([]byte(compact), jwe.WithKey(jwa.RSA_OAEP_256, s.priv))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// inlineJWKS marshals the RSA public key as an inline JWKS for an OIDCClient.
func inlineJWKS(t *testing.T, priv *rsa.PrivateKey) *json.RawMessage {
	t.Helper()
	pub, err := jwk.FromRaw(priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, testKID))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	rm := json.RawMessage(raw)
	return &rm
}

// signedRequestObject builds a signed JAR request object for the federation RP.
func signedRequestObject(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(jweClientID).
		Audience([]string{jweIssuer}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5*time.Minute)).
		JwtID("jti-jwe-1").
		Claim("client_id", jweClientID).
		Claim("response_type", "code").
		Claim("scope", "openid profile").
		Claim("redirect_uri", "https://rp.example.com/cb").
		Claim("state", "xyz").
		Build()
	require.NoError(t, err)
	privKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, testKID))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	require.NoError(t, err)
	return string(signed)
}

func TestParseJAR_EncryptedRequestObject(t *testing.T) {
	rpKey := generateRSAKey(t)   // RP signs the request object
	opEncKey := generateRSAKey(t) // OP decrypts the JWE

	client := &models.OIDCClient{
		ClientID: jweClientID,
		JWKS:     inlineJWKS(t, rpKey),
		// federation_entity_id marks this as a federation client (RFC 9101 timing).
		Metadata: map[string]interface{}{"federation_entity_id": "https://rp.example.com"},
	}

	inner := signedRequestObject(t, rpKey)

	// Wrap the signed request object in a JWE to the OP's published enc key.
	jweCompact, err := jwe.Encrypt(
		[]byte(inner),
		jwe.WithKey(jwa.RSA_OAEP_256, &opEncKey.PublicKey),
		jwe.WithContentEncryption(jwa.A256GCM),
	)
	require.NoError(t, err)
	require.True(t, oidc.IsJWE(string(jweCompact)), "encrypted request object must be detected as JWE")

	// With a decrypter the encrypted request object is unwrapped and verified.
	params, err := oidc.ParseJAR(
		context.Background(),
		string(jweCompact),
		client,
		jweIssuer,
		oidc.WithJWEDecrypter(stubDecrypter{priv: opEncKey}),
	)
	require.NoError(t, err)
	assert.Equal(t, "code", params["response_type"])
	assert.Equal(t, "openid profile", params["scope"])
	assert.Equal(t, "https://rp.example.com/cb", params["redirect_uri"])
	assert.Equal(t, "xyz", params["state"])

	// Without a decrypter an encrypted request object is rejected (matches an OP
	// that does not publish an encryption key).
	_, err = oidc.ParseJAR(context.Background(), string(jweCompact), client, jweIssuer)
	require.Error(t, err)
	assert.True(t, oidc.IsJARError(err))
}

func TestIsJWE(t *testing.T) {
	assert.False(t, oidc.IsJWE("a.b"))       // unsecured JWT
	assert.False(t, oidc.IsJWE("a.b.c"))     // compact JWS
	assert.True(t, oidc.IsJWE("a.b.c.d.e"))  // compact JWE
}

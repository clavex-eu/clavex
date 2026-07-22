package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	jbTokenEndpoint = "https://clavex.example.com/test-org/token"
	jbExternalIss   = "https://idp.partner.example.com"
	jbSubject       = "partner-user-42"
)

// makeJWTBearerAssertion creates a signed RFC 7523 JWT Bearer grant assertion.
// Unlike a private_key_jwt client assertion, iss (the external issuer) and sub
// (the asserted subject) are intentionally independent.
func makeJWTBearerAssertion(t *testing.T, priv *rsa.PrivateKey, kid string, opts ...func(*jwt.Builder) *jwt.Builder) string {
	t.Helper()
	b := jwt.NewBuilder().
		Issuer(jbExternalIss).
		Subject(jbSubject).
		Audience([]string{jbTokenEndpoint}).
		JwtID(uuid.NewString()).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute))
	for _, o := range opts {
		b = o(b)
	}
	tok, err := b.Build()
	require.NoError(t, err)
	privKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, kid))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	require.NoError(t, err)
	return string(signed)
}

func jbPublicKeySet(t *testing.T, priv *rsa.PrivateKey, kid string) jwk.Set {
	t.Helper()
	pub, err := jwk.FromRaw(priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	s := jwk.NewSet()
	require.NoError(t, s.AddKey(pub))
	return s
}

func TestValidateJWTBearerGrant_Valid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks := jbPublicKeySet(t, priv, "kid-1")
	assertion := makeJWTBearerAssertion(t, priv, "kid-1")

	tok, err := oidc.ValidateJWTBearerGrant(context.Background(), assertion, ks, jbTokenEndpoint, nil)
	require.NoError(t, err)
	assert.Equal(t, jbSubject, tok.Subject())
	assert.Equal(t, jbExternalIss, tok.Issuer())
}

func TestValidateJWTBearerGrant_UntrustedIssuerKeyMismatch(t *testing.T) {
	// Simulates the caller resolving the wrong (untrusted) issuer's key set —
	// signature verification fails because the assertion was signed by a
	// different key than the one on file for the claimed issuer.
	signingPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Server has the wrong (untrusted) issuer's public key on file.
	wrongKS := jbPublicKeySet(t, otherPriv, "kid-1")
	assertion := makeJWTBearerAssertion(t, signingPriv, "kid-1")

	_, err = oidc.ValidateJWTBearerGrant(context.Background(), assertion, wrongKS, jbTokenEndpoint, nil)
	require.Error(t, err)
	var te *oidc.TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
	assert.Contains(t, te.Description, "verification failed")
}

func TestValidateJWTBearerGrant_Expired(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks := jbPublicKeySet(t, priv, "kid-1")

	assertion := makeJWTBearerAssertion(t, priv, "kid-1", func(b *jwt.Builder) *jwt.Builder {
		return b.
			IssuedAt(time.Now().Add(-10 * time.Minute)).
			Expiration(time.Now().Add(-5 * time.Minute)) // well outside 30s skew
	})

	_, err = oidc.ValidateJWTBearerGrant(context.Background(), assertion, ks, jbTokenEndpoint, nil)
	require.Error(t, err)
	var te *oidc.TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
}

func TestValidateJWTBearerGrant_NotYetValid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks := jbPublicKeySet(t, priv, "kid-1")

	assertion := makeJWTBearerAssertion(t, priv, "kid-1", func(b *jwt.Builder) *jwt.Builder {
		return b.NotBefore(time.Now().Add(10 * time.Minute)) // well outside 30s skew
	})

	_, err = oidc.ValidateJWTBearerGrant(context.Background(), assertion, ks, jbTokenEndpoint, nil)
	require.Error(t, err)
	var te *oidc.TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
}

func TestValidateJWTBearerGrant_WrongAudience(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks := jbPublicKeySet(t, priv, "kid-1")

	assertion := makeJWTBearerAssertion(t, priv, "kid-1", func(b *jwt.Builder) *jwt.Builder {
		return b.Audience([]string{"https://other-server.example.com/token"})
	})

	_, err = oidc.ValidateJWTBearerGrant(context.Background(), assertion, ks, jbTokenEndpoint, nil)
	require.Error(t, err)
	var te *oidc.TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
	assert.Contains(t, te.Description, "aud")
}

func TestValidateJWTBearerGrant_MissingSub(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks := jbPublicKeySet(t, priv, "kid-1")

	tok, err := jwt.NewBuilder().
		Issuer(jbExternalIss).
		Audience([]string{jbTokenEndpoint}).
		JwtID(uuid.NewString()).
		IssuedAt(time.Now()).Expiration(time.Now().Add(5 * time.Minute)).
		Build()
	require.NoError(t, err)
	privKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "kid-1"))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	require.NoError(t, err)

	_, err = oidc.ValidateJWTBearerGrant(context.Background(), string(signed), ks, jbTokenEndpoint, nil)
	require.Error(t, err)
	var te *oidc.TokenError
	require.ErrorAs(t, err, &te)
	assert.Contains(t, te.Description, "sub")
}

func TestValidateJWTBearerGrant_AlgNoneRejected(t *testing.T) {
	tok, err := jwt.NewBuilder().
		Issuer(jbExternalIss).Subject(jbSubject).
		Audience([]string{jbTokenEndpoint}).
		JwtID(uuid.NewString()).
		IssuedAt(time.Now()).Expiration(time.Now().Add(5 * time.Minute)).
		Build()
	require.NoError(t, err)
	noneAssertion, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	require.NoError(t, err)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks := jbPublicKeySet(t, priv, "kid-1")

	_, err = oidc.ValidateJWTBearerGrant(context.Background(), string(noneAssertion), ks, jbTokenEndpoint, nil)
	require.Error(t, err)
	var te *oidc.TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
}

func TestValidateJWTBearerGrant_JTIReplay(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks := jbPublicKeySet(t, priv, "kid-1")
	cache := newMapJTICache()

	fixedJTI := uuid.NewString()
	assertion := makeJWTBearerAssertion(t, priv, "kid-1", func(b *jwt.Builder) *jwt.Builder {
		return b.JwtID(fixedJTI)
	})

	_, err = oidc.ValidateJWTBearerGrant(context.Background(), assertion, ks, jbTokenEndpoint, cache)
	require.NoError(t, err)

	_, err = oidc.ValidateJWTBearerGrant(context.Background(), assertion, ks, jbTokenEndpoint, cache)
	require.Error(t, err)
	var te *oidc.TokenError
	require.ErrorAs(t, err, &te)
	assert.Contains(t, te.Description, "jti")
}

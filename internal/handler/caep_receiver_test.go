package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

// caepTestTransmitter spins up a JWKS server for a freshly generated RSA key and
// returns the signing key + the JWKS URL.
func caepTestTransmitter(t *testing.T) (jwk.Key, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)
	_ = signKey.Set(jwk.KeyIDKey, "k1")
	_ = signKey.Set(jwk.AlgorithmKey, jwa.RS256)

	pub, err := signKey.PublicKey()
	require.NoError(t, err)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(ts.Close)
	return signKey, ts.URL
}

func signSET(t *testing.T, key jwk.Key, issuer string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		IssuedAt(time.Now()).
		Claim("events", map[string]any{"https://schemas.openid.net/secevent/caep/event-type/session-revoked": map[string]any{}}).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key))
	require.NoError(t, err)
	return string(signed)
}

func TestVerifySET_AcceptsTrustedSignedSET(t *testing.T) {
	signKey, jwksURL := caepTestTransmitter(t)
	const iss = "https://trusted-transmitter.example"
	h := NewCAEPReceiverHandler(nil, nil, nil, nil).
		WithTrustedTransmitters([]config.SSFTrustedTransmitter{{Issuer: iss, JWKSURI: jwksURL}})

	tok, err := h.verifySET(context.Background(), signSET(t, signKey, iss))
	require.NoError(t, err)
	require.Equal(t, iss, tok.Issuer())
}

func TestVerifySET_RejectsUnknownIssuer(t *testing.T) {
	signKey, jwksURL := caepTestTransmitter(t)
	h := NewCAEPReceiverHandler(nil, nil, nil, nil).
		WithTrustedTransmitters([]config.SSFTrustedTransmitter{{Issuer: "https://trusted.example", JWKSURI: jwksURL}})

	// SET signed by the same key but with an issuer not in the allow-list.
	_, err := h.verifySET(context.Background(), signSET(t, signKey, "https://evil.example"))
	require.Error(t, err)
}

func TestVerifySET_RejectsWhenNoTransmittersConfigured(t *testing.T) {
	signKey, _ := caepTestTransmitter(t)
	h := NewCAEPReceiverHandler(nil, nil, nil, nil) // fail-closed: nothing configured

	_, err := h.verifySET(context.Background(), signSET(t, signKey, "https://whoever.example"))
	require.Error(t, err)
}

func TestVerifySET_RejectsWrongKeySignature(t *testing.T) {
	_, jwksURL := caepTestTransmitter(t)
	const iss = "https://trusted.example"
	h := NewCAEPReceiverHandler(nil, nil, nil, nil).
		WithTrustedTransmitters([]config.SSFTrustedTransmitter{{Issuer: iss, JWKSURI: jwksURL}})

	// Sign with a DIFFERENT key than the one published in the trusted JWKS.
	otherPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := jwk.FromRaw(otherPriv)
	_ = otherKey.Set(jwk.KeyIDKey, "k1")
	_, err := h.verifySET(context.Background(), signSET(t, otherKey, iss))
	require.Error(t, err)
}

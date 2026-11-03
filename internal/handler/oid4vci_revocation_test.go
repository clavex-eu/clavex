package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestVCIJWTAccessRevocationEnforcedBeforeIssuance(t *testing.T) {
	f := vciFixture(t)
	h, clientID, secret := confidentialWallet(t, f)
	raw, verifier := createWalletCode(t, f, clientID, oid4w.CredentialConfigID(f.cfg.VCT))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {raw}, "redirect_uri": {"https://wallet.example/callback"}, "code_verifier": {verifier}}
	rec := walletHTTP(t, f, basicWallet(h.Token, clientID, secret), "token", form, nil, "", "", nil)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var tokens walletTokens
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tokens))
	tc := &oidc.TokenConfig{Keys: f.h.keys, Issuer: "https://issuer.example/" + f.org.Slug}
	_, jti, _, err := tc.VerifyAccessToken(tokens.Access)
	require.NoError(t, err)
	// A missing proof reaches the proof check with a valid, active token.
	body := map[string]any{"credential_configuration_id": oid4w.CredentialConfigID(f.cfg.VCT)}
	rec = f.request(t, f.h.Credential, tokens.Access, body)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.NoError(t, session.NewStore(f.h.rdb).RevokeToken(context.Background(), jti, time.Minute))
	rec = f.request(t, f.h.Credential, tokens.Access, body)
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	// No usable revocation store means no issuance, even with a valid signature.
	original := f.h.rdb
	f.h.rdb = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: time.Millisecond})

	rec = f.request(t, f.h.Credential, tokens.Access, body)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	_ = f.h.rdb.Close()
	f.h.rdb = original
}

func TestVCICodeReplayRevokesJWTButInvalidReplayDoesNot(t *testing.T) {
	f := vciFixture(t)
	h, id, secret := confidentialWallet(t, f)
	other, otherSecret, err := h.clients.Create(context.Background(), f.org.ID, "", "other", []string{"https://wallet.example/callback"}, nil, nil, nil, nil, false)
	require.NoError(t, err)
	raw, verifier := createWalletCode(t, f, id, oid4w.CredentialConfigID(f.cfg.VCT))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {raw}, "redirect_uri": {"https://wallet.example/callback"}, "code_verifier": {verifier}}
	rec := walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var tokens walletTokens
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tokens))
	body := map[string]any{"credential_configuration_id": oid4w.CredentialConfigID(f.cfg.VCT)}
	check := func(want int) {
		t.Helper()
		r := f.request(t, f.h.Credential, tokens.Access, body)
		require.Equal(t, want, r.Code, r.Body.String())
	}
	check(400) // Valid token proceeds to proof validation.
	rec = walletHTTP(t, f, basicWallet(h.Token, other.ClientID, otherSecret), "token", form, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	check(400)
	form.Set("code_verifier", "wrong")
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	check(400)
	form.Set("code_verifier", verifier)
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	check(401)
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}}
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", refresh, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
}

func TestVCIWalletCodeReplayInvalidatesOnlyTheAuthenticatedGrant(t *testing.T) {
	f := vciFixture(t)
	h, id, secret := confidentialWallet(t, f)
	_, err := f.pool.Exec(context.Background(), `UPDATE identity.credential_configs SET deferred_issuance=true WHERE id=$1`, f.cfg.ID)
	require.NoError(t, err)
	raw, verifier := createWalletCode(t, f, id, oid4w.CredentialConfigID(f.cfg.VCT))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {raw}, "redirect_uri": {"https://wallet.example/callback"}, "code_verifier": {verifier}}
	tokens := decodeWalletTokens(t, walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil))
	untouchedRaw, untouchedVerifier := createWalletCode(t, f, id, oid4w.CredentialConfigID(f.cfg.VCT))
	untouchedForm := url.Values{"grant_type": {"authorization_code"}, "code": {untouchedRaw}, "redirect_uri": {"https://wallet.example/callback"}, "code_verifier": {untouchedVerifier}}
	untouched := decodeWalletTokens(t, walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", untouchedForm, nil, "", "", nil))
	other, otherSecret, err := h.clients.Create(context.Background(), f.org.ID, "", "other wallet", []string{"https://wallet.example/callback"}, nil, nil, nil, nil, false)
	require.NoError(t, err)
	rec := walletHTTP(t, f, basicWallet(h.Token, other.ClientID, otherSecret), "token", form, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	unrevoked, _, _, err := f.h.repo.WalletGrantForToken(context.Background(), hashToken(tokens.Access), "access")
	require.NoError(t, err)
	require.Nil(t, unrevoked.RevokedAt)
	// A wrong verifier does not revoke the grant or consume a good access token.
	form.Set("code_verifier", "wrong")
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	require.Equal(t, 400, rec.Code)
	grant, _, _, err := f.h.repo.WalletGrantForToken(context.Background(), hashToken(tokens.Access), "access")
	require.NoError(t, err)
	require.Nil(t, grant.RevokedAt)
	form.Set("code_verifier", verifier)
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	require.Equal(t, 400, rec.Code)
	body := map[string]any{"credential_configuration_id": oid4w.CredentialConfigID(f.cfg.VCT)}
	rec = f.request(t, f.h.Credential, tokens.Access, body)
	require.Equal(t, 401, rec.Code, rec.Body.String())
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}}
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", refresh, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	refresh.Set("refresh_token", untouched.Refresh)
	decodeWalletTokens(t, walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", refresh, nil, "", "", nil))
}

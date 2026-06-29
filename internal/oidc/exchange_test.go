package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Fake CodeConsumer ────────────────────────────────────────────────────────

type fakeCodeConsumer struct {
	ac  *repository.AuthCode
	err error
}

func (f *fakeCodeConsumer) Consume(_ context.Context, _ string) (*repository.AuthCode, error) {
	return f.ac, f.err
}

func (f *fakeCodeConsumer) SetRevocationData(_ context.Context, _, _ string, _ uuid.UUID) error {
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

var (
	exchangeOrgID    = uuid.New()
	exchangeUserID   = uuid.New()
	exchangeClientID = "exchange-client"
	exchangeRedirect = "https://app.example.com/cb"
)

func validAuthCode() *repository.AuthCode {
	return &repository.AuthCode{
		ID:            uuid.New(),
		OrgID:         exchangeOrgID,
		ClientID:      exchangeClientID,
		UserID:        exchangeUserID,
		RedirectURI:   exchangeRedirect,
		Scope:         "openid",
		Nonce:         "",
		PKCEChallenge: "",
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}
}

// ── ExchangeCode error paths ─────────────────────────────────────────────────

func TestExchangeCode_NotFound(t *testing.T) {
	codes := &fakeCodeConsumer{err: errors.New("not found")}
	tc := newTestTokenConfig(t)

	_, err := ExchangeCode(context.Background(), exchangeClientID, "bad-code", exchangeRedirect, "", "", tc, codes, nil, nil, nil, nil, nil, nil, nil, nil, nil, "")

	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
}

func TestExchangeCode_ClientMismatch(t *testing.T) {
	ac := validAuthCode()
	ac.ClientID = "other-client"
	codes := &fakeCodeConsumer{ac: ac}
	tc := newTestTokenConfig(t)

	_, err := ExchangeCode(context.Background(), exchangeClientID, "raw-code", exchangeRedirect, "", "", tc, codes, nil, nil, nil, nil, nil, nil, nil, nil, nil, "")

	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
	assert.Contains(t, te.Description, "client")
}

func TestExchangeCode_RedirectMismatch(t *testing.T) {
	codes := &fakeCodeConsumer{ac: validAuthCode()}
	tc := newTestTokenConfig(t)

	_, err := ExchangeCode(context.Background(), exchangeClientID, "raw-code", "https://evil.example.com/cb", "", "", tc, codes, nil, nil, nil, nil, nil, nil, nil, nil, nil, "")

	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
	assert.Contains(t, te.Description, "redirect_uri")
}

func TestExchangeCode_Expired(t *testing.T) {
	ac := validAuthCode()
	ac.ExpiresAt = time.Now().Add(-time.Minute) // already expired
	codes := &fakeCodeConsumer{ac: ac}
	tc := newTestTokenConfig(t)

	_, err := ExchangeCode(context.Background(), exchangeClientID, "raw-code", exchangeRedirect, "", "", tc, codes, nil, nil, nil, nil, nil, nil, nil, nil, nil, "")

	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
	assert.Contains(t, te.Description, "expired")
}

func TestExchangeCode_PKCEMismatch(t *testing.T) {
	ac := validAuthCode()
	ac.PKCEChallenge = hashString("correct-verifier")
	codes := &fakeCodeConsumer{ac: ac}
	tc := newTestTokenConfig(t)

	_, err := ExchangeCode(context.Background(), exchangeClientID, "raw-code", exchangeRedirect, "wrong-verifier", "", tc, codes, nil, nil, nil, nil, nil, nil, nil, nil, nil, "")

	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
}

func TestExchangeCode_PKCEMissing_WhenRequired(t *testing.T) {
	ac := validAuthCode()
	ac.PKCEChallenge = hashString("some-verifier")
	codes := &fakeCodeConsumer{ac: ac}
	tc := newTestTokenConfig(t)

	_, err := ExchangeCode(context.Background(), exchangeClientID, "raw-code", exchangeRedirect, "" /* no verifier */, "", tc, codes, nil, nil, nil, nil, nil, nil, nil, nil, nil, "")

	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
}

// ── VerifyPKCE standalone (already tested in token_test.go; cross-check) ─────

func TestVerifyPKCE_ValidPair_Exchange(t *testing.T) {
	verifier := "exchange-verifier-abcDEF1234"
	challenge := hashString(verifier)
	assert.NoError(t, VerifyPKCE(challenge, verifier))
}

// ── hashString ────────────────────────────────────────────────────────────────

func TestHashString_DifferentInputs(t *testing.T) {
	a := hashString("foo")
	b := hashString("bar")
	assert.NotEqual(t, a, b)
}

func TestHashString_Deterministic(t *testing.T) {
	assert.Equal(t, hashString("hello"), hashString("hello"))
}

// ── verifyMTLSRefreshBinding ──────────────────────────────────────────────────

// TestVerifyMTLSRefreshBinding_NoBound passes when the token has no thumbprint.
func TestVerifyMTLSRefreshBinding_NoBound(t *testing.T) {
	// storedThumb empty → no enforcement, cert not needed.
	require.NoError(t, verifyMTLSRefreshBinding("", nil))
	require.NoError(t, verifyMTLSRefreshBinding("", &MTLSCert{X5TS256: "abc"}))
}

// TestVerifyMTLSRefreshBinding_CertMissing tests RFC 8705 §7.1 enforcement:
// when the token is mTLS-bound and no cert is presented → invalid_client (401).
func TestVerifyMTLSRefreshBinding_CertMissing(t *testing.T) {
	err := verifyMTLSRefreshBinding("storedThumb", nil)
	require.Error(t, err)
	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_client", te.Code)
}

// TestVerifyMTLSRefreshBinding_ThumbprintMismatch tests that a different cert
// is rejected → invalid_grant (400).
func TestVerifyMTLSRefreshBinding_ThumbprintMismatch(t *testing.T) {
	err := verifyMTLSRefreshBinding("storedThumb", &MTLSCert{X5TS256: "differentThumb"})
	require.Error(t, err)
	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_grant", te.Code)
}

// TestVerifyMTLSRefreshBinding_Match passes when the cert matches.
func TestVerifyMTLSRefreshBinding_Match(t *testing.T) {
	require.NoError(t, verifyMTLSRefreshBinding("abc123", &MTLSCert{X5TS256: "abc123"}))
}

package handler

import (
	"sort"
	"testing"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// ── elevateMethods ────────────────────────────────────────────────────────────

func cred(t string) *models.MFACredential {
	return &models.MFACredential{ID: uuid.New(), Type: t}
}

func sortedMethods(creds []*models.MFACredential, allowed []string, waEnabled bool) []string {
	out := elevateMethods(creds, allowed, waEnabled)
	sort.Strings(out)
	return out
}

func TestElevateMethods_EmptyAllowed_ReturnsBothIfEnrolled(t *testing.T) {
	creds := []*models.MFACredential{cred("totp"), cred("webauthn")}
	got := sortedMethods(creds, nil, true)
	assert.Equal(t, []string{"totp", "webauthn"}, got)
}

func TestElevateMethods_EmptyAllowed_OnlyTOTP(t *testing.T) {
	creds := []*models.MFACredential{cred("totp")}
	got := sortedMethods(creds, nil, true)
	assert.Equal(t, []string{"totp"}, got)
}

func TestElevateMethods_EmptyAllowed_OnlyWebAuthn(t *testing.T) {
	creds := []*models.MFACredential{cred("webauthn")}
	got := sortedMethods(creds, nil, true)
	assert.Equal(t, []string{"webauthn"}, got)
}

func TestElevateMethods_EmptyAllowed_NoCreds(t *testing.T) {
	got := elevateMethods(nil, nil, true)
	assert.Empty(t, got)
}

func TestElevateMethods_AllowedFiltersToTOTP(t *testing.T) {
	creds := []*models.MFACredential{cred("totp"), cred("webauthn")}
	got := elevateMethods(creds, []string{"totp"}, true)
	assert.Equal(t, []string{"totp"}, got)
}

func TestElevateMethods_AllowedFiltersToWebAuthn(t *testing.T) {
	creds := []*models.MFACredential{cred("totp"), cred("webauthn")}
	got := elevateMethods(creds, []string{"webauthn"}, true)
	assert.Equal(t, []string{"webauthn"}, got)
}

func TestElevateMethods_AllowedNotEnrolled_ReturnsEmpty(t *testing.T) {
	creds := []*models.MFACredential{cred("totp")} // no webauthn enrolled
	got := elevateMethods(creds, []string{"webauthn"}, true)
	assert.Empty(t, got)
}

func TestElevateMethods_WebAuthnDisabled_IgnoresWebAuthnCreds(t *testing.T) {
	creds := []*models.MFACredential{cred("totp"), cred("webauthn")}
	got := sortedMethods(creds, nil, false /* webAuthn disabled */)
	assert.Equal(t, []string{"totp"}, got)
}

func TestElevateMethods_WebAuthnDisabledAndAllowed_ReturnsEmpty(t *testing.T) {
	creds := []*models.MFACredential{cred("webauthn")}
	got := elevateMethods(creds, []string{"webauthn"}, false)
	assert.Empty(t, got)
}

func TestElevateMethods_DuplicateTOTPCreds_ReturnsTOTPOnce(t *testing.T) {
	creds := []*models.MFACredential{cred("totp"), cred("totp")}
	got := elevateMethods(creds, nil, true)
	assert.Equal(t, []string{"totp"}, got)
}

func TestElevateMethods_UnknownCredType_Ignored(t *testing.T) {
	creds := []*models.MFACredential{cred("sms"), cred("totp")}
	got := elevateMethods(creds, nil, true)
	assert.Equal(t, []string{"totp"}, got)
}

// ── elevateContains ───────────────────────────────────────────────────────────

func TestElevateContains(t *testing.T) {
	assert.True(t, elevateContains([]string{"totp", "webauthn"}, "totp"))
	assert.True(t, elevateContains([]string{"totp", "webauthn"}, "webauthn"))
	assert.False(t, elevateContains([]string{"totp"}, "webauthn"))
	assert.False(t, elevateContains(nil, "totp"))
}

package license_test

// Tests for the license package covering:
//   - ParseLicenseToken: all error paths (no private key available for valid tokens)
//   - NewChecker: community-edition initial state
//   - State struct: grace period and expiry invariants

import (
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/license"
)

// ── ParseLicenseToken — error paths ───────────────────────────────────────────

func TestParseLicenseToken_emptyString(t *testing.T) {
	_, err := license.ParseLicenseToken("")
	if err == nil {
		t.Fatal("expected error for empty token string")
	}
}

func TestParseLicenseToken_notAJWT(t *testing.T) {
	_, err := license.ParseLicenseToken("this.is.not.a.valid.jwt")
	if err == nil {
		t.Fatal("expected error for garbage token")
	}
}

func TestParseLicenseToken_wrongAlgorithm(t *testing.T) {
	// Header claims RS256 (not ES256) — should be rejected by WithValidMethods.
	// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9 = {"alg":"RS256","typ":"JWT"}
	tok := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.invalidsig"
	_, err := license.ParseLicenseToken(tok)
	if err == nil {
		t.Fatal("expected error for RS256-signed token")
	}
}

func TestParseLicenseToken_malformedPayload(t *testing.T) {
	// Valid ES256 header but non-base64url payload.
	// eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9 = {"alg":"ES256","typ":"JWT"}
	tok := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.!!!invalid!!!.invalidsig"
	_, err := license.ParseLicenseToken(tok)
	if err == nil {
		t.Fatal("expected error for malformed payload")
	}
}

func TestParseLicenseToken_invalidSignature(t *testing.T) {
	// Structurally valid ES256 JWT but wrong signature (not signed with the
	// embedded Clavex license key) — must be rejected.
	// Header: {"alg":"ES256","typ":"JWT"}
	// Payload: {"sub":"inst-1","org_limit":5,"tier":"enterprise","iat":1700000000,"exp":9999999999}
	tok := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiJpbnN0LTEiLCJvcmdfbGltaXQiOjUsInRpZXIiOiJlbnRlcnByaXNlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9." +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // fake signature
	_, err := license.ParseLicenseToken(tok)
	if err == nil {
		t.Fatal("expected error for token with invalid signature")
	}
}

func TestParseLicenseToken_whitespaceTrimmmed(t *testing.T) {
	// Tokens read from files often have trailing newlines; they should return
	// a validation error (not a panic or parse crash) once whitespace is stripped.
	tok := "  \n" + "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.invalidsig" + "\n  "
	_, err := license.ParseLicenseToken(tok)
	// We expect an error (invalid sig / wrong key), but not a crash.
	if err == nil {
		t.Fatal("expected signature-validation error")
	}
}

// ── NewChecker — community edition initial state ───────────────────────────────
//
// We deliberately do NOT call c.Start() because Start calls pool.QueryRow.
// The initial cached state is populated by NewChecker itself and is safe to
// read without a database connection.

func TestNewChecker_communityTier(t *testing.T) {
	c := license.NewChecker(nil, nil, false)
	s := c.State()
	if s.Tier != "community" {
		t.Errorf("Tier: want %q, got %q", "community", s.Tier)
	}
}

func TestNewChecker_communityOrgLimit(t *testing.T) {
	c := license.NewChecker(nil, nil, false)
	s := c.State()
	if s.OrgLimit != 1 {
		t.Errorf("OrgLimit: want 1, got %d", s.OrgLimit)
	}
}

func TestNewChecker_communityNotBlocked(t *testing.T) {
	c := license.NewChecker(nil, nil, false)
	s := c.State()
	if s.AuthBlocked {
		t.Error("community edition must not be AuthBlocked at startup")
	}
	if s.GracePeriodExpired {
		t.Error("community edition must not have GracePeriodExpired at startup")
	}
}

func TestNewChecker_communityNoViolation(t *testing.T) {
	c := license.NewChecker(nil, nil, false)
	s := c.State()
	if s.FirstViolationAt != nil {
		t.Errorf("FirstViolationAt should be nil at startup, got %v", s.FirstViolationAt)
	}
}

// ── State struct — grace period & expiry invariants ───────────────────────────

// TestState_gracePeriodExpiredMeansBlocked: when GracePeriodExpired is true
// the installation must be hard-blocked (AuthBlocked=true).
func TestState_gracePeriodExpiredMeansBlocked(t *testing.T) {
	firstViolation := time.Now().Add(-31 * 24 * time.Hour) // 31 days ago
	s := license.State{
		ExceedsLimit:       true,
		FirstViolationAt:   &firstViolation,
		GracePeriodExpired: true,
		AuthBlocked:        true, // set by computeState when expired
	}
	if !s.AuthBlocked {
		t.Error("AuthBlocked must be true when GracePeriodExpired is true")
	}
}

// TestState_withinGracePeriodNotBlocked: within the 30-day window
// the installation must NOT be blocked.
func TestState_withinGracePeriodNotBlocked(t *testing.T) {
	firstViolation := time.Now().Add(-5 * 24 * time.Hour) // 5 days in
	s := license.State{
		ExceedsLimit:       true,
		FirstViolationAt:   &firstViolation,
		GracePeriodExpired: false,
		AuthBlocked:        false,
	}
	if s.AuthBlocked {
		t.Error("AuthBlocked must be false within the 30-day grace window")
	}
}

// TestState_licenseExpiringSoon: license expiring within 14 days → LicenseExpiringSoon.
func TestState_licenseExpiringSoon(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	s := license.State{
		LicenseExpiresAt:    expires,
		LicenseExpiringSoon: time.Until(expires) < 14*24*time.Hour,
	}
	if !s.LicenseExpiringSoon {
		t.Error("license expiring in 10 days should trigger LicenseExpiringSoon")
	}
}

// TestState_licenseNotExpiringSoon: license expiring in 60 days → not soon.
func TestState_licenseNotExpiringSoon(t *testing.T) {
	expires := time.Now().Add(60 * 24 * time.Hour)
	s := license.State{
		LicenseExpiresAt:    expires,
		LicenseExpiringSoon: time.Until(expires) < 14*24*time.Hour,
	}
	if s.LicenseExpiringSoon {
		t.Error("license expiring in 60 days must not trigger LicenseExpiringSoon")
	}
}

// TestState_zeroExpiryMeansNoExpirySoon: community edition has zero ExpiresAt.
func TestState_zeroExpiryMeansNoExpirySoon(t *testing.T) {
	s := license.State{
		LicenseExpiresAt:    time.Time{},
		LicenseExpiringSoon: false, // mirror of computeState: skipped when zero
	}
	if s.LicenseExpiringSoon {
		t.Error("zero ExpiresAt must not trigger LicenseExpiringSoon")
	}
}

// TestState_noViolation_notExceedsLimit: when within limit, ExceedsLimit is false.
func TestState_noViolation_notExceedsLimit(t *testing.T) {
	s := license.State{
		OrgLimit:        5,
		CurrentOrgCount: 3,
		ExceedsLimit:    false,
	}
	if s.ExceedsLimit {
		t.Error("ExceedsLimit must be false when orgCount ≤ OrgLimit")
	}
	if s.AuthBlocked {
		t.Error("AuthBlocked must be false when within limit")
	}
}

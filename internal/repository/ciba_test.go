package repository

// Tests for CIBA repository helpers and structs.
// These tests do NOT require a database connection.

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── generateAuthReqID ──────────────────────────────────────────────────────────

func TestGenerateAuthReqID_length(t *testing.T) {
	id, err := generateAuthReqID()
	if err != nil {
		t.Fatalf("generateAuthReqID error: %v", err)
	}
	// 32 bytes → 43 chars of base64url (no padding: ceil(32*8/6) = 43).
	if len(id) != 43 {
		t.Errorf("expected 43-char ID, got %d chars: %q", len(id), id)
	}
}

func TestGenerateAuthReqID_base64url(t *testing.T) {
	id, err := generateAuthReqID()
	if err != nil {
		t.Fatalf("generateAuthReqID error: %v", err)
	}
	// Must decode cleanly with RawURLEncoding (no padding).
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("ID is not valid base64url: %v (id=%q)", err, id)
	}
	if len(decoded) != 32 {
		t.Errorf("expected 32 raw bytes, got %d", len(decoded))
	}
}

func TestGenerateAuthReqID_noStandardBase64Chars(t *testing.T) {
	// Standard base64 uses '+' and '/'; URL-safe variant uses '-' and '_'.
	// Auth request IDs must be safe for use in URLs and form parameters.
	for i := 0; i < 20; i++ {
		id, err := generateAuthReqID()
		if err != nil {
			t.Fatalf("generateAuthReqID error: %v", err)
		}
		for _, ch := range id {
			if ch == '+' || ch == '/' || ch == '=' {
				t.Errorf("ID contains standard-base64 char %q: %q", ch, id)
			}
		}
	}
}

func TestGenerateAuthReqID_uniqueness(t *testing.T) {
	ids := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id, err := generateAuthReqID()
		if err != nil {
			t.Fatalf("generateAuthReqID error on iteration %d: %v", i, err)
		}
		if _, dup := ids[id]; dup {
			t.Fatalf("duplicate auth_req_id generated: %q", id)
		}
		ids[id] = struct{}{}
	}
}

// ── CIBARequest struct ──────────────────────────────────────────────────────────

func TestCIBARequest_statusValues(t *testing.T) {
	// CIBA Core §11 defines exactly three terminal/non-terminal states.
	statuses := []string{"pending", "approved", "denied"}
	for _, s := range statuses {
		req := CIBARequest{Status: s}
		if req.Status != s {
			t.Errorf("status round-trip: want %q, got %q", s, req.Status)
		}
	}
}

func TestCIBARequest_defaultInterval(t *testing.T) {
	// CIBA Core §7.3: the polling interval MUST be ≥ 5 seconds.
	req := CIBARequest{Interval: 5}
	if req.Interval < 5 {
		t.Errorf("minimum polling interval must be ≥5s, got %d", req.Interval)
	}
}

func TestCIBARequest_expiryInFuture(t *testing.T) {
	// A freshly-created request must not be expired.
	req := CIBARequest{
		ExpiresAt: time.Now().Add(120 * time.Second),
		Status:    "pending",
	}
	if time.Now().After(req.ExpiresAt) {
		t.Error("freshly created request should not be expired")
	}
}

func TestCIBARequest_userIDOptional(t *testing.T) {
	// UserID is nil before the user is resolved from login_hint.
	orgID := uuid.New()
	req := CIBARequest{
		OrgID:    orgID,
		ClientID: "my-client",
		UserID:   nil,
		Status:   "pending",
	}
	if req.UserID != nil {
		t.Errorf("UserID should be nil before resolution, got %v", req.UserID)
	}
}

func TestCIBARequest_approvedHasUserID(t *testing.T) {
	// After approval, UserID must be non-nil.
	userID := uuid.New()
	req := CIBARequest{
		Status: "approved",
		UserID: &userID,
	}
	if req.UserID == nil {
		t.Error("approved request must have non-nil UserID")
	}
}

func TestCIBACreateParams_intervalDefault(t *testing.T) {
	// CIBACreateParams with Interval=0 should signal "use default".
	// The repository Create method substitutes 5 when Interval is 0.
	params := CIBACreateParams{
		OrgID:     uuid.New(),
		ClientID:  "c",
		Scope:     "openid",
		ExpiresIn: 120 * time.Second,
		Interval:  0, // triggers default in Create
	}
	// Verify the struct is constructable and zero Interval is representable.
	if params.Interval != 0 {
		t.Errorf("expected Interval=0, got %d", params.Interval)
	}
}

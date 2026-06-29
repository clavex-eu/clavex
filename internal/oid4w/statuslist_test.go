package oid4w_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/google/uuid"
)

// ── NewStatusList ──────────────────────────────────────────────────────────

func TestNewStatusList_AllValid(t *testing.T) {
	sl := oid4w.NewStatusList()
	for _, idx := range []int{0, 1, 1023, 65535} {
		v, err := sl.Get(idx)
		if err != nil {
			t.Fatalf("Get(%d): %v", idx, err)
		}
		if v != oid4w.StatusValid {
			t.Fatalf("expected all valid, got %d at index %d", v, idx)
		}
	}
}

// ── Set / Get ─────────────────────────────────────────────────────────────

func TestSet_RevokeThenGet(t *testing.T) {
	sl := oid4w.NewStatusList()
	if err := sl.Set(42, oid4w.StatusRevoked); err != nil {
		t.Fatalf("Set: %v", err)
	}
	v, err := sl.Get(42)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if v != oid4w.StatusRevoked {
		t.Fatalf("expected revoked, got %d", v)
	}
}

func TestSet_InvalidValue(t *testing.T) {
	sl := oid4w.NewStatusList()
	if err := sl.Set(0, 2); err == nil {
		t.Fatal("expected error for val=2")
	}
}

func TestGet_OutOfRange(t *testing.T) {
	sl := oid4w.NewStatusList()
	if _, err := sl.Get(-1); err == nil {
		t.Fatal("expected error for index -1")
	}
	if _, err := sl.Get(65536); err == nil {
		t.Fatal("expected error for index 65536")
	}
}

// ── Revoke / Restore / IsRevoked ─────────────────────────────────────────

func TestRevoke(t *testing.T) {
	sl := oid4w.NewStatusList()
	if err := sl.Revoke(100); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	ok, err := sl.IsRevoked(100)
	if err != nil || !ok {
		t.Fatalf("IsRevoked after Revoke: revoked=%v err=%v", ok, err)
	}
}

func TestRestore(t *testing.T) {
	sl := oid4w.NewStatusList()
	_ = sl.Revoke(200)
	if err := sl.Restore(200); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	ok, err := sl.IsRevoked(200)
	if err != nil || ok {
		t.Fatalf("IsRevoked after Restore: revoked=%v err=%v", ok, err)
	}
}

func TestRevoke_MultipleBitsIndependent(t *testing.T) {
	sl := oid4w.NewStatusList()
	for _, idx := range []int{0, 7, 8, 15, 16, 63, 64} {
		_ = sl.Revoke(idx)
	}
	for _, idx := range []int{0, 7, 8, 15, 16, 63, 64} {
		ok, _ := sl.IsRevoked(idx)
		if !ok {
			t.Errorf("index %d should be revoked", idx)
		}
	}
	// Neighbouring bits should still be valid.
	for _, idx := range []int{1, 6, 9, 14, 17, 62, 65} {
		ok, _ := sl.IsRevoked(idx)
		if ok {
			t.Errorf("index %d should NOT be revoked", idx)
		}
	}
}

// ── Encode / Decode round-trip ────────────────────────────────────────────

func TestEncode_Decode_RoundTrip(t *testing.T) {
	sl := oid4w.NewStatusList()
	_ = sl.Revoke(0)
	_ = sl.Revoke(255)
	_ = sl.Revoke(1000)
	_ = sl.Revoke(65535)

	encoded, err := sl.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded == "" {
		t.Fatal("Encode returned empty string")
	}

	sl2, err := oid4w.DecodeStatusList(encoded)
	if err != nil {
		t.Fatalf("DecodeStatusList: %v", err)
	}

	for _, idx := range []int{0, 255, 1000, 65535} {
		ok, _ := sl2.IsRevoked(idx)
		if !ok {
			t.Errorf("expected revoked at %d after decode", idx)
		}
	}
	// A non-revoked index should still be valid.
	ok, _ := sl2.IsRevoked(1)
	if ok {
		t.Errorf("index 1 should be valid after decode")
	}
}

func TestDecodeStatusList_InvalidInput(t *testing.T) {
	if _, err := oid4w.DecodeStatusList("!!!not_base64!!!"); err == nil {
		t.Fatal("expected error on invalid base64")
	}
}

// ── IssueStatusListJWT / CheckStatus round-trip ───────────────────────────

func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return k
}

func TestIssueStatusListJWT_CheckStatus(t *testing.T) {
	priv := newTestRSAKey(t)
	sl := oid4w.NewStatusList()
	_ = sl.Revoke(5)

	listID := uuid.New()
	params := oid4w.StatusListJWTParams{
		Issuer:     "https://clavex.example.com",
		ListID:     listID,
		StatusList: sl,
		TTL:        1 * time.Hour,
		PrivateKey: priv,
		KID:        "test-kid",
	}
	tokenStr, err := oid4w.IssueStatusListJWT(params)
	if err != nil {
		t.Fatalf("IssueStatusListJWT: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty JWT")
	}

	// A valid credential (not revoked) should pass.
	sc := oid4w.BuildStatusClaim("https://clavex.example.com/status/"+listID.String(), 10)
	if err := oid4w.CheckStatus(tokenStr, sc, &priv.PublicKey); err != nil {
		t.Fatalf("CheckStatus for valid credential: %v", err)
	}

	// A revoked credential should return ErrRevoked.
	scRevoked := oid4w.BuildStatusClaim("https://clavex.example.com/status/"+listID.String(), 5)
	err = oid4w.CheckStatus(tokenStr, scRevoked, &priv.PublicKey)
	if err != oid4w.ErrRevoked {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

func TestCheckStatus_InvalidJWT(t *testing.T) {
	priv := newTestRSAKey(t)
	sc := oid4w.BuildStatusClaim("https://example.com/list/1", 0)
	err := oid4w.CheckStatus("not.a.jwt", sc, &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error on invalid JWT")
	}
}

func TestCheckStatus_WrongKey(t *testing.T) {
	priv := newTestRSAKey(t)
	other := newTestRSAKey(t)
	sl := oid4w.NewStatusList()
	listID := uuid.New()
	params := oid4w.StatusListJWTParams{
		Issuer:     "https://clavex.example.com",
		ListID:     listID,
		StatusList: sl,
		TTL:        1 * time.Hour,
		PrivateKey: priv,
	}
	tokenStr, _ := oid4w.IssueStatusListJWT(params)
	sc := oid4w.BuildStatusClaim("https://clavex.example.com/status/"+listID.String(), 0)
	if err := oid4w.CheckStatus(tokenStr, sc, &other.PublicKey); err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}

// ── BuildStatusClaim ──────────────────────────────────────────────────────

func TestBuildStatusClaim(t *testing.T) {
	sc := oid4w.BuildStatusClaim("https://example.com/list/abc", 42)
	if sc.StatusList.IDX != 42 {
		t.Errorf("expected IDX=42, got %d", sc.StatusList.IDX)
	}
	if sc.StatusList.URI != "https://example.com/list/abc" {
		t.Errorf("unexpected URI: %s", sc.StatusList.URI)
	}
}

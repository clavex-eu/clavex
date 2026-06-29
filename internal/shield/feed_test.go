package shield_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/shield"
)

// ── Private IP guard ─────────────────────────────────────────────────────────

func TestFeedClient_CheckIP_SkipsPrivate(t *testing.T) {
	cfg := config.ThreatFeedConfig{
		Enabled:   true,
		URL:       "http://localhost",
		SharedKey: "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
	}
	fc, err := shield.NewFeedClient(cfg, "")
	if err != nil {
		t.Fatalf("NewFeedClient: %v", err)
	}
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"} {
		if ok, _ := fc.CheckIP(ip); ok {
			t.Errorf("private/loopback IP %s should not match feed", ip)
		}
	}
}

// ── Enqueue no-ops for Report=false ──────────────────────────────────────────

func TestFeedClient_Enqueue_NoopWhenDisabled(t *testing.T) {
	cfg := config.ThreatFeedConfig{
		Enabled:   true,
		URL:       "http://localhost",
		SharedKey: "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
		Report:    false,
	}
	fc, _ := shield.NewFeedClient(cfg, "")
	// Should not panic.
	fc.Enqueue("203.0.113.1", "brute_force", 0.9)
}

// ── Refresh rejects expired feed ─────────────────────────────────────────────

func TestFeedClient_Refresh_RejectsExpired(t *testing.T) {
	past := time.Now().UTC().Add(-1 * time.Hour)
	feed := shield.SignedFeed{
		Version:   1,
		IssuedAt:  past.Add(-15 * time.Minute),
		ExpiresAt: past,
		Entries:   []shield.FeedEntry{},
		Signature: "dGVzdA",
	}
	feedJSON, _ := json.Marshal(feed)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(feedJSON)
	}))
	defer ts.Close()

	cfg := config.ThreatFeedConfig{
		Enabled:   true,
		URL:       ts.URL,
		SharedKey: "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
	}
	fc, _ := shield.NewFeedClient(cfg, "")
	if err := fc.Refresh(context.Background()); err == nil {
		t.Error("expected error for expired feed, got nil")
	}
}

// ── Refresh + signature verification round-trip ───────────────────────────────

func TestFeedClient_Refresh_SignedFeed(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	feed := &shield.SignedFeed{
		Version:   1,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
		Entries: []shield.FeedEntry{
			{Hash: "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd",
				AttackType: "brute_force", Confidence: 0.9},
		},
	}
	if err := shield.SignFeed(feed, privKey); err != nil {
		t.Fatalf("SignFeed: %v", err)
	}
	feedJSON, _ := json.Marshal(feed)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(feedJSON)
	}))
	defer ts.Close()

	pubPEM := ecPublicKeyPEM(t, &privKey.PublicKey)

	cfg := config.ThreatFeedConfig{
		Enabled:       true,
		URL:           ts.URL,
		SharedKey:     "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
		SigningPubKey: pubPEM,
	}
	fc, err := shield.NewFeedClient(cfg, "")
	if err != nil {
		t.Fatalf("NewFeedClient: %v", err)
	}

	if err := fc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh with valid signature: %v", err)
	}
}

// ── Signature tampering is rejected ──────────────────────────────────────────

func TestFeedClient_Refresh_RejectsBadSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	now := time.Now().UTC()
	feed := &shield.SignedFeed{
		Version:   1,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
		Entries:   []shield.FeedEntry{},
	}
	// Sign with privKey but configure client with otherKey's public key.
	_ = shield.SignFeed(feed, privKey)
	feedJSON, _ := json.Marshal(feed)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(feedJSON)
	}))
	defer ts.Close()

	pubPEM := ecPublicKeyPEM(t, &otherKey.PublicKey)
	cfg := config.ThreatFeedConfig{
		Enabled:       true,
		URL:           ts.URL,
		SharedKey:     "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
		SigningPubKey: pubPEM,
	}
	fc, _ := shield.NewFeedClient(cfg, "")
	if err := fc.Refresh(context.Background()); err == nil {
		t.Error("expected signature verification failure, got nil")
	}
}

// ── helper ────────────────────────────────────────────────────────────────────

func ecPublicKeyPEM(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

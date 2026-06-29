package merkle_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"

	"github.com/clavex-eu/clavex/internal/merkle"
	"github.com/google/uuid"
	"time"
)

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ── LeafHash ──────────────────────────────────────────────────────────────────

func TestLeafHash_Deterministic(t *testing.T) {
	data := []byte(`{"id":1,"action":"user.login"}`)
	h1 := merkle.LeafHash(data)
	h2 := merkle.LeafHash(data)
	if hex.EncodeToString(h1) != hex.EncodeToString(h2) {
		t.Fatal("LeafHash is not deterministic")
	}
}

func TestLeafHash_Different(t *testing.T) {
	h1 := merkle.LeafHash([]byte(`{"id":1}`))
	h2 := merkle.LeafHash([]byte(`{"id":2}`))
	if hex.EncodeToString(h1) == hex.EncodeToString(h2) {
		t.Fatal("different inputs produced the same hash")
	}
}

// ── Root ──────────────────────────────────────────────────────────────────────

func TestRoot_Empty(t *testing.T) {
	if merkle.Root(nil) != nil {
		t.Fatal("empty leaves should return nil")
	}
}

func TestRoot_Single(t *testing.T) {
	leaf := merkle.LeafHash([]byte("a"))
	root := merkle.Root([][]byte{leaf})
	if hex.EncodeToString(root) != hex.EncodeToString(leaf) {
		t.Fatal("single leaf: root should equal the leaf")
	}
}

func TestRoot_Two(t *testing.T) {
	leaves := [][]byte{
		merkle.LeafHash([]byte("a")),
		merkle.LeafHash([]byte("b")),
	}
	root := merkle.Root(leaves)
	if len(root) != 32 {
		t.Fatalf("expected 32-byte root, got %d", len(root))
	}
}

func TestRoot_OddLeaves(t *testing.T) {
	// Three leaves — last one is duplicated internally.
	leaves := [][]byte{
		merkle.LeafHash([]byte("a")),
		merkle.LeafHash([]byte("b")),
		merkle.LeafHash([]byte("c")),
	}
	root := merkle.Root(leaves)
	if root == nil {
		t.Fatal("unexpected nil root for 3 leaves")
	}
}

func TestRoot_Deterministic(t *testing.T) {
	leaves := [][]byte{
		merkle.LeafHash([]byte("x")),
		merkle.LeafHash([]byte("y")),
		merkle.LeafHash([]byte("z")),
	}
	r1 := hex.EncodeToString(merkle.Root(leaves))
	r2 := hex.EncodeToString(merkle.Root(leaves))
	if r1 != r2 {
		t.Fatal("Root is not deterministic")
	}
}

func TestRoot_OrderSensitive(t *testing.T) {
	l1 := merkle.LeafHash([]byte("a"))
	l2 := merkle.LeafHash([]byte("b"))
	r1 := hex.EncodeToString(merkle.Root([][]byte{l1, l2}))
	r2 := hex.EncodeToString(merkle.Root([][]byte{l2, l1}))
	if r1 == r2 {
		t.Fatal("Root should be order-sensitive")
	}
}

// ── Sign / Verify round-trip ──────────────────────────────────────────────────

func TestSignVerify(t *testing.T) {
	key := genKey(t)
	leaves := [][]byte{
		merkle.LeafHash([]byte(`{"id":1}`)),
		merkle.LeafHash([]byte(`{"id":2}`)),
	}
	root := merkle.Root(leaves)
	orgID := uuid.NewString()

	proof, err := merkle.Sign(root, "", key, "kid-1", orgID, 1, 2, 2)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if proof.MerkleRoot == "" || proof.Signature == "" || proof.ChainHash == "" {
		t.Fatal("Sign returned empty fields")
	}

	if err := merkle.Verify(proof, &key.PublicKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	key := genKey(t)
	other := genKey(t)
	root := merkle.Root([][]byte{merkle.LeafHash([]byte("x"))})
	proof, _ := merkle.Sign(root, "", key, "k", uuid.NewString(), 1, 1, 1)
	if err := merkle.Verify(proof, &other.PublicKey); err == nil {
		t.Fatal("expected error with wrong key")
	}
}

func TestVerify_TamperedRoot(t *testing.T) {
	key := genKey(t)
	root := merkle.Root([][]byte{merkle.LeafHash([]byte("x"))})
	proof, _ := merkle.Sign(root, "", key, "k", uuid.NewString(), 1, 1, 1)
	proof.MerkleRoot = "deadbeef" + proof.MerkleRoot[8:] // tamper
	if err := merkle.Verify(proof, &key.PublicKey); err == nil {
		t.Fatal("expected error for tampered root")
	}
}

// ── VerifyChain ───────────────────────────────────────────────────────────────

func TestVerifyChain_Valid(t *testing.T) {
	key := genKey(t)
	orgID := uuid.NewString()

	rows1 := [][]byte{merkle.LeafHash([]byte("a")), merkle.LeafHash([]byte("b"))}
	root1 := merkle.Root(rows1)
	p1, _ := merkle.Sign(root1, "", key, "k", orgID, 1, 2, 2)

	rows2 := [][]byte{merkle.LeafHash([]byte("c")), merkle.LeafHash([]byte("d"))}
	root2 := merkle.Root(rows2)
	p2, _ := merkle.Sign(root2, p1.MerkleRoot, key, "k", orgID, 3, 4, 2)

	if err := merkle.VerifyChain([]*merkle.Proof{p1, p2}, &key.PublicKey); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestVerifyChain_BrokenLink(t *testing.T) {
	key := genKey(t)
	orgID := uuid.NewString()
	root1 := merkle.Root([][]byte{merkle.LeafHash([]byte("a"))})
	p1, _ := merkle.Sign(root1, "", key, "k", orgID, 1, 1, 1)

	root2 := merkle.Root([][]byte{merkle.LeafHash([]byte("b"))})
	// Intentionally pass wrong prev_root.
	p2, _ := merkle.Sign(root2, "wrongprev", key, "k", orgID, 2, 2, 1)

	if err := merkle.VerifyChain([]*merkle.Proof{p1, p2}, &key.PublicKey); err == nil {
		t.Fatal("expected error for broken chain link")
	}
}

// ── RebuildRoot ───────────────────────────────────────────────────────────────

func TestRebuildRoot_MatchesOriginal(t *testing.T) {
	rows := [][]byte{
		[]byte(`{"id":1,"action":"login","status":"success","created_at":"2026-01-01T00:00:00Z"}`),
		[]byte(`{"id":2,"action":"user.create","status":"success","created_at":"2026-01-01T00:01:00Z"}`),
		[]byte(`{"id":3,"action":"user.delete","status":"success","created_at":"2026-01-01T00:02:00Z"}`),
	}
	leaves := make([][]byte, len(rows))
	for i, r := range rows {
		leaves[i] = merkle.LeafHash(r)
	}
	original := merkle.Root(leaves)
	rebuilt := merkle.RebuildRoot(rows)
	if hex.EncodeToString(original) != hex.EncodeToString(rebuilt) {
		t.Fatal("RebuildRoot does not match original root")
	}
}

func TestRebuildRoot_TamperedRow(t *testing.T) {
	rows := [][]byte{
		[]byte(`{"id":1,"action":"login"}`),
		[]byte(`{"id":2,"action":"logout"}`),
	}
	original := merkle.RebuildRoot(rows)

	tampered := [][]byte{
		[]byte(`{"id":1,"action":"login"}`),
		[]byte(`{"id":2,"action":"TAMPERED"}`), // changed
	}
	rebuilt := merkle.RebuildRoot(tampered)
	if hex.EncodeToString(original) == hex.EncodeToString(rebuilt) {
		t.Fatal("tampered row should produce a different root")
	}
}

// ── CanonicalAuditJSON ────────────────────────────────────────────────────────

func TestCanonicalAuditJSON_Deterministic(t *testing.T) {
	j1, err := merkle.CanonicalAuditJSON(1, "evt-1", "org-1", "user.login", "success", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	j2, _ := merkle.CanonicalAuditJSON(1, "evt-1", "org-1", "user.login", "success", "2026-01-01T00:00:00Z")
	if string(j1) != string(j2) {
		t.Fatal("CanonicalAuditJSON is not deterministic")
	}
}

// ensure time import is used
var _ = time.Now

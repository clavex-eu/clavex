package oidc_test

import (
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/clavex-eu/clavex/internal/oidc"
)

func generateTestKeyPair(t *testing.T) (*mldsa65.PublicKey, *mldsa65.PrivateKey) {
	t.Helper()
	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// TestPQCSigner_SignAndVerify verifies the ML-DSA-65 sign/verify cycle works correctly.
func TestPQCSigner_SignAndVerify(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	msg := []byte("test message for ML-DSA-65 signing — NIST FIPS 204")

	var sig [mldsa65.SignatureSize]byte
	if err := mldsa65.SignTo(priv, msg, nil, false, sig[:]); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	if !mldsa65.Verify(pub, msg, nil, sig[:]) {
		t.Fatal("Verify: expected true, got false")
	}

	// Tampered signature must fail.
	sig[0] ^= 0xFF
	if mldsa65.Verify(pub, msg, nil, sig[:]) {
		t.Fatal("Verify with tampered signature: expected false, got true")
	}
}

// TestPQCSigner_KeySerializeRoundtrip verifies private key bytes can be round-tripped.
func TestPQCSigner_KeySerializeRoundtrip(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	var priv2 mldsa65.PrivateKey
	if err := priv2.UnmarshalBinary(priv.Bytes()); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	if !pub.Equal(priv2.Public()) {
		t.Fatal("round-tripped private key yields different public key")
	}

	msg := []byte("roundtrip test")
	var sig [mldsa65.SignatureSize]byte
	if err := mldsa65.SignTo(priv, msg, nil, false, sig[:]); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	pub2, ok := priv2.Public().(*mldsa65.PublicKey)
	if !ok {
		t.Fatal("priv2.Public() is not *mldsa65.PublicKey")
	}
	if !mldsa65.Verify(pub2, msg, nil, sig[:]) {
		t.Fatal("Verify with round-tripped key: expected true")
	}
}

// TestPQCSigner_HybridJWKS verifies that MergeJWKS produces a valid JWKS
// containing both the classical RSA key and the PQC ML-DSA-65 key.
func TestPQCSigner_HybridJWKS(t *testing.T) {
	classicalJWKS := []byte(`{"keys":[{"kty":"RSA","use":"sig","kid":"rsakid","n":"abcdef","e":"AQAB"}]}`)
	pqcJWK := []byte(`{"kty":"MLWE","alg":"CV-ML-DSA-65","kid":"pqckid","use":"sig","pub":"xyz"}`)

	merged := oidc.MergeJWKS(classicalJWKS, pqcJWK)

	var result struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(merged, &result); err != nil {
		t.Fatalf("merged JWKS is not valid JSON: %v\nraw: %s", err, merged)
	}

	if len(result.Keys) != 2 {
		t.Fatalf("expected 2 keys in merged JWKS, got %d\nraw: %s", len(result.Keys), merged)
	}

	var first, second map[string]string
	if err := json.Unmarshal(result.Keys[0], &first); err != nil {
		t.Fatalf("parse first key: %v", err)
	}
	if err := json.Unmarshal(result.Keys[1], &second); err != nil {
		t.Fatalf("parse second key: %v", err)
	}

	if first["kty"] != "RSA" {
		t.Errorf("first key kty: got %q, want RSA", first["kty"])
	}
	if second["kty"] != "MLWE" {
		t.Errorf("second key kty: got %q, want MLWE", second["kty"])
	}
	if second["alg"] != "CV-ML-DSA-65" {
		t.Errorf("second key alg: got %q, want CV-ML-DSA-65", second["alg"])
	}
}

// TestMergeJWKS_EmptyClassical verifies nil classical returns nil.
func TestMergeJWKS_EmptyClassical(t *testing.T) {
	pqcJWK := []byte(`{"kty":"MLWE","kid":"k1"}`)
	if result := oidc.MergeJWKS(nil, pqcJWK); result != nil {
		t.Errorf("expected nil for nil classical, got %s", result)
	}
}

// TestMergeJWKS_EmptyKeysArray verifies merging into an empty keys array works.
func TestMergeJWKS_EmptyKeysArray(t *testing.T) {
	classical := []byte(`{"keys":[]}`)
	pqcJWK := []byte(`{"kty":"MLWE","kid":"k1","alg":"CV-ML-DSA-65","use":"sig","pub":"xyz"}`)

	merged := oidc.MergeJWKS(classical, pqcJWK)

	var result struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(merged, &result); err != nil {
		t.Fatalf("merged JWKS is not valid JSON: %v\nraw: %s", err, merged)
	}
	if len(result.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d\nraw: %s", len(result.Keys), merged)
	}
}

// TestPQCSigner_AlgorithmConstants verifies the exported constant values.
func TestPQCSigner_AlgorithmConstants(t *testing.T) {
	if oidc.PQCAlgorithmMLDSA65 != "ml-dsa-65" {
		t.Errorf("PQCAlgorithmMLDSA65 = %q, want ml-dsa-65", oidc.PQCAlgorithmMLDSA65)
	}
	if oidc.PQCJWAAlgorithm != "CV-ML-DSA-65" {
		t.Errorf("PQCJWAAlgorithm = %q, want CV-ML-DSA-65", oidc.PQCJWAAlgorithm)
	}
	if oidc.PQCKeyType != "MLWE" {
		t.Errorf("PQCKeyType = %q, want MLWE", oidc.PQCKeyType)
	}
}

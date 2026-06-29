package oidc

import (
	"encoding/json"
	"testing"
)

func TestExtractIDAMetadata_NilMeta(t *testing.T) {
	if m := ExtractIDAMetadata(nil); m != nil {
		t.Fatalf("expected nil, got %+v", m)
	}
}

func TestExtractIDAMetadata_Missing(t *testing.T) {
	meta := map[string]interface{}{"some_key": "val"}
	if m := ExtractIDAMetadata(meta); m != nil {
		t.Fatalf("expected nil, got %+v", m)
	}
}

func TestExtractIDAMetadata_Valid(t *testing.T) {
	meta := map[string]interface{}{
		"_ida": map[string]interface{}{
			"trust_framework":  "eidas",
			"assurance_level": "substantial",
		},
	}
	m := ExtractIDAMetadata(meta)
	if m == nil {
		t.Fatal("expected IDAMetadata, got nil")
	}
	if m.TrustFramework != "eidas" {
		t.Fatalf("trust_framework = %q, want eidas", m.TrustFramework)
	}
	if m.AssuranceLevel != "substantial" {
		t.Fatalf("assurance_level = %q, want substantial", m.AssuranceLevel)
	}
}

func TestBuildVerifiedClaims_NoIDA(t *testing.T) {
	meta := map[string]interface{}{"some": "data"}
	if vc := BuildVerifiedClaims(meta, nil, nil); vc != nil {
		t.Fatalf("expected nil when no _ida, got %+v", vc)
	}
}

func TestBuildVerifiedClaims_WithIDA(t *testing.T) {
	meta := map[string]interface{}{
		"_ida": map[string]interface{}{
			"trust_framework": "eidas",
			"assurance_level": "high",
		},
	}
	profile := map[string]any{
		"given_name":  "Max",
		"family_name": "Meier",
	}
	vc := BuildVerifiedClaims(meta, profile, nil)
	if vc == nil {
		t.Fatal("expected verified_claims object, got nil")
	}
	verif, ok := vc["verification"].(map[string]any)
	if !ok {
		t.Fatalf("verification is not a map: %T", vc["verification"])
	}
	if verif["trust_framework"] != "eidas" {
		t.Fatalf("trust_framework = %v, want eidas", verif["trust_framework"])
	}
	claims, ok := vc["claims"].(map[string]any)
	if !ok {
		t.Fatalf("claims is not a map: %T", vc["claims"])
	}
	if claims["given_name"] != "Max" {
		t.Fatalf("given_name = %v, want Max", claims["given_name"])
	}
}

func TestBuildVerifiedClaims_TrustFrameworkConstraint_Pass(t *testing.T) {
	meta := map[string]interface{}{
		"_ida": map[string]interface{}{"trust_framework": "eidas"},
	}
	profile := map[string]any{"given_name": "Anna"}

	req := json.RawMessage(`{"verification":{"trust_framework":{"value":"eidas"}},"claims":{"given_name":null}}`)
	vc := BuildVerifiedClaims(meta, profile, req)
	if vc == nil {
		t.Fatal("expected verified_claims to pass trust_framework constraint")
	}
}

func TestBuildVerifiedClaims_TrustFrameworkConstraint_Fail(t *testing.T) {
	meta := map[string]interface{}{
		"_ida": map[string]interface{}{"trust_framework": "it_spid"},
	}
	profile := map[string]any{"given_name": "Luigi"}

	req := json.RawMessage(`{"verification":{"trust_framework":{"value":"de_aml"}},"claims":{"given_name":null}}`)
	vc := BuildVerifiedClaims(meta, profile, req)
	if vc != nil {
		t.Fatalf("expected nil when trust_framework does not match, got %+v", vc)
	}
}

func TestBuildVerifiedClaims_RequestedClaimsFilter(t *testing.T) {
	meta := map[string]interface{}{
		"_ida": map[string]interface{}{"trust_framework": "eidas"},
	}
	profile := map[string]any{
		"given_name":  "Max",
		"family_name": "Meier",
		"birthdate":   "1990-01-01",
	}

	// Only request given_name, not family_name or birthdate.
	req := json.RawMessage(`{"claims":{"given_name":null}}`)
	vc := BuildVerifiedClaims(meta, profile, req)
	if vc == nil {
		t.Fatal("expected verified_claims, got nil")
	}
	claims := vc["claims"].(map[string]any)
	if _, ok := claims["given_name"]; !ok {
		t.Fatal("given_name should be present")
	}
	if _, ok := claims["family_name"]; ok {
		t.Fatal("family_name should be absent (not requested)")
	}
}

func TestBuildVerifiedClaims_TrustFrameworkValues_Match(t *testing.T) {
	meta := map[string]interface{}{
		"_ida": map[string]interface{}{"trust_framework": "it_cie"},
	}
	profile := map[string]any{"given_name": "Lucia"}

	req := json.RawMessage(`{"verification":{"trust_framework":{"values":["eidas","it_cie","it_spid"]}},"claims":{"given_name":null}}`)
	vc := BuildVerifiedClaims(meta, profile, req)
	if vc == nil {
		t.Fatal("expected verified_claims to match one of the values")
	}
}

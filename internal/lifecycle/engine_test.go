package lifecycle

// Tests for the pure-logic functions in engine.go:
//   - buildAttrs     — user → attribute map
//   - matchesAll     — condition evaluation (all operators)
//
// execAction / Apply require live DB repositories and are covered by
// integration tests; here we focus on the two critical pure functions
// that carry the rule-matching logic.

import (
	"testing"

	"github.com/clavex-eu/clavex/internal/models"
)

// ── buildAttrs ────────────────────────────────────────────────────────────────

func TestBuildAttrs_BasicFields(t *testing.T) {
	fn := "Alice"
	ln := "Smith"
	u := &models.User{
		Email:     "alice@example.com",
		FirstName: &fn,
		LastName:  &ln,
		IsActive:  true,
	}
	attrs := buildAttrs(UserContext{User: u})

	cases := map[string]string{
		"email":      "alice@example.com",
		"first_name": "Alice",
		"last_name":  "Smith",
		"is_active":  "true",
	}
	for k, want := range cases {
		if got := attrs[k]; got != want {
			t.Errorf("buildAttrs[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestBuildAttrs_NilPointers(t *testing.T) {
	u := &models.User{Email: "x@example.com"} // FirstName/LastName nil
	attrs := buildAttrs(UserContext{User: u})

	if _, ok := attrs["first_name"]; ok {
		t.Error("first_name should be absent when nil")
	}
	if _, ok := attrs["last_name"]; ok {
		t.Error("last_name should be absent when nil")
	}
}

func TestBuildAttrs_MetadataStrings(t *testing.T) {
	u := &models.User{
		Email:    "a@b.com",
		Metadata: map[string]interface{}{"department": "engineering", "level": 3},
	}
	attrs := buildAttrs(UserContext{User: u})

	if got := attrs["department"]; got != "engineering" {
		t.Errorf("metadata string got %q, want engineering", got)
	}
	if _, ok := attrs["level"]; ok {
		t.Error("non-string metadata value should not appear in attrs")
	}
}

// ── matchesAll ────────────────────────────────────────────────────────────────

func cond(field, op, value string) models.LifecycleCondition {
	return models.LifecycleCondition{Field: field, Op: op, Value: value}
}

func TestMatchesAll_EmptyConditions(t *testing.T) {
	// Empty conditions → always match (used for "run always" rules).
	if !matchesAll(nil, map[string]string{"email": "a@b.com"}) {
		t.Error("empty conditions should always match")
	}
}

func TestMatchesAll_Eq_Match(t *testing.T) {
	attrs := map[string]string{"department": "engineering"}
	if !matchesAll([]models.LifecycleCondition{cond("department", "eq", "Engineering")}, attrs) {
		t.Error("eq should be case-insensitive and match")
	}
}

func TestMatchesAll_Eq_NoMatch(t *testing.T) {
	attrs := map[string]string{"department": "sales"}
	if matchesAll([]models.LifecycleCondition{cond("department", "eq", "engineering")}, attrs) {
		t.Error("eq should not match different value")
	}
}

func TestMatchesAll_Neq_Match(t *testing.T) {
	attrs := map[string]string{"department": "sales"}
	if !matchesAll([]models.LifecycleCondition{cond("department", "neq", "engineering")}, attrs) {
		t.Error("neq should match when values differ")
	}
}

func TestMatchesAll_Neq_NoMatch(t *testing.T) {
	attrs := map[string]string{"department": "engineering"}
	if matchesAll([]models.LifecycleCondition{cond("department", "neq", "Engineering")}, attrs) {
		t.Error("neq should not match when values are equal (case-insensitive)")
	}
}

func TestMatchesAll_Contains_Match(t *testing.T) {
	attrs := map[string]string{"email": "alice@contractor.example.com"}
	if !matchesAll([]models.LifecycleCondition{cond("email", "contains", "contractor")}, attrs) {
		t.Error("contains should match substring")
	}
}

func TestMatchesAll_Contains_CaseInsensitive(t *testing.T) {
	attrs := map[string]string{"email": "alice@Contractor.example.com"}
	if !matchesAll([]models.LifecycleCondition{cond("email", "contains", "CONTRACTOR")}, attrs) {
		t.Error("contains should be case-insensitive")
	}
}

func TestMatchesAll_StartsWith_Match(t *testing.T) {
	attrs := map[string]string{"email": "admin@example.com"}
	if !matchesAll([]models.LifecycleCondition{cond("email", "starts_with", "admin")}, attrs) {
		t.Error("starts_with should match")
	}
}

func TestMatchesAll_StartsWith_NoMatch(t *testing.T) {
	attrs := map[string]string{"email": "user@example.com"}
	if matchesAll([]models.LifecycleCondition{cond("email", "starts_with", "admin")}, attrs) {
		t.Error("starts_with should not match wrong prefix")
	}
}

func TestMatchesAll_EndsWith_Match(t *testing.T) {
	attrs := map[string]string{"email": "alice@contractor.example.com"}
	if !matchesAll([]models.LifecycleCondition{cond("email", "ends_with", ".example.com")}, attrs) {
		t.Error("ends_with should match")
	}
}

func TestMatchesAll_EndsWith_NoMatch(t *testing.T) {
	attrs := map[string]string{"email": "alice@other.com"}
	if matchesAll([]models.LifecycleCondition{cond("email", "ends_with", ".example.com")}, attrs) {
		t.Error("ends_with should not match")
	}
}

func TestMatchesAll_Exists_Present(t *testing.T) {
	attrs := map[string]string{"department": "eng"}
	if !matchesAll([]models.LifecycleCondition{cond("department", "exists", "")}, attrs) {
		t.Error("exists should match when key is present")
	}
}

func TestMatchesAll_Exists_Absent(t *testing.T) {
	attrs := map[string]string{}
	if matchesAll([]models.LifecycleCondition{cond("department", "exists", "")}, attrs) {
		t.Error("exists should not match when key is absent")
	}
}

func TestMatchesAll_NotExists_Absent(t *testing.T) {
	attrs := map[string]string{}
	if !matchesAll([]models.LifecycleCondition{cond("department", "not_exists", "")}, attrs) {
		t.Error("not_exists should match when key is absent")
	}
}

func TestMatchesAll_NotExists_Present(t *testing.T) {
	attrs := map[string]string{"department": "eng"}
	if matchesAll([]models.LifecycleCondition{cond("department", "not_exists", "")}, attrs) {
		t.Error("not_exists should not match when key is present")
	}
}

func TestMatchesAll_UnknownOp_ConservativeNoMatch(t *testing.T) {
	// Unknown operators must conservatively return false (security invariant:
	// misconfigured rules must not accidentally grant access).
	attrs := map[string]string{"field": "value"}
	if matchesAll([]models.LifecycleCondition{cond("field", "regex", ".*")}, attrs) {
		t.Error("unknown op should conservatively not match")
	}
}

func TestMatchesAll_MissingFieldWithEq_NoMatch(t *testing.T) {
	// eq on a field that doesn't exist should not match.
	attrs := map[string]string{}
	if matchesAll([]models.LifecycleCondition{cond("department", "eq", "engineering")}, attrs) {
		t.Error("eq on missing field should not match")
	}
}

func TestMatchesAll_AndLogic_AllMustPass(t *testing.T) {
	attrs := map[string]string{
		"department": "engineering",
		"email":      "alice@example.com",
		"is_active":  "true",
	}
	// All three pass → match
	all := []models.LifecycleCondition{
		cond("department", "eq", "engineering"),
		cond("email", "contains", "example"),
		cond("is_active", "eq", "true"),
	}
	if !matchesAll(all, attrs) {
		t.Error("all conditions pass — should match")
	}

	// Third condition fails → no match
	failing := []models.LifecycleCondition{
		cond("department", "eq", "engineering"),
		cond("email", "contains", "example"),
		cond("is_active", "eq", "false"), // ← fails
	}
	if matchesAll(failing, attrs) {
		t.Error("one failing condition — should not match")
	}
}

func TestMatchesAll_FirstFailureShortCircuits(t *testing.T) {
	// Ensure that a false on first condition prevents subsequent ones from
	// affecting the result (important for correctness with "neq on missing field").
	attrs := map[string]string{"email": "x@y.com"}
	conds := []models.LifecycleCondition{
		cond("email", "eq", "other@y.com"),         // fails
		cond("nonexistent", "not_exists", ""),       // would pass
	}
	if matchesAll(conds, attrs) {
		t.Error("first failing condition should make the whole rule not match")
	}
}

// ── buildAttrs coverage for inactive user ─────────────────────────────────────

func TestBuildAttrs_IsActiveFalse(t *testing.T) {
	u := &models.User{Email: "x@y.com", IsActive: false}
	attrs := buildAttrs(UserContext{User: u})
	if got := attrs["is_active"]; got != "false" {
		t.Errorf("is_active = %q, want false", got)
	}
}

// ── leaver rule: email ends_with contractor + is_active eq false ──────────────

func TestMatchesAll_LeaverContractorRule(t *testing.T) {
	// Simulates: "On leaver, if user is contractor and deactivated → revoke sessions"
	// This is the highest-risk rule — a bug here could revoke the wrong sessions.
	attrs := map[string]string{
		"email":      "bob@contractor.example.com",
		"is_active":  "false",
		"department": "vendor",
	}
	rule := []models.LifecycleCondition{
		cond("email", "ends_with", "@contractor.example.com"),
		cond("is_active", "eq", "false"),
	}
	if !matchesAll(rule, attrs) {
		t.Error("leaver contractor rule should match deactivated contractor")
	}

	// Active contractor should NOT trigger leaver rule.
	attrs["is_active"] = "true"
	if matchesAll(rule, attrs) {
		t.Error("active contractor should not match leaver rule")
	}
}

// ── role-assignment rule: department eq engineering ───────────────────────────

func TestMatchesAll_JoinerEngineerRole(t *testing.T) {
	// "On joiner, if department eq engineering → assign_role engineer"
	attrs := map[string]string{
		"department": "Engineering", // mixed case from provider
	}
	rule := []models.LifecycleCondition{
		cond("department", "eq", "engineering"),
	}
	if !matchesAll(rule, attrs) {
		t.Error("case-insensitive eq should match Engineering vs engineering")
	}
}

func TestMatchesAll_JoinerEngineerRole_WrongDept(t *testing.T) {
	attrs := map[string]string{"department": "Sales"}
	rule := []models.LifecycleCondition{cond("department", "eq", "engineering")}
	if matchesAll(rule, attrs) {
		t.Error("Sales department should not get engineer role")
	}
}

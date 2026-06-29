package handler

// Tests for sms_settings.go pure secret-handling logic:
//   - redactSMSSecrets — password-type fields blanked, others preserved
//   - mergeSMSSecrets  — blank password fields fall back to stored secret
//
// Full DB-backed tests (Get/Put/Test endpoints) require a live Postgres
// instance and live in integration tests.

import (
	"testing"
)

// twilio schema (from connectorregistry/sms.go) has one password field: auth_token.
// All other fields (account_sid, from) are text.

func TestRedactSMSSecrets_BlanksPasswordFields(t *testing.T) {
	cfg := map[string]interface{}{
		"account_sid": "AC123",
		"auth_token":  "super-secret",
		"from":        "+14155552671",
	}
	got := redactSMSSecrets("twilio", cfg)

	if got["auth_token"] != "" {
		t.Errorf("auth_token = %q, want blanked", got["auth_token"])
	}
	if got["account_sid"] != "AC123" {
		t.Errorf("account_sid = %q, want preserved", got["account_sid"])
	}
	if got["from"] != "+14155552671" {
		t.Errorf("from = %q, want preserved", got["from"])
	}
	// Original map must not be mutated.
	if cfg["auth_token"] != "super-secret" {
		t.Error("redactSMSSecrets mutated the input map")
	}
}

func TestRedactSMSSecrets_UnknownProviderReturnsCopy(t *testing.T) {
	cfg := map[string]interface{}{"api_key": "k"}
	got := redactSMSSecrets("does-not-exist", cfg)
	if got["api_key"] != "k" {
		t.Errorf("api_key = %q, want unchanged for unknown provider", got["api_key"])
	}
}

func TestMergeSMSSecrets_PreservesStoredSecretWhenBlank(t *testing.T) {
	incoming := map[string]interface{}{
		"account_sid": "AC999",
		"auth_token":  "", // blanked by the UI — should fall back to stored value
		"from":        "+10000000000",
	}
	stored := map[string]interface{}{
		"account_sid": "AC123",
		"auth_token":  "stored-secret",
		"from":        "+14155552671",
	}
	called := 0
	got := mergeSMSSecrets("twilio", incoming, func() map[string]interface{} {
		called++
		return stored
	})

	if got["auth_token"] != "stored-secret" {
		t.Errorf("auth_token = %q, want carried over from stored", got["auth_token"])
	}
	if got["account_sid"] != "AC999" {
		t.Errorf("account_sid = %q, want incoming value", got["account_sid"])
	}
	if called != 1 {
		t.Errorf("existing() called %d times, want exactly 1 (lazy, single fetch)", called)
	}
}

func TestMergeSMSSecrets_NewSecretOverwrites(t *testing.T) {
	incoming := map[string]interface{}{
		"account_sid": "AC123",
		"auth_token":  "new-secret",
		"from":        "+14155552671",
	}
	called := 0
	got := mergeSMSSecrets("twilio", incoming, func() map[string]interface{} {
		called++
		return map[string]interface{}{"auth_token": "old-secret"}
	})

	if got["auth_token"] != "new-secret" {
		t.Errorf("auth_token = %q, want new value", got["auth_token"])
	}
	if called != 0 {
		t.Errorf("existing() called %d times, want 0 when a new secret is supplied", called)
	}
}

func TestMergeSMSSecrets_NoStoredSecretLeavesBlank(t *testing.T) {
	incoming := map[string]interface{}{
		"account_sid": "AC123",
		"auth_token":  "",
	}
	got := mergeSMSSecrets("twilio", incoming, func() map[string]interface{} {
		return nil // nothing stored yet
	})
	if v, ok := got["auth_token"]; !ok || v != "" {
		t.Errorf("auth_token = %v, want blank when nothing stored", v)
	}
}

func TestMergeSMSSecrets_UnknownProviderReturnsCopy(t *testing.T) {
	incoming := map[string]interface{}{"api_key": ""}
	called := 0
	got := mergeSMSSecrets("does-not-exist", incoming, func() map[string]interface{} {
		called++
		return map[string]interface{}{"api_key": "x"}
	})
	if got["api_key"] != "" {
		t.Errorf("api_key = %q, want unchanged for unknown provider", got["api_key"])
	}
	if called != 0 {
		t.Errorf("existing() called %d times, want 0 for unknown provider", called)
	}
}

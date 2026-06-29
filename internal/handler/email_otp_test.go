package handler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── buildEmailOTPBody ─────────────────────────────────────────────────────────

func TestBuildEmailOTPBody_ContainsCode(t *testing.T) {
	body := buildEmailOTPBody("Acme Corp", "482931")
	assert.Contains(t, body, "482931", "plaintext code must appear in email body")
}

func TestBuildEmailOTPBody_ContainsOrgName(t *testing.T) {
	body := buildEmailOTPBody("Köln GmbH", "000000")
	assert.Contains(t, body, "Köln GmbH", "org name must appear verbatim (UTF-8 safe)")
}

func TestBuildEmailOTPBody_IsValidHTML(t *testing.T) {
	body := buildEmailOTPBody("Acme", "123456")
	assert.True(t, strings.HasPrefix(strings.TrimSpace(body), "<!DOCTYPE html>"),
		"body must start with a DOCTYPE declaration")
	assert.Contains(t, body, "</html>", "body must contain closing html tag")
}

func TestBuildEmailOTPBody_MentionsTTL(t *testing.T) {
	body := buildEmailOTPBody("Acme", "000001")
	assert.Contains(t, body, "10", "body should mention the 10-minute expiry")
}

func TestBuildEmailOTPBody_NoScriptInjection(t *testing.T) {
	// An org name with HTML special chars must not produce unescaped markup.
	// The current implementation uses string concatenation, so we check that a
	// naive XSS payload does not survive as a live <script> tag.
	body := buildEmailOTPBody("<script>alert(1)</script>", "000002")
	// The raw "<script>" string must not appear as-is (either escaped or absent).
	assert.NotContains(t, body, "<script>alert(1)</script>",
		"org name with HTML special chars must be escaped or rejected")
}

func TestBuildEmailOTPBody_SixDigitCodeFormat(t *testing.T) {
	// Verify that a zero-padded code renders correctly (not trimmed to 5 digits).
	body := buildEmailOTPBody("Zero Inc", "007654")
	assert.Contains(t, body, "007654",
		"zero-padded 6-digit codes must appear exactly as generated")
}

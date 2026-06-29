package handler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── maskPhone ─────────────────────────────────────────────────────────────────

func TestMaskPhone_TenDigit(t *testing.T) {
	// Standard 10-digit phone: keep first 3 + last 4, mask middle.
	got := maskPhone("+391234567890")
	assert.Equal(t, "+39 *** 7890", got)
}

func TestMaskPhone_KeepsFirst3AndLast4(t *testing.T) {
	got := maskPhone("+447700900123")
	assert.True(t, strings.HasPrefix(got, "+44"))
	assert.True(t, strings.HasSuffix(got, "0123"))
}

func TestMaskPhone_ShortNumber_ReturnedAsIs(t *testing.T) {
	// Numbers shorter than 5 chars are returned unchanged.
	got := maskPhone("1234")
	assert.Equal(t, "1234", got)
}

func TestMaskPhone_ExactlyFiveChars(t *testing.T) {
	got := maskPhone("+1234")
	// len == 5, masked with 1 asterisk + last 2.
	assert.NotEmpty(t, got)
	assert.Contains(t, got, "*")
}

func TestMaskPhone_EightChars_Masked(t *testing.T) {
	got := maskPhone("+3912345")
	// len == 7, uses the <= 7 branch.
	assert.Contains(t, got, "*")
}

func TestMaskPhone_Empty_ReturnedAsIs(t *testing.T) {
	got := maskPhone("")
	assert.Equal(t, "", got)
}

func TestMaskPhone_NeverExposesFullNumber(t *testing.T) {
	phone := "+391234567890"
	got := maskPhone(phone)
	assert.NotEqual(t, phone, got, "full phone number must not be returned verbatim")
}

func TestMaskPhone_ContainsAsterisk(t *testing.T) {
	got := maskPhone("+391234567890")
	assert.Contains(t, got, "*")
}

// ── orgLogoURL ────────────────────────────────────────────────────────────────

func TestOrgLogoURL_Nil_ReturnsEmpty(t *testing.T) {
	got := orgLogoURL(nil)
	assert.Equal(t, "", got)
}

func TestOrgLogoURL_NonNil_ReturnsValue(t *testing.T) {
	url := "https://cdn.example.com/logo.png"
	got := orgLogoURL(&url)
	assert.Equal(t, url, got)
}

func TestOrgLogoURL_EmptyString(t *testing.T) {
	empty := ""
	got := orgLogoURL(&empty)
	assert.Equal(t, "", got)
}

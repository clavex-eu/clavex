package worker

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// anonEmailFor replicates the deterministic anonymised email derivation used in
// runErasure so we can test the invariant without a DB.
func anonEmailFor(userID uuid.UUID) string {
	h256 := sha256.Sum256([]byte(userID.String()))
	return fmt.Sprintf("erased_%x@gdpr.invalid", h256[:8])
}

func TestAnonEmail_Format(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	email := anonEmailFor(id)

	if !strings.HasPrefix(email, "erased_") {
		t.Errorf("anonEmail should start with 'erased_', got %q", email)
	}
	if !strings.HasSuffix(email, "@gdpr.invalid") {
		t.Errorf("anonEmail should end with '@gdpr.invalid', got %q", email)
	}
	// hex component must be exactly 16 chars (8 bytes → 16 hex digits).
	parts := strings.SplitN(email, "@", 2)
	hex := strings.TrimPrefix(parts[0], "erased_")
	if len(hex) != 16 {
		t.Errorf("hex component should be 16 chars, got %d in %q", len(hex), hex)
	}
}

func TestAnonEmail_Deterministic(t *testing.T) {
	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	e1 := anonEmailFor(id)
	e2 := anonEmailFor(id)
	if e1 != e2 {
		t.Errorf("anonEmail should be deterministic: %q != %q", e1, e2)
	}
}

func TestAnonEmail_DifferentUsersProduceDifferentEmails(t *testing.T) {
	id1 := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	id2 := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	e1 := anonEmailFor(id1)
	e2 := anonEmailFor(id2)
	if e1 == e2 {
		t.Errorf("different users should produce different anon emails, both got %q", e1)
	}
}

func TestAnonEmail_ValidEmail(t *testing.T) {
	id := uuid.New()
	email := anonEmailFor(id)
	if !strings.Contains(email, "@") {
		t.Errorf("anonEmail should be a valid email address, got %q", email)
	}
	// The domain must be a reserved domain that cannot receive real mail (RFC 2606).
	domain := strings.SplitN(email, "@", 2)[1]
	if domain != "gdpr.invalid" {
		t.Errorf("domain should be gdpr.invalid, got %q", domain)
	}
}

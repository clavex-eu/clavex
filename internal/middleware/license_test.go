package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clavex-eu/clavex/internal/license"
	"github.com/labstack/echo/v4"
)

// runBusinessGate invokes RequireBusinessLicense with a fixed state and returns
// the resulting HTTP status (200 when the inner handler runs, 402 when gated).
func runBusinessGate(t *testing.T, st license.State) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/marketplace/listings", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := RequireBusinessLicense(func() license.State { return st })(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	if err := h(c); err != nil {
		if he, ok := err.(*echo.HTTPError); ok {
			return he.Code
		}
		t.Fatalf("unexpected error: %v", err)
	}
	return rec.Code
}

func TestRequireBusinessLicense_CommunityBlocked(t *testing.T) {
	// No license loaded — community installation cannot publish.
	if got := runBusinessGate(t, license.State{Valid: false, Tier: "community"}); got != http.StatusPaymentRequired {
		t.Errorf("community install publishing: want 402, got %d", got)
	}
}

func TestRequireBusinessLicense_BusinessAllowed(t *testing.T) {
	if got := runBusinessGate(t, license.State{Valid: true, Tier: "business"}); got != http.StatusOK {
		t.Errorf("valid business license publishing: want 200, got %d", got)
	}
}

func TestRequireBusinessLicense_EnterpriseAllowed(t *testing.T) {
	if got := runBusinessGate(t, license.State{Valid: true, Tier: "enterprise"}); got != http.StatusOK {
		t.Errorf("valid enterprise license publishing: want 200, got %d", got)
	}
}

func TestRequireBusinessLicense_ExpiredBlocked(t *testing.T) {
	// A trial/subscription that has expired: the Checker recomputes Valid=false
	// and drops the tier back to community. Publishing must 402 again.
	if got := runBusinessGate(t, license.State{Valid: false, Tier: "community"}); got != http.StatusPaymentRequired {
		t.Errorf("expired license publishing: want 402, got %d", got)
	}
}

func TestRequireBusinessLicense_TrialTierBusinessAllowed(t *testing.T) {
	// A 30-day Business trial is a Tier="business" license carrying a plan claim;
	// while valid it is entitled exactly like a paid Business license.
	if got := runBusinessGate(t, license.State{Valid: true, Tier: "business", Plan: "business_trial"}); got != http.StatusOK {
		t.Errorf("active business trial publishing: want 200, got %d", got)
	}
}

func TestHasBusinessEntitlement(t *testing.T) {
	cases := []struct {
		name string
		st   license.State
		want bool
	}{
		{"invalid community", license.State{Valid: false, Tier: "community"}, false},
		{"valid community", license.State{Valid: true, Tier: "community"}, false},
		{"valid business", license.State{Valid: true, Tier: "business"}, true},
		{"valid enterprise", license.State{Valid: true, Tier: "enterprise"}, true},
		{"invalid business (expired)", license.State{Valid: false, Tier: "business"}, false},
		{"unknown tier", license.State{Valid: true, Tier: "startup"}, false},
	}
	for _, tc := range cases {
		if got := tc.st.HasBusinessEntitlement(); got != tc.want {
			t.Errorf("%s: HasBusinessEntitlement()=%v, want %v", tc.name, got, tc.want)
		}
	}
}

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/labstack/echo/v4"
)

// runCSRF executes CSRFProtect for one request and returns the status code plus
// the recorder (to inspect Set-Cookie).
func runCSRF(req *http.Request) (int, *httptest.ResponseRecorder) {
	e := echo.New()
	cfg := &config.Config{}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	h := CSRFProtect(cfg)(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	if err := h(c); err != nil {
		if he, ok := err.(*echo.HTTPError); ok {
			return he.Code, rec
		}
		return http.StatusInternalServerError, rec
	}
	return rec.Code, rec
}

func csrfCookieFrom(rec *httptest.ResponseRecorder) string {
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == CSRFCookieName {
			return ck.Value
		}
	}
	return ""
}

func TestCSRFProtect(t *testing.T) {
	t.Run("GET issues a token cookie and passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		status, rec := runCSRF(req)
		if status != http.StatusOK {
			t.Fatalf("GET: want 200, got %d", status)
		}
		if csrfCookieFrom(rec) == "" {
			t.Fatal("GET: expected a CSRF token cookie to be issued")
		}
	})

	t.Run("cookie-auth POST without token is forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: AdminCookieName, Value: "session-jwt"})
		if status, _ := runCSRF(req); status != http.StatusForbidden {
			t.Fatalf("no-token POST: want 403, got %d", status)
		}
	})

	t.Run("matching double-submit token passes", func(t *testing.T) {
		token := "matching-token-value"
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: AdminCookieName, Value: "session-jwt"})
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
		req.Header.Set(CSRFHeaderName, token)
		if status, _ := runCSRF(req); status != http.StatusOK {
			t.Fatalf("matched POST: want 200, got %d", status)
		}
	})

	t.Run("mismatched token is forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: AdminCookieName, Value: "session-jwt"})
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "real-token"})
		req.Header.Set(CSRFHeaderName, "attacker-guess")
		if status, _ := runCSRF(req); status != http.StatusForbidden {
			t.Fatalf("mismatched POST: want 403, got %d", status)
		}
	})

	t.Run("bearer-auth POST is exempt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer something")
		if status, _ := runCSRF(req); status != http.StatusOK {
			t.Fatalf("bearer POST: want 200 (exempt), got %d", status)
		}
	})

	t.Run("api-key POST is exempt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-API-Key", "ck_live_xxx")
		if status, _ := runCSRF(req); status != http.StatusOK {
			t.Fatalf("api-key POST: want 200 (exempt), got %d", status)
		}
	})
}

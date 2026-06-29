package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

const testAdminSecret = "test-admin-secret-at-least-32-chars-long!!"

func signAdminJWT(t *testing.T, isAdmin bool) string {
	t.Helper()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		OrgID:   "org-1",
		Email:   "admin@example.com",
		IsAdmin: isAdmin,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testAdminSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// invoke runs RequireAdminJWT against a single request and returns the status.
func invoke(req *http.Request) int {
	e := echo.New()
	cfg := &config.Config{}
	cfg.Auth.AdminSecret = testAdminSecret
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	h := RequireAdminJWT(cfg)(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	if err := h(c); err != nil {
		if he, ok := err.(*echo.HTTPError); ok {
			return he.Code
		}
		return http.StatusInternalServerError
	}
	return rec.Code
}

func TestRequireAdminJWT_Transport(t *testing.T) {
	t.Run("bearer header still authenticates", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+signAdminJWT(t, true))
		if got := invoke(req); got != http.StatusOK {
			t.Fatalf("bearer: want 200, got %d", got)
		}
	})

	t.Run("cookie authenticates", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: AdminCookieName, Value: signAdminJWT(t, true)})
		if got := invoke(req); got != http.StatusOK {
			t.Fatalf("cookie: want 200, got %d", got)
		}
	})

	t.Run("bearer wins over cookie", func(t *testing.T) {
		// Valid bearer + garbage cookie → bearer is tried first, must pass.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+signAdminJWT(t, true))
		req.AddCookie(&http.Cookie{Name: AdminCookieName, Value: "garbage"})
		if got := invoke(req); got != http.StatusOK {
			t.Fatalf("bearer-priority: want 200, got %d", got)
		}
	})

	t.Run("no credential is unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if got := invoke(req); got != http.StatusUnauthorized {
			t.Fatalf("none: want 401, got %d", got)
		}
	})

	t.Run("non-admin cookie is forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: AdminCookieName, Value: signAdminJWT(t, false)})
		if got := invoke(req); got != http.StatusForbidden {
			t.Fatalf("non-admin: want 403, got %d", got)
		}
	})

	t.Run("invalid cookie is unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: AdminCookieName, Value: "not-a-jwt"})
		if got := invoke(req); got != http.StatusUnauthorized {
			t.Fatalf("invalid: want 401, got %d", got)
		}
	})
}

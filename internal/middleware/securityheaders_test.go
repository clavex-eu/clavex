package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/labstack/echo/v4"
)

func newEcho() *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	return e
}

// ── ExtraSecurityHeaders ──────────────────────────────────────────────────────

func TestExtraSecurityHeaders_Present(t *testing.T) {
	e := newEcho()
	e.Use(middleware.ExtraSecurityHeaders())
	e.GET("/", func(c echo.Context) error { return c.String(http.StatusOK, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	want := map[string]string{
		"Referrer-Policy":            "strict-origin-when-cross-origin",
		"Permissions-Policy":         "geolocation=(), microphone=(), camera=()",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for header, expected := range want {
		got := rec.Header().Get(header)
		if got != expected {
			t.Errorf("%s = %q, want %q", header, got, expected)
		}
	}
}

// ── HTMLPageCSP ───────────────────────────────────────────────────────────────

func TestHTMLPageCSP_HeaderSet(t *testing.T) {
	e := newEcho()
	e.Use(middleware.HTMLPageCSP())
	e.GET("/", func(c echo.Context) error { return c.String(http.StatusOK, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header not set")
	}
	if !strings.Contains(csp, "nonce-") {
		t.Errorf("CSP does not contain nonce directive: %s", csp)
	}
	if !strings.Contains(csp, "'strict-dynamic'") {
		t.Errorf("CSP does not contain strict-dynamic: %s", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors: %s", csp)
	}
}

func TestHTMLPageCSP_NonceAccessible(t *testing.T) {
	e := newEcho()
	e.Use(middleware.HTMLPageCSP())

	var capturedNonce string
	e.GET("/", func(c echo.Context) error {
		capturedNonce = middleware.GetCSPNonce(c)
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if capturedNonce == "" {
		t.Fatal("GetCSPNonce returned empty string inside handler")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, capturedNonce) {
		t.Errorf("nonce %q not found in CSP header: %s", capturedNonce, csp)
	}
}

func TestHTMLPageCSP_NonceUniquePerRequest(t *testing.T) {
	e := newEcho()
	e.Use(middleware.HTMLPageCSP())

	nonces := make([]string, 0, 10)
	e.GET("/", func(c echo.Context) error {
		nonces = append(nonces, middleware.GetCSPNonce(c))
		return c.String(http.StatusOK, "ok")
	})

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
	}

	seen := map[string]bool{}
	for _, n := range nonces {
		if seen[n] {
			t.Fatalf("duplicate nonce detected: %q", n)
		}
		seen[n] = true
	}
}

func TestHTMLPageCSP_OverridesGlobalCSP(t *testing.T) {
	e := newEcho()
	// Simulate global middleware setting a strict CSP (as in server.go).
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("Content-Security-Policy", "default-src 'none'")
			return next(c)
		}
	})
	// Route-group middleware adds the nonce-based CSP — should override.
	g := e.Group("/html", middleware.HTMLPageCSP())
	g.GET("", func(c echo.Context) error { return c.String(http.StatusOK, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/html", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "nonce-") {
		t.Errorf("route-group CSP did not override global CSP: %s", csp)
	}
}

func TestGetCSPNonce_EmptyWithoutMiddleware(t *testing.T) {
	e := newEcho()
	var nonce string
	e.GET("/", func(c echo.Context) error {
		nonce = middleware.GetCSPNonce(c)
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if nonce != "" {
		t.Errorf("expected empty nonce without middleware, got %q", nonce)
	}
}

func TestNonceInRequestContext(t *testing.T) {
	e := newEcho()
	e.Use(middleware.HTMLPageCSP())

	var ctxNonce interface{}
	e.GET("/", func(c echo.Context) error {
		ctxNonce = c.Request().Context().Value(middleware.NonceKey{})
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if ctxNonce == nil || ctxNonce.(string) == "" {
		t.Fatal("nonce not found in request context")
	}
}

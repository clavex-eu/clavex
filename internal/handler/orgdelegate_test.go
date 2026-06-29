package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

// TestOrgAdminDelegate verifies the :org_id → :id param bridge: a handler that
// reads uuidParam(c,"id") must see the org_id value. Regression for the 400
// caused by mutating param names before reading ParamValues().
func TestOrgAdminDelegate(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// Simulate the matched route /organizations/:org_id/email-policy.
	c.SetParamNames("org_id")
	c.SetParamValues("494a2d8c-8710-4a98-aed3-a39756dedbf1")

	var seen string
	err := orgAdminDelegate(c, "org_id", func(c echo.Context) error {
		seen = c.Param("id")
		return nil
	})
	if err != nil {
		t.Fatalf("delegate returned error: %v", err)
	}
	if seen != "494a2d8c-8710-4a98-aed3-a39756dedbf1" {
		t.Fatalf(`c.Param("id") = %q, want the org_id value`, seen)
	}
	// Original param must remain intact.
	if got := c.Param("org_id"); got != "494a2d8c-8710-4a98-aed3-a39756dedbf1" {
		t.Fatalf(`c.Param("org_id") = %q, want it preserved`, got)
	}
}

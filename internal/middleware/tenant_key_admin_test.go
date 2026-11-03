package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestTenantKeyAdministrationRoles(t *testing.T) {
	cases := []struct {
		name   string
		claims *Claims
		method string
		status int
	}{
		{"non-admin", &Claims{OrgID: "tenant"}, http.MethodPost, 403},
		{"tenant admin", &Claims{OrgID: "tenant", IsAdmin: true}, http.MethodPost, 204},
		{"security writer", &Claims{OrgID: "tenant", IsAdmin: true, Permissions: []string{"security:write"}}, http.MethodPost, 204},
		{"security reader cannot rotate", &Claims{OrgID: "tenant", IsAdmin: true, Permissions: []string{"security:read"}}, http.MethodPost, 403},
		{"security reader can inspect", &Claims{OrgID: "tenant", IsAdmin: true, Permissions: []string{"security:read"}}, http.MethodGet, 204},
		{"other tenant", &Claims{OrgID: "other", IsAdmin: true}, http.MethodPost, 403},
		{"installation account", &Claims{OrgID: "tenant", IsAdmin: true, IsSuperAdmin: true}, http.MethodPost, 403},
		{"unauthenticated", nil, http.MethodPost, 401},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			rec := httptest.NewRecorder()
			c := e.NewContext(httptest.NewRequest(tt.method, "/", nil), rec)
			c.SetParamNames("org_id")
			c.SetParamValues("tenant")
			if tt.claims != nil {
				c.Set(string(claimsKey), tt.claims)
			}
			h := RequireTenantKeyAdministrator()(RequireResourcePermission("security")(func(c echo.Context) error { return c.NoContent(204) }))
			if err := h(c); err != nil {
				e.HTTPErrorHandler(err, c)
			}
			require.Equal(t, tt.status, rec.Code)
		})
	}
}

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── EffectivePermissions ──────────────────────────────────────────────────────

func TestEffectivePermissions_LegacyAdminGetsFullCatalogue(t *testing.T) {
	// Permissions == nil means a legacy/full org admin — they hold everything.
	got := EffectivePermissions(&Claims{Permissions: nil})
	require.Len(t, got, len(AllPermissions))
	set := map[string]struct{}{}
	for _, tok := range got {
		set[tok] = struct{}{}
	}
	for _, p := range AllPermissions {
		_, ok := set[p.Token]
		assert.True(t, ok, "full catalogue must include %s", p.Token)
	}
}

func TestEffectivePermissions_SuperAdminGetsFullCatalogue(t *testing.T) {
	got := EffectivePermissions(&Claims{IsSuperAdmin: true, Permissions: []string{PermUsersRead}})
	assert.Len(t, got, len(AllPermissions), "superadmin holds the whole catalogue regardless of assigned tokens")
}

func TestEffectivePermissions_DelegatedAdminGetsExactTokens(t *testing.T) {
	held := []string{PermClientsWrite, PermRolesRead}
	got := EffectivePermissions(&Claims{Permissions: held})
	assert.Equal(t, held, got)
}

func TestEffectivePermissions_NilClaims(t *testing.T) {
	assert.Nil(t, EffectivePermissions(nil))
}

// ── PermissionsNotHeld (non-escalation) ───────────────────────────────────────

func TestPermissionsNotHeld_LegacyAdminHoldsEverything(t *testing.T) {
	// A full admin may grant any valid permission.
	missing := PermissionsNotHeld(&Claims{Permissions: nil}, []string{PermClientsWrite, PermSecurityWrite})
	assert.Nil(t, missing)
}

func TestPermissionsNotHeld_SuperAdminHoldsEverything(t *testing.T) {
	missing := PermissionsNotHeld(&Claims{IsSuperAdmin: true}, []string{PermUsersWrite})
	assert.Nil(t, missing)
}

func TestPermissionsNotHeld_DelegatedSubsetIsAllowed(t *testing.T) {
	// Requesting a subset of held permissions is fine.
	claims := &Claims{Permissions: []string{PermClientsWrite, PermRolesWrite, PermSecurityWrite}}
	missing := PermissionsNotHeld(claims, []string{PermClientsWrite, PermRolesWrite})
	assert.Empty(t, missing)
}

func TestPermissionsNotHeld_EscalationIsRejected(t *testing.T) {
	// A delegated admin holding only clients:write cannot grant security:write.
	claims := &Claims{Permissions: []string{PermClientsWrite}}
	missing := PermissionsNotHeld(claims, []string{PermClientsWrite, PermSecurityWrite})
	assert.Equal(t, []string{PermSecurityWrite}, missing,
		"the un-held token must be reported as an escalation")
}

func TestPermissionsNotHeld_WriteImpliesRead(t *testing.T) {
	// Holding clients:write must satisfy a request for clients:read.
	claims := &Claims{Permissions: []string{PermClientsWrite}}
	missing := PermissionsNotHeld(claims, []string{PermClientsRead})
	assert.Empty(t, missing, "write permission implicitly grants the matching read")
}

func TestPermissionsNotHeld_ReadDoesNotImplyWrite(t *testing.T) {
	// The reverse must NOT hold: read does not grant write.
	claims := &Claims{Permissions: []string{PermClientsRead}}
	missing := PermissionsNotHeld(claims, []string{PermClientsWrite})
	assert.Equal(t, []string{PermClientsWrite}, missing)
}

func TestPermissionsNotHeld_NilClaimsHoldsNothing(t *testing.T) {
	missing := PermissionsNotHeld(nil, []string{PermUsersRead})
	assert.Equal(t, []string{PermUsersRead}, missing)
}

// ── UI/server coherence contract ──────────────────────────────────────────────
//
// The role- and API-key creation UIs offer exactly the tokens returned by
// EffectivePermissions (via GET /my-admin-permissions) as selectable options.
// The server then rejects any request containing a token PermissionsNotHeld
// flags. These two must agree: everything the UI can offer must be grantable,
// for every class of caller. Otherwise the UI would present options the server
// refuses (or hide options the server would accept).

func assertOfferedSetIsGrantable(t *testing.T, claims *Claims) {
	t.Helper()
	offered := EffectivePermissions(claims)
	missing := PermissionsNotHeld(claims, offered)
	assert.Empty(t, missing,
		"every permission the UI offers must be one the server accepts")
}

func TestOfferedPermissionsAreAlwaysGrantable(t *testing.T) {
	assertOfferedSetIsGrantable(t, &Claims{Permissions: nil})                        // legacy full admin
	assertOfferedSetIsGrantable(t, &Claims{IsSuperAdmin: true})                      // superadmin
	assertOfferedSetIsGrantable(t, &Claims{Permissions: []string{PermClientsWrite}}) // delegated (write)
	assertOfferedSetIsGrantable(t, &Claims{Permissions: []string{PermRolesRead}})    // delegated (read)
	assertOfferedSetIsGrantable(t, &Claims{Permissions: []string{}})                 // delegated, no perms
	assertOfferedSetIsGrantable(t, &Claims{Permissions: []string{PermClientsWrite, PermSecurityWrite}})
}

// ── RequireOrgAccess: an admin cannot target another org ──────────────────────

func orgAccessStatus(t *testing.T, claims *Claims, pathOrgID string) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id")
	c.SetParamValues(pathOrgID)
	c.Set("claims", claims)

	h := RequireOrgAccess()(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	err := h(c)
	if err != nil {
		if he, ok := err.(*echo.HTTPError); ok {
			return he.Code
		}
		t.Fatalf("unexpected error: %v", err)
	}
	return rec.Code
}

func TestRequireOrgAccess_RejectsForeignOrg(t *testing.T) {
	claims := &Claims{OrgID: "org-A", Permissions: []string{PermSecurityWrite}}
	assert.Equal(t, http.StatusForbidden, orgAccessStatus(t, claims, "org-B"),
		"an org admin must not reach a route scoped to a different org")
}

func TestRequireOrgAccess_AllowsOwnOrg(t *testing.T) {
	claims := &Claims{OrgID: "org-A", Permissions: []string{PermSecurityWrite}}
	assert.Equal(t, http.StatusOK, orgAccessStatus(t, claims, "org-A"))
}

func TestRequireOrgAccess_SuperAdminAnyOrg(t *testing.T) {
	claims := &Claims{OrgID: "org-A", IsSuperAdmin: true}
	assert.Equal(t, http.StatusOK, orgAccessStatus(t, claims, "org-B"))
}

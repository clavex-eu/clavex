package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createRoleCtx builds an echo context for POST /organizations/:org_id/admin-roles.
func createRoleCtx(t *testing.T, orgID string, claims *middleware.Claims, body map[string]any) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(raw)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id")
	c.SetParamValues(orgID)
	if claims != nil {
		c.Set("claims", claims)
	}
	return c, rec
}

// updateRoleCtx builds an echo context for PATCH .../admin-roles/:role_id.
func updateRoleCtx(t *testing.T, orgID, roleID string, claims *middleware.Claims, body map[string]any) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(string(raw)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id", "role_id")
	c.SetParamValues(orgID, roleID)
	if claims != nil {
		c.Set("claims", claims)
	}
	return c, rec
}

// ── Non-escalation on role creation/update (no DB required) ────────────────────

func TestRoleCreate_RejectsEscalation(t *testing.T) {
	// A delegated admin holding only clients:write cannot create a role that also
	// carries security:write.
	h := NewAdminDelegationHandler(nil)
	claims := &middleware.Claims{OrgID: "org-A", Permissions: []string{middleware.PermClientsWrite}}
	c, _ := createRoleCtx(t, uuid.NewString(), claims, map[string]any{
		"name":        "over-broad",
		"permissions": []string{middleware.PermClientsWrite, middleware.PermSecurityWrite},
	})
	he := httpErr(t, h.Create(c))
	assert.Equal(t, http.StatusForbidden, he.Code)
	assert.Contains(t, he.Message, middleware.PermSecurityWrite,
		"the 403 must name the permission that was refused")
}

func TestRoleUpdate_RejectsEscalation(t *testing.T) {
	h := NewAdminDelegationHandler(nil)
	claims := &middleware.Claims{OrgID: "org-A", Permissions: []string{middleware.PermClientsWrite}}
	c, _ := updateRoleCtx(t, uuid.NewString(), uuid.NewString(), claims, map[string]any{
		"name":        "over-broad",
		"permissions": []string{middleware.PermClientsWrite, middleware.PermUsersWrite},
	})
	he := httpErr(t, h.Update(c))
	assert.Equal(t, http.StatusForbidden, he.Code)
	assert.Contains(t, he.Message, middleware.PermUsersWrite)
}

func TestRoleCreate_RejectsUnknownTokenBeforeEscalation(t *testing.T) {
	// Token-catalogue validation (400) runs before the non-escalation check.
	h := NewAdminDelegationHandler(nil)
	claims := &middleware.Claims{OrgID: "org-A", Permissions: nil}
	c, _ := createRoleCtx(t, uuid.NewString(), claims, map[string]any{
		"name":        "bad-token",
		"permissions": []string{"superpower:delete"},
	})
	he := httpErr(t, h.Create(c))
	assert.Equal(t, http.StatusBadRequest, he.Code)
	assert.Contains(t, he.Message, "superpower:delete")
}

func TestRoleCreate_WriteImpliesReadIsAllowed(t *testing.T) {
	// Holding clients:write must let the caller grant clients:read in a role.
	// With a nil pool the authz checks pass and the flow reaches repo.Create,
	// which panics on a nil pool — so assert via the middleware primitive that the
	// request is NOT an escalation (the handler-level success path is covered by
	// the DB-backed test below).
	claims := &middleware.Claims{Permissions: []string{middleware.PermClientsWrite}}
	missing := middleware.PermissionsNotHeld(claims, []string{middleware.PermClientsRead})
	assert.Empty(t, missing)
}

// ── DB-backed integration ─────────────────────────────────────────────────────

func roleTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed role escalation tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func TestRoleCreate_LegacyAdminUnrestricted(t *testing.T) {
	// A legacy/full admin (Permissions == nil) may still create a role with any
	// valid permission — the non-escalation rule does not constrain them.
	pool := roleTestPool(t)
	ctx := context.Background()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "role-"+uuid.NewString(), "role-"+uuid.NewString(), nil)
	require.NoError(t, err)

	h := NewAdminDelegationHandler(pool)
	legacy := &middleware.Claims{OrgID: org.ID.String(), Permissions: nil}
	c, rec := createRoleCtx(t, org.ID.String(), legacy, map[string]any{
		"name":        "full-" + uuid.NewString(),
		"permissions": []string{middleware.PermSecurityWrite, middleware.PermUsersWrite},
	})
	require.NoError(t, h.Create(c))
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestRoleCreate_DelegatedAdminSubsetSucceeds(t *testing.T) {
	pool := roleTestPool(t)
	ctx := context.Background()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "role2-"+uuid.NewString(), "role2-"+uuid.NewString(), nil)
	require.NoError(t, err)

	h := NewAdminDelegationHandler(pool)
	delegated := &middleware.Claims{
		OrgID:       org.ID.String(),
		Permissions: []string{middleware.PermClientsWrite, middleware.PermRolesWrite},
	}
	c, rec := createRoleCtx(t, org.ID.String(), delegated, map[string]any{
		"name":        "subset-" + uuid.NewString(),
		"permissions": []string{middleware.PermClientsWrite, middleware.PermClientsRead},
	})
	require.NoError(t, h.Create(c))
	require.Equal(t, http.StatusCreated, rec.Code)

	var role models.AdminRole
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &role))
	assert.ElementsMatch(t, []string{middleware.PermClientsWrite, middleware.PermClientsRead}, role.Permissions)
}

func TestRoleCreate_PopulatesCreatedBy(t *testing.T) {
	// A role minted via the handler records the authoring admin (claims.Subject).
	pool := roleTestPool(t)
	ctx := context.Background()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "roleCB-"+uuid.NewString(), "roleCB-"+uuid.NewString(), nil)
	require.NoError(t, err)
	// created_by is an FK to identity.users — the author must be a real user.
	author, err := repository.NewUserRepository(pool).Create(ctx, org.ID, "author-"+uuid.NewString()+"@example.com", nil, nil)
	require.NoError(t, err)

	h := NewAdminDelegationHandler(pool)
	claims := &middleware.Claims{OrgID: org.ID.String(), Permissions: nil}
	claims.Subject = author.ID.String()

	c, rec := createRoleCtx(t, org.ID.String(), claims, map[string]any{
		"name":        "authored-" + uuid.NewString(),
		"permissions": []string{middleware.PermClientsWrite},
	})
	require.NoError(t, h.Create(c))
	require.Equal(t, http.StatusCreated, rec.Code)

	var role models.AdminRole
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &role))
	require.NotNil(t, role.CreatedBy, "created_by must be populated on new roles")
	assert.Equal(t, author.ID, *role.CreatedBy)
}

func TestRoleCreate_NonUUIDSubjectLeavesCreatedByNull(t *testing.T) {
	// If the caller's subject is not a user UUID (e.g. an API-key principal),
	// created_by is left NULL rather than failing the create.
	pool := roleTestPool(t)
	ctx := context.Background()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "roleCB2-"+uuid.NewString(), "roleCB2-"+uuid.NewString(), nil)
	require.NoError(t, err)

	h := NewAdminDelegationHandler(pool)
	claims := &middleware.Claims{OrgID: org.ID.String(), Permissions: nil}
	claims.Subject = "not-a-uuid"

	c, rec := createRoleCtx(t, org.ID.String(), claims, map[string]any{
		"name":        "no-author-" + uuid.NewString(),
		"permissions": []string{middleware.PermClientsWrite},
	})
	require.NoError(t, h.Create(c))
	require.Equal(t, http.StatusCreated, rec.Code)

	var role models.AdminRole
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &role))
	assert.Nil(t, role.CreatedBy)
}

func TestEnsureSystemRoles_LeaveCreatedByNull(t *testing.T) {
	// System roles are seeded by Clavex, not authored by a human — created_by NULL.
	pool := roleTestPool(t)
	ctx := context.Background()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "roleSys-"+uuid.NewString(), "roleSys-"+uuid.NewString(), nil)
	require.NoError(t, err)

	repo := repository.NewAdminRoleRepository(pool)
	require.NoError(t, repo.EnsureSystemRoles(ctx, org.ID))

	roles, err := repo.List(ctx, org.ID)
	require.NoError(t, err)
	require.NotEmpty(t, roles)
	for _, r := range roles {
		if r.IsSystem {
			assert.Nil(t, r.CreatedBy, "system role %s must have NULL created_by", r.Name)
		}
	}
}

func TestRoleUpdate_DelegatedAdminCannotBroadenLegacyRole(t *testing.T) {
	// A role created (legacy) with broad permissions can still be edited, but a
	// delegated admin editing it may not retain permissions they lack: future
	// updates must respect the subset constraint even for pre-existing roles.
	pool := roleTestPool(t)
	ctx := context.Background()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "role3-"+uuid.NewString(), "role3-"+uuid.NewString(), nil)
	require.NoError(t, err)

	// Pre-existing broad role (as if created before the constraint existed).
	role, err := repository.NewAdminRoleRepository(pool).Create(ctx, org.ID, "broad-"+uuid.NewString(), nil,
		[]string{middleware.PermSecurityWrite, middleware.PermClientsWrite}, nil)
	require.NoError(t, err)

	h := NewAdminDelegationHandler(pool)
	delegated := &middleware.Claims{OrgID: org.ID.String(), Permissions: []string{middleware.PermClientsWrite}}

	// Attempt to keep security:write (not held) → 403.
	c, _ := updateRoleCtx(t, org.ID.String(), role.ID.String(), delegated, map[string]any{
		"name":        role.Name,
		"permissions": []string{middleware.PermClientsWrite, middleware.PermSecurityWrite},
	})
	he := httpErr(t, h.Update(c))
	assert.Equal(t, http.StatusForbidden, he.Code)
	assert.Contains(t, he.Message, middleware.PermSecurityWrite)

	// Narrowing to held-only permissions succeeds.
	c2, rec2 := updateRoleCtx(t, org.ID.String(), role.ID.String(), delegated, map[string]any{
		"name":        role.Name,
		"permissions": []string{middleware.PermClientsWrite},
	})
	require.NoError(t, h.Update(c2))
	assert.Equal(t, http.StatusOK, rec2.Code)
}

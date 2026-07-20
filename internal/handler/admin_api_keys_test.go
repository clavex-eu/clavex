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

// createOrgKeyCtx builds an echo context for POST /organizations/:org_id/api-keys
// with the given caller claims and JSON body.
func createOrgKeyCtx(t *testing.T, orgID string, claims *middleware.Claims, body map[string]any) (echo.Context, *httptest.ResponseRecorder) {
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

func httpErr(t *testing.T, err error) *echo.HTTPError {
	t.Helper()
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok, "expected an echo.HTTPError, got %T", err)
	return he
}

// ── Non-escalation and validation (no DB required) ────────────────────────────

func TestCreateOrgScoped_RejectsEscalation(t *testing.T) {
	// A delegated admin holding only clients:write cannot mint a key that also
	// carries security:write.
	h := NewAdminAPIKeyHandler(nil)
	claims := &middleware.Claims{OrgID: "org-A", Permissions: []string{middleware.PermClientsWrite}}
	c, _ := createOrgKeyCtx(t, uuid.NewString(), claims, map[string]any{
		"name":        "escalate",
		"permissions": []string{middleware.PermClientsWrite, middleware.PermSecurityWrite},
	})
	he := httpErr(t, h.CreateOrgScoped(c))
	assert.Equal(t, http.StatusForbidden, he.Code)
	assert.Contains(t, he.Message, middleware.PermSecurityWrite,
		"the 403 must name the permission that was refused")
}

func TestCreateOrgScoped_RejectsEmptyPermissions(t *testing.T) {
	// Even a legacy/full admin (Permissions == nil) may not mint an unrestricted
	// key here — an explicit, non-empty list is mandatory; unrestricted keys stay
	// superadmin-only.
	h := NewAdminAPIKeyHandler(nil)
	claims := &middleware.Claims{OrgID: "org-A", Permissions: nil}
	c, _ := createOrgKeyCtx(t, uuid.NewString(), claims, map[string]any{
		"name":        "no-perms",
		"permissions": []string{},
	})
	he := httpErr(t, h.CreateOrgScoped(c))
	assert.Equal(t, http.StatusBadRequest, he.Code)
	assert.Contains(t, he.Message, "superadmin-only")
}

func TestCreateOrgScoped_RejectsUnknownToken(t *testing.T) {
	h := NewAdminAPIKeyHandler(nil)
	claims := &middleware.Claims{OrgID: "org-A", Permissions: nil}
	c, _ := createOrgKeyCtx(t, uuid.NewString(), claims, map[string]any{
		"name":        "bad-token",
		"permissions": []string{"superpower:delete"},
	})
	he := httpErr(t, h.CreateOrgScoped(c))
	assert.Equal(t, http.StatusBadRequest, he.Code)
	assert.Contains(t, he.Message, "superpower:delete")
}

func TestCreateOrgScoped_RejectsMissingName(t *testing.T) {
	h := NewAdminAPIKeyHandler(nil)
	claims := &middleware.Claims{OrgID: "org-A", Permissions: nil}
	c, _ := createOrgKeyCtx(t, uuid.NewString(), claims, map[string]any{
		"permissions": []string{middleware.PermClientsWrite},
	})
	he := httpErr(t, h.CreateOrgScoped(c))
	assert.Equal(t, http.StatusBadRequest, he.Code)
}

// ── DB-backed integration (create / list / revoke ownership) ──────────────────

func apiKeyTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed API key tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func newOrgKeyCtx(t *testing.T, orgID uuid.UUID, claims *middleware.Claims, body map[string]any) (echo.Context, *httptest.ResponseRecorder) {
	return createOrgKeyCtx(t, orgID.String(), claims, body)
}

func TestOrgScopedKeys_CreateListRevokeOwnership(t *testing.T) {
	pool := apiKeyTestPool(t)
	ctx := context.Background()
	orgs := repository.NewOrgRepository(pool)

	orgA, err := orgs.Create(ctx, "keyA-"+uuid.NewString(), "keyA-"+uuid.NewString(), nil)
	require.NoError(t, err)
	orgB, err := orgs.Create(ctx, "keyB-"+uuid.NewString(), "keyB-"+uuid.NewString(), nil)
	require.NoError(t, err)

	h := NewAdminAPIKeyHandler(pool)
	claimsA := &middleware.Claims{OrgID: orgA.ID.String(), Permissions: []string{middleware.PermClientsWrite}}

	// Create a key in org A.
	c, rec := newOrgKeyCtx(t, orgA.ID, claimsA, map[string]any{
		"name":        "operator",
		"permissions": []string{middleware.PermClientsWrite},
	})
	require.NoError(t, h.CreateOrgScoped(c))
	require.Equal(t, http.StatusCreated, rec.Code)

	var created createAPIKeyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.True(t, strings.HasPrefix(created.Key, "clv_"), "raw key must be returned once")
	meta := created.Meta.(map[string]any)
	keyID := meta["id"].(string)

	// List for org A returns exactly this key; org B sees nothing.
	lc, lrec := listOrgKeyCtx(t, orgA.ID)
	require.NoError(t, h.ListOrgScoped(lc))
	var listA []models.AdminAPIKey
	require.NoError(t, json.Unmarshal(lrec.Body.Bytes(), &listA))
	require.Len(t, listA, 1)
	assert.Equal(t, keyID, listA[0].ID.String())

	lcB, lrecB := listOrgKeyCtx(t, orgB.ID)
	require.NoError(t, h.ListOrgScoped(lcB))
	var listB []models.AdminAPIKey
	require.NoError(t, json.Unmarshal(lrecB.Body.Bytes(), &listB))
	assert.Empty(t, listB, "org B must not see org A's keys")

	// Org B cannot revoke org A's key (ownership enforced at the SQL layer).
	rcB, _ := revokeOrgKeyCtx(t, orgB.ID, keyID)
	heB := httpErr(t, h.RevokeOrgScoped(rcB))
	assert.Equal(t, http.StatusNotFound, heB.Code)

	// Org A can revoke its own key.
	rcA, rrecA := revokeOrgKeyCtx(t, orgA.ID, keyID)
	require.NoError(t, h.RevokeOrgScoped(rcA))
	assert.Equal(t, http.StatusNoContent, rrecA.Code)
}

func TestCreateOrgScoped_IgnoresBodyOrgID(t *testing.T) {
	// A rogue org_id in the body must be inert: the key is stored under the path
	// org (which RequireOrgAccess pins to the caller's org), never the body value.
	pool := apiKeyTestPool(t)
	ctx := context.Background()
	orgs := repository.NewOrgRepository(pool)
	orgA, err := orgs.Create(ctx, "keyPathA-"+uuid.NewString(), "keyPathA-"+uuid.NewString(), nil)
	require.NoError(t, err)
	orgB, err := orgs.Create(ctx, "keyBodyB-"+uuid.NewString(), "keyBodyB-"+uuid.NewString(), nil)
	require.NoError(t, err)

	h := NewAdminAPIKeyHandler(pool)
	claimsA := &middleware.Claims{OrgID: orgA.ID.String(), Permissions: []string{middleware.PermClientsWrite}}
	c, rec := newOrgKeyCtx(t, orgA.ID, claimsA, map[string]any{
		"name":        "rogue-org",
		"org_id":      orgB.ID.String(), // must be ignored
		"permissions": []string{middleware.PermClientsWrite},
	})
	require.NoError(t, h.CreateOrgScoped(c))
	require.Equal(t, http.StatusCreated, rec.Code)

	var created createAPIKeyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	meta := created.Meta.(map[string]any)
	assert.Equal(t, orgA.ID.String(), meta["org_id"], "key must be scoped to the path org, not the body org_id")

	// It appears in org A's list, never org B's.
	lcB, lrecB := listOrgKeyCtx(t, orgB.ID)
	require.NoError(t, h.ListOrgScoped(lcB))
	var listB []models.AdminAPIKey
	require.NoError(t, json.Unmarshal(lrecB.Body.Bytes(), &listB))
	assert.Empty(t, listB)
}

func TestOrgScopedList_ExcludesSuperadminKeys(t *testing.T) {
	pool := apiKeyTestPool(t)
	ctx := context.Background()
	orgs := repository.NewOrgRepository(pool)
	org, err := orgs.Create(ctx, "keyC-"+uuid.NewString(), "keyC-"+uuid.NewString(), nil)
	require.NoError(t, err)

	repo := repository.NewAdminAPIKeyRepository(pool)
	// A legacy superadmin (cross-org, org_id NULL) key must never surface in an
	// org's list.
	_, _, err = repo.Create(ctx, "legacy-superadmin", "read-write", nil, nil, nil, nil)
	require.NoError(t, err)

	h := NewAdminAPIKeyHandler(pool)
	lc, lrec := listOrgKeyCtx(t, org.ID)
	require.NoError(t, h.ListOrgScoped(lc))
	var list []models.AdminAPIKey
	require.NoError(t, json.Unmarshal(lrec.Body.Bytes(), &list))
	assert.Empty(t, list, "cross-org superadmin keys are not this org's keys")
}

func listOrgKeyCtx(t *testing.T, orgID uuid.UUID) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id")
	c.SetParamValues(orgID.String())
	return c, rec
}

func revokeOrgKeyCtx(t *testing.T, orgID uuid.UUID, keyID string) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id", "id")
	c.SetParamValues(orgID.String(), keyID)
	return c, rec
}

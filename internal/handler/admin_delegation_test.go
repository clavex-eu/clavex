package handler

import (
	"net/http"
	"testing"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── validatePermissions ───────────────────────────────────────────────────────

func TestValidatePermissions_AllKnownTokens(t *testing.T) {
	// Every token in AllPermissions must be accepted without error.
	all := make([]string, 0, len(middleware.AllPermissions))
	for _, p := range middleware.AllPermissions {
		all = append(all, p.Token)
	}
	require.NoError(t, validatePermissions(all),
		"the complete set of canonical tokens must validate cleanly")
}

func TestValidatePermissions_EmptySlice(t *testing.T) {
	// An empty permission list is valid — a role with no permissions is allowed.
	assert.NoError(t, validatePermissions([]string{}))
	assert.NoError(t, validatePermissions(nil))
}

func TestValidatePermissions_UnknownToken(t *testing.T) {
	err := validatePermissions([]string{"users:read", "superpower:delete"})
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok, "error must be an echo.HTTPError")
	assert.Equal(t, http.StatusBadRequest, he.Code)
	assert.Contains(t, he.Message, "superpower:delete",
		"error message should name the offending token")
}

func TestValidatePermissions_CaseSensitive(t *testing.T) {
	// Permission tokens are case-sensitive lowercase; "Users:Read" must be rejected.
	err := validatePermissions([]string{"Users:Read"})
	require.Error(t, err, "mixed-case token must be rejected")
}

func TestValidatePermissions_SingleValidToken(t *testing.T) {
	assert.NoError(t, validatePermissions([]string{middleware.PermUsersRead}))
}

func TestValidatePermissions_DuplicateTokens(t *testing.T) {
	// Duplicates of a valid token must still pass (deduplication is not required).
	perms := []string{middleware.PermUsersRead, middleware.PermUsersRead}
	assert.NoError(t, validatePermissions(perms))
}

func TestValidatePermissions_WriteImpliesReadTokensAreDistinct(t *testing.T) {
	// users:read and users:write are separate tokens — both must validate.
	assert.NoError(t, validatePermissions([]string{
		middleware.PermUsersRead,
		middleware.PermUsersWrite,
	}))
}

func TestValidatePermissions_AllPermissionsHaveResourceAndAction(t *testing.T) {
	// Sanity-check the catalogue: every entry must have non-empty Token, Resource, Action.
	for _, p := range middleware.AllPermissions {
		assert.NotEmpty(t, p.Token, "permission token must not be empty")
		assert.NotEmpty(t, p.Resource, "resource must not be empty for token %s", p.Token)
		assert.NotEmpty(t, p.Action, "action must not be empty for token %s", p.Token)
	}
}

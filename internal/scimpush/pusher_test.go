package scimpush

import (
	"testing"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }

func newUser(email string, firstName, lastName *string, active bool) *models.User {
	return &models.User{
		ID:        uuid.New(),
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		IsActive:  active,
	}
}

// ── buildSCIMUser ─────────────────────────────────────────────────────────────

func TestBuildSCIMUser_BasicMapping(t *testing.T) {
	u := newUser("alice@example.com", nil, nil, true)
	su := buildSCIMUser(u)

	assert.Equal(t, []string{scimSchema}, su.Schemas)
	assert.Equal(t, u.ID.String(), su.ID)
	assert.Equal(t, u.ID.String(), su.ExternalID)
	assert.Equal(t, "alice@example.com", su.UserName)
	assert.True(t, su.Active)
}

func TestBuildSCIMUser_EmailList(t *testing.T) {
	u := newUser("bob@acme.com", nil, nil, true)
	su := buildSCIMUser(u)

	require.Len(t, su.Emails, 1)
	assert.Equal(t, "bob@acme.com", su.Emails[0].Value)
	assert.Equal(t, "work", su.Emails[0].Type)
	assert.True(t, su.Emails[0].Primary)
}

func TestBuildSCIMUser_NoNameFields_NameIsNil(t *testing.T) {
	u := newUser("carol@test.io", nil, nil, true)
	su := buildSCIMUser(u)
	assert.Nil(t, su.Name, "Name should be nil when both first and last name are absent")
}

func TestBuildSCIMUser_BothNames(t *testing.T) {
	u := newUser("dave@test.io", strPtr("Dave"), strPtr("Smith"), true)
	su := buildSCIMUser(u)

	require.NotNil(t, su.Name)
	assert.Equal(t, "Dave", su.Name.GivenName)
	assert.Equal(t, "Smith", su.Name.FamilyName)
	assert.Equal(t, "Dave Smith", su.Name.Formatted)
}

func TestBuildSCIMUser_OnlyFirstName(t *testing.T) {
	u := newUser("eve@test.io", strPtr("Eve"), nil, true)
	su := buildSCIMUser(u)

	require.NotNil(t, su.Name)
	assert.Equal(t, "Eve", su.Name.GivenName)
	assert.Equal(t, "", su.Name.FamilyName)
	// Formatted: "Eve " — has trailing space but name block is set
	assert.Contains(t, su.Name.Formatted, "Eve")
}

func TestBuildSCIMUser_OnlyLastName(t *testing.T) {
	u := newUser("frank@test.io", nil, strPtr("Jones"), true)
	su := buildSCIMUser(u)

	require.NotNil(t, su.Name)
	assert.Equal(t, "", su.Name.GivenName)
	assert.Equal(t, "Jones", su.Name.FamilyName)
}

func TestBuildSCIMUser_InactiveUser(t *testing.T) {
	u := newUser("ghost@test.io", strPtr("Ghost"), strPtr("User"), false)
	su := buildSCIMUser(u)
	assert.False(t, su.Active)
}

func TestBuildSCIMUser_UUIDPreserved(t *testing.T) {
	id := uuid.MustParse("12345678-1234-1234-1234-123456789abc")
	u := &models.User{ID: id, Email: "x@x.io", IsActive: true}
	su := buildSCIMUser(u)
	assert.Equal(t, "12345678-1234-1234-1234-123456789abc", su.ID)
	assert.Equal(t, "12345678-1234-1234-1234-123456789abc", su.ExternalID)
}

func TestBuildSCIMUser_SchemaAlwaysSet(t *testing.T) {
	u := &models.User{ID: uuid.New(), Email: "z@z.io", IsActive: true}
	su := buildSCIMUser(u)
	assert.Equal(t, scimSchema, su.Schemas[0])
}

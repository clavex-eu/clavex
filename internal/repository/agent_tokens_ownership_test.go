package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Self-service ownership harness for the "My Active Agents" panel.
//
// ListMine / RevokeByOwner are keyed on user_id (not org) and must never let one
// user see or revoke another user's agent token — even when both users belong to
// the SAME organization. This guards the self-service DELETE endpoint against the
// IDOR where user B revokes user A's delegated agent by its globally unique id.
//
// DB-backed; skipped when TEST_DATABASE_URL is unset (reuses idorPool/skip).
func createAgentToken(t *testing.T, ctx context.Context, repo *AgentTokenRepository, orgID, userID uuid.UUID, scope string) uuid.UUID {
	t.Helper()
	tok, err := repo.Create(ctx, orgID, userID,
		"agent-"+uuid.NewString(), "Test Agent", scope, "jti-"+uuid.NewString(),
		time.Now().Add(1*time.Hour), &userID, nil, nil)
	require.NoError(t, err)
	return tok.ID
}

func TestAgentToken_RevokeByOwner_CrossUserRejected(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	// Both users live in the SAME org — ownership must still isolate them.
	org, _ := twoOrgs(t, ctx, pool)
	users := NewUserRepository(pool)
	repo := NewAgentTokenRepository(pool)

	owner, err := users.Create(ctx, org, "owner-"+uuid.NewString()+"@t.local", nil, nil)
	require.NoError(t, err)
	attacker, err := users.Create(ctx, org, "attacker-"+uuid.NewString()+"@t.local", nil, nil)
	require.NoError(t, err)

	tokID := createAgentToken(t, ctx, repo, org, owner.ID, "mcp:read")

	// Attacker (same org, different user) cannot revoke the owner's token.
	require.ErrorIs(t, repo.RevokeByOwner(ctx, tokID, attacker.ID), pgx.ErrNoRows)

	// Token is still active (attacker revoke was a no-op).
	mine, err := repo.ListMine(ctx, owner.ID)
	require.NoError(t, err)
	require.Len(t, mine, 1)
	require.False(t, mine[0].IsRevoked)

	// Owner can revoke their own token.
	require.NoError(t, repo.RevokeByOwner(ctx, tokID, owner.ID))

	// Second revoke is a no-op (already revoked) → ErrNoRows.
	require.ErrorIs(t, repo.RevokeByOwner(ctx, tokID, owner.ID), pgx.ErrNoRows)
}

func TestAgentToken_ListMine_OnlyOwnTokens(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	org, _ := twoOrgs(t, ctx, pool)
	users := NewUserRepository(pool)
	repo := NewAgentTokenRepository(pool)

	alice, err := users.Create(ctx, org, "alice-"+uuid.NewString()+"@t.local", nil, nil)
	require.NoError(t, err)
	bob, err := users.Create(ctx, org, "bob-"+uuid.NewString()+"@t.local", nil, nil)
	require.NoError(t, err)

	createAgentToken(t, ctx, repo, org, alice.ID, "mcp:read")
	createAgentToken(t, ctx, repo, org, alice.ID, "mcp:write")
	createAgentToken(t, ctx, repo, org, bob.ID, "mcp:read")

	// Alice sees only her two grants, never Bob's — even though same org.
	mine, err := repo.ListMine(ctx, alice.ID)
	require.NoError(t, err)
	require.Len(t, mine, 2)
	for _, tok := range mine {
		require.Equal(t, alice.ID, tok.UserID)
	}

	bobMine, err := repo.ListMine(ctx, bob.ID)
	require.NoError(t, err)
	require.Len(t, bobMine, 1)
	require.Equal(t, bob.ID, bobMine[0].UserID)
}

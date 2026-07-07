package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentUsageRepository records and summarises how a specific AI agent identity
// (agent_id) has historically used its tokens. It is the behavioural history the
// UEBA agent scorer consumes to detect anomalous call frequency and scope drift.
type AgentUsageRepository struct {
	pool *pgxpool.Pool
}

func NewAgentUsageRepository(pool *pgxpool.Pool) *AgentUsageRepository {
	return &AgentUsageRepository{pool: pool}
}

// Record appends one usage event for an agent token presentation. Best-effort:
// the caller sits on a hot introspection path, so a failed write must never fail
// the request — errors are returned but callers may choose to ignore them.
func (r *AgentUsageRepository) Record(ctx context.Context, orgID uuid.UUID, agentID, jti, scope string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO agent_token_usage (org_id, agent_id, jti, scope, used_at)
		VALUES ($1, $2, $3, $4, NOW())`, orgID, agentID, jti, scope)
	return err
}

// AgentUsageStats is the compact behavioural summary for one agent identity.
type AgentUsageStats struct {
	// TotalCalls is the number of recorded usage events for the agent.
	TotalCalls int
	// FirstSeen is the timestamp of the earliest recorded usage event.
	FirstSeen time.Time
	// CallsLastHour is the number of usage events in the trailing 1-hour window.
	CallsLastHour int
	// ScopeCounts maps each individual scope token the agent has historically
	// presented to how many usage events carried it.
	ScopeCounts map[string]int
}

// Stats computes the behavioural summary for (orgID, agentID) in two queries:
// aggregate counts, then the historical per-scope distribution. Both are bounded
// by the agent_token_usage index on (org_id, agent_id, used_at).
func (r *AgentUsageRepository) Stats(ctx context.Context, orgID uuid.UUID, agentID string) (*AgentUsageStats, error) {
	s := &AgentUsageStats{ScopeCounts: make(map[string]int)}

	row := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COALESCE(MIN(used_at), NOW()),
			COUNT(*) FILTER (WHERE used_at >= NOW() - INTERVAL '1 hour')
		FROM agent_token_usage
		WHERE org_id = $1 AND agent_id = $2`, orgID, agentID)
	if err := row.Scan(&s.TotalCalls, &s.FirstSeen, &s.CallsLastHour); err != nil {
		return nil, err
	}

	// Historical scope distribution: split each stored space-separated scope
	// string into individual tokens and count occurrences.
	rows, err := r.pool.Query(ctx, `
		SELECT tok, COUNT(*)
		FROM agent_token_usage,
		     LATERAL regexp_split_to_table(trim(scope), '\s+') AS tok
		WHERE org_id = $1 AND agent_id = $2 AND trim(scope) <> ''
		GROUP BY tok`, orgID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var tok string
		var n int
		if err := rows.Scan(&tok, &n); err != nil {
			return nil, err
		}
		if tok != "" {
			s.ScopeCounts[tok] = n
		}
	}
	return s, rows.Err()
}

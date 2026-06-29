package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CrossOrgTrustRepository manages directional cross-organisation token exchange
// trust relationships (RFC 8693 multi-tenant).
type CrossOrgTrustRepository struct {
	pool *pgxpool.Pool
}

func NewCrossOrgTrustRepository(pool *pgxpool.Pool) *CrossOrgTrustRepository {
	return &CrossOrgTrustRepository{pool: pool}
}

const crossOrgTrustCols = `id, source_org_id, target_org_id, allowed_scopes,
	allowed_client_ids, max_token_ttl, require_mfa, is_active, created_at, created_by`

func scanCrossOrgTrust(row pgx.Row) (*models.CrossOrgTrust, error) {
	t := &models.CrossOrgTrust{}
	err := row.Scan(
		&t.ID, &t.SourceOrgID, &t.TargetOrgID,
		&t.AllowedScopes, &t.AllowedClientIDs,
		&t.MaxTokenTTL, &t.RequireMFA,
		&t.IsActive, &t.CreatedAt, &t.CreatedBy,
	)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Create inserts a new cross-org trust. Returns an error if the pair already exists.
func (r *CrossOrgTrustRepository) Create(
	ctx context.Context,
	sourceOrgID, targetOrgID uuid.UUID,
	allowedScopes, allowedClientIDs []string,
	maxTokenTTL *int,
	requireMFA bool,
	createdBy string,
) (*models.CrossOrgTrust, error) {
	if sourceOrgID == targetOrgID {
		return nil, fmt.Errorf("source and target org must differ")
	}
	return scanCrossOrgTrust(r.pool.QueryRow(ctx, `
		INSERT INTO cross_org_trusts
		    (source_org_id, target_org_id, allowed_scopes, allowed_client_ids,
		     max_token_ttl, require_mfa, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+crossOrgTrustCols,
		sourceOrgID, targetOrgID,
		toNullableTextArray(allowedScopes),
		toNullableTextArray(allowedClientIDs),
		maxTokenTTL,
		requireMFA,
		createdBy,
	))
}

// GetTrust returns the active trust for the given source→target pair, or
// ErrNotFound (pgx.ErrNoRows) if no active trust exists.
func (r *CrossOrgTrustRepository) GetTrust(
	ctx context.Context,
	sourceOrgID, targetOrgID uuid.UUID,
) (*models.CrossOrgTrust, error) {
	return scanCrossOrgTrust(r.pool.QueryRow(ctx, `
		SELECT `+crossOrgTrustCols+`
		FROM cross_org_trusts
		WHERE source_org_id = $1 AND target_org_id = $2 AND is_active = TRUE
	`, sourceOrgID, targetOrgID))
}

// ListBySourceOrg returns all trust records (active and revoked) where this org
// is the source — i.e., outbound trusts this org has granted.
func (r *CrossOrgTrustRepository) ListBySourceOrg(
	ctx context.Context,
	sourceOrgID uuid.UUID,
) ([]*models.CrossOrgTrust, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+crossOrgTrustCols+`
		FROM cross_org_trusts
		WHERE source_org_id = $1
		ORDER BY created_at DESC
	`, sourceOrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectCrossOrgTrusts(rows)
}

// ListByTargetOrg returns all trust records where this org is the target —
// i.e., which orgs are allowed to exchange tokens into this org.
func (r *CrossOrgTrustRepository) ListByTargetOrg(
	ctx context.Context,
	targetOrgID uuid.UUID,
) ([]*models.CrossOrgTrust, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+crossOrgTrustCols+`
		FROM cross_org_trusts
		WHERE target_org_id = $1
		ORDER BY created_at DESC
	`, targetOrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectCrossOrgTrusts(rows)
}

// Revoke soft-deletes a trust by setting is_active = FALSE.
// Returns ErrNotFound if the trust doesn't exist or doesn't belong to the
// given sourceOrgID (prevents cross-tenant manipulation).
func (r *CrossOrgTrustRepository) Revoke(
	ctx context.Context,
	trustID, sourceOrgID uuid.UUID,
) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE cross_org_trusts
		SET is_active = FALSE
		WHERE id = $1 AND source_org_id = $2 AND is_active = TRUE
	`, trustID, sourceOrgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// GetByID returns a trust by its UUID, scoped to the given sourceOrgID.
func (r *CrossOrgTrustRepository) GetByID(
	ctx context.Context,
	trustID, sourceOrgID uuid.UUID,
) (*models.CrossOrgTrust, error) {
	return scanCrossOrgTrust(r.pool.QueryRow(ctx, `
		SELECT `+crossOrgTrustCols+`
		FROM cross_org_trusts
		WHERE id = $1 AND source_org_id = $2
	`, trustID, sourceOrgID))
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// toNullableTextArray converts an empty slice to nil (SQL NULL) so that the
// JSONB semantics (NULL = no restriction) are preserved.
func toNullableTextArray(s []string) interface{} {
	if len(s) == 0 {
		return nil
	}
	return s
}

func collectCrossOrgTrusts(rows pgx.Rows) ([]*models.CrossOrgTrust, error) {
	var out []*models.CrossOrgTrust
	for rows.Next() {
		t, err := scanCrossOrgTrust(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// IsTrustAllowed checks a loaded trust against the requesting client_id and
// the intersection of requested scopes. Returns true if the exchange is
// permitted, plus the effective (narrowed) scope string.
func IsTrustAllowed(trust *models.CrossOrgTrust, clientID, requestedScope string) (allowed bool, effectiveScope string) {
	// Client restriction.
	if len(trust.AllowedClientIDs) > 0 {
		ok := false
		for _, c := range trust.AllowedClientIDs {
			if c == clientID {
				ok = true
				break
			}
		}
		if !ok {
			return false, ""
		}
	}

	// Scope narrowing against trust's allowed_scopes.
	effectiveScope = requestedScope
	if len(trust.AllowedScopes) > 0 && requestedScope != "" {
		effectiveScope = intersectScopes(trust.AllowedScopes, requestedScope)
		if effectiveScope == "" {
			return false, ""
		}
	}
	return true, effectiveScope
}

// intersectScopes returns the space-joined intersection of allowedScopes and
// the space-separated requested string. Returns "" if nothing survives.
func intersectScopes(allowed []string, requested string) string {
	set := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		set[s] = true
	}
	var result []string
	for _, s := range splitWords(requested) {
		if set[s] {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return ""
	}
	out := result[0]
	for i := 1; i < len(result); i++ {
		out += " " + result[i]
	}
	return out
}

func splitWords(s string) []string {
	var out []string
	start := -1
	for i, c := range s {
		if c == ' ' || c == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

// ErrTrustNotFound is returned when no active trust is found.
var ErrTrustNotFound = errors.New("no active cross-org trust found")

// TrustAge returns how long the trust has been active.
func TrustAge(t *models.CrossOrgTrust) time.Duration {
	return time.Since(t.CreatedAt)
}

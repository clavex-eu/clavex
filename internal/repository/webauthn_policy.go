package repository

import (
	"context"
	"errors"
	"time"

	"github.com/clavex-eu/clavex/internal/attestation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebAuthnPolicyRepository manages per-org WebAuthn attestation enforcement policies.
type WebAuthnPolicyRepository struct {
	pool *pgxpool.Pool
}

func NewWebAuthnPolicyRepository(pool *pgxpool.Pool) *WebAuthnPolicyRepository {
	return &WebAuthnPolicyRepository{pool: pool}
}

// Get returns the attestation policy for an org.
// Returns a disabled (no-op) policy if the org has not configured one.
func (r *WebAuthnPolicyRepository) Get(ctx context.Context, orgID uuid.UUID) (*attestation.Policy, error) {
	p := &attestation.Policy{}
	err := r.pool.QueryRow(ctx, `
		SELECT enabled, require_attestation, allowed_formats, allowed_aaguids, allowed_transports,
		       COALESCE(require_mds_certification, false),
		       COALESCE(min_certification_level, ''),
		       COALESCE(exclude_revoked_authenticators, false)
		FROM webauthn_attestation_policies
		WHERE org_id = $1
	`, orgID).Scan(
		&p.Enabled,
		&p.RequireAttestation,
		&p.AllowedFormats,
		&p.AllowedAAGUIDs,
		&p.AllowedTransports,
		&p.RequireMDSCertification,
		&p.MinCertificationLevel,
		&p.ExcludeRevokedAuthenticators,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No policy configured — return a disabled (pass-through) policy.
			return &attestation.Policy{Enabled: false}, nil
		}
		return nil, err
	}
	return p, nil
}

// Upsert creates or replaces the attestation policy for an org.
// An entity event (policy.webauthn_changed) is written atomically in the same transaction.
func (r *WebAuthnPolicyRepository) Upsert(ctx context.Context, orgID uuid.UUID, p *attestation.Policy) (*attestation.Policy, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	out := &attestation.Policy{}
	minCertLevel := ""
	if p.MinCertificationLevel != "" {
		minCertLevel = p.MinCertificationLevel
	}
	if err = tx.QueryRow(ctx, `
		INSERT INTO webauthn_attestation_policies
			(org_id, enabled, require_attestation, allowed_formats, allowed_aaguids, allowed_transports,
			 require_mds_certification, min_certification_level, exclude_revoked_authenticators, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8,''), $9, NOW())
		ON CONFLICT (org_id) DO UPDATE SET
			enabled                        = EXCLUDED.enabled,
			require_attestation            = EXCLUDED.require_attestation,
			allowed_formats                = EXCLUDED.allowed_formats,
			allowed_aaguids                = EXCLUDED.allowed_aaguids,
			allowed_transports             = EXCLUDED.allowed_transports,
			require_mds_certification      = EXCLUDED.require_mds_certification,
			min_certification_level        = EXCLUDED.min_certification_level,
			exclude_revoked_authenticators = EXCLUDED.exclude_revoked_authenticators,
			updated_at                     = NOW()
		RETURNING enabled, require_attestation, allowed_formats, allowed_aaguids, allowed_transports,
		          COALESCE(require_mds_certification, false),
		          COALESCE(min_certification_level, ''),
		          COALESCE(exclude_revoked_authenticators, false)
	`, orgID, p.Enabled, p.RequireAttestation, p.AllowedFormats, p.AllowedAAGUIDs, p.AllowedTransports,
		p.RequireMDSCertification, minCertLevel, p.ExcludeRevokedAuthenticators,
	).Scan(
		&out.Enabled,
		&out.RequireAttestation,
		&out.AllowedFormats,
		&out.AllowedAAGUIDs,
		&out.AllowedTransports,
		&out.RequireMDSCertification,
		&out.MinCertificationLevel,
		&out.ExcludeRevokedAuthenticators,
	); err != nil {
		return nil, err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "policy",
		EntityID:   orgID.String(),
		EventType:  "policy.webauthn_changed",
		Payload: map[string]any{
			"enabled":                        p.Enabled,
			"require_attestation":            p.RequireAttestation,
			"require_mds_certification":      p.RequireMDSCertification,
			"exclude_revoked_authenticators": p.ExcludeRevokedAuthenticators,
		},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	return out, tx.Commit(ctx)
}

// Delete removes the attestation policy for an org (resets to no policy / pass-through).
// An entity event (policy.webauthn_deleted) is written atomically in the same transaction.
func (r *WebAuthnPolicyRepository) Delete(ctx context.Context, orgID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `DELETE FROM webauthn_attestation_policies WHERE org_id = $1`, orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "policy",
		EntityID:   orgID.String(),
		EventType:  "policy.webauthn_deleted",
		Payload:    map[string]any{"deleted": true},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ScopedPolicy represents a scoped attestation policy attached to a group or role.
type ScopedPolicy struct {
	ID        uuid.UUID          `json:"id"`
	OrgID     uuid.UUID          `json:"org_id"`
	ScopeType string             `json:"scope_type"` // "group" or "role"
	ScopeID   uuid.UUID          `json:"scope_id"`
	Policy    attestation.Policy `json:"policy"`
}

// UpsertScoped creates or replaces a scoped attestation policy for a group or role.
// An entity event (policy.webauthn_scoped_changed) is written atomically in the same transaction.
func (r *WebAuthnPolicyRepository) UpsertScoped(ctx context.Context, orgID uuid.UUID, scopeType string, scopeID uuid.UUID, policy *attestation.Policy) (*ScopedPolicy, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	out := &ScopedPolicy{}
	if err = tx.QueryRow(ctx, `
		INSERT INTO webauthn_scoped_attestation_policies
			(org_id, scope_type, scope_id, policy, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (org_id, scope_type, scope_id)
		DO UPDATE SET policy = EXCLUDED.policy, updated_at = now()
		RETURNING id, org_id, scope_type, scope_id, policy
	`, orgID, scopeType, scopeID, policy).Scan(&out.ID, &out.OrgID, &out.ScopeType, &out.ScopeID, &out.Policy); err != nil {
		return nil, err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "policy",
		EntityID:   out.ID.String(),
		EventType:  "policy.webauthn_scoped_changed",
		Payload:    map[string]any{"scope_type": scopeType, "scope_id": scopeID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	return out, tx.Commit(ctx)
}

// GetScoped returns the scoped policy for a specific scope, or nil if not found.
func (r *WebAuthnPolicyRepository) GetScoped(ctx context.Context, orgID uuid.UUID, scopeType string, scopeID uuid.UUID) (*ScopedPolicy, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, org_id, scope_type, scope_id, policy
		FROM webauthn_scoped_attestation_policies
		WHERE org_id = $1 AND scope_type = $2 AND scope_id = $3
	`, orgID, scopeType, scopeID)

	out := &ScopedPolicy{}
	err := row.Scan(&out.ID, &out.OrgID, &out.ScopeType, &out.ScopeID, &out.Policy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListScoped returns all scoped policies for an org.
func (r *WebAuthnPolicyRepository) ListScoped(ctx context.Context, orgID uuid.UUID) ([]*ScopedPolicy, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, scope_type, scope_id, policy
		FROM webauthn_scoped_attestation_policies
		WHERE org_id = $1
		ORDER BY scope_type, scope_id
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*ScopedPolicy
	for rows.Next() {
		p := &ScopedPolicy{}
		if err := rows.Scan(&p.ID, &p.OrgID, &p.ScopeType, &p.ScopeID, &p.Policy); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteScoped removes a scoped policy for a group or role.
// An entity event (policy.webauthn_scoped_deleted) is written atomically in the same transaction.
func (r *WebAuthnPolicyRepository) DeleteScoped(ctx context.Context, orgID uuid.UUID, scopeType string, scopeID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `
		DELETE FROM webauthn_scoped_attestation_policies
		WHERE org_id = $1 AND scope_type = $2 AND scope_id = $3
	`, orgID, scopeType, scopeID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "policy",
		EntityID:   scopeID.String(),
		EventType:  "policy.webauthn_scoped_deleted",
		Payload:    map[string]any{"scope_type": scopeType, "scope_id": scopeID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// GetScopedForUser returns all scoped attestation policies applicable to the given user
// (via their group and role memberships).
func (r *WebAuthnPolicyRepository) GetScopedForUser(ctx context.Context, orgID, userID uuid.UUID) ([]*attestation.Policy, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT p.policy
		FROM webauthn_scoped_attestation_policies p
		WHERE p.org_id = $1
		  AND (
		    (p.scope_type = 'group' AND p.scope_id IN (
		        SELECT group_id FROM group_members WHERE user_id = $2
		    ))
		    OR
		    (p.scope_type = 'role' AND p.scope_id IN (
		        SELECT role_id FROM user_roles WHERE user_id = $2
		    ))
		  )
	`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*attestation.Policy
	for rows.Next() {
		p := &attestation.Policy{}
		if err := rows.Scan(p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

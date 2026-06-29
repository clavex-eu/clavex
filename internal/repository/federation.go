package repository

// federation.go — repository operations for OpenID Federation Trust Anchor support.
//
// Covers:
//   - Subordinate entity registration (OIDF §7.3.1, §7.3.2)
//   - Trust Mark type management (OIDF §8)
//   - Trust Mark issuance and revocation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Model types ───────────────────────────────────────────────────────────────

// FederationSubordinate is a registered subordinate entity in the private
// Trust Anchor's federation.
type FederationSubordinate struct {
	ID               uuid.UUID
	OrgID            uuid.UUID
	EntityID         string
	Name             string
	EntityTypes      []string
	JWKS             json.RawMessage // {"keys":[...]}
	JWKSUri          string
	MetadataOverride json.RawMessage
	MetadataPolicy   json.RawMessage
	TrustMarkIDs     []string
	Status           string
	StatementLifetime int
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// FederationTrustMarkType describes a Trust Mark that this TA can issue.
type FederationTrustMarkType struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	TrustMarkID string // URI identifier
	Name        string
	Description string
	LogoURI     string
	RefURI      string
	LifetimeSecs int
	CreatedAt   time.Time
}

// FederationTrustMark is an issued (signed) trust mark for a specific subject.
type FederationTrustMark struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	TrustMarkID string
	Subject     string
	IssuedJWT   string
	ExpiresAt   time.Time
	Revoked     bool
	RevokedAt   *time.Time
	RevokedReason string
	IssuedAt    time.Time
}

// ── Params ────────────────────────────────────────────────────────────────────

// UpsertSubordinateParams holds the data for registering or updating a
// subordinate entity in the TA's federation.
type UpsertSubordinateParams struct {
	OrgID            uuid.UUID
	EntityID         string
	Name             string
	EntityTypes      []string
	JWKS             json.RawMessage
	JWKSUri          string
	MetadataOverride json.RawMessage
	MetadataPolicy   json.RawMessage
	TrustMarkIDs     []string
	Status           string // "active" | "suspended" | "revoked"
	StatementLifetime int
}

// IssueTrustMarkParams holds the data needed to persist an issued trust mark.
type IssueTrustMarkParams struct {
	OrgID       uuid.UUID
	TrustMarkID string
	Subject     string
	IssuedJWT   string
	ExpiresAt   time.Time
}

// ── Repository ────────────────────────────────────────────────────────────────

// FederationRepository manages Trust Anchor data.
type FederationRepository struct {
	pool *pgxpool.Pool
}

// NewFederationRepository constructs a FederationRepository.
func NewFederationRepository(pool *pgxpool.Pool) *FederationRepository {
	return &FederationRepository{pool: pool}
}

// ── Subordinates ──────────────────────────────────────────────────────────────

// UpsertSubordinate creates or updates a subordinate entity registration.
func (r *FederationRepository) UpsertSubordinate(ctx context.Context, p UpsertSubordinateParams) (*FederationSubordinate, error) {
	if p.Status == "" {
		p.Status = "active"
	}
	const q = `
INSERT INTO federation_subordinates
    (org_id, entity_id, name, entity_types, jwks, jwks_uri,
     metadata_override, metadata_policy, trust_mark_ids, status, statement_lifetime)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (org_id, entity_id) DO UPDATE SET
    name               = EXCLUDED.name,
    entity_types       = EXCLUDED.entity_types,
    jwks               = EXCLUDED.jwks,
    jwks_uri           = EXCLUDED.jwks_uri,
    metadata_override  = EXCLUDED.metadata_override,
    metadata_policy    = EXCLUDED.metadata_policy,
    trust_mark_ids     = EXCLUDED.trust_mark_ids,
    status             = EXCLUDED.status,
    statement_lifetime = EXCLUDED.statement_lifetime,
    updated_at         = now()
RETURNING id, org_id, entity_id, name, entity_types, jwks, jwks_uri,
          metadata_override, metadata_policy, trust_mark_ids, status,
          statement_lifetime, created_at, updated_at`

	row := r.pool.QueryRow(ctx, q,
		p.OrgID, p.EntityID, p.Name, p.EntityTypes,
		nullableJSON(p.JWKS), nullableStr(p.JWKSUri),
		nullableJSON(p.MetadataOverride), nullableJSON(p.MetadataPolicy),
		p.TrustMarkIDs, p.Status, p.StatementLifetime,
	)
	return scanSubordinate(row)
}

// GetSubordinateByEntityID returns the subordinate with the given entity ID
// within the specified org, or an error wrapping pgx.ErrNoRows if not found.
func (r *FederationRepository) GetSubordinateByEntityID(ctx context.Context, orgID uuid.UUID, entityID string) (*FederationSubordinate, error) {
	const q = `
SELECT id, org_id, entity_id, name, entity_types, jwks, jwks_uri,
       metadata_override, metadata_policy, trust_mark_ids, status,
       statement_lifetime, created_at, updated_at
FROM   federation_subordinates
WHERE  org_id = $1 AND entity_id = $2`

	row := r.pool.QueryRow(ctx, q, orgID, entityID)
	s, err := scanSubordinate(row)
	if err != nil {
		return nil, fmt.Errorf("federation: get subordinate %s: %w", entityID, err)
	}
	return s, nil
}

// ListSubordinates returns all subordinate entity IDs for the given org.
// Only active subordinates are returned (suspended/revoked are excluded).
func (r *FederationRepository) ListSubordinates(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	const q = `
SELECT entity_id
FROM   federation_subordinates
WHERE  org_id = $1 AND status = 'active'
ORDER  BY entity_id`

	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("federation: list subordinates: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// UpdateSubordinateStatus sets the lifecycle status of a subordinate.
func (r *FederationRepository) UpdateSubordinateStatus(ctx context.Context, orgID uuid.UUID, entityID, status string) error {
	const q = `
UPDATE federation_subordinates
SET    status = $3, updated_at = now()
WHERE  org_id = $1 AND entity_id = $2`
	_, err := r.pool.Exec(ctx, q, orgID, entityID, status)
	return err
}

// ListSubordinatesFull returns complete subordinate records for the given org.
// Pass status="" to return all statuses; pass "active", "suspended", or "revoked"
// to filter. Results are ordered by entity_id.
func (r *FederationRepository) ListSubordinatesFull(ctx context.Context, orgID uuid.UUID, status string) ([]*FederationSubordinate, error) {
	const q = `
SELECT id, org_id, entity_id, name, entity_types, jwks, jwks_uri,
       metadata_override, metadata_policy, trust_mark_ids, status,
       statement_lifetime, created_at, updated_at
FROM   federation_subordinates
WHERE  org_id = $1
  AND  ($2 = '' OR status = $2)
ORDER  BY entity_id`

	rows, err := r.pool.Query(ctx, q, orgID, status)
	if err != nil {
		return nil, fmt.Errorf("federation: list subordinates full: %w", err)
	}
	defer rows.Close()

	var out []*FederationSubordinate
	for rows.Next() {
		s, err := scanSubordinate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ── Trust Mark Types ──────────────────────────────────────────────────────────

// UpsertTrustMarkType creates or updates a trust mark type definition.
func (r *FederationRepository) UpsertTrustMarkType(ctx context.Context, orgID uuid.UUID, t FederationTrustMarkType) (*FederationTrustMarkType, error) {
	const q = `
INSERT INTO federation_trust_mark_types
    (org_id, trust_mark_id, name, description, logo_uri, ref_uri, lifetime_secs)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (org_id, trust_mark_id) DO UPDATE SET
    name          = EXCLUDED.name,
    description   = EXCLUDED.description,
    logo_uri      = EXCLUDED.logo_uri,
    ref_uri       = EXCLUDED.ref_uri,
    lifetime_secs = EXCLUDED.lifetime_secs
RETURNING id, org_id, trust_mark_id, name, description, logo_uri, ref_uri, lifetime_secs, created_at`

	row := r.pool.QueryRow(ctx, q,
		orgID, t.TrustMarkID, t.Name, t.Description,
		nullableStr(t.LogoURI), nullableStr(t.RefURI), t.LifetimeSecs,
	)
	return scanTrustMarkType(row)
}

// GetTrustMarkType returns the trust mark type definition for the given ID.
func (r *FederationRepository) GetTrustMarkType(ctx context.Context, orgID uuid.UUID, trustMarkID string) (*FederationTrustMarkType, error) {
	const q = `
SELECT id, org_id, trust_mark_id, name, description, logo_uri, ref_uri, lifetime_secs, created_at
FROM   federation_trust_mark_types
WHERE  org_id = $1 AND trust_mark_id = $2`

	row := r.pool.QueryRow(ctx, q, orgID, trustMarkID)
	t, err := scanTrustMarkType(row)
	if err != nil {
		return nil, fmt.Errorf("federation: get trust mark type %s: %w", trustMarkID, err)
	}
	return t, nil
}

// ListTrustMarkTypes returns all trust mark types for the given org.
func (r *FederationRepository) ListTrustMarkTypes(ctx context.Context, orgID uuid.UUID) ([]*FederationTrustMarkType, error) {
	const q = `
SELECT id, org_id, trust_mark_id, name, description, logo_uri, ref_uri, lifetime_secs, created_at
FROM   federation_trust_mark_types
WHERE  org_id = $1
ORDER  BY trust_mark_id`

	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var types []*FederationTrustMarkType
	for rows.Next() {
		t, err := scanTrustMarkType(rows)
		if err != nil {
			return nil, err
		}
		types = append(types, t)
	}
	return types, rows.Err()
}

// ── Trust Mark Issuance ───────────────────────────────────────────────────────

// IssueTrustMark persists a newly signed trust mark. Uses INSERT … ON CONFLICT
// to replace an existing non-revoked mark for the same (org, trust_mark_id, subject).
func (r *FederationRepository) IssueTrustMark(ctx context.Context, p IssueTrustMarkParams) (*FederationTrustMark, error) {
	const q = `
INSERT INTO federation_trust_marks
    (org_id, trust_mark_id, subject, issued_jwt, expires_at)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (org_id, trust_mark_id, subject) DO UPDATE SET
    issued_jwt = EXCLUDED.issued_jwt,
    expires_at = EXCLUDED.expires_at,
    revoked    = false,
    revoked_at = NULL,
    revoked_reason = NULL,
    issued_at  = now()
RETURNING id, org_id, trust_mark_id, subject, issued_jwt, expires_at,
          revoked, revoked_at, revoked_reason, issued_at`

	row := r.pool.QueryRow(ctx, q, p.OrgID, p.TrustMarkID, p.Subject, p.IssuedJWT, p.ExpiresAt)
	return scanTrustMark(row)
}

// GetTrustMark returns the latest trust mark for (org, trust_mark_id, subject).
func (r *FederationRepository) GetTrustMark(ctx context.Context, orgID uuid.UUID, trustMarkID, subject string) (*FederationTrustMark, error) {
	const q = `
SELECT id, org_id, trust_mark_id, subject, issued_jwt, expires_at,
       revoked, revoked_at, revoked_reason, issued_at
FROM   federation_trust_marks
WHERE  org_id = $1 AND trust_mark_id = $2 AND subject = $3`

	row := r.pool.QueryRow(ctx, q, orgID, trustMarkID, subject)
	tm, err := scanTrustMark(row)
	if err != nil {
		return nil, fmt.Errorf("federation: get trust mark (%s, %s): %w", trustMarkID, subject, err)
	}
	return tm, nil
}

// ListTrustMarkSubjects returns all subject entity IDs that hold the given
// trust mark (only active, non-expired, non-revoked marks).
func (r *FederationRepository) ListTrustMarkSubjects(ctx context.Context, orgID uuid.UUID, trustMarkID string) ([]string, error) {
	const q = `
SELECT subject
FROM   federation_trust_marks
WHERE  org_id = $1 AND trust_mark_id = $2
  AND  NOT revoked AND expires_at > now()
ORDER  BY subject`

	rows, err := r.pool.Query(ctx, q, orgID, trustMarkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subjects []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		subjects = append(subjects, s)
	}
	return subjects, rows.Err()
}

// RevokeTrustMark marks the trust mark for (org, trust_mark_id, subject) as revoked.
func (r *FederationRepository) RevokeTrustMark(ctx context.Context, orgID uuid.UUID, trustMarkID, subject, reason string) error {
	const q = `
UPDATE federation_trust_marks
SET    revoked = true, revoked_at = now(), revoked_reason = $4
WHERE  org_id = $1 AND trust_mark_id = $2 AND subject = $3`
	_, err := r.pool.Exec(ctx, q, orgID, trustMarkID, subject, reason)
	return err
}

// ── Scan helpers ──────────────────────────────────────────────────────────────

type pgxScanner interface {
	Scan(dest ...any) error
}

func scanSubordinate(row pgxScanner) (*FederationSubordinate, error) {
	var s FederationSubordinate
	var jwks, metaOverride, metaPolicy []byte
	var jwksUri *string
	err := row.Scan(
		&s.ID, &s.OrgID, &s.EntityID, &s.Name, &s.EntityTypes,
		&jwks, &jwksUri,
		&metaOverride, &metaPolicy,
		&s.TrustMarkIDs, &s.Status, &s.StatementLifetime,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	s.JWKS = jwks
	if jwksUri != nil {
		s.JWKSUri = *jwksUri
	}
	s.MetadataOverride = metaOverride
	s.MetadataPolicy = metaPolicy
	return &s, nil
}

func scanTrustMarkType(row pgxScanner) (*FederationTrustMarkType, error) {
	var t FederationTrustMarkType
	var logoURI, refURI *string
	err := row.Scan(
		&t.ID, &t.OrgID, &t.TrustMarkID, &t.Name, &t.Description,
		&logoURI, &refURI, &t.LifetimeSecs, &t.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if logoURI != nil {
		t.LogoURI = *logoURI
	}
	if refURI != nil {
		t.RefURI = *refURI
	}
	return &t, nil
}

func scanTrustMark(row pgxScanner) (*FederationTrustMark, error) {
	var tm FederationTrustMark
	err := row.Scan(
		&tm.ID, &tm.OrgID, &tm.TrustMarkID, &tm.Subject,
		&tm.IssuedJWT, &tm.ExpiresAt,
		&tm.Revoked, &tm.RevokedAt, &tm.RevokedReason,
		&tm.IssuedAt,
	)
	if err != nil {
		return nil, err
	}
	return &tm, nil
}

// ── Nullable helpers (shared with other repos) ────────────────────────────────

func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullableJSON(b json.RawMessage) *json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	return &b
}

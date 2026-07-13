package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const signingKeyGracePeriod = 24 * time.Hour

// SigningKeyRow represents a row from the signing_keys table.
type SigningKeyRow struct {
	ID        uuid.UUID
	KID       string
	Algorithm string
	KeyEnc    []byte     // AES-256-GCM encrypted PKCS#8 DER: nonce(12) || ciphertext+tag
	Status    string     // "active" | "retired" | "expired"
	OrgID     *uuid.UUID // NULL = global installation key; NOT NULL = org-specific (BYOK)
	CreatedAt time.Time
	RetiredAt *time.Time
	ExpiresAt *time.Time
}

// SigningKeyRepository manages signing key persistence.
type SigningKeyRepository struct {
	pool *pgxpool.Pool
}

func NewSigningKeyRepository(pool *pgxpool.Pool) *SigningKeyRepository {
	return &SigningKeyRepository{pool: pool}
}

// GetActive returns the single global active signing key (org_id IS NULL),
// or pgx.ErrNoRows if none exists.
func (r *SigningKeyRepository) GetActive(ctx context.Context) (*SigningKeyRow, error) {
	const q = `
		SELECT id, kid, algorithm, key_enc, status, org_id, created_at, retired_at, expires_at
		FROM signing_keys
		WHERE status = 'active' AND org_id IS NULL AND key_use = 'sig'
		LIMIT 1`

	row := r.pool.QueryRow(ctx, q)
	var k SigningKeyRow
	err := row.Scan(&k.ID, &k.KID, &k.Algorithm, &k.KeyEnc, &k.Status, &k.OrgID,
		&k.CreatedAt, &k.RetiredAt, &k.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// GetJWKSKeys returns all global keys (org_id IS NULL) that should appear in
// the public JWKS: the active key plus any retired keys within the grace window.
func (r *SigningKeyRepository) GetJWKSKeys(ctx context.Context) ([]*SigningKeyRow, error) {
	const q = `
		SELECT id, kid, algorithm, key_enc, status, org_id, created_at, retired_at, expires_at
		FROM signing_keys
		WHERE org_id IS NULL AND key_use = 'sig'
		  AND (status = 'active' OR (status = 'retired' AND expires_at > NOW()))
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*SigningKeyRow
	for rows.Next() {
		var k SigningKeyRow
		if err := rows.Scan(&k.ID, &k.KID, &k.Algorithm, &k.KeyEnc, &k.Status, &k.OrgID,
			&k.CreatedAt, &k.RetiredAt, &k.ExpiresAt); err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, rows.Err()
}

// Insert stores a new global (org_id IS NULL) key as active.
func (r *SigningKeyRepository) Insert(ctx context.Context, kid, algorithm string, keyEnc []byte) error {
	const q = `
		INSERT INTO signing_keys (kid, algorithm, key_enc, status, org_id)
		VALUES ($1, $2, $3, 'active', NULL)`
	_, err := r.pool.Exec(ctx, q, kid, algorithm, keyEnc)
	return err
}

// RetireActive marks the current global active key as retired.
func (r *SigningKeyRepository) RetireActive(ctx context.Context) error {
	const q = `
		UPDATE signing_keys
		SET status     = 'retired',
		    retired_at = NOW(),
		    expires_at = NOW() + $1
		WHERE status = 'active' AND org_id IS NULL`
	_, err := r.pool.Exec(ctx, q, signingKeyGracePeriod)
	return err
}

// ExpireOldRetired transitions retired keys past their grace window to 'expired'.
// Call this periodically (e.g. once per hour) to keep the table tidy.
func (r *SigningKeyRepository) ExpireOldRetired(ctx context.Context) error {
	const q = `
		UPDATE signing_keys
		SET status = 'expired'
		WHERE status = 'retired' AND expires_at <= NOW()`
	_, err := r.pool.Exec(ctx, q)
	return err
}

// ── Per-org (BYOK) methods ────────────────────────────────────────────────────

// GetActiveForOrg returns the org-specific active signing key,
// or pgx.ErrNoRows if the org has not registered its own key.
func (r *SigningKeyRepository) GetActiveForOrg(ctx context.Context, orgID uuid.UUID) (*SigningKeyRow, error) {
	const q = `
		SELECT id, kid, algorithm, key_enc, status, org_id, created_at, retired_at, expires_at
		FROM signing_keys
		WHERE status = 'active' AND org_id = $1
		LIMIT 1`

	row := r.pool.QueryRow(ctx, q, orgID)
	var k SigningKeyRow
	err := row.Scan(&k.ID, &k.KID, &k.Algorithm, &k.KeyEnc, &k.Status, &k.OrgID,
		&k.CreatedAt, &k.RetiredAt, &k.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// GetJWKSKeysForOrg returns all org-specific JWKS-eligible keys (active + retired
// within the grace window). The caller should fall back to GetJWKSKeys if the
// result is empty.
// GetJWKSKeysForOrg returns the classical signing keys published in an org's
// JWKS: the org's own active + retired-within-grace keys, PLUS the global
// (org_id IS NULL) active + retired-within-grace keys.
//
// Including the global key is what preserves token continuity across the switch
// to per-org keys: before the switch every org's issuer JWKS served the shared
// global key, so tokens still in flight carry the global kid. A global UNIQUE
// constraint on kid means that kid lives in exactly one row and cannot be copied
// per-org, so the org JWKS must surface the global row itself. The migration
// retires the global key with a grace window, after which it drops out here.
func (r *SigningKeyRepository) GetJWKSKeysForOrg(ctx context.Context, orgID uuid.UUID) ([]*SigningKeyRow, error) {
	const q = `
		SELECT id, kid, algorithm, key_enc, status, org_id, created_at, retired_at, expires_at
		FROM signing_keys
		WHERE (org_id = $1 OR org_id IS NULL)
		  AND key_use = 'sig'
		  AND pqc_algorithm IS NULL
		  AND (status = 'active' OR (status = 'retired' AND expires_at > NOW()))
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*SigningKeyRow
	for rows.Next() {
		var k SigningKeyRow
		if err := rows.Scan(&k.ID, &k.KID, &k.Algorithm, &k.KeyEnc, &k.Status, &k.OrgID,
			&k.CreatedAt, &k.RetiredAt, &k.ExpiresAt); err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, rows.Err()
}

// InsertForOrg stores a new org-specific key as active for the given org.
// key_source defaults to 'generated' (server-held material, auto-rotatable).
func (r *SigningKeyRepository) InsertForOrg(ctx context.Context, orgID uuid.UUID, kid, algorithm string, keyEnc []byte) error {
	const q = `
		INSERT INTO signing_keys (kid, algorithm, key_enc, status, org_id)
		VALUES ($1, $2, $3, 'active', $4)`
	_, err := r.pool.Exec(ctx, q, kid, algorithm, keyEnc, orgID)
	return err
}

// InsertImportedForOrg stores a new org-specific key as active, tagged
// key_source='imported' (BYOK / external custody). The scheduled rotation
// worker never regenerates imported keys.
func (r *SigningKeyRepository) InsertImportedForOrg(ctx context.Context, orgID uuid.UUID, kid, algorithm string, keyEnc []byte) error {
	const q = `
		INSERT INTO signing_keys (kid, algorithm, key_enc, status, org_id, key_source)
		VALUES ($1, $2, $3, 'active', $4, 'imported')`
	_, err := r.pool.Exec(ctx, q, kid, algorithm, keyEnc, orgID)
	return err
}

// RetireActiveGlobalOIDCWithGrace retires the global (org_id IS NULL) classical
// OIDC signing key with a caller-chosen grace window, so it keeps appearing in
// every org's JWKS (via GetJWKSKeysForOrg) for `grace` and then drops out. Used
// by the per-org key migration to end the transition period. Scoped to the
// classical sig key so it never touches the global PQC or request-object enc key.
func (r *SigningKeyRepository) RetireActiveGlobalOIDCWithGrace(ctx context.Context, grace time.Duration) error {
	const q = `
		UPDATE signing_keys
		SET status     = 'retired',
		    retired_at = NOW(),
		    expires_at = NOW() + $1
		WHERE status = 'active' AND org_id IS NULL AND pqc_algorithm IS NULL AND key_use = 'sig'`
	_, err := r.pool.Exec(ctx, q, grace)
	return err
}

// GetActiveKeySourceForOrg returns the key_source ('generated' | 'imported') of
// the org's active signing key, or pgx.ErrNoRows if the org has no active key.
func (r *SigningKeyRepository) GetActiveKeySourceForOrg(ctx context.Context, orgID uuid.UUID) (string, error) {
	const q = `
		SELECT key_source FROM signing_keys
		WHERE status = 'active' AND org_id = $1 AND key_use = 'sig'
		LIMIT 1`
	var source string
	err := r.pool.QueryRow(ctx, q, orgID).Scan(&source)
	return source, err
}

// RetireActiveForOrg marks the org's current active key as retired (grace 24 h).
func (r *SigningKeyRepository) RetireActiveForOrg(ctx context.Context, orgID uuid.UUID) error {
	const q = `
		UPDATE signing_keys
		SET status     = 'retired',
		    retired_at = NOW(),
		    expires_at = NOW() + $1
		WHERE status = 'active' AND org_id = $2`
	_, err := r.pool.Exec(ctx, q, signingKeyGracePeriod, orgID)
	return err
}

// DeleteAllForOrg hard-deletes every signing key for an org (use only when
// removing BYOK entirely; the org reverts to the global key).
func (r *SigningKeyRepository) DeleteAllForOrg(ctx context.Context, orgID uuid.UUID) error {
	const q = `DELETE FROM signing_keys WHERE org_id = $1`
	_, err := r.pool.Exec(ctx, q, orgID)
	return err
}

// ensure pgx.ErrNoRows is used directly by callers
var _ = pgx.ErrNoRows

// ── PQC signing keys (migration 000162) ──────────────────────────────────────

// PQCSigningKeyRow represents a PQC signing key row (pqc_algorithm IS NOT NULL).
type PQCSigningKeyRow struct {
	ID           uuid.UUID
	KID          string
	PQCAlgorithm string // 'ml-dsa-65' | 'slh-dsa-sha2-128s'
	KeyEnc       []byte // AES-256-GCM encrypted raw private key bytes
	PQCPublicKey []byte // raw public key bytes (JWKS cache)
	Status       string
	CreatedAt    time.Time
}

// GetActivePQC returns the global active PQC signing key, or pgx.ErrNoRows if none.
func (r *SigningKeyRepository) GetActivePQC(ctx context.Context) (*PQCSigningKeyRow, error) {
	const q = `
		SELECT id, kid, pqc_algorithm, key_enc, pqc_public_key, status, created_at
		FROM signing_keys
		WHERE status = 'active' AND org_id IS NULL AND pqc_algorithm IS NOT NULL
		LIMIT 1`

	row := r.pool.QueryRow(ctx, q)
	var k PQCSigningKeyRow
	err := row.Scan(&k.ID, &k.KID, &k.PQCAlgorithm, &k.KeyEnc, &k.PQCPublicKey,
		&k.Status, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// InsertPQC stores a new global PQC key as active.
// algorithm is the JWA-style algorithm string (e.g. "CV-ML-DSA-65").
// pqcAlgorithm is the NIST name (e.g. "ml-dsa-65").
func (r *SigningKeyRepository) InsertPQC(ctx context.Context, kid, algorithm, pqcAlgorithm string, keyEnc, pqcPublicKey []byte) error {
	const q = `
		INSERT INTO signing_keys (kid, algorithm, key_enc, status, org_id, pqc_algorithm, pqc_public_key)
		VALUES ($1, $2, $3, 'active', NULL, $4, $5)`
	_, err := r.pool.Exec(ctx, q, kid, algorithm, keyEnc, pqcAlgorithm, pqcPublicKey)
	return err
}

// RetireActivePQC marks the current global active PQC key as retired (grace 24 h).
func (r *SigningKeyRepository) RetireActivePQC(ctx context.Context) error {
	const q = `
		UPDATE signing_keys
		SET status     = 'retired',
		    retired_at = NOW(),
		    expires_at = NOW() + $1
		WHERE status = 'active' AND org_id IS NULL AND pqc_algorithm IS NOT NULL`
	_, err := r.pool.Exec(ctx, q, signingKeyGracePeriod)
	return err
}

// ── Per-org PQC signing keys ──────────────────────────────────────────────────
//
// PQC keys share the signing_keys table (pqc_algorithm IS NOT NULL) and the same
// org_id column as classical keys — no separate table. The per-scope active
// index (migration 000169) keys on (org_id, key_use, pqc_algorithm, status), so
// an org may hold one active classical 'sig' key AND one active PQC key at once
// without collision. These mirror the OIDC per-org methods above.

// GetActivePQCForOrg returns the org-specific active PQC signing key, or
// pgx.ErrNoRows if the org has not registered its own PQC key.
func (r *SigningKeyRepository) GetActivePQCForOrg(ctx context.Context, orgID uuid.UUID) (*PQCSigningKeyRow, error) {
	const q = `
		SELECT id, kid, pqc_algorithm, key_enc, pqc_public_key, status, created_at
		FROM signing_keys
		WHERE status = 'active' AND org_id = $1 AND pqc_algorithm IS NOT NULL
		LIMIT 1`

	row := r.pool.QueryRow(ctx, q, orgID)
	var k PQCSigningKeyRow
	err := row.Scan(&k.ID, &k.KID, &k.PQCAlgorithm, &k.KeyEnc, &k.PQCPublicKey,
		&k.Status, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// InsertPQCForOrg stores a new org-specific PQC key as active for the given org.
func (r *SigningKeyRepository) InsertPQCForOrg(ctx context.Context, orgID uuid.UUID, kid, algorithm, pqcAlgorithm string, keyEnc, pqcPublicKey []byte) error {
	const q = `
		INSERT INTO signing_keys (kid, algorithm, key_enc, status, org_id, pqc_algorithm, pqc_public_key)
		VALUES ($1, $2, $3, 'active', $4, $5, $6)`
	_, err := r.pool.Exec(ctx, q, kid, algorithm, keyEnc, orgID, pqcAlgorithm, pqcPublicKey)
	return err
}

// RetireActivePQCForOrg marks the org's current active PQC key as retired
// (grace 24 h). Scoped to PQC rows so it never touches the org's classical key.
func (r *SigningKeyRepository) RetireActivePQCForOrg(ctx context.Context, orgID uuid.UUID) error {
	const q = `
		UPDATE signing_keys
		SET status     = 'retired',
		    retired_at = NOW(),
		    expires_at = NOW() + $1
		WHERE status = 'active' AND org_id = $2 AND pqc_algorithm IS NOT NULL`
	_, err := r.pool.Exec(ctx, q, signingKeyGracePeriod, orgID)
	return err
}

// ── Request-object encryption keys (migration 000168, key_use = 'enc') ────────
//
// Encryption keys share the signing_keys table and SigningKeyRow shape but are
// discriminated by key_use = 'enc'. algorithm holds the JWE key-management alg
// (e.g. 'RSA-OAEP-256'). Retired enc keys are kept within the grace window so a
// request object an RP encrypted to the previously published key can still be
// decrypted until the RP re-fetches the OP JWKS.

// GetActiveEnc returns the global active encryption key, or pgx.ErrNoRows if none.
func (r *SigningKeyRepository) GetActiveEnc(ctx context.Context) (*SigningKeyRow, error) {
	const q = `
		SELECT id, kid, algorithm, key_enc, status, org_id, created_at, retired_at, expires_at
		FROM signing_keys
		WHERE status = 'active' AND org_id IS NULL AND key_use = 'enc'
		LIMIT 1`

	row := r.pool.QueryRow(ctx, q)
	var k SigningKeyRow
	err := row.Scan(&k.ID, &k.KID, &k.Algorithm, &k.KeyEnc, &k.Status, &k.OrgID,
		&k.CreatedAt, &k.RetiredAt, &k.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// GetEncJWKSKeys returns all global encryption keys that should be usable: the
// active key plus any retired keys within the grace window (still decryptable
// and still published with use=enc so in-flight request objects verify).
func (r *SigningKeyRepository) GetEncJWKSKeys(ctx context.Context) ([]*SigningKeyRow, error) {
	const q = `
		SELECT id, kid, algorithm, key_enc, status, org_id, created_at, retired_at, expires_at
		FROM signing_keys
		WHERE org_id IS NULL AND key_use = 'enc'
		  AND (status = 'active' OR (status = 'retired' AND expires_at > NOW()))
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*SigningKeyRow
	for rows.Next() {
		var k SigningKeyRow
		if err := rows.Scan(&k.ID, &k.KID, &k.Algorithm, &k.KeyEnc, &k.Status, &k.OrgID,
			&k.CreatedAt, &k.RetiredAt, &k.ExpiresAt); err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, rows.Err()
}

// InsertEnc stores a new global encryption key as active.
// algorithm is the JWE key-management alg (e.g. "RSA-OAEP-256").
func (r *SigningKeyRepository) InsertEnc(ctx context.Context, kid, algorithm string, keyEnc []byte) error {
	const q = `
		INSERT INTO signing_keys (kid, algorithm, key_enc, status, org_id, key_use)
		VALUES ($1, $2, $3, 'active', NULL, 'enc')`
	_, err := r.pool.Exec(ctx, q, kid, algorithm, keyEnc)
	return err
}

// RetireActiveEnc marks the current global active encryption key as retired (grace 24 h).
func (r *SigningKeyRepository) RetireActiveEnc(ctx context.Context) error {
	const q = `
		UPDATE signing_keys
		SET status     = 'retired',
		    retired_at = NOW(),
		    expires_at = NOW() + $1
		WHERE status = 'active' AND org_id IS NULL AND key_use = 'enc'`
	_, err := r.pool.Exec(ctx, q, signingKeyGracePeriod)
	return err
}

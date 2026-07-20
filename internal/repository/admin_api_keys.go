package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// keyPrefix is the human-readable prefix for all admin API keys.
const keyPrefix = "clv_"

// AdminAPIKeyRepository manages admin API key persistence.
type AdminAPIKeyRepository struct {
	pool *pgxpool.Pool
}

func NewAdminAPIKeyRepository(pool *pgxpool.Pool) *AdminAPIKeyRepository {
	return &AdminAPIKeyRepository{pool: pool}
}

// APIKeyAuth is the minimal identity returned after a successful key verification.
// Server.go converts this to middleware.Claims.
type APIKeyAuth struct {
	KeyID       uuid.UUID
	Scope       string
	OrgID       *uuid.UUID // nil = superadmin key (cross-org)
	Permissions []string   // nil = unrestricted within Scope
}

// generateKey creates a new raw key: "clv_" + 32 random bytes (base64url, no padding).
func generateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return keyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func hashKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// Create generates a new API key, persists the hash, and returns the model along
// with the raw key (shown once — the caller must relay it to the user).
//
// orgID scopes the key to a single organization; pass nil for a legacy
// superadmin (cross-org) key. permissions further restricts the key beyond
// scope (e.g. []string{"clients:write"}); pass nil for unrestricted access
// within scope.
func (r *AdminAPIKeyRepository) Create(
	ctx context.Context,
	name, scope string,
	orgID *uuid.UUID,
	permissions []string,
	createdBy *uuid.UUID,
	expiresAt *string, // optional ISO-8601 string; nil = never expires
) (*models.AdminAPIKey, string, error) {
	rawKey, err := generateKey()
	if err != nil {
		return nil, "", err
	}
	hash := hashKey(rawKey)
	prefix := strings.TrimPrefix(rawKey, keyPrefix)
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}

	k := &models.AdminAPIKey{}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO admin_api_keys (name, key_hash, key_prefix, scope, org_id, permissions, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7,
		        CASE WHEN $8::text IS NULL THEN NULL
		             ELSE $8::timestamptz END)
		RETURNING id, name, key_prefix, scope, org_id, permissions, created_by, last_used_at, expires_at, is_active, created_at
	`, name, hash, prefix, scope, orgID, permissions, createdBy, expiresAt).Scan(
		&k.ID, &k.Name, &k.KeyPrefix, &k.Scope, &k.OrgID, &k.Permissions, &k.CreatedBy,
		&k.LastUsedAt, &k.ExpiresAt, &k.IsActive, &k.CreatedAt,
	)
	if err != nil {
		return nil, "", err
	}
	return k, rawKey, nil
}

// List returns all API keys (active and revoked) ordered newest first.
// If orgID is non-nil, only keys scoped to that org are returned (superadmin
// keys with org_id NULL are excluded — they are not "this org's" keys).
func (r *AdminAPIKeyRepository) List(ctx context.Context, orgID *uuid.UUID) ([]*models.AdminAPIKey, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, key_prefix, scope, org_id, permissions, created_by, last_used_at, expires_at, is_active, created_at
		FROM admin_api_keys
		WHERE $1::uuid IS NULL OR org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.AdminAPIKey
	for rows.Next() {
		k := &models.AdminAPIKey{}
		if err := rows.Scan(
			&k.ID, &k.Name, &k.KeyPrefix, &k.Scope, &k.OrgID, &k.Permissions, &k.CreatedBy,
			&k.LastUsedAt, &k.ExpiresAt, &k.IsActive, &k.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Revoke marks an API key as inactive.
func (r *AdminAPIKeyRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE admin_api_keys SET is_active = FALSE WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// RevokeForOrg marks an API key inactive only when it belongs to orgID. Used by
// the org-admin self-service route so an admin can never revoke another org's
// key (or a superadmin cross-org key, whose org_id is NULL and never matches).
// Returns pgx.ErrNoRows when no active key with that id exists in the org.
func (r *AdminAPIKeyRepository) RevokeForOrg(ctx context.Context, id, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE admin_api_keys SET is_active = FALSE WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// VerifyKey validates a raw API key and returns its identity, or (nil, nil) if
// the key does not match our prefix (so the caller can fall back to JWT auth).
// Returns an error if the key has our prefix but is invalid/revoked/expired.
func (r *AdminAPIKeyRepository) VerifyKey(ctx context.Context, rawKey string) (*APIKeyAuth, error) {
	if !strings.HasPrefix(rawKey, keyPrefix) {
		return nil, nil // not our format
	}
	hash := hashKey(rawKey)

	auth := &APIKeyAuth{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, scope, org_id, permissions FROM admin_api_keys
		WHERE key_hash = $1
		  AND is_active = TRUE
		  AND (expires_at IS NULL OR expires_at > NOW())
	`, hash).Scan(&auth.KeyID, &auth.Scope, &auth.OrgID, &auth.Permissions)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("invalid or revoked api key")
	}
	if err != nil {
		return nil, err
	}

	// Update last_used_at without blocking the request.
	go func() {
		_, _ = r.pool.Exec(context.Background(),
			`UPDATE admin_api_keys SET last_used_at = NOW() WHERE id = $1`, auth.KeyID)
	}()

	return auth, nil
}

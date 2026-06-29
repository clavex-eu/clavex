package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MagicLink represents a one-time authentication link.
type MagicLink struct {
	ID         uuid.UUID  `db:"id"           json:"id"`
	OrgID      uuid.UUID  `db:"org_id"       json:"org_id"`
	UserID     *uuid.UUID `db:"user_id"      json:"user_id,omitempty"`
	Email      string     `db:"email"        json:"email"`
	Purpose    string     `db:"purpose"      json:"purpose"` // "login" | "mfa"
	AuthReqKey *string    `db:"auth_req_key" json:"auth_req_key,omitempty"`
	ExpiresAt  time.Time  `db:"expires_at"   json:"expires_at"`
	UsedAt     *time.Time `db:"used_at"      json:"used_at,omitempty"`
	CreatedAt  time.Time  `db:"created_at"   json:"created_at"`
}

// MagicLinkRepository manages magic link tokens.
type MagicLinkRepository struct {
	pool *pgxpool.Pool
}

func NewMagicLinkRepository(pool *pgxpool.Pool) *MagicLinkRepository {
	return &MagicLinkRepository{pool: pool}
}

// Create issues a new magic link. Returns (record, rawToken).
func (r *MagicLinkRepository) Create(ctx context.Context, orgID uuid.UUID, userID *uuid.UUID, email, purpose string, authReqKey *string, ttl time.Duration) (*MagicLink, string, error) {
	raw, err := generateMagicToken()
	if err != nil {
		return nil, "", err
	}
	hash := hashMagicToken(raw)
	ml := &MagicLink{}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO magic_links (org_id, user_id, email, token_hash, purpose, auth_req_key, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW() + $7::interval)
		RETURNING id, org_id, user_id, email, purpose, auth_req_key, expires_at, used_at, created_at
	`, orgID, userID, email, hash, purpose, authReqKey, ttl.String()).Scan(
		&ml.ID, &ml.OrgID, &ml.UserID, &ml.Email, &ml.Purpose, &ml.AuthReqKey,
		&ml.ExpiresAt, &ml.UsedAt, &ml.CreatedAt,
	)
	return ml, raw, err
}

// GetByToken finds a magic link by raw token. Returns nil if not found or already used.
func (r *MagicLinkRepository) GetByToken(ctx context.Context, rawToken string) (*MagicLink, error) {
	hash := hashMagicToken(rawToken)
	ml := &MagicLink{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, email, purpose, auth_req_key, expires_at, used_at, created_at
		FROM magic_links WHERE token_hash = $1 AND used_at IS NULL
	`, hash).Scan(
		&ml.ID, &ml.OrgID, &ml.UserID, &ml.Email, &ml.Purpose, &ml.AuthReqKey,
		&ml.ExpiresAt, &ml.UsedAt, &ml.CreatedAt,
	)
	return ml, err
}

// MarkUsed consumes a magic link (idempotent).
func (r *MagicLinkRepository) MarkUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE magic_links SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, id)
	return err
}

func generateMagicToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashMagicToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

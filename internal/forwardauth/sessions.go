package forwardauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BrowserSession represents a persistent browser session for forward auth.
type BrowserSession struct {
	ID          uuid.UUID `db:"id"`
	OrgID       uuid.UUID `db:"org_id"`
	UserID      uuid.UUID `db:"user_id"`
	SessionHash string    `db:"session_hash"`
	UserAgent   string    `db:"user_agent"`
	IPAddress   string    `db:"ip_address"`
	CreatedAt   time.Time `db:"created_at"`
	LastSeenAt  time.Time `db:"last_seen_at"`
	ExpiresAt   time.Time `db:"expires_at"`
}

// BrowserSessionRepository handles browser_sessions persistence.
type BrowserSessionRepository struct {
	pool *pgxpool.Pool
}

func NewBrowserSessionRepository(pool *pgxpool.Pool) *BrowserSessionRepository {
	return &BrowserSessionRepository{pool: pool}
}

func (r *BrowserSessionRepository) Create(ctx context.Context, orgID, userID uuid.UUID, sessionHash, userAgent, ipAddress string, ttl time.Duration) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO browser_sessions (org_id, user_id, session_hash, user_agent, ip_address, expires_at)
		VALUES ($1, $2, $3, $4, $5, NOW() + $6::interval)
	`, orgID, userID, sessionHash, userAgent, ipAddress, ttl.String())
	return err
}

func (r *BrowserSessionRepository) GetByHash(ctx context.Context, sessionHash string) (*BrowserSession, error) {
	s := &BrowserSession{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, session_hash, user_agent, ip_address, created_at, last_seen_at, expires_at
		FROM browser_sessions WHERE session_hash = $1
	`, sessionHash).Scan(&s.ID, &s.OrgID, &s.UserID, &s.SessionHash, &s.UserAgent, &s.IPAddress, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (r *BrowserSessionRepository) Touch(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE browser_sessions SET last_seen_at = NOW() WHERE id = $1`, id)
	return err
}

func (r *BrowserSessionRepository) DeleteByHash(ctx context.Context, sessionHash string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM browser_sessions WHERE session_hash = $1`, sessionHash)
	return err
}

func (r *BrowserSessionRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*BrowserSession, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, user_id, session_hash, user_agent, ip_address, created_at, last_seen_at, expires_at
		FROM browser_sessions WHERE user_id = $1 ORDER BY last_seen_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BrowserSession
	for rows.Next() {
		s := &BrowserSession{}
		if err := rows.Scan(&s.ID, &s.OrgID, &s.UserID, &s.SessionHash, &s.UserAgent, &s.IPAddress, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// hashSession returns the SHA-256 hex of a raw session token.
func hashSession(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// generateToken creates a cryptographically random hex token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

package repository

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/clavex-eu/clavex/internal/lockout"
	"github.com/jackc/pgx/v5/pgxpool"
)

const lockoutCacheTTL = 30 * time.Second

// LockoutRepository reads and writes per-org adaptive lockout configuration.
// Bands are cached in-process for lockoutCacheTTL to avoid a DB round-trip on
// every login attempt.
type LockoutRepository struct {
	pool  *pgxpool.Pool
	mu    sync.RWMutex
	cache map[string]cachedLockout
}

type cachedLockout struct {
	bands      []lockout.Band
	alertAdmin bool
	expiresAt  time.Time
}

// OrgLockoutConfig is the full config returned by GetLockoutConfig.
type OrgLockoutConfig struct {
	OrgID      string         `json:"org_id"`
	Bands      []lockout.Band `json:"bands"`
	AlertAdmin bool           `json:"alert_admin"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// NewLockoutRepository creates a repository backed by pool.
func NewLockoutRepository(pool *pgxpool.Pool) *LockoutRepository {
	return &LockoutRepository{pool: pool, cache: map[string]cachedLockout{}}
}

// Bands returns the lockout bands for orgID, using DefaultBands if no row exists.
// This is the function passed to lockout.New as a BandsLoader.
func (r *LockoutRepository) Bands(ctx context.Context, orgID string) []lockout.Band {
	r.mu.RLock()
	if c, ok := r.cache[orgID]; ok && time.Now().Before(c.expiresAt) {
		r.mu.RUnlock()
		return c.bands
	}
	r.mu.RUnlock()

	bands, alertAdmin := r.loadFromDB(ctx, orgID)

	r.mu.Lock()
	r.cache[orgID] = cachedLockout{bands: bands, alertAdmin: alertAdmin, expiresAt: time.Now().Add(lockoutCacheTTL)}
	r.mu.Unlock()

	return bands
}

// AlertAdmin returns true if a critical lockout (highest band) should fire an
// admin alert event. Returned alongside bands but cached separately.
func (r *LockoutRepository) AlertAdmin(ctx context.Context, orgID string) bool {
	r.mu.RLock()
	if c, ok := r.cache[orgID]; ok && time.Now().Before(c.expiresAt) {
		r.mu.RUnlock()
		return c.alertAdmin
	}
	r.mu.RUnlock()
	_, alertAdmin := r.loadFromDB(ctx, orgID)
	return alertAdmin
}

// GetLockoutConfig returns the full config (for the admin API).
func (r *LockoutRepository) GetLockoutConfig(ctx context.Context, orgID string) (*OrgLockoutConfig, error) {
	cfg := &OrgLockoutConfig{OrgID: orgID, Bands: lockout.DefaultBands}
	var raw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT bands, alert_admin, updated_at FROM org_lockout_config WHERE org_id = $1`, orgID,
	).Scan(&raw, &cfg.AlertAdmin, &cfg.UpdatedAt)
	if err != nil {
		// No row → return defaults (not an error for the caller).
		return cfg, nil
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &cfg.Bands)
	}
	return cfg, nil
}

// UpsertLockoutConfig creates or replaces the lockout config for an org.
// Pass nil for bands to keep the current value (not yet supported — always pass bands).
func (r *LockoutRepository) UpsertLockoutConfig(ctx context.Context, orgID string, bands []lockout.Band, alertAdmin bool) error {
	bandsJSON, err := json.Marshal(bands)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO org_lockout_config (org_id, bands, alert_admin, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (org_id) DO UPDATE
		SET bands = EXCLUDED.bands,
		    alert_admin = EXCLUDED.alert_admin,
		    updated_at = NOW()
	`, orgID, bandsJSON, alertAdmin)
	if err != nil {
		return err
	}
	// Invalidate cache.
	r.mu.Lock()
	delete(r.cache, orgID)
	r.mu.Unlock()
	return nil
}

func (r *LockoutRepository) loadFromDB(ctx context.Context, orgID string) ([]lockout.Band, bool) {
	var raw []byte
	var alertAdmin bool
	err := r.pool.QueryRow(ctx,
		`SELECT bands, alert_admin FROM org_lockout_config WHERE org_id = $1`, orgID,
	).Scan(&raw, &alertAdmin)
	if err != nil {
		return lockout.DefaultBands, false
	}
	bands := lockout.DefaultBands
	if len(raw) > 0 {
		var b []lockout.Band
		if jerr := json.Unmarshal(raw, &b); jerr == nil && len(b) > 0 {
			bands = b
		}
	}
	return bands, alertAdmin
}

// DeleteLockoutConfig removes a custom lockout config row, resetting the org to defaults.
func (r *LockoutRepository) DeleteLockoutConfig(ctx context.Context, orgID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM org_lockout_config WHERE org_id = $1`, orgID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.cache, orgID)
	r.mu.Unlock()
	return nil
}

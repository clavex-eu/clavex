package repository

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/clavex-eu/clavex/internal/analytics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CredentialAnalyticsRepository handles privacy-preserving analytics for credential issuers.
type CredentialAnalyticsRepository struct {
	pool     *pgxpool.Pool
	keyCache sync.Map // orgID (string) → *rsa.PrivateKey
}

func NewCredentialAnalyticsRepository(pool *pgxpool.Pool) *CredentialAnalyticsRepository {
	return &CredentialAnalyticsRepository{pool: pool}
}

// ── Key management ────────────────────────────────────────────────────────────

// GetOrCreateKey returns the RSA-2048 analytics signing key for an org.
// On first call it generates a new key and stores it; subsequent calls hit
// the in-process cache.
func (r *CredentialAnalyticsRepository) GetOrCreateKey(ctx context.Context, orgID uuid.UUID) (*rsa.PrivateKey, error) {
	if v, ok := r.keyCache.Load(orgID.String()); ok {
		return v.(*rsa.PrivateKey), nil
	}

	var pemStr string
	err := r.pool.QueryRow(ctx, `
		SELECT private_key_pem FROM analytics_keys WHERE org_id = $1
	`, orgID).Scan(&pemStr)

	if errors.Is(err, pgx.ErrNoRows) {
		priv, genErr := analytics.GenerateKeyPair()
		if genErr != nil {
			return nil, fmt.Errorf("credential_analytics: generate key: %w", genErr)
		}
		der, marshalErr := x509.MarshalPKCS8PrivateKey(priv)
		if marshalErr != nil {
			return nil, marshalErr
		}
		pemStr = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

		if _, err = r.pool.Exec(ctx, `
			INSERT INTO analytics_keys (org_id, private_key_pem)
			VALUES ($1, $2) ON CONFLICT (org_id) DO NOTHING
		`, orgID, pemStr); err != nil {
			return nil, err
		}
		// Re-read to get the winner in case of concurrent insert.
		if e2 := r.pool.QueryRow(ctx, `
			SELECT private_key_pem FROM analytics_keys WHERE org_id = $1
		`, orgID).Scan(&pemStr); e2 != nil {
			return nil, e2
		}
	} else if err != nil {
		return nil, err
	}

	priv, parseErr := parseAnalyticsKeyPEM(pemStr)
	if parseErr != nil {
		return nil, parseErr
	}
	r.keyCache.Store(orgID.String(), priv)
	return priv, nil
}

func parseAnalyticsKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("credential_analytics: invalid PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("credential_analytics: key is not RSA")
	}
	return rk, nil
}

// ── Spent-token registry ──────────────────────────────────────────────────────

// IsTokenSpent returns true if this token hash has already been redeemed.
func (r *CredentialAnalyticsRepository) IsTokenSpent(ctx context.Context, orgID uuid.UUID, tokenHash string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM analytics_spent WHERE token_hash = $1 AND org_id = $2)
	`, tokenHash, orgID).Scan(&exists)
	return exists, err
}

// MarkTokenSpent records a token as redeemed; errors on duplicate (double-spend attempt).
func (r *CredentialAnalyticsRepository) MarkTokenSpent(ctx context.Context, orgID uuid.UUID, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO analytics_spent (token_hash, org_id) VALUES ($1, $2)
	`, tokenHash, orgID)
	return err
}

// PurgeOldSpentTokens deletes spent tokens older than the given duration.
func (r *CredentialAnalyticsRepository) PurgeOldSpentTokens(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM analytics_spent WHERE spent_at < NOW() - $1::INTERVAL
	`, fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ── Aggregate events ──────────────────────────────────────────────────────────

// RecordEvent upserts an aggregate counter for (org, vct, day, purpose, country).
func (r *CredentialAnalyticsRepository) RecordEvent(
	ctx context.Context,
	orgID uuid.UUID,
	vct, purposeHint, countryHint string,
	day time.Time,
) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO analytics_events (org_id, vct, day, purpose_hint, country_hint, count)
		VALUES ($1, $2, $3::date, $4, $5, 1)
		ON CONFLICT (org_id, vct, day, purpose_hint, country_hint)
		DO UPDATE SET count = analytics_events.count + 1
	`, orgID, vct, day.UTC().Truncate(24*time.Hour), purposeHint, countryHint)
	return err
}

// CredAnalyticsSummaryRow is one row in the admin analytics view.
type CredAnalyticsSummaryRow struct {
	VCT         string    `json:"vct"`
	Day         time.Time `json:"day"`
	PurposeHint string    `json:"purpose_hint"`
	CountryHint string    `json:"country_hint"`
	Count       int64     `json:"count"`
}

// GetSummary returns aggregate rows for the given org and date range.
func (r *CredentialAnalyticsRepository) GetSummary(
	ctx context.Context,
	orgID uuid.UUID,
	from, to time.Time,
) ([]CredAnalyticsSummaryRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT vct, day, purpose_hint, country_hint, count
		FROM analytics_events
		WHERE org_id = $1
		  AND day BETWEEN $2::date AND $3::date
		ORDER BY day DESC, vct, purpose_hint
		LIMIT 2000
	`, orgID, from.UTC(), to.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CredAnalyticsSummaryRow
	for rows.Next() {
		var row CredAnalyticsSummaryRow
		if err := rows.Scan(&row.VCT, &row.Day, &row.PurposeHint, &row.CountryHint, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// GetTotals returns per-VCT total presentation counts for the given org.
func (r *CredentialAnalyticsRepository) GetTotals(ctx context.Context, orgID uuid.UUID) (map[string]int64, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT vct, SUM(count) FROM analytics_events WHERE org_id = $1 GROUP BY vct
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var vct string
		var count int64
		if err := rows.Scan(&vct, &count); err != nil {
			return nil, err
		}
		out[vct] = count
	}
	return out, rows.Err()
}

package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CIBANotificationConfig holds the per-org CIBA notification channel settings.
type CIBANotificationConfig struct {
	OrgID          uuid.UUID
	WebhookURL     *string
	WebhookSecret  *string
	WebhookHeaders map[string]string
	EmailEnabled   bool
	SMSEnabled     bool
	// BaseURL is the base URL for approve/deny deep links.
	// Nil → the handler derives it from the server's own base URL.
	BaseURL *string
	// Push notification config (APNs + FCM).
	PushEnabled          bool
	APNsKeyP8            *string // .p8 file content (EC private key PEM)
	APNsKeyID            *string // 10-char key identifier
	APNsTeamID           *string // Apple team ID
	APNsBundleID         *string // App bundle ID (APNs topic)
	APNsProduction       bool    // true=production, false=sandbox
	FCMServiceAccountJSON *string // Google service account JSON
}

// CIBANotificationRepository manages org_ciba_notification_config rows.
type CIBANotificationRepository struct {
	pool *pgxpool.Pool
}

// NewCIBANotificationRepository creates a new CIBANotificationRepository.
func NewCIBANotificationRepository(pool *pgxpool.Pool) *CIBANotificationRepository {
	return &CIBANotificationRepository{pool: pool}
}

// Get loads the CIBA notification config for an org.
// Returns nil, nil if no config row exists (CIBA notifications are disabled).
func (r *CIBANotificationRepository) Get(ctx context.Context, orgID uuid.UUID) (*CIBANotificationConfig, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT org_id, webhook_url, webhook_secret, webhook_headers,
		       email_enabled, sms_enabled, base_url,
		       COALESCE(push_enabled, FALSE),
		       apns_key_p8, apns_key_id, apns_team_id, apns_bundle_id,
		       COALESCE(apns_production, FALSE),
		       fcm_service_account_json
		FROM org_ciba_notification_config
		WHERE org_id = $1
	`, orgID)

	cfg := &CIBANotificationConfig{}
	var headersJSON map[string]interface{}

	err := row.Scan(
		&cfg.OrgID,
		&cfg.WebhookURL,
		&cfg.WebhookSecret,
		&headersJSON,
		&cfg.EmailEnabled,
		&cfg.SMSEnabled,
		&cfg.BaseURL,
		&cfg.PushEnabled,
		&cfg.APNsKeyP8,
		&cfg.APNsKeyID,
		&cfg.APNsTeamID,
		&cfg.APNsBundleID,
		&cfg.APNsProduction,
		&cfg.FCMServiceAccountJSON,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	// Convert map[string]interface{} → map[string]string
	if headersJSON != nil {
		cfg.WebhookHeaders = make(map[string]string, len(headersJSON))
		for k, v := range headersJSON {
			if s, ok := v.(string); ok {
				cfg.WebhookHeaders[k] = s
			}
		}
	}

	return cfg, nil
}

// Upsert creates or replaces the CIBA notification config for an org.
func (r *CIBANotificationRepository) Upsert(ctx context.Context, cfg CIBANotificationConfig) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO org_ciba_notification_config (
		    org_id, webhook_url, webhook_secret, webhook_headers,
		    email_enabled, sms_enabled, base_url,
		    push_enabled, apns_key_p8, apns_key_id, apns_team_id, apns_bundle_id,
		    apns_production, fcm_service_account_json
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (org_id) DO UPDATE SET
		    webhook_url              = EXCLUDED.webhook_url,
		    webhook_secret           = EXCLUDED.webhook_secret,
		    webhook_headers          = EXCLUDED.webhook_headers,
		    email_enabled            = EXCLUDED.email_enabled,
		    sms_enabled              = EXCLUDED.sms_enabled,
		    base_url                 = EXCLUDED.base_url,
		    push_enabled             = EXCLUDED.push_enabled,
		    apns_key_p8              = EXCLUDED.apns_key_p8,
		    apns_key_id              = EXCLUDED.apns_key_id,
		    apns_team_id             = EXCLUDED.apns_team_id,
		    apns_bundle_id           = EXCLUDED.apns_bundle_id,
		    apns_production          = EXCLUDED.apns_production,
		    fcm_service_account_json = EXCLUDED.fcm_service_account_json,
		    updated_at               = NOW()
	`, cfg.OrgID, cfg.WebhookURL, cfg.WebhookSecret, cfg.WebhookHeaders,
		cfg.EmailEnabled, cfg.SMSEnabled, cfg.BaseURL,
		cfg.PushEnabled, cfg.APNsKeyP8, cfg.APNsKeyID, cfg.APNsTeamID, cfg.APNsBundleID,
		cfg.APNsProduction, cfg.FCMServiceAccountJSON,
	)
	return err
}

// Delete removes the CIBA notification config for an org (disables all channels).
func (r *CIBANotificationRepository) Delete(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM org_ciba_notification_config WHERE org_id = $1`, orgID)
	return err
}

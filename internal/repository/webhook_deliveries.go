package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhookDeliveryRepository persists and queries webhook delivery attempts.
type WebhookDeliveryRepository struct {
	pool *pgxpool.Pool
}

func NewWebhookDeliveryRepository(pool *pgxpool.Pool) *WebhookDeliveryRepository {
	return &WebhookDeliveryRepository{pool: pool}
}

// RecordParams is the input for a single delivery attempt row.
type RecordDeliveryParams struct {
	WebhookID  uuid.UUID
	OrgID      uuid.UUID
	DeliveryID string // matches Payload.ID
	Event      string
	Payload    []byte
	Attempt    int
	Status     string // "pending" | "success" | "failed"
	HTTPStatus *int
	Error      *string
	DurationMs *int
}

// Record inserts a delivery attempt row. It is fire-and-forget safe; callers may
// ignore the error (a write failure must not block the webhook response path).
func (r *WebhookDeliveryRepository) Record(ctx context.Context, p RecordDeliveryParams) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO webhook_deliveries
		    (webhook_id, org_id, delivery_id, event, payload, attempt, status, http_status, error, duration_ms)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, p.WebhookID, p.OrgID, p.DeliveryID, p.Event,
		p.Payload, p.Attempt, p.Status, p.HTTPStatus, p.Error, p.DurationMs)
	return err
}

// ListByWebhook returns the last limit delivery rows for a webhook, newest first.
// Default limit is 50; hard cap is 200.
func (r *WebhookDeliveryRepository) ListByWebhook(
	ctx context.Context, orgID, webhookID uuid.UUID, limit int,
) ([]*models.WebhookDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	rows, err := r.pool.Query(ctx, `
		SELECT id, webhook_id, org_id, delivery_id, event, payload,
		       attempt, status, http_status, error, duration_ms, attempted_at
		FROM webhook_deliveries
		WHERE org_id = $1 AND webhook_id = $2
		ORDER BY attempted_at DESC, id DESC
		LIMIT $3
	`, orgID, webhookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.WebhookDelivery
	for rows.Next() {
		d := &models.WebhookDelivery{}
		var rawPayload []byte
		if err := rows.Scan(
			&d.ID, &d.WebhookID, &d.OrgID, &d.DeliveryID, &d.Event, &rawPayload,
			&d.Attempt, &d.Status, &d.HTTPStatus, &d.Error, &d.DurationMs, &d.AttemptedAt,
		); err != nil {
			return nil, err
		}
		d.Payload = rawPayload
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDelivery returns a single delivery row (used for the retry endpoint).
func (r *WebhookDeliveryRepository) GetDelivery(
	ctx context.Context, orgID uuid.UUID, deliveryID uuid.UUID,
) (*models.WebhookDelivery, error) {
	d := &models.WebhookDelivery{}
	var rawPayload []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, webhook_id, org_id, delivery_id, event, payload,
		       attempt, status, http_status, error, duration_ms, attempted_at
		FROM webhook_deliveries
		WHERE org_id = $1 AND id = $2
	`, orgID, deliveryID).Scan(
		&d.ID, &d.WebhookID, &d.OrgID, &d.DeliveryID, &d.Event, &rawPayload,
		&d.Attempt, &d.Status, &d.HTTPStatus, &d.Error, &d.DurationMs, &d.AttemptedAt,
	)
	if err != nil {
		return nil, err
	}
	d.Payload = rawPayload
	return d, nil
}

// MaxAttempt returns the highest attempt number for a given delivery_id (idempotency key).
func (r *WebhookDeliveryRepository) MaxAttempt(
	ctx context.Context, webhookID uuid.UUID, deliveryID string,
) (int, error) {
	var max int
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(attempt), 0)
		FROM webhook_deliveries
		WHERE webhook_id = $1 AND delivery_id = $2
	`, webhookID, deliveryID).Scan(&max)
	return max, err
}

// GetWebhookForOrg looks up a webhook by ID scoped to an org.
func (r *WebhookDeliveryRepository) GetWebhookForOrg(
	ctx context.Context, orgID, webhookID uuid.UUID,
) (*models.Webhook, error) {
	w := &models.Webhook{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, url, events, secret, is_active, created_at, updated_at
		FROM webhooks WHERE id = $1 AND org_id = $2
	`, webhookID, orgID).Scan(
		&w.ID, &w.OrgID, &w.URL, &w.Events, &w.Secret, &w.IsActive, &w.CreatedAt, &w.UpdatedAt,
	)
	return w, err
}

// RetriableDelivery holds the minimal data needed to re-attempt a failed delivery.
type RetriableDelivery struct {
	WebhookID    uuid.UUID
	OrgID        uuid.UUID
	DeliveryID   string
	Event        string
	Payload      []byte
	AttemptCount int
	LastAttempt  time.Time
}

// ListRetriable returns failed deliveries that have no success row and fewer than
// maxAttempts total attempts. The result includes the most-recent payload and
// the timestamp of the last attempt so the caller can apply back-off logic.
func (r *WebhookDeliveryRepository) ListRetriable(ctx context.Context, maxAttempts int) ([]*RetriableDelivery, error) {
	rows, err := r.pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (webhook_id, delivery_id)
				webhook_id, org_id, delivery_id, event, payload, attempted_at
			FROM webhook_deliveries
			ORDER BY webhook_id, delivery_id, attempted_at DESC
		),
		counts AS (
			SELECT webhook_id, delivery_id, COUNT(*) AS attempt_count
			FROM webhook_deliveries
			GROUP BY webhook_id, delivery_id
		)
		SELECT l.webhook_id, l.org_id, l.delivery_id, l.event, l.payload,
		       c.attempt_count, l.attempted_at
		FROM latest l
		JOIN counts c ON c.webhook_id = l.webhook_id AND c.delivery_id = l.delivery_id
		WHERE c.attempt_count < $1
		  AND NOT EXISTS (
		      SELECT 1 FROM webhook_deliveries s
		      WHERE s.webhook_id = l.webhook_id
		        AND s.delivery_id = l.delivery_id
		        AND s.status = 'success'
		  )
	`, maxAttempts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*RetriableDelivery
	for rows.Next() {
		d := &RetriableDelivery{}
		var rawPayload []byte
		if err := rows.Scan(
			&d.WebhookID, &d.OrgID, &d.DeliveryID, &d.Event,
			&rawPayload, &d.AttemptCount, &d.LastAttempt,
		); err != nil {
			return nil, err
		}
		d.Payload = rawPayload
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeliveryPayload unmarshals the raw JSONB payload stored in a delivery row.
func DeliveryPayload(d *models.WebhookDelivery) (map[string]json.RawMessage, error) {
	var out map[string]json.RawMessage
	return out, json.Unmarshal(d.Payload, &out)
}

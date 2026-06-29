package repository

import (
	"context"
	"fmt"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhookRepository handles webhook persistence.
type WebhookRepository struct {
	pool *pgxpool.Pool
	enc  *crypto.Encryptor
}

func NewWebhookRepository(pool *pgxpool.Pool) *WebhookRepository {
	return &WebhookRepository{pool: pool}
}

func NewWebhookRepositoryWithEnc(pool *pgxpool.Pool, enc *crypto.Encryptor) *WebhookRepository {
	return &WebhookRepository{pool: pool, enc: enc}
}

func (r *WebhookRepository) encryptSecret(s string) (string, error) {
	if r.enc == nil || s == "" {
		return s, nil
	}
	return r.enc.Encrypt(s)
}

func (r *WebhookRepository) decryptSecret(s string) string {
	if r.enc == nil || s == "" {
		return s
	}
	plain, err := r.enc.Decrypt(s)
	if err != nil {
		return s
	}
	return plain
}

// webhookCols is the fixed column list for all webhook SELECT statements.
// Keep in sync with scanWebhook.
const webhookCols = `id, org_id, url, events, event_filter, secret, is_active, created_at, updated_at`

func (r *WebhookRepository) scanWebhook(w *models.Webhook, row interface {
	Scan(dest ...any) error
}) error {
	if err := row.Scan(&w.ID, &w.OrgID, &w.URL, &w.Events, &w.EventFilter, &w.Secret, &w.IsActive, &w.CreatedAt, &w.UpdatedAt); err != nil {
		return err
	}
	w.Secret = r.decryptSecret(w.Secret)
	if w.EventFilter == nil {
		w.EventFilter = []string{}
	}
	return nil
}

func (r *WebhookRepository) Create(ctx context.Context, orgID uuid.UUID, url string, events []string, secret string) (*models.Webhook, error) {
	encSecret, err := r.encryptSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt webhook secret: %w", err)
	}
	w := &models.Webhook{}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO webhooks (org_id, url, events, secret)
		VALUES ($1, $2, $3, $4)
		RETURNING `+webhookCols,
		orgID, url, events, encSecret)
	if err := r.scanWebhook(w, row); err != nil {
		return nil, err
	}
	return w, nil
}

func (r *WebhookRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.Webhook, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+webhookCols+`
		FROM webhooks WHERE org_id = $1
		ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.Webhook
	for rows.Next() {
		w := &models.Webhook{}
		if err := r.scanWebhook(w, rows); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ListByOrgPage returns a cursor-paginated slice of webhooks for an org.
func (r *WebhookRepository) ListByOrgPage(ctx context.Context, orgID uuid.UUID, p models.PageParams) (*models.Page[*models.Webhook], error) {
	limit := p.Limit
	if limit <= 0 {
		limit = models.DefaultPageSize
	}
	if limit > models.MaxPageSize {
		limit = models.MaxPageSize
	}
	fetchLimit := limit + 1

	var rows pgx.Rows
	var err error

	if p.After == nil {
		rows, err = r.pool.Query(ctx, `SELECT `+webhookCols+`
			FROM webhooks WHERE org_id = $1
			ORDER BY created_at DESC, id ASC LIMIT $2`, orgID, fetchLimit)
	} else {
		var cursorTime pgtype.Timestamptz
		if e := r.pool.QueryRow(ctx, `SELECT created_at FROM webhooks WHERE id = $1`, *p.After).Scan(&cursorTime); e != nil {
			return nil, fmt.Errorf("invalid cursor: %w", e)
		}
		rows, err = r.pool.Query(ctx, `SELECT `+webhookCols+`
			FROM webhooks WHERE org_id = $1
			  AND (created_at < $2 OR (created_at = $2 AND id > $3))
			ORDER BY created_at DESC, id ASC LIMIT $4`,
			orgID, cursorTime, *p.After, fetchLimit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	webhooks := make([]*models.Webhook, 0, limit)
	for rows.Next() {
		w := &models.Webhook{}
		if err := r.scanWebhook(w, rows); err != nil {
			return nil, err
		}
		webhooks = append(webhooks, w)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	hasMore := len(webhooks) > limit
	if hasMore {
		webhooks = webhooks[:limit]
	}
	page := &models.Page[*models.Webhook]{
		Items:   webhooks,
		HasMore: hasMore,
	}
	if hasMore {
		last := webhooks[len(webhooks)-1].ID.String()
		page.NextCursor = &last
	}
	return page, nil
}

func (r *WebhookRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Webhook, error) {
	w := &models.Webhook{}
	row := r.pool.QueryRow(ctx, `SELECT `+webhookCols+` FROM webhooks WHERE id = $1`, id)
	if err := r.scanWebhook(w, row); err != nil {
		return nil, err
	}
	return w, nil
}

func (r *WebhookRepository) Update(ctx context.Context, id uuid.UUID, url *string, events []string, isActive *bool, eventFilter []string) (*models.Webhook, error) {
	w := &models.Webhook{}
	row := r.pool.QueryRow(ctx, `
		UPDATE webhooks SET
			url          = COALESCE($2, url),
			events       = COALESCE($3, events),
			is_active    = COALESCE($4, is_active),
			event_filter = CASE WHEN $5::text[] IS NOT NULL THEN $5 ELSE event_filter END,
			updated_at   = NOW()
		WHERE id = $1
		RETURNING `+webhookCols,
		id, url, events, isActive, eventFilter)
	if err := r.scanWebhook(w, row); err != nil {
		return nil, err
	}
	return w, nil
}

func (r *WebhookRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM webhooks WHERE id = $1`, id)
	return err
}

// ListActiveByOrgAndEvent returns all active webhooks for an org that subscribe to the given event.
// If a webhook has a non-empty event_filter, the event must also match one of those subtypes.
func (r *WebhookRepository) ListActiveByOrgAndEvent(ctx context.Context, orgID uuid.UUID, event string) ([]*models.Webhook, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+webhookCols+`
		FROM webhooks
		WHERE org_id = $1
		  AND is_active = TRUE
		  AND $2 = ANY(events)
		  AND (array_length(event_filter, 1) IS NULL OR $2 = ANY(event_filter))
		ORDER BY created_at ASC`,
		orgID, event)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.Webhook
	for rows.Next() {
		w := &models.Webhook{}
		if err := r.scanWebhook(w, rows); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

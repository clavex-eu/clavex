package repository

import (
	"context"
	"fmt"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const scimPushCols = `id, org_id, name, endpoint_url, bearer_token, enabled_events, is_active, created_at, updated_at`

// ScimPushRepository manages outbound SCIM push configuration records.
type ScimPushRepository struct {
	pool *pgxpool.Pool
	enc  *crypto.Encryptor
}

func NewScimPushRepository(pool *pgxpool.Pool) *ScimPushRepository {
	return &ScimPushRepository{pool: pool}
}

func NewScimPushRepositoryWithEnc(pool *pgxpool.Pool, enc *crypto.Encryptor) *ScimPushRepository {
	return &ScimPushRepository{pool: pool, enc: enc}
}

func (r *ScimPushRepository) encryptToken(tok string) (string, error) {
	if r.enc == nil || tok == "" {
		return tok, nil
	}
	return r.enc.Encrypt(tok)
}

func (r *ScimPushRepository) decryptToken(tok string) string {
	if r.enc == nil || tok == "" {
		return tok
	}
	plain, err := r.enc.Decrypt(tok)
	if err != nil {
		return tok
	}
	return plain
}

func (r *ScimPushRepository) scanAndDecrypt(row interface {
	Scan(dest ...any) error
}) (*models.ScimPushConfig, error) {
	c := &models.ScimPushConfig{}
	err := row.Scan(
		&c.ID, &c.OrgID, &c.Name, &c.EndpointURL, &c.BearerToken,
		&c.EnabledEvents, &c.IsActive, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	c.BearerToken = r.decryptToken(c.BearerToken)
	return c, nil
}

func (r *ScimPushRepository) Create(
	ctx context.Context, orgID uuid.UUID,
	name, endpointURL, bearerToken string, events []string,
) (*models.ScimPushConfig, error) {
	encToken, err := r.encryptToken(bearerToken)
	if err != nil {
		return nil, fmt.Errorf("encrypt bearer_token: %w", err)
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO scim_push_configs (org_id, name, endpoint_url, bearer_token, enabled_events)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING `+scimPushCols,
		orgID, name, endpointURL, encToken, events,
	)
	return r.scanAndDecrypt(row)
}

func (r *ScimPushRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.ScimPushConfig, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+scimPushCols+`
		FROM scim_push_configs WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.ScimPushConfig
	for rows.Next() {
		c, err := r.scanAndDecrypt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListActiveByOrgAndEvent returns configs that are active and subscribed to the given event.
func (r *ScimPushRepository) ListActiveByOrgAndEvent(
	ctx context.Context, orgID uuid.UUID, event string,
) ([]*models.ScimPushConfig, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+scimPushCols+`
		FROM scim_push_configs
		WHERE org_id = $1 AND is_active = TRUE AND $2 = ANY(enabled_events)
	`, orgID, event)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.ScimPushConfig
	for rows.Next() {
		c, err := r.scanAndDecrypt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type UpdateScimPushParams struct {
	Name          *string
	EndpointURL   *string
	BearerToken   *string // if non-nil and non-empty, replace token
	EnabledEvents []string
	IsActive      *bool
}

func (r *ScimPushRepository) Update(
	ctx context.Context, orgID, id uuid.UUID, p UpdateScimPushParams,
) (*models.ScimPushConfig, error) {
	var encToken *string
	if p.BearerToken != nil && *p.BearerToken != "" {
		ct, err := r.encryptToken(*p.BearerToken)
		if err != nil {
			return nil, fmt.Errorf("encrypt bearer_token: %w", err)
		}
		encToken = &ct
	} else {
		encToken = p.BearerToken
	}
	row := r.pool.QueryRow(ctx, `
		UPDATE scim_push_configs SET
		    name           = COALESCE($3, name),
		    endpoint_url   = COALESCE($4, endpoint_url),
		    bearer_token   = COALESCE($5, bearer_token),
		    enabled_events = COALESCE($6, enabled_events),
		    is_active      = COALESCE($7, is_active),
		    updated_at     = NOW()
		WHERE id = $1 AND org_id = $2
		RETURNING `+scimPushCols,
		id, orgID, p.Name, p.EndpointURL, encToken, p.EnabledEvents, p.IsActive,
	)
	return r.scanAndDecrypt(row)
}

func (r *ScimPushRepository) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM scim_push_configs WHERE id = $1 AND org_id = $2`, id, orgID)
	return err
}

// GetByID fetches a config by its primary key (used by the retry endpoint).
func (r *ScimPushRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ScimPushConfig, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+scimPushCols+` FROM scim_push_configs WHERE id = $1`, id)
	return r.scanAndDecrypt(row)
}

// ── SCIM Push Delivery Log ────────────────────────────────────────────────────

// ScimPushDeliveryRepository records outbound SCIM push attempts and exposes
// query methods for the delivery-log admin API.
type ScimPushDeliveryRepository struct {
	pool *pgxpool.Pool
}

// NewScimPushDeliveryRepository creates a delivery-log repository.
func NewScimPushDeliveryRepository(pool *pgxpool.Pool) *ScimPushDeliveryRepository {
	return &ScimPushDeliveryRepository{pool: pool}
}

// ScimDeliveryParams are the fields written by the Pusher after each attempt.
type ScimDeliveryParams struct {
	ConfigID    uuid.UUID
	Event       string
	SubjectID   *uuid.UUID
	SubjectType string // "user" | "group"
	HTTPStatus  *int
	ErrorMsg    *string
	DurationMS  *int
}

// Record writes a single delivery attempt. Errors are absorbed — the delivery
// log is observability-only and must never break the sync path.
func (r *ScimPushDeliveryRepository) Record(ctx context.Context, p ScimDeliveryParams) {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO scim_push_deliveries
		    (config_id, event, subject_id, subject_type, http_status, error_msg, duration_ms)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, p.ConfigID, p.Event, p.SubjectID, p.SubjectType, p.HTTPStatus, p.ErrorMsg, p.DurationMS)
	if err != nil {
		// Non-fatal: delivery log is best-effort.
		_ = err
	}
}

// ListDeliveries returns the most-recent deliveries for a SCIM push config.
// limit defaults to 50; max 200.
func (r *ScimPushDeliveryRepository) ListDeliveries(ctx context.Context, configID uuid.UUID, limit int) ([]*models.ScimPushDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, config_id, event, subject_id, subject_type,
		       http_status, error_msg, duration_ms, success, created_at
		FROM scim_push_deliveries
		WHERE config_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2
	`, configID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.ScimPushDelivery
	for rows.Next() {
		d := &models.ScimPushDelivery{}
		if err := rows.Scan(
			&d.ID, &d.ConfigID, &d.Event, &d.SubjectID, &d.SubjectType,
			&d.HTTPStatus, &d.ErrorMsg, &d.DurationMS, &d.Success, &d.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDelivery fetches a single delivery by ID (for the retry endpoint).
func (r *ScimPushDeliveryRepository) GetDelivery(ctx context.Context, id int64) (*models.ScimPushDelivery, error) {
	d := &models.ScimPushDelivery{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, config_id, event, subject_id, subject_type,
		       http_status, error_msg, duration_ms, success, created_at
		FROM scim_push_deliveries WHERE id = $1
	`, id).Scan(
		&d.ID, &d.ConfigID, &d.Event, &d.SubjectID, &d.SubjectType,
		&d.HTTPStatus, &d.ErrorMsg, &d.DurationMS, &d.Success, &d.CreatedAt,
	)
	return d, err
}

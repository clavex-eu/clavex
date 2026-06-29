package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SSFStreamRepository handles persistence of SSF streams and pending SETs.
type SSFStreamRepository struct {
	pool *pgxpool.Pool
}

func NewSSFStreamRepository(pool *pgxpool.Pool) *SSFStreamRepository {
	return &SSFStreamRepository{pool: pool}
}

// ── SSF Streams ──────────────────────────────────────────────────────────────

const ssfStreamColumns = `id, org_id, client_id, delivery_method, push_endpoint,
  push_secret_hash, events_requested, status, description, created_at, updated_at`

func scanSSFStream(row pgx.Row) (*models.SSFStream, error) {
	s := &models.SSFStream{}
	err := row.Scan(
		&s.ID, &s.OrgID, &s.ClientID, &s.DeliveryMethod,
		&s.PushEndpoint, &s.PushSecretHash,
		&s.EventsRequested, &s.Status, &s.Description,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Create inserts a new SSF stream and returns it with the generated ID.
func (r *SSFStreamRepository) Create(ctx context.Context, s *models.SSFStream) (*models.SSFStream, error) {
	q := `INSERT INTO ssf_streams
	  (org_id, client_id, delivery_method, push_endpoint, push_secret_hash,
	   events_requested, status, description)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	RETURNING ` + ssfStreamColumns
	row := r.pool.QueryRow(ctx, q,
		s.OrgID, s.ClientID, s.DeliveryMethod, s.PushEndpoint, s.PushSecretHash,
		s.EventsRequested, s.Status, s.Description,
	)
	out, err := scanSSFStream(row)
	if err != nil {
		return nil, fmt.Errorf("ssf: create stream: %w", err)
	}
	return out, nil
}

// GetByID returns a stream by its primary key, scoped to an org.
func (r *SSFStreamRepository) GetByID(ctx context.Context, orgID, streamID uuid.UUID) (*models.SSFStream, error) {
	q := `SELECT ` + ssfStreamColumns + ` FROM ssf_streams WHERE id=$1 AND org_id=$2`
	row := r.pool.QueryRow(ctx, q, streamID, orgID)
	out, err := scanSSFStream(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("ssf: get stream: %w", err)
	}
	return out, nil
}

// GetByClientID returns a stream by org + client_id (unique constraint).
func (r *SSFStreamRepository) GetByClientID(ctx context.Context, orgID uuid.UUID, clientID string) (*models.SSFStream, error) {
	q := `SELECT ` + ssfStreamColumns + ` FROM ssf_streams WHERE org_id=$1 AND client_id=$2`
	row := r.pool.QueryRow(ctx, q, orgID, clientID)
	out, err := scanSSFStream(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("ssf: get stream by client: %w", err)
	}
	return out, nil
}

// ListByOrg returns all streams for an org.
func (r *SSFStreamRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.SSFStream, error) {
	q := `SELECT ` + ssfStreamColumns + ` FROM ssf_streams WHERE org_id=$1 ORDER BY created_at`
	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("ssf: list streams: %w", err)
	}
	defer rows.Close()
	var out []*models.SSFStream
	for rows.Next() {
		s, err := scanSSFStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListPushEnabled returns enabled push streams for an org (used by the push worker).
func (r *SSFStreamRepository) ListPushEnabled(ctx context.Context, orgID uuid.UUID) ([]*models.SSFStream, error) {
	q := `SELECT ` + ssfStreamColumns + `
	  FROM ssf_streams
	  WHERE org_id=$1 AND delivery_method='push' AND status='enabled'`
	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("ssf: list push enabled: %w", err)
	}
	defer rows.Close()
	var out []*models.SSFStream
	for rows.Next() {
		s, err := scanSSFStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListAllPushEnabled returns all enabled push streams across all orgs (push worker).
func (r *SSFStreamRepository) ListAllPushEnabled(ctx context.Context) ([]*models.SSFStream, error) {
	q := `SELECT ` + ssfStreamColumns + `
	  FROM ssf_streams WHERE delivery_method='push' AND status='enabled'`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("ssf: list all push enabled: %w", err)
	}
	defer rows.Close()
	var out []*models.SSFStream
	for rows.Next() {
		s, err := scanSSFStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListPollEnabled returns enabled poll streams for an org (used by dispatcher).
func (r *SSFStreamRepository) ListPollEnabled(ctx context.Context, orgID uuid.UUID) ([]*models.SSFStream, error) {
	q := `SELECT ` + ssfStreamColumns + `
	  FROM ssf_streams
	  WHERE org_id=$1 AND delivery_method='poll' AND status='enabled'`
	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("ssf: list poll enabled: %w", err)
	}
	defer rows.Close()
	var out []*models.SSFStream
	for rows.Next() {
		s, err := scanSSFStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Update modifies a stream's mutable fields.
func (r *SSFStreamRepository) Update(ctx context.Context, s *models.SSFStream) (*models.SSFStream, error) {
	q := `UPDATE ssf_streams SET
	  push_endpoint=$1, push_secret_hash=$2, events_requested=$3,
	  status=$4, description=$5, updated_at=now()
	WHERE id=$6 AND org_id=$7
	RETURNING ` + ssfStreamColumns
	row := r.pool.QueryRow(ctx, q,
		s.PushEndpoint, s.PushSecretHash, s.EventsRequested,
		s.Status, s.Description, s.ID, s.OrgID,
	)
	out, err := scanSSFStream(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("ssf: update stream: %w", err)
	}
	return out, nil
}

// Delete removes a stream and its pending SETs (cascade).
func (r *SSFStreamRepository) Delete(ctx context.Context, orgID, streamID uuid.UUID) error {
	q := `DELETE FROM ssf_streams WHERE id=$1 AND org_id=$2`
	ct, err := r.pool.Exec(ctx, q, streamID, orgID)
	if err != nil {
		return fmt.Errorf("ssf: delete stream: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ── SSF Pending SETs (poll delivery) ────────────────────────────────────────

// EnqueueSET adds a SET to the poll queue for a stream.
func (r *SSFStreamRepository) EnqueueSET(ctx context.Context, streamID uuid.UUID, jti, compactJWT, eventType string) error {
	q := `INSERT INTO ssf_pending_sets (jti, stream_id, payload, event_type)
	      VALUES ($1, $2, $3::jsonb, $4)
	      ON CONFLICT (jti) DO NOTHING`
	// Store the compact JWT as a JSON string value to satisfy the jsonb column.
	payload := `"` + compactJWT + `"`
	_, err := r.pool.Exec(ctx, q, jti, streamID, payload, eventType)
	if err != nil {
		return fmt.Errorf("ssf: enqueue SET: %w", err)
	}
	return nil
}

// PollSETs returns up to maxEvents pending SETs for a stream.
// The returned records include the compact JWT payload.
func (r *SSFStreamRepository) PollSETs(ctx context.Context, streamID uuid.UUID, maxEvents int) ([]*models.SSFPendingSet, error) {
	if maxEvents <= 0 {
		maxEvents = 100
	}
	// payload #>> '{}' extracts the JSON string value as text.
	q := `SELECT jti, stream_id, payload #>> '{}', event_type, created_at, expires_at
	     FROM ssf_pending_sets
	     WHERE stream_id=$1 AND expires_at > now()
	     ORDER BY created_at
	     LIMIT $2`
	rows, err := r.pool.Query(ctx, q, streamID, maxEvents)
	if err != nil {
		return nil, fmt.Errorf("ssf: poll sets: %w", err)
	}
	defer rows.Close()
	var out []*models.SSFPendingSet
	for rows.Next() {
		s := &models.SSFPendingSet{}
		if err := rows.Scan(&s.JTI, &s.StreamID, &s.Payload, &s.EventType, &s.CreatedAt, &s.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// AcknowledgeSETs removes acknowledged SETs from the poll queue.
func (r *SSFStreamRepository) AcknowledgeSETs(ctx context.Context, streamID uuid.UUID, jtis []string) error {
	if len(jtis) == 0 {
		return nil
	}
	q := `DELETE FROM ssf_pending_sets WHERE stream_id=$1 AND jti=ANY($2)`
	_, err := r.pool.Exec(ctx, q, streamID, jtis)
	if err != nil {
		return fmt.Errorf("ssf: acknowledge sets: %w", err)
	}
	return nil
}

// CountPendingSETs returns the number of SETs still queued for a stream.
func (r *SSFStreamRepository) CountPendingSETs(ctx context.Context, streamID uuid.UUID) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ssf_pending_sets WHERE stream_id=$1 AND expires_at > now()`, streamID).Scan(&n)
	return n, err
}

// PurgeExpiredSETs removes SETs past their expiry time. Called by the maintenance job.
func (r *SSFStreamRepository) PurgeExpiredSETs(ctx context.Context) (int64, error) {
	ct, err := r.pool.Exec(ctx, `DELETE FROM ssf_pending_sets WHERE expires_at <= $1`, time.Now())
	if err != nil {
		return 0, fmt.Errorf("ssf: purge expired: %w", err)
	}
	return ct.RowsAffected(), nil
}

package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditRepository handles all audit log persistence including the new
// structured CloudEvents schema, retention settings, and sink management.
type AuditRepository struct {
	pool *pgxpool.Pool
}

func NewAuditRepository(pool *pgxpool.Pool) *AuditRepository {
	return &AuditRepository{pool: pool}
}

// ── Implements audit.Recorder ─────────────────────────────────────────────────

// Dispatcher is set by the server wiring so the repository can fan-out events.
var globalDispatcher interface{ Publish(e *audit.Event) }

// SetDispatcher injects the fan-out dispatcher.
// Called once during server initialisation.
func SetDispatcher(d interface{ Publish(e *audit.Event) }) {
	globalDispatcher = d
}

// RecordEvent persists a CloudEvents audit event. Satisfies audit.Recorder.
func (r *AuditRepository) RecordEvent(ctx context.Context, e *audit.Event, data *audit.EventData) error {
	metadataJSON, err := json.Marshal(data.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	// Parse actor UUID (may be nil for system events).
	var actorID *uuid.UUID
	if data.ActorID != nil {
		id, parseErr := uuid.Parse(*data.ActorID)
		if parseErr == nil {
			actorID = &id
		}
	}
	orgID, _ := uuid.Parse(e.OrgID)

	sesID := (*string)(nil)
	if e.SessionID != "" {
		sesID = &e.SessionID
	}
	reqID := (*string)(nil)
	if e.RequestID != "" {
		reqID = &e.RequestID
	}

	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit.audit_logs (
			event_id, spec_version, event_source, event_type, subject,
			org_id, user_id, actor_email, action, resource_type, resource_id,
			status, ip_address, user_agent, country_code,
			session_id, request_id, metadata
		) VALUES (
			$1,$2,$3,$4,$5,
			$6,$7,$8,$9,$10,$11,
			$12,$13,$14,$15,
			$16,$17,$18
		)`,
		e.ID, e.SpecVersion, e.Source, e.Type, e.Subject,
		orgID, actorID, data.ActorEmail, data.Action, data.ResourceType, data.ResourceID,
		data.Status, data.IPAddress, data.UserAgent, data.CountryCode,
		sesID, reqID, metadataJSON,
	)
	return err
}

// PublishToChannel hands the event to the fan-out dispatcher (non-blocking).
// Satisfies audit.Recorder.
func (r *AuditRepository) PublishToChannel(e *audit.Event) {
	if globalDispatcher != nil {
		globalDispatcher.Publish(e)
	}
}

// Record is a backwards-compatible helper used by handlers that were written
// before the structured CloudEvents schema. It persists the legacy AuditLog
// row directly and does not fan-out to sinks.
func (r *AuditRepository) Record(ctx context.Context, entry *models.AuditLog) error {
	metadataJSON, _ := json.Marshal(entry.Metadata)
	eventID := uuid.New().String()
	eventType := "clavex." + strings.ReplaceAll(entry.Action, ".", ".")
	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit.audit_logs (org_id, user_id, actor_email, action, resource_type, resource_id,
			status, ip_address, user_agent, metadata, event_id, spec_version, event_source, event_type)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		entry.OrgID, entry.UserID, entry.ActorEmail, entry.Action,
		entry.ResourceType, entry.ResourceID, entry.Status,
		entry.IPAddress, entry.UserAgent, metadataJSON,
		eventID, "1.0", "clavex", eventType,
	)
	return err
}

// ── Query API ─────────────────────────────────────────────────────────────────

// AuditFilter describes query parameters for the structured audit log.
type AuditFilter struct {
	OrgID        uuid.UUID
	Action       string // exact match
	ActionPrefix string // LIKE 'prefix.%' — mutually exclusive with Action
	ResourceType string
	ResourceID   string
	ActorID      string
	Status       string // "success" | "failure"
	SessionID    string
	Since        *time.Time
	Until        *time.Time
	// Cursor-based pagination
	Cursor int64 // last seen row ID (0 = first page)
	Limit  int   // max 500
}

// AuditPage is a single page of results with a cursor for the next page.
type AuditPage struct {
	Events     []*AuditEvent `json:"events"`
	NextCursor int64         `json:"next_cursor,omitempty"` // 0 = no more pages
	Total      int64         `json:"total"`
}

// AuditEvent is the query-friendly view of an audit log row.
type AuditEvent struct {
	ID           int64                  `json:"id"`
	EventID      string                 `json:"event_id"`
	SpecVersion  string                 `json:"specversion"`
	Source       string                 `json:"source"`
	Type         string                 `json:"type"`
	Time         time.Time              `json:"time"`
	Subject      string                 `json:"subject,omitempty"`
	OrgID        uuid.UUID              `json:"org_id"`
	ActorID      *uuid.UUID             `json:"actor_id,omitempty"`
	ActorEmail   *string                `json:"actor_email,omitempty"`
	Action       string                 `json:"action"`
	ResourceType *string                `json:"resource_type,omitempty"`
	ResourceID   *string                `json:"resource_id,omitempty"`
	Status       string                 `json:"status"`
	IPAddress    *string                `json:"ip_address,omitempty"`
	UserAgent    *string                `json:"user_agent,omitempty"`
	CountryCode  *string                `json:"country_code,omitempty"`
	SessionID    *string                `json:"session_id,omitempty"`
	RequestID    *string                `json:"request_id,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// List returns a single page of structured audit events.
func (r *AuditRepository) List(ctx context.Context, f AuditFilter) (*AuditPage, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}

	args := []interface{}{f.OrgID}
	conds := []string{"org_id = $1"}
	n := 2
	add := func(cond string, val interface{}) {
		conds = append(conds, fmt.Sprintf(cond, n))
		args = append(args, val)
		n++
	}

	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.ActionPrefix != "" && f.Action == "" {
		add("action LIKE $%d", f.ActionPrefix+".%")
	}
	if f.ResourceType != "" {
		add("resource_type = $%d", f.ResourceType)
	}
	if f.ResourceID != "" {
		add("resource_id = $%d", f.ResourceID)
	}
	if f.Status != "" {
		add("status = $%d", f.Status)
	}
	if f.SessionID != "" {
		add("session_id = $%d", f.SessionID)
	}
	if f.Since != nil {
		add("created_at >= $%d", *f.Since)
	}
	if f.Until != nil {
		add("created_at <= $%d", *f.Until)
	}
	if f.ActorID != "" {
		id, err := uuid.Parse(f.ActorID)
		if err == nil {
			add("user_id = $%d", id)
		}
	}
	if f.Cursor > 0 {
		add("id < $%d", f.Cursor)
	}

	where := strings.Join(conds, " AND ")

	var total int64
	if err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit.audit_logs WHERE "+where, args[:n-1]...,
	).Scan(&total); err != nil {
		return nil, err
	}

	// Fetch one extra row to determine if there's a next page.
	fetchArgs := append(args[:n-1], f.Limit+1)
	q := fmt.Sprintf(
		`SELECT id,event_id,spec_version,
		        COALESCE(event_source,''),COALESCE(event_type,''),COALESCE(subject,''),
		        org_id,user_id,actor_email,action,resource_type,resource_id,
		        status,ip_address::text,user_agent,country_code,session_id,request_id,
		        metadata,created_at
		 FROM audit.audit_logs WHERE %s ORDER BY id DESC LIMIT $%d`,
		where, n,
	)
	rows, err := r.pool.Query(ctx, q, fetchArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]*AuditEvent, 0, f.Limit)
	for rows.Next() {
		e := &AuditEvent{}
		var metaRaw []byte
		if err := rows.Scan(
			&e.ID, &e.EventID, &e.SpecVersion, &e.Source, &e.Type, &e.Subject,
			&e.OrgID, &e.ActorID, &e.ActorEmail, &e.Action, &e.ResourceType, &e.ResourceID,
			&e.Status, &e.IPAddress, &e.UserAgent, &e.CountryCode, &e.SessionID, &e.RequestID,
			&metaRaw, &e.Time,
		); err != nil {
			return nil, err
		}
		if len(metaRaw) > 0 {
			_ = json.Unmarshal(metaRaw, &e.Metadata)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var nextCursor int64
	if len(events) > f.Limit {
		events = events[:f.Limit]
		nextCursor = events[len(events)-1].ID
	}

	return &AuditPage{Events: events, NextCursor: nextCursor, Total: total}, nil
}

// ExportAll streams all audit events matching the filter into a JSON-lines
// writer. It does NOT paginate — intended for bulk export.
func (r *AuditRepository) ExportAll(ctx context.Context, f AuditFilter, emit func(*AuditEvent) error) error {
	f.Limit = 500
	cursor := int64(0)
	for {
		f.Cursor = cursor
		page, err := r.List(ctx, f)
		if err != nil {
			return err
		}
		for _, e := range page.Events {
			if err := emit(e); err != nil {
				return err
			}
		}
		if page.NextCursor == 0 {
			break
		}
		cursor = page.NextCursor
	}
	return nil
}

// ── Sink management ───────────────────────────────────────────────────────────

// AuditSink mirrors the audit_sinks row.
type AuditSink struct {
	ID             uuid.UUID              `json:"id"`
	OrgID          uuid.UUID              `json:"org_id"`
	Name           string                 `json:"name"`
	SinkType       string                 `json:"sink_type"`
	IsActive       bool                   `json:"is_active"`
	Config         map[string]interface{} `json:"config"`
	FilterActions  []string               `json:"filter_actions,omitempty"`
	FilterStatuses []string               `json:"filter_statuses,omitempty"`
	LastSuccessAt  *time.Time             `json:"last_success_at,omitempty"`
	LastErrorAt    *time.Time             `json:"last_error_at,omitempty"`
	LastErrorMsg   *string                `json:"last_error_msg,omitempty"`
	SuccessCount   int64                  `json:"success_count"`
	FailureCount   int64                  `json:"failure_count"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// CreateSink inserts a new sink definition.
func (r *AuditRepository) CreateSink(ctx context.Context, s *AuditSink) error {
	cfgJSON, err := json.Marshal(s.Config)
	if err != nil {
		return err
	}
	s.ID = uuid.New()
	return r.pool.QueryRow(ctx, `
		INSERT INTO audit_sinks (id, org_id, name, sink_type, is_active, config, filter_actions, filter_statuses)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING created_at, updated_at`,
		s.ID, s.OrgID, s.Name, s.SinkType, s.IsActive,
		cfgJSON, s.FilterActions, s.FilterStatuses,
	).Scan(&s.CreatedAt, &s.UpdatedAt)
}

// ListSinks returns all sinks for an org.
func (r *AuditRepository) ListSinks(ctx context.Context, orgID uuid.UUID) ([]*AuditSink, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,org_id,name,sink_type,is_active,config,filter_actions,filter_statuses,
		       last_success_at,last_error_at,last_error_msg,
		       success_count,failure_count,created_at,updated_at
		FROM audit_sinks WHERE org_id=$1 ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sinks []*AuditSink
	for rows.Next() {
		s := &AuditSink{}
		var cfgRaw []byte
		if err := rows.Scan(
			&s.ID, &s.OrgID, &s.Name, &s.SinkType, &s.IsActive, &cfgRaw,
			&s.FilterActions, &s.FilterStatuses,
			&s.LastSuccessAt, &s.LastErrorAt, &s.LastErrorMsg,
			&s.SuccessCount, &s.FailureCount, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cfgRaw, &s.Config)
		sinks = append(sinks, s)
	}
	return sinks, rows.Err()
}

// GetSink returns a single sink by ID, scoped to orgID.
func (r *AuditRepository) GetSink(ctx context.Context, orgID, sinkID uuid.UUID) (*AuditSink, error) {
	s := &AuditSink{}
	var cfgRaw []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id,org_id,name,sink_type,is_active,config,filter_actions,filter_statuses,
		       last_success_at,last_error_at,last_error_msg,
		       success_count,failure_count,created_at,updated_at
		FROM audit_sinks WHERE org_id=$1 AND id=$2`, orgID, sinkID,
	).Scan(
		&s.ID, &s.OrgID, &s.Name, &s.SinkType, &s.IsActive, &cfgRaw,
		&s.FilterActions, &s.FilterStatuses,
		&s.LastSuccessAt, &s.LastErrorAt, &s.LastErrorMsg,
		&s.SuccessCount, &s.FailureCount, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(cfgRaw, &s.Config)
	return s, nil
}

// UpdateSink replaces mutable fields of a sink.
func (r *AuditRepository) UpdateSink(ctx context.Context, s *AuditSink) error {
	cfgJSON, err := json.Marshal(s.Config)
	if err != nil {
		return err
	}
	return r.pool.QueryRow(ctx, `
		UPDATE audit_sinks
		SET name=$3, is_active=$4, config=$5, filter_actions=$6, filter_statuses=$7,
		    updated_at=NOW()
		WHERE org_id=$1 AND id=$2
		RETURNING updated_at`,
		s.OrgID, s.ID, s.Name, s.IsActive, cfgJSON,
		s.FilterActions, s.FilterStatuses,
	).Scan(&s.UpdatedAt)
}

// DeleteSink removes a sink.
func (r *AuditRepository) DeleteSink(ctx context.Context, orgID, sinkID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		"DELETE FROM audit_sinks WHERE org_id=$1 AND id=$2", orgID, sinkID)
	return err
}

// ActiveSinksForOrg satisfies audit.SinkLoader.
func (r *AuditRepository) ActiveSinksForOrg(ctx context.Context, orgID uuid.UUID) ([]audit.SinkConfig, error) {
	sinks, err := r.ListSinks(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]audit.SinkConfig, 0, len(sinks))
	for _, s := range sinks {
		if !s.IsActive {
			continue
		}
		out = append(out, audit.SinkConfig{
			ID:             s.ID,
			OrgID:          s.OrgID,
			Name:           s.Name,
			SinkType:       s.SinkType,
			Config:         s.Config,
			FilterActions:  s.FilterActions,
			FilterStatuses: s.FilterStatuses,
		})
	}
	return out, nil
}

// UpdateSinkStats satisfies audit.SinkStatsUpdater.
func (r *AuditRepository) UpdateSinkStats(ctx context.Context, sinkID uuid.UUID, success bool, errMsg string) error {
	if success {
		_, err := r.pool.Exec(ctx, `
			UPDATE audit_sinks
			SET last_success_at=NOW(), success_count=success_count+1, updated_at=NOW()
			WHERE id=$1`, sinkID)
		return err
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE audit_sinks
		SET last_error_at=NOW(), last_error_msg=$2, failure_count=failure_count+1, updated_at=NOW()
		WHERE id=$1`, sinkID, errMsg)
	return err
}

// ── Retention settings ────────────────────────────────────────────────────────

// AuditRetention mirrors the audit_retention row.
type AuditRetention struct {
	OrgID         uuid.UUID   `json:"org_id"`
	RetentionDays int         `json:"retention_days"`
	ExportEnabled bool        `json:"export_enabled"`
	ExportConfig  interface{} `json:"export_config,omitempty"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// GetRetention returns the retention settings for an org (defaults if missing).
func (r *AuditRepository) GetRetention(ctx context.Context, orgID uuid.UUID) (*AuditRetention, error) {
	ar := &AuditRetention{OrgID: orgID, RetentionDays: 90}
	var cfgRaw []byte
	err := r.pool.QueryRow(ctx,
		"SELECT retention_days,export_enabled,export_config,updated_at FROM audit_retention WHERE org_id=$1",
		orgID,
	).Scan(&ar.RetentionDays, &ar.ExportEnabled, &cfgRaw, &ar.UpdatedAt)
	if err != nil {
		if isNotFound(err) {
			return ar, nil // return defaults
		}
		return nil, err
	}
	_ = json.Unmarshal(cfgRaw, &ar.ExportConfig)
	return ar, nil
}

// UpsertRetention creates or replaces retention settings for an org.
func (r *AuditRepository) UpsertRetention(ctx context.Context, ar *AuditRetention) error {
	cfgJSON, _ := json.Marshal(ar.ExportConfig)
	return r.pool.QueryRow(ctx, `
		INSERT INTO audit_retention (org_id, retention_days, export_enabled, export_config)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (org_id) DO UPDATE
		SET retention_days=$2, export_enabled=$3, export_config=$4, updated_at=NOW()
		RETURNING updated_at`,
		ar.OrgID, ar.RetentionDays, ar.ExportEnabled, cfgJSON,
	).Scan(&ar.UpdatedAt)
}

// ── Retention worker support ──────────────────────────────────────────────────

// DeleteExpiredEvents satisfies audit.RetentionStore.
// It deletes audit_log rows older than each org's configured retention_days.
// Orgs without a retention row get the default 90-day policy.
func (r *AuditRepository) DeleteExpiredEvents(ctx context.Context) (int64, error) {
	res, err := r.pool.Exec(ctx, `
		DELETE FROM audit.audit_logs al
		USING (
			SELECT o.id AS org_id,
			       COALESCE(ar.retention_days, 90) AS days
			FROM   organizations o
			LEFT   JOIN audit_retention ar ON ar.org_id = o.id
		) AS policy
		WHERE  al.org_id = policy.org_id
		  AND  al.created_at < NOW() - (policy.days || ' days')::interval
	`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// isNotFound is a lightweight pgx "no rows" check.
func isNotFound(err error) bool {
	return err != nil && err.Error() == "no rows in result set"
}

// ── Merkle checkpoint persistence ────────────────────────────────────────────

// AuditMerkleCheckpoint is the DB model for audit_merkle_checkpoints.
type AuditMerkleCheckpoint struct {
	ID         int64     `db:"id"           json:"id"`
	OrgID      uuid.UUID `db:"org_id"       json:"org_id"`
	FirstLogID int64     `db:"first_log_id" json:"first_log_id"`
	LastLogID  int64     `db:"last_log_id"  json:"last_log_id"`
	LogCount   int       `db:"log_count"    json:"log_count"`
	MerkleRoot string    `db:"merkle_root"  json:"merkle_root"`
	PrevRoot   string    `db:"prev_root"    json:"prev_root"`
	ChainHash  string    `db:"chain_hash"   json:"chain_hash"`
	Signature  string    `db:"signature"    json:"signature"`
	KID        string    `db:"kid"          json:"kid"`
	CreatedAt  time.Time `db:"created_at"   json:"created_at"`
}

// InsertMerkleCheckpoint stores a new checkpoint row.
func (r *AuditRepository) InsertMerkleCheckpoint(ctx context.Context, cp *AuditMerkleCheckpoint) error {
	return r.pool.QueryRow(ctx, `
		INSERT INTO audit_merkle_checkpoints
		    (org_id, first_log_id, last_log_id, log_count, merkle_root, prev_root, chain_hash, signature, kid)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, created_at`,
		cp.OrgID, cp.FirstLogID, cp.LastLogID, cp.LogCount,
		cp.MerkleRoot, cp.PrevRoot, cp.ChainHash, cp.Signature, cp.KID,
	).Scan(&cp.ID, &cp.CreatedAt)
}

// LatestCheckpoint returns the most recent checkpoint for an org, or nil if none.
func (r *AuditRepository) LatestCheckpoint(ctx context.Context, orgID uuid.UUID) (*AuditMerkleCheckpoint, error) {
	cp := &AuditMerkleCheckpoint{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, first_log_id, last_log_id, log_count,
		       merkle_root, prev_root, chain_hash, signature, kid, created_at
		FROM audit_merkle_checkpoints
		WHERE org_id = $1
		ORDER BY id DESC LIMIT 1`, orgID,
	).Scan(&cp.ID, &cp.OrgID, &cp.FirstLogID, &cp.LastLogID, &cp.LogCount,
		&cp.MerkleRoot, &cp.PrevRoot, &cp.ChainHash, &cp.Signature, &cp.KID, &cp.CreatedAt)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return cp, nil
}

// ListCheckpoints returns all checkpoints for an org in ascending order.
func (r *AuditRepository) ListCheckpoints(ctx context.Context, orgID uuid.UUID, limit int) ([]*AuditMerkleCheckpoint, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, first_log_id, last_log_id, log_count,
		       merkle_root, prev_root, chain_hash, signature, kid, created_at
		FROM audit_merkle_checkpoints
		WHERE org_id = $1
		ORDER BY id ASC
		LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditMerkleCheckpoint
	for rows.Next() {
		cp := &AuditMerkleCheckpoint{}
		if err := rows.Scan(&cp.ID, &cp.OrgID, &cp.FirstLogID, &cp.LastLogID, &cp.LogCount,
			&cp.MerkleRoot, &cp.PrevRoot, &cp.ChainHash, &cp.Signature, &cp.KID, &cp.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, rows.Err()
}

// OrgSlug returns the slug of an organization by its UUID.
// Used to construct JWKS URIs in public proof bundles.
func (r *AuditRepository) OrgSlug(ctx context.Context, orgID uuid.UUID) (string, error) {
	var slug string
	err := r.pool.QueryRow(ctx, `SELECT slug FROM organizations WHERE id = $1`, orgID).Scan(&slug)
	return slug, err
}

// OrgIDFromSlug returns the UUID of an organization by its slug.
// Used by the public slug-based proof endpoint so auditors can use the
// human-readable org slug instead of the internal UUID.
func (r *AuditRepository) OrgIDFromSlug(ctx context.Context, slug string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `SELECT id FROM organizations WHERE slug = $1`, slug).Scan(&id)
	return id, err
}

// UnsealedAuditRows returns up to limit audit rows with id > afterID for an org,
// along with the canonical JSON needed to recompute leaf hashes.
func (r *AuditRepository) UnsealedAuditRows(ctx context.Context, orgID uuid.UUID, afterID int64, limit int) ([]*AuditMerkleCheckpoint, [][]byte, []int64, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,
		       COALESCE(event_id,''), org_id::text,
		       COALESCE(action,''), COALESCE(status,'success'),
		       created_at::text
		FROM audit.audit_logs
		WHERE org_id = $1 AND id > $2
		ORDER BY id ASC
		LIMIT $3`, orgID, afterID, limit)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()

	var (
		jsons [][]byte
		ids   []int64
	)
	for rows.Next() {
		var id int64
		var eventID, orgIDStr, action, status, createdAt string
		if err := rows.Scan(&id, &eventID, &orgIDStr, &action, &status, &createdAt); err != nil {
			return nil, nil, nil, err
		}
		j, err := json.Marshal(map[string]interface{}{
			"id":         id,
			"event_id":   eventID,
			"org_id":     orgIDStr,
			"action":     action,
			"status":     status,
			"created_at": createdAt,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		jsons = append(jsons, j)
		ids = append(ids, id)
	}
	return nil, jsons, ids, rows.Err()
}

// DistinctOrgIDsWithAuditLogs returns every org_id that has at least one row
// in audit.audit_logs. Used by the Merkle sealer to discover orgs dynamically.
func (r *AuditRepository) DistinctOrgIDsWithAuditLogs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, `SELECT DISTINCT org_id FROM audit.audit_logs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// CountUnsealedRows counts audit rows not yet covered by any checkpoint.
func (r *AuditRepository) CountUnsealedRows(ctx context.Context, orgID uuid.UUID, afterID int64) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit.audit_logs WHERE org_id = $1 AND id > $2`, orgID, afterID,
	).Scan(&count)
	return count, err
}

// SignedExportRow pairs a full AuditEvent with the exact canonical JSON bytes
// used to compute its Merkle leaf hash. Both are needed for the signed export.
type SignedExportRow struct {
	Event    *AuditEvent `json:"event"`
	LeafJSON string      `json:"_leaf"` // exact bytes fed to SHA-256 for Merkle leaf
}

// ExportAllAscSigned streams all audit events for an org in ascending id order.
// For each row it also provides the canonical leaf JSON (same byte string used
// by the Merkle sealer) so offline auditors can recompute the Merkle tree.
func (r *AuditRepository) ExportAllAscSigned(
	ctx context.Context,
	orgID uuid.UUID,
	emit func(row *SignedExportRow) error,
) error {
	var lastID int64
	for {
		rows, err := r.pool.Query(ctx, `
                        SELECT id, event_id, spec_version,
                               COALESCE(event_source,''), COALESCE(event_type,''), COALESCE(subject,''),
                               org_id, user_id, actor_email, action, resource_type, resource_id,
                               status, ip_address::text, user_agent, country_code, session_id, request_id,
                               metadata, created_at,
                               COALESCE(event_id,'')      AS leaf_event_id,
                               org_id::text               AS leaf_org_id,
                               COALESCE(action,'')        AS leaf_action,
                               COALESCE(status,'success') AS leaf_status,
                               created_at::text           AS leaf_created_at
                        FROM audit.audit_logs
                        WHERE org_id = $1 AND id > $2
                        ORDER BY id ASC
                        LIMIT 500`, orgID, lastID)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			e := &AuditEvent{}
			var metaRaw []byte
			var leafEventID, leafOrgID, leafAction, leafStatus, leafCreatedAt string
			if err := rows.Scan(
				&e.ID, &e.EventID, &e.SpecVersion, &e.Source, &e.Type, &e.Subject,
				&e.OrgID, &e.ActorID, &e.ActorEmail, &e.Action, &e.ResourceType, &e.ResourceID,
				&e.Status, &e.IPAddress, &e.UserAgent, &e.CountryCode, &e.SessionID, &e.RequestID,
				&metaRaw, &e.Time,
				&leafEventID, &leafOrgID, &leafAction, &leafStatus, &leafCreatedAt,
			); err != nil {
				rows.Close()
				return err
			}
			if len(metaRaw) > 0 {
				_ = json.Unmarshal(metaRaw, &e.Metadata)
			}
			leafJSON, err := json.Marshal(map[string]interface{}{
				"id":         e.ID,
				"event_id":   leafEventID,
				"org_id":     leafOrgID,
				"action":     leafAction,
				"status":     leafStatus,
				"created_at": leafCreatedAt,
			})
			if err != nil {
				rows.Close()
				return err
			}
			if err := emit(&SignedExportRow{Event: e, LeafJSON: string(leafJSON)}); err != nil {
				rows.Close()
				return err
			}
			lastID = e.ID
			count++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if count < 500 {
			break
		}
	}
	return nil
}

// ListAllCheckpoints returns every Merkle checkpoint for an org in ascending order.
func (r *AuditRepository) ListAllCheckpoints(ctx context.Context, orgID uuid.UUID) ([]*AuditMerkleCheckpoint, error) {
	rows, err := r.pool.Query(ctx, `
                SELECT id, org_id, first_log_id, last_log_id, log_count,
                       merkle_root, prev_root, chain_hash, signature, kid, created_at
                FROM audit_merkle_checkpoints
                WHERE org_id = $1
                ORDER BY id ASC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditMerkleCheckpoint
	for rows.Next() {
		cp := &AuditMerkleCheckpoint{}
		if err := rows.Scan(
			&cp.ID, &cp.OrgID, &cp.FirstLogID, &cp.LastLogID, &cp.LogCount,
			&cp.MerkleRoot, &cp.PrevRoot, &cp.ChainHash, &cp.Signature, &cp.KID, &cp.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, rows.Err()
}

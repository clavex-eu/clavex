package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/mds3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MDSEntry is the DB model for a single FIDO MDS3 authenticator entry.
type MDSEntry struct {
	AAGUID             string          `json:"aaguid"              db:"aaguid"`
	Description        string          `json:"description"         db:"description"`
	CertificationLevel *string         `json:"certification_level" db:"certification_level"`
	CertificateNumber  *string         `json:"certificate_number"  db:"certificate_number"`
	CertifiedAt        *string         `json:"certified_at"        db:"certified_at"`
	StatusReports      []string        `json:"status_reports"      db:"status_reports"`
	MetadataStatement  json.RawMessage `json:"metadata_statement,omitempty" db:"metadata_statement"`
	RootCertificates   []string        `json:"root_certificates"   db:"root_certificates"`
	AuthenticatorType  string          `json:"authenticator_type"  db:"authenticator_type"`
	EffectiveDate      *string         `json:"effective_date,omitempty" db:"effective_date"`
	RefreshedAt        time.Time       `json:"refreshed_at"        db:"refreshed_at"`
	MDSEntryNumber     int64           `json:"mds_entry_number"    db:"mds_entry_number"`
}

// MDSSyncStatus is the singleton row from fido_mds_sync.
type MDSSyncStatus struct {
	LastSyncedAt     *time.Time `json:"last_synced_at"`
	EntryCount       int        `json:"entry_count"`
	LastNo           int64      `json:"last_no"`
	HTTPETag         *string    `json:"http_etag,omitempty"`
	HTTPLastModified *string    `json:"http_last_modified,omitempty"`
	LastError        *string    `json:"last_error,omitempty"`
	TokenExpiresAt   *time.Time `json:"token_expires_at,omitempty"`
}

// MDSListFilter controls how ListMDSEntries filters results.
type MDSListFilter struct {
	// MinCertLevel filters to entries at or above this certification level.
	// Valid values: "L1", "L1+", "L1p", "L2", "L2+", "L3", "L3+". Empty = no filter.
	MinCertLevel string
	// ExcludeRevoked excludes entries with status_reports containing "REVOKED".
	ExcludeRevoked bool
	// AAGUIDs filters to specific AAGUIDs (for lookup by policy engine).
	AAGUIDs []string
	// Search filters description by substring (case-insensitive).
	Search string
	// Limit/Offset for pagination.
	Limit  int
	Offset int
}

// MDSRepository manages FIDO MDS3 entries and sync state.
type MDSRepository struct {
	pool *pgxpool.Pool
}

func NewMDSRepository(pool *pgxpool.Pool) *MDSRepository {
	return &MDSRepository{pool: pool}
}

// ── Sync status ────────────────────────────────────────────────────────────────

// GetSyncStatus returns the current MDS sync state (ETag, last sync time, etc.).
func (r *MDSRepository) GetSyncStatus(ctx context.Context) (*MDSSyncStatus, error) {
	s := &MDSSyncStatus{}
	err := r.pool.QueryRow(ctx, `
		SELECT last_synced_at, entry_count, last_no,
		       http_etag, http_last_modified, last_error, token_expires_at
		FROM fido_mds_sync WHERE id = 1
	`).Scan(
		&s.LastSyncedAt, &s.EntryCount, &s.LastNo,
		&s.HTTPETag, &s.HTTPLastModified, &s.LastError, &s.TokenExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &MDSSyncStatus{}, nil
		}
		return nil, fmt.Errorf("mds repo: get sync status: %w", err)
	}
	return s, nil
}

// UpdateSyncSuccess records a successful MDS3 sync.
func (r *MDSRepository) UpdateSyncSuccess(ctx context.Context, entryCount int, no int64, meta *mds3.SyncMeta) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx, `
		INSERT INTO fido_mds_sync (id, last_synced_at, entry_count, last_no,
		    http_etag, http_last_modified, last_error, token_expires_at)
		VALUES (1, $1, $2, $3, $4, $5, NULL, $6)
		ON CONFLICT (id) DO UPDATE SET
		    last_synced_at    = $1,
		    entry_count       = $2,
		    last_no           = $3,
		    http_etag         = $4,
		    http_last_modified = $5,
		    last_error        = NULL,
		    token_expires_at  = $6
	`, now, entryCount, no,
		nilIfEmpty(meta.HTTPETag), nilIfEmpty(meta.HTTPLastModified),
		meta.TokenExpiresAt,
	)
	return err
}

// UpdateSyncError records a failed MDS3 sync attempt.
func (r *MDSRepository) UpdateSyncError(ctx context.Context, errMsg string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO fido_mds_sync (id, last_error)
		VALUES (1, $1)
		ON CONFLICT (id) DO UPDATE SET last_error = $1
	`, errMsg)
	return err
}

// ── Entry upsert ───────────────────────────────────────────────────────────────

// UpsertEntries bulk-upserts a slice of parsed MDS3 entries.
// Entries not in the new blob (stale) are left untouched — the worker
// compares the blob sequence number and can prune if needed.
func (r *MDSRepository) UpsertEntries(ctx context.Context, entries []mds3.Entry) error {
	now := time.Now()
	for i := range entries {
		e := &entries[i]
		if e.AAGUID == "" {
			continue // skip entries without AAGUID (e.g. U2F devices)
		}
		statusJSON, err := json.Marshal(mds3.StatusReportStrings(e.StatusReports))
		if err != nil {
			return fmt.Errorf("mds repo: marshal status reports for %s: %w", e.AAGUID, err)
		}

		var msJSON json.RawMessage
		if len(e.MetadataStatement) > 0 {
			msJSON = e.MetadataStatement
		}

		certLevel := nilIfEmpty(e.CertificationLevel)
		certNumber := nilIfEmpty(e.CertificateNumber)
		certAt := nilIfEmpty(e.CertifiedAt)
		effectiveDate := nilIfEmpty(e.TimeOfLastStatusChange)

		// pgx v5 encodes a nil []string as SQL NULL, which violates the NOT NULL
		// constraint on root_certificates. Normalise to an empty slice instead.
		rootCerts := e.RootCertificates
		if rootCerts == nil {
			rootCerts = []string{}
		}

		_, err = r.pool.Exec(ctx, `
			INSERT INTO fido_mds_entries (
			    aaguid, description, certification_level, certificate_number,
			    certified_at, status_reports, metadata_statement, root_certificates,
			    authenticator_type, effective_date, refreshed_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (aaguid) DO UPDATE SET
			    description         = EXCLUDED.description,
			    certification_level = EXCLUDED.certification_level,
			    certificate_number  = EXCLUDED.certificate_number,
			    certified_at        = EXCLUDED.certified_at,
			    status_reports      = EXCLUDED.status_reports,
			    metadata_statement  = EXCLUDED.metadata_statement,
			    root_certificates   = EXCLUDED.root_certificates,
			    authenticator_type  = EXCLUDED.authenticator_type,
			    effective_date      = EXCLUDED.effective_date,
			    refreshed_at        = EXCLUDED.refreshed_at
		`, e.AAGUID, e.Description, certLevel, certNumber,
			certAt, statusJSON, msJSON, rootCerts,
			e.AuthenticatorType, effectiveDate, now,
		)
		if err != nil {
			return fmt.Errorf("mds repo: upsert %s: %w", e.AAGUID, err)
		}
	}
	return nil
}

// ── Queries ────────────────────────────────────────────────────────────────────

// GetByAAGUID looks up a single entry by AAGUID.
// Returns nil, nil if not found.
func (r *MDSRepository) GetByAAGUID(ctx context.Context, aaguid string) (*MDSEntry, error) {
	e := &MDSEntry{}
	err := r.pool.QueryRow(ctx, `
		SELECT aaguid, description, certification_level, certificate_number,
		       certified_at, status_reports, metadata_statement, root_certificates,
		       authenticator_type, effective_date, refreshed_at, mds_entry_number
		FROM fido_mds_entries WHERE aaguid = $1
	`, strings.ToLower(aaguid)).Scan(
		&e.AAGUID, &e.Description, &e.CertificationLevel, &e.CertificateNumber,
		&e.CertifiedAt, &e.StatusReports, &e.MetadataStatement, &e.RootCertificates,
		&e.AuthenticatorType, &e.EffectiveDate, &e.RefreshedAt, &e.MDSEntryNumber,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mds repo: get by aaguid: %w", err)
	}
	return e, nil
}

// GetByAAGUIDs looks up multiple entries by AAGUID in one query.
// Used by the policy engine during passkey enrollment.
func (r *MDSRepository) GetByAAGUIDs(ctx context.Context, aaguids []string) (map[string]*MDSEntry, error) {
	if len(aaguids) == 0 {
		return map[string]*MDSEntry{}, nil
	}
	lower := make([]string, len(aaguids))
	for i, a := range aaguids {
		lower[i] = strings.ToLower(a)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT aaguid, description, certification_level, certificate_number,
		       certified_at, status_reports, metadata_statement, root_certificates,
		       authenticator_type, effective_date, refreshed_at, mds_entry_number
		FROM fido_mds_entries WHERE aaguid = ANY($1)
	`, lower)
	if err != nil {
		return nil, fmt.Errorf("mds repo: get by aaguids: %w", err)
	}
	defer rows.Close()
	out := make(map[string]*MDSEntry, len(aaguids))
	for rows.Next() {
		e := &MDSEntry{}
		if err := rows.Scan(
			&e.AAGUID, &e.Description, &e.CertificationLevel, &e.CertificateNumber,
			&e.CertifiedAt, &e.StatusReports, &e.MetadataStatement, &e.RootCertificates,
			&e.AuthenticatorType, &e.EffectiveDate, &e.RefreshedAt, &e.MDSEntryNumber,
		); err != nil {
			return nil, err
		}
		out[e.AAGUID] = e
	}
	return out, rows.Err()
}

// ListEntries returns a filtered, paginated list of MDS entries for the admin UI.
func (r *MDSRepository) ListEntries(ctx context.Context, f MDSListFilter) ([]*MDSEntry, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}

	where := []string{"1=1"}
	args := []any{}
	idx := 1

	if f.MinCertLevel != "" {
		levelOrder := map[string]int{"L1": 1, "L1p": 2, "L1+": 3, "L2": 4, "L2+": 5, "L3": 6, "L3+": 7}
		minPriority, ok := levelOrder[f.MinCertLevel]
		if ok {
			inClause := []string{}
			for lvl, p := range levelOrder {
				if p >= minPriority {
					args = append(args, lvl)
					inClause = append(inClause, fmt.Sprintf("$%d", idx))
					idx++
				}
			}
			where = append(where, fmt.Sprintf("certification_level IN (%s)", strings.Join(inClause, ",")))
		}
	}
	if f.ExcludeRevoked {
		where = append(where, fmt.Sprintf("NOT (status_reports @> $%d::jsonb)", idx))
		args = append(args, `["REVOKED"]`)
		idx++
	}
	if len(f.AAGUIDs) > 0 {
		lower := make([]string, len(f.AAGUIDs))
		for i, a := range f.AAGUIDs {
			lower[i] = strings.ToLower(a)
		}
		args = append(args, lower)
		where = append(where, fmt.Sprintf("aaguid = ANY($%d)", idx))
		idx++
	}
	if f.Search != "" {
		args = append(args, "%"+strings.ToLower(f.Search)+"%")
		where = append(where, fmt.Sprintf("LOWER(description) LIKE $%d", idx))
		idx++
	}

	whereStr := strings.Join(where, " AND ")

	// Total count.
	var total int
	if err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM fido_mds_entries WHERE "+whereStr, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("mds repo: count: %w", err)
	}

	// Page.
	args = append(args, f.Limit, f.Offset)
	rows, err := r.pool.Query(ctx, fmt.Sprintf(`
		SELECT aaguid, description, certification_level, certificate_number,
		       certified_at, status_reports, metadata_statement, root_certificates,
		       authenticator_type, effective_date, refreshed_at, mds_entry_number
		FROM fido_mds_entries
		WHERE %s
		ORDER BY certification_level DESC NULLS LAST, description ASC
		LIMIT $%d OFFSET $%d
	`, whereStr, idx, idx+1), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("mds repo: list: %w", err)
	}
	defer rows.Close()

	var out []*MDSEntry
	for rows.Next() {
		e := &MDSEntry{}
		if err := rows.Scan(
			&e.AAGUID, &e.Description, &e.CertificationLevel, &e.CertificateNumber,
			&e.CertifiedAt, &e.StatusReports, &e.MetadataStatement, &e.RootCertificates,
			&e.AuthenticatorType, &e.EffectiveDate, &e.RefreshedAt, &e.MDSEntryNumber,
		); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// ── Helpers ────────────────────────────────────────────────────────────────────

// QueryEligibleAAGUIDs returns summary info for all MDS3 entries whose
// certification level is >= minCertLevel and (if excludeRevoked) have no
// "REVOKED" status report. This implements the explicit policy preview query:
//
//	SELECT aaguid, description, certification_level, authenticator_type
//	FROM fido_mds_entries
//	WHERE certification_level IN ($levels...) [AND NOT status_reports @> '["REVOKED"]']
//	ORDER BY certification_level DESC, description ASC
//
// Used by the attestation policy preview endpoint to show admins how many
// devices would qualify under their configured certification level rule.
func (r *MDSRepository) QueryEligibleAAGUIDs(
	ctx context.Context,
	minCertLevel string,
	excludeRevoked bool,
) ([]*MDSEntry, error) {
	levelOrder := map[string]int{"L1": 1, "L1p": 2, "L1+": 3, "L2": 4, "L2+": 5, "L3": 6, "L3+": 7}
	minPriority, ok := levelOrder[minCertLevel]
	if !ok || minCertLevel == "" {
		// No level filter — return all non-revoked (or all) entries.
		minPriority = 0
	}

	// Build the IN-clause for qualifying levels.
	var where []string
	var args []any
	idx := 1

	if minPriority > 0 {
		var inClauses []string
		for lvl, p := range levelOrder {
			if p >= minPriority {
				args = append(args, lvl)
				inClauses = append(inClauses, fmt.Sprintf("$%d", idx))
				idx++
			}
		}
		where = append(where, fmt.Sprintf("certification_level IN (%s)", strings.Join(inClauses, ",")))
	}
	if excludeRevoked {
		where = append(where, fmt.Sprintf("NOT (status_reports @> $%d::jsonb)", idx))
		args = append(args, `["REVOKED"]`)
	}

	whereStr := "1=1"
	if len(where) > 0 {
		whereStr = strings.Join(where, " AND ")
	}

	rows, err := r.pool.Query(ctx, fmt.Sprintf(`
		SELECT aaguid, description, certification_level, certificate_number,
		       certified_at, status_reports, metadata_statement, root_certificates,
		       authenticator_type, effective_date, refreshed_at, mds_entry_number
		FROM fido_mds_entries
		WHERE %s
		ORDER BY
		    CASE certification_level
		        WHEN 'L3+' THEN 7 WHEN 'L3' THEN 6 WHEN 'L2+' THEN 5
		        WHEN 'L2'  THEN 4 WHEN 'L1+' THEN 3 WHEN 'L1p' THEN 2
		        WHEN 'L1'  THEN 1 ELSE 0 END DESC,
		    description ASC
	`, whereStr), args...)
	if err != nil {
		return nil, fmt.Errorf("mds repo: query eligible aaguids: %w", err)
	}
	defer rows.Close()

	var out []*MDSEntry
	for rows.Next() {
		e := &MDSEntry{}
		if err := rows.Scan(
			&e.AAGUID, &e.Description, &e.CertificationLevel, &e.CertificateNumber,
			&e.CertifiedAt, &e.StatusReports, &e.MetadataStatement, &e.RootCertificates,
			&e.AuthenticatorType, &e.EffectiveDate, &e.RefreshedAt, &e.MDSEntryNumber,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// NonCompliantCredential describes a WebAuthn credential that violates the
// org's current attestation policy after an MDS3 refresh.
type NonCompliantCredential struct {
	OrgID        uuid.UUID
	OrgSlug      string
	UserID       uuid.UUID
	CredentialID uuid.UUID
	AAGUID       string
	// Reason is a short machine-readable description:
	//   "revoked"                   — device was REVOKED in MDS3
	//   "below_min_cert_level:L2"  — device cert level is below the policy minimum
	//   "not_in_mds"               — device not found in MDS3 (require_mds_certification)
	Reason string
}

// certLevelSQL returns an inline SQL CASE expression that converts a
// certification_level TEXT column to a comparable integer priority.
func certLevelSQL(col string) string {
	return fmt.Sprintf(`CASE %s
		WHEN 'L3+' THEN 7 WHEN 'L3' THEN 6
		WHEN 'L2+' THEN 5 WHEN 'L2'  THEN 4
		WHEN 'L1+' THEN 3 WHEN 'L1p' THEN 2
		WHEN 'L1'  THEN 1 ELSE 0 END`, col)
}

// FindNonCompliantCredentials returns every WebAuthn credential (across all orgs)
// whose authenticator now violates the org's attestation policy.
//
// Called by the MDS3 post-refresh policy enforcer after a catalog update so
// that sessions for affected users can be revoked automatically and CAEP
// credential-change SETs dispatched to registered resource servers.
//
// The query is intentionally a single cross-join so the work is done in the DB,
// not in application memory.
func (r *MDSRepository) FindNonCompliantCredentials(ctx context.Context) ([]*NonCompliantCredential, error) {
	rows, err := r.pool.Query(ctx, `
		WITH policies AS (
		    SELECT
		        wap.org_id,
		        o.slug                           AS org_slug,
		        wap.require_mds_certification,
		        wap.min_certification_level,
		        wap.exclude_revoked_authenticators
		    FROM webauthn_attestation_policies wap
		    JOIN organizations o ON o.id = wap.org_id
		    WHERE wap.enabled = TRUE
		      AND (
		              wap.require_mds_certification = TRUE
		          OR  wap.min_certification_level IS NOT NULL
		          OR  wap.exclude_revoked_authenticators = TRUE
		          )
		),
		webauthn_creds AS (
		    SELECT
		        mc.id                     AS cred_id,
		        mc.user_id,
		        u.org_id,
		        mc.data->>'aaguid'        AS aaguid
		    FROM mfa_credentials mc
		    JOIN users u ON u.id = mc.user_id
		    WHERE mc.type = 'webauthn'
		      AND mc.data ? 'aaguid'
		      AND mc.data->>'aaguid' <> ''
		)
		SELECT
		    p.org_id,
		    p.org_slug,
		    wc.user_id,
		    wc.cred_id,
		    wc.aaguid,
		    CASE
		        WHEN p.exclude_revoked_authenticators
		             AND me.status_reports @> '["REVOKED"]'::jsonb
		             THEN 'revoked'
		        WHEN p.min_certification_level IS NOT NULL
		             AND (
		                 me.aaguid IS NULL
		                 OR me.certification_level IS NULL
		                 OR `+certLevelSQL("me.certification_level")+` < `+certLevelSQL("p.min_certification_level")+`
		             )
		             THEN 'below_min_cert_level:' || COALESCE(p.min_certification_level, '')
		        WHEN p.require_mds_certification AND me.aaguid IS NULL THEN 'not_in_mds'
		        ELSE NULL
		    END AS reason
		FROM policies p
		JOIN webauthn_creds wc ON wc.org_id = p.org_id
		LEFT JOIN fido_mds_entries me ON me.aaguid = wc.aaguid
		WHERE (
		       (p.exclude_revoked_authenticators AND me.status_reports @> '["REVOKED"]'::jsonb)
		    OR (p.min_certification_level IS NOT NULL AND (
		            me.aaguid IS NULL
		            OR me.certification_level IS NULL
		            OR `+certLevelSQL("me.certification_level")+` < `+certLevelSQL("p.min_certification_level")+`
		        ))
		    OR (p.require_mds_certification AND me.aaguid IS NULL)
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("mds repo: find non-compliant credentials: %w", err)
	}
	defer rows.Close()

	var out []*NonCompliantCredential
	for rows.Next() {
		nc := &NonCompliantCredential{}
		var reason *string
		if err := rows.Scan(
			&nc.OrgID, &nc.OrgSlug, &nc.UserID, &nc.CredentialID, &nc.AAGUID, &reason,
		); err != nil {
			return nil, err
		}
		if reason != nil {
			nc.Reason = *reason
		}
		out = append(out, nc)
	}
	return out, rows.Err()
}

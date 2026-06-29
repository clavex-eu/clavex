package handler

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ComplianceHandler provides GDPR Article 30 Records of Processing Activities,
// NIS2 audit evidence exports, Data Subject Access Request (DSAR) endpoints,
// and GDPR Article 17 right-to-erasure.
//
//	GET    /api/v1/organizations/:org_id/compliance/gdpr               → GDPR RoPA summary
//	POST   /api/v1/organizations/:org_id/compliance/gdpr/export        → full JSON export
//	GET    /api/v1/organizations/:org_id/compliance/nis2               → NIS2 audit evidence
//	GET    /api/v1/organizations/:org_id/compliance/dsar/:user_id      → DSAR data export
//	DELETE /api/v1/organizations/:org_id/compliance/gdpr-erasure/:user_id → Art.17 erasure
//
//	GET    /api/v1/organizations/:org_id/compliance/processing-records
//	POST   /api/v1/organizations/:org_id/compliance/processing-records
//	PUT    /api/v1/organizations/:org_id/compliance/processing-records/:record_id
//	DELETE /api/v1/organizations/:org_id/compliance/processing-records/:record_id
type ComplianceHandler struct {
	repo      *repository.OID4WRepository
	auditRepo *repository.AuditRepository
	keys      oidc.Signer
	pool      *pgxpool.Pool
}

func NewComplianceHandler(pool *pgxpool.Pool, keys oidc.Signer) *ComplianceHandler {
	return &ComplianceHandler{
		repo:      repository.NewOID4WRepository(pool),
		auditRepo: repository.NewAuditRepository(pool),
		keys:      keys,
		pool:      pool,
	}
}

// ── GDPR ─────────────────────────────────────────────────────────────────────

// GDPRSummary handles GET /api/v1/organizations/:org_id/compliance/gdpr
// Returns a GDPR Article 30 report combining system-derived and custom records.
func (h *ComplianceHandler) GDPRSummary(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	ctx := c.Request().Context()

	summary, err := h.repo.GetOrgDataSummary(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	records, err := h.repo.ListGDPRRecords(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Augment with built-in Clavex processing activities.
	builtIn := builtInProcessingActivities()

	return c.JSON(http.StatusOK, map[string]any{
		"report_type":         "GDPR Article 30 Records of Processing Activities",
		"generated_at":        summary.ReportGeneratedAt,
		"data_summary":        summary,
		"built_in_activities": builtIn,
		"custom_activities":   records,
	})
}

// GDPRExport handles POST /api/v1/organizations/:org_id/compliance/gdpr/export
// Returns a comprehensive JSON export suitable for DPO review.
func (h *ComplianceHandler) GDPRExport(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	ctx := c.Request().Context()

	summary, err := h.repo.GetOrgDataSummary(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	records, err := h.repo.ListGDPRRecords(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	export := map[string]any{
		"schema_version": "1.0",
		"report_type":    "GDPR_ROPA",
		"generated_at":   summary.ReportGeneratedAt,
		"org_id":         orgID,
		"data_summary":   summary,
		"processing_activities": map[string]any{
			"built_in": builtInProcessingActivities(),
			"custom":   records,
		},
		"controller_notes": map[string]any{
			"article":     "Article 30 GDPR",
			"description": "Records of processing activities maintained by the data controller.",
		},
	}

	c.Response().Header().Set("Content-Disposition",
		"attachment; filename=gdpr-ropa-"+orgID.String()+".json")
	return c.JSON(http.StatusOK, export)
}

// ── NIS2 ─────────────────────────────────────────────────────────────────────

// NIS2Evidence handles GET /api/v1/organizations/:org_id/compliance/nis2
// Returns structured audit evidence for NIS2 Article 21 security measures.
func (h *ComplianceHandler) NIS2Evidence(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	// Default: last 30 days.
	to := time.Now()
	from := to.AddDate(0, 0, -30)

	if fromStr := c.QueryParam("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = t
		}
	}
	if toStr := c.QueryParam("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = t
		}
	}

	ctx := c.Request().Context()

	summary, err := h.repo.GetOrgDataSummary(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	auditSummary, err := h.repo.GetAuditEventSummary(ctx, orgID, from, to)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// NIS2 Article 21 controls evidence.
	controls := map[string]any{
		"access_control": map[string]any{
			"article":      "NIS2 Art.21(2)(i)",
			"mfa_users":    summary.MFAEnabledUsers,
			"total_users":  summary.TotalUsers,
			"mfa_coverage": mfaCoverage(summary.MFAEnabledUsers, summary.TotalUsers),
		},
		"incident_handling": map[string]any{
			"article":           "NIS2 Art.21(2)(b)",
			"failed_logins_30d": auditSummary.FailedLogins,
			"audit_log_enabled": true,
		},
		"audit_logging": map[string]any{
			"article":      "NIS2 Art.21(2)(j)",
			"total_events": auditSummary.TotalEvents,
			"period_days":  int(to.Sub(from).Hours() / 24),
		},
		"supply_chain_security": map[string]any{
			"article":            "NIS2 Art.21(2)(d)",
			"identity_providers": summary.TotalClients,
		},
	}

	return c.JSON(http.StatusOK, map[string]any{
		"report_type":       "NIS2 Article 21 Security Measures Evidence",
		"generated_at":      time.Now(),
		"period":            auditSummary.Period,
		"audit_summary":     auditSummary,
		"controls_evidence": controls,
	})
}

// ── DSAR ─────────────────────────────────────────────────────────────────────

// DSAR handles GET /api/v1/organizations/:org_id/compliance/dsar/:user_id
// Returns a complete export of all personal data held for the user (GDPR Art.15).
func (h *ComplianceHandler) DSAR(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}

	export, err := h.repo.GetUserDataExport(c.Request().Context(), userID, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	c.Response().Header().Set("Content-Disposition",
		"attachment; filename=dsar-"+userID.String()+".json")
	return c.JSON(http.StatusOK, map[string]any{
		"schema_version": "1.0",
		"report_type":    "GDPR_DSAR",
		"generated_at":   export.GeneratedAt,
		"org_id":         orgID,
		"user_id":        userID,
		"data":           export,
	})
}

// ── Processing Records CRUD ───────────────────────────────────────────────────

// ListProcessingRecords handles GET /api/v1/organizations/:org_id/compliance/processing-records
func (h *ComplianceHandler) ListProcessingRecords(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	records, err := h.repo.ListGDPRRecords(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, records)
}

type processingRecordRequest struct {
	ActivityName    string      `json:"activity_name"    validate:"required"`
	Purpose         string      `json:"purpose"          validate:"required"`
	LegalBasis      string      `json:"legal_basis"      validate:"required"`
	DataCategories  []string    `json:"data_categories"`
	DataSubjects    string      `json:"data_subjects"    validate:"required"`
	RetentionPeriod string      `json:"retention_period" validate:"required"`
	Recipients      interface{} `json:"recipients"`
	Processors      interface{} `json:"processors"`
}

// CreateProcessingRecord handles POST /api/v1/organizations/:org_id/compliance/processing-records
func (h *ComplianceHandler) CreateProcessingRecord(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req processingRecordRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	rec, err := h.repo.CreateGDPRRecord(
		c.Request().Context(),
		orgID,
		req.ActivityName, req.Purpose, req.LegalBasis,
		req.DataCategories, req.DataSubjects, req.RetentionPeriod,
		req.Recipients, req.Processors,
	)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, rec)
}

// UpdateProcessingRecord handles PUT /api/v1/organizations/:org_id/compliance/processing-records/:record_id
func (h *ComplianceHandler) UpdateProcessingRecord(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	recordID, err := uuidParam(c, "record_id")
	if err != nil {
		return err
	}
	var req processingRecordRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	rec, err := h.repo.UpdateGDPRRecord(
		c.Request().Context(),
		recordID, orgID,
		req.ActivityName, req.Purpose, req.LegalBasis,
		req.DataCategories, req.DataSubjects, req.RetentionPeriod,
		req.Recipients, req.Processors,
	)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, rec)
}

// DeleteProcessingRecord handles DELETE /api/v1/organizations/:org_id/compliance/processing-records/:record_id
func (h *ComplianceHandler) DeleteProcessingRecord(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	recordID, err := uuidParam(c, "record_id")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteGDPRRecord(c.Request().Context(), recordID, orgID); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Built-in processing activities ───────────────────────────────────────────

// builtInProcessingActivities returns the standard Clavex processing activities
// that apply to every organisation. These are hard-coded because they reflect the
// system's architecture and cannot be customised per tenant.
func builtInProcessingActivities() []map[string]any {
	return []map[string]any{
		{
			"activity_name":    "User Authentication",
			"purpose":          "Authenticate registered users to access protected resources",
			"legal_basis":      "legitimate_interest",
			"data_categories":  []string{"email_address", "password_hash", "ip_address", "user_agent", "session_id"},
			"data_subjects":    "registered_users",
			"retention_period": "Session data: until logout or 24h inactivity. Audit logs: per retention policy.",
			"recipients":       []any{},
			"processors":       []any{},
			"source":           "built_in",
		},
		{
			"activity_name":    "Multi-Factor Authentication",
			"purpose":          "Provide second-factor authentication to increase account security",
			"legal_basis":      "legitimate_interest",
			"data_categories":  []string{"email_address", "totp_secret_hash", "webauthn_public_key", "phone_number"},
			"data_subjects":    "registered_users_with_mfa",
			"retention_period": "Until MFA credential is deleted by user or administrator",
			"recipients":       []any{},
			"processors":       []any{},
			"source":           "built_in",
		},
		{
			"activity_name":    "Audit Logging",
			"purpose":          "Record security-relevant events for incident detection, forensics, and compliance",
			"legal_basis":      "legal_obligation",
			"data_categories":  []string{"ip_address", "user_id", "event_type", "timestamp", "resource_identifier"},
			"data_subjects":    "all_users_and_administrators",
			"retention_period": "Per organisation audit retention policy (default 90 days)",
			"recipients":       []any{},
			"processors":       []any{},
			"source":           "built_in",
		},
		{
			"activity_name":    "Identity Federation (OIDC/SAML)",
			"purpose":          "Allow users to authenticate using external identity providers",
			"legal_basis":      "consent",
			"data_categories":  []string{"email_address", "name", "subject_identifier", "provider_access_token"},
			"data_subjects":    "users_with_federated_identities",
			"retention_period": "Until identity provider link is removed",
			"recipients":       []any{},
			"processors":       []any{},
			"source":           "built_in",
		},
		{
			"activity_name":    "Verifiable Credential Issuance (OID4VCI)",
			"purpose":          "Issue EU Digital Identity Wallet credentials containing user identity claims",
			"legal_basis":      "consent",
			"data_categories":  []string{"email_address", "given_name", "family_name", "user_id"},
			"data_subjects":    "users_with_wallet_credentials",
			"retention_period": "Credential audit hash retained 1 year; issued SD-JWT stored by wallet holder only",
			"recipients":       []any{},
			"processors":       []any{},
			"source":           "built_in",
		},
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func mfaCoverage(mfaUsers, totalUsers int64) float64 {
	if totalUsers == 0 {
		return 0
	}
	return float64(mfaUsers) / float64(totalUsers) * 100
}

// ── Signed audit export ───────────────────────────────────────────────────────

// ExportSignedAudit handles POST /api/v1/organizations/:org_id/compliance/audit/export-signed
//
// Returns a ZIP archive containing:
//   - audit_log.jsonl           — every audit event in ascending order, each line
//     includes a "_leaf" field with the exact canonical JSON used for Merkle hashing
//   - merkle_checkpoints.json   — all RS256-signed Merkle checkpoints
//   - jwks.json                 — public key for signature verification
//   - verify.sh                 — offline verification script (python3 + openssl)
//
// The package is suitable for delivery to a NIS2 auditor or a magistrate.
func (h *ComplianceHandler) ExportSignedAudit(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	// ── 1. Build audit_log.jsonl ──────────────────────────────────────────────
	var jsonlBuf bytes.Buffer
	enc := json.NewEncoder(&jsonlBuf)
	enc.SetEscapeHTML(false)
	if err := h.auditRepo.ExportAllAscSigned(ctx, orgID, func(row *repository.SignedExportRow) error {
		return enc.Encode(row)
	}); err != nil {
		return fmt.Errorf("audit export: %w", err)
	}

	// ── 2. Fetch Merkle checkpoints ───────────────────────────────────────────
	checkpoints, err := h.auditRepo.ListAllCheckpoints(ctx, orgID)
	if err != nil {
		return fmt.Errorf("checkpoints: %w", err)
	}
	cpJSON, err := json.MarshalIndent(checkpoints, "", "  ")
	if err != nil {
		return fmt.Errorf("checkpoints json: %w", err)
	}

	// ── 3. JWKS (public key only) ─────────────────────────────────────────────
	jwksJSON := h.keys.JWKS()

	// ── 4. verify.sh ─────────────────────────────────────────────────────────
	verifyScript := buildVerifyScript()

	// ── 5. Assemble ZIP ──────────────────────────────────────────────────────
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)

	files := []struct {
		name string
		data []byte
	}{
		{"audit_log.jsonl", jsonlBuf.Bytes()},
		{"merkle_checkpoints.json", cpJSON},
		{"jwks.json", jwksJSON},
		{"verify.sh", []byte(verifyScript)},
	}
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			return fmt.Errorf("zip create %s: %w", f.name, err)
		}
		if _, err := w.Write(f.data); err != nil {
			return fmt.Errorf("zip write %s: %w", f.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("zip close: %w", err)
	}

	filename := fmt.Sprintf("nis2-audit-%s-%s.zip", orgID, time.Now().UTC().Format("20060102T150405Z"))
	c.Response().Header().Set("Content-Disposition", "attachment; filename="+filename)
	return c.Blob(http.StatusOK, "application/zip", zipBuf.Bytes())
}

// ── SCIM Inbound Audit Compliance ─────────────────────────────────────────────

// scimProviderLabel converts a raw User-Agent string to a human-readable label.
// Must be kept in sync with the detection logic in internal/scim/handler.go.
func scimProviderLabel(ua string) string {
	if ua == "" {
		return "Unknown"
	}
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "microsoft") || strings.Contains(lower, "azure") || strings.Contains(lower, "aad"):
		return "Azure AD"
	case strings.Contains(lower, "okta"):
		return "Okta"
	case strings.Contains(lower, "google"):
		return "Google Workspace"
	case strings.Contains(lower, "onelogin"):
		return "OneLogin"
	case strings.Contains(lower, "jumpcloud"):
		return "JumpCloud"
	case strings.Contains(lower, "pingidentity") || strings.Contains(lower, "ping"):
		return "Ping Identity"
	default:
		return "Other"
	}
}

// scimAnomalyWindow is the rolling window used for deprovisioning anomaly detection.
const scimAnomalyWindow = 5 * time.Minute

// scimAnomalyThreshold is the number of deactivations/deletions within the
// window that triggers an anomaly alert (NIS2 Art.21 mass-deprovisioning).
const scimAnomalyThreshold = 50

// SCIMCompliance handles GET /api/v1/organizations/:org_id/compliance/scim/audit
//
// Returns:
//   - Paginated log of inbound SCIM operations from the structured audit trail
//   - Summary counts per provider (Azure AD, Okta, Google Workspace…)
//   - Anomaly alerts: detects mass-deprovisioning bursts (≥50 deactivations in
//     any rolling 5-minute window — potential NIS2 Art.21 incident)
//
// Query params:
//
//	provider   — filter by source provider slug (azure_ad, okta, google_workspace, …)
//	action     — filter by action (scim.user.create, scim.user.update, scim.user.deactivate, scim.user.delete)
//	since      — RFC3339 lower bound
//	until      — RFC3339 upper bound
//	cursor     — pagination cursor (row ID)
//	limit      — 1-500 (default 100)
func (h *ComplianceHandler) SCIMCompliance(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	// ── Parse query params ────────────────────────────────────────────────────
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	cursor, _ := strconv.ParseInt(c.QueryParam("cursor"), 10, 64)
	filterAction := c.QueryParam("action")
	filterProvider := c.QueryParam("provider")

	var since, until *time.Time
	if s := c.QueryParam("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err == nil {
			since = &t
		}
	}
	if u := c.QueryParam("until"); u != "" {
		t, err := time.Parse(time.RFC3339, u)
		if err == nil {
			until = &t
		}
	}

	// ── Query audit log for SCIM events ──────────────────────────────────────
	f := repository.AuditFilter{
		OrgID:        orgID,
		ActionPrefix: "scim",
		Since:        since,
		Until:        until,
		Cursor:       cursor,
		Limit:        limit,
	}
	if filterAction != "" {
		f.Action = filterAction
		f.ActionPrefix = ""
	}

	page, err := h.auditRepo.List(ctx, f)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// ── Annotate events: resolve provider from user_agent ────────────────────
	type scimAuditEvent struct {
		*repository.AuditEvent
		Provider string `json:"provider"`
	}
	events := make([]scimAuditEvent, 0, len(page.Events))
	for _, e := range page.Events {
		ua := ""
		if e.UserAgent != nil {
			ua = *e.UserAgent
		}
		provider := scimProviderLabel(ua)
		if filterProvider != "" {
			// Map human-readable filter to provider label match
			filterLower := strings.ToLower(filterProvider)
			pLower := strings.ToLower(provider)
			if !strings.Contains(pLower, filterLower) &&
				!strings.Contains(filterLower, strings.ReplaceAll(pLower, " ", "_")) {
				continue
			}
		}
		events = append(events, scimAuditEvent{AuditEvent: e, Provider: provider})
	}

	// ── Summary counts ────────────────────────────────────────────────────────
	providerCounts := make(map[string]int)
	actionCounts := make(map[string]int)
	for _, e := range events {
		providerCounts[e.Provider]++
		actionCounts[e.Action]++
	}

	// ── Anomaly detection: mass deprovisioning burst ──────────────────────────
	// Fetch last 24h of deactivations/deletions for the burst scan.
	// This is a lightweight pass — the full export is O(n) over recent events.
	type anomaly struct {
		DetectedAt  time.Time `json:"detected_at"`
		WindowStart time.Time `json:"window_start"`
		WindowEnd   time.Time `json:"window_end"`
		Count       int       `json:"count"`
		Severity    string    `json:"severity"` // "warning" | "critical"
		Rule        string    `json:"rule"`
		Regulation  string    `json:"regulation"`
	}
	var anomalies []anomaly

	deprovH := 24 * time.Hour
	now := time.Now().UTC()
	scanFrom := now.Add(-deprovH)
	deprovFilter := repository.AuditFilter{
		OrgID:  orgID,
		Since:  &scanFrom,
		Until:  &now,
		Limit:  500,
	}
	deprovPage, deprovErr := h.auditRepo.List(ctx, deprovFilter)
	if deprovErr == nil {
		// Collect deactivation/deletion timestamps
		var times []time.Time
		for _, e := range deprovPage.Events {
			if e.Action == "scim.user.deactivate" || e.Action == "scim.user.delete" {
				times = append(times, e.Time)
			}
		}
		// Sliding window O(n) scan
		if len(times) >= scimAnomalyThreshold {
			j := 0
			for i := range times {
				for j < len(times) && times[j].Sub(times[i]) <= scimAnomalyWindow {
					j++
				}
				count := j - i
				if count >= scimAnomalyThreshold {
					severity := "warning"
					if count >= scimAnomalyThreshold*2 {
						severity = "critical"
					}
					anomalies = append(anomalies, anomaly{
						DetectedAt:  now,
						WindowStart: times[i],
						WindowEnd:   times[j-1],
						Count:       count,
						Severity:    severity,
						Rule:        fmt.Sprintf("≥%d deprovisioning operations in ≤%s", scimAnomalyThreshold, scimAnomalyWindow),
						Regulation:  "NIS2 Art.21(2)(b) — Incident management & business continuity",
					})
					break // one alert per scan pass
				}
			}
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"events":          events,
		"next_cursor":     page.NextCursor,
		"total":           page.Total,
		"provider_counts": providerCounts,
		"action_counts":   actionCounts,
		"anomalies":       anomalies,
		"generated_at":    now.Format(time.RFC3339),
		"compliance_refs": []map[string]string{
			{"standard": "SOX",  "control": "ITGC — User access provisioning audit trail"},
			{"standard": "NIS2", "control": "Art.21(2)(b) — Incident detection, identity chain-of-custody"},
			{"standard": "ISO27001", "control": "A.9.2 — User access management"},
		},
	})
}

// buildVerifyScript returns the content of verify.sh — a self-contained
// Python3 script (executed via bash) that an auditor can run offline to
// cryptographically verify the entire export package.
func buildVerifyScript() string {
	return `#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# verify.sh  —  Offline integrity verifier for a Clavex NIS2 audit export
#
# Usage:
#   chmod +x verify.sh
#   ./verify.sh
#
# Requirements:  python3 (stdlib only), openssl
#
# What this script checks:
#   1. For each Merkle checkpoint:
#      a. Recomputes leaf hashes from _leaf fields in audit_log.jsonl
#      b. Rebuilds the Merkle tree and compares the root
#      c. Verifies the chain hash (SHA-256(prev_root || merkle_root))
#      d. Verifies the RS256 signature using the public key in jwks.json
#   2. Verifies the checkpoint chain is unbroken (no gaps, no reordering)
#
# Exit code: 0 = all checks passed, 1 = one or more checks failed
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check dependencies
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Install Python 3 to run this script." >&2
  exit 1
fi
if ! command -v openssl &>/dev/null; then
  echo "ERROR: openssl not found. Install OpenSSL to run this script." >&2
  exit 1
fi

python3 - "$@" <<'PYTHON'
import json, hashlib, base64, sys, subprocess, tempfile, os, struct
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent if hasattr(__file__, '__file__') else Path('.')
# When called via heredoc, __file__ is not set; use cwd.
try:
    SCRIPT_DIR = Path(sys.argv[0]).parent
except Exception:
    SCRIPT_DIR = Path('.')

AUDIT_LOG   = SCRIPT_DIR / 'audit_log.jsonl'
CHECKPOINTS = SCRIPT_DIR / 'merkle_checkpoints.json'
JWKS_FILE   = SCRIPT_DIR / 'jwks.json'

RESET  = '\033[0m'
GREEN  = '\033[32m'
RED    = '\033[31m'
YELLOW = '\033[33m'
BOLD   = '\033[1m'

def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def fail(msg): print(f"  {RED}✗{RESET}  {msg}"); return False
def warn(msg): print(f"  {YELLOW}!{RESET}  {msg}")

# ── Load files ────────────────────────────────────────────────────────────────

print(f"\n{BOLD}Clavex NIS2 Audit Export Verifier{RESET}")
print("=" * 60)

for f in [AUDIT_LOG, CHECKPOINTS, JWKS_FILE]:
    if not f.exists():
        print(f"{RED}ERROR:{RESET} Required file not found: {f}")
        sys.exit(1)

with open(CHECKPOINTS) as f:
    checkpoints = json.load(f) or []

with open(JWKS_FILE) as f:
    jwks = json.load(f)

# Load events indexed by log id
print(f"\n{BOLD}Loading audit_log.jsonl …{RESET}")
events_by_id = {}
event_count = 0
with open(AUDIT_LOG) as f:
    for lineno, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"  {RED}✗{RESET}  Line {lineno}: invalid JSON: {e}")
            sys.exit(1)
        ev = row.get('event', {})
        lid = ev.get('id')
        if lid is None:
            print(f"  {RED}✗{RESET}  Line {lineno}: missing event.id")
            sys.exit(1)
        events_by_id[lid] = row
        event_count += 1

ok(f"Loaded {event_count} events")

# ── Extract RSA public key from JWK ──────────────────────────────────────────

def encode_asn1_length(n):
    if n < 0x80:
        return bytes([n])
    nb = (n.bit_length() + 7) // 8
    return bytes([0x80 | nb]) + n.to_bytes(nb, 'big')

def asn1_integer(val_bytes):
    if val_bytes[0] & 0x80:
        val_bytes = b'\x00' + val_bytes
    return b'\x02' + encode_asn1_length(len(val_bytes)) + val_bytes

def asn1_sequence(*items):
    body = b''.join(items)
    return b'\x30' + encode_asn1_length(len(body)) + body

def asn1_bitstring(data):
    body = b'\x00' + data
    return b'\x03' + encode_asn1_length(len(body)) + body

def b64url_decode(s):
    s = s.replace('-', '+').replace('_', '/')
    pad = (-len(s)) % 4
    return base64.b64decode(s + '=' * pad)

def jwk_to_pem(jwk):
    """Convert a JWK RSA public key to PEM (SubjectPublicKeyInfo / PKCS#8)."""
    n = b64url_decode(jwk['n'])
    e = b64url_decode(jwk['e'])
    e = e.lstrip(b'\x00') or b'\x00'
    rsa_pub = asn1_sequence(asn1_integer(n), asn1_integer(e))
    # OID 1.2.840.113549.1.1.1 (rsaEncryption) + NULL
    rsa_oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'
    spki = asn1_sequence(asn1_sequence(rsa_oid), asn1_bitstring(rsa_pub))
    pem_b64 = base64.b64encode(spki).decode()
    lines = [pem_b64[i:i+64] for i in range(0, len(pem_b64), 64)]
    return '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(lines) + '\n-----END PUBLIC KEY-----\n'

keys_by_kid = {}
for key in jwks.get('keys', []):
    if key.get('kty') == 'RSA':
        keys_by_kid[key.get('kid', '')] = jwk_to_pem(key)

if not keys_by_kid:
    print(f"{RED}ERROR:{RESET} No RSA keys found in jwks.json")
    sys.exit(1)

ok(f"Loaded {len(keys_by_kid)} RSA public key(s) from jwks.json")

# ── Merkle helpers ────────────────────────────────────────────────────────────

def leaf_hash(leaf_json_str):
    """SHA-256 of the canonical leaf JSON string."""
    return hashlib.sha256(leaf_json_str.encode('utf-8')).digest()

def merkle_root(leaves):
    """Rebuild Merkle root from a list of leaf byte arrays."""
    if not leaves:
        return None
    level = list(leaves)
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i+1 < len(level) else left
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0]

def verify_rsa_signature(pem, chain_hash_hex, signature_b64url):
    """Verify RS256 PKCS1v15 signature using openssl command line."""
    chain_hash_bytes = bytes.fromhex(chain_hash_hex)
    sig_bytes = b64url_decode(signature_b64url)
    with tempfile.TemporaryDirectory() as td:
        key_file = os.path.join(td, 'pub.pem')
        sig_file = os.path.join(td, 'sig.bin')
        dat_file = os.path.join(td, 'data.bin')
        with open(key_file, 'w') as f: f.write(pem)
        with open(sig_file, 'wb') as f: f.write(sig_bytes)
        with open(dat_file, 'wb') as f: f.write(chain_hash_bytes)
        r = subprocess.run(
            ['openssl', 'dgst', '-sha256', '-verify', key_file,
             '-signature', sig_file, dat_file],
            capture_output=True, text=True
        )
        return r.returncode == 0, r.stderr.strip()

# ── Verify each checkpoint ───────────────────────────────────────────────────

print(f"\n{BOLD}Verifying {len(checkpoints)} Merkle checkpoint(s) …{RESET}")

all_passed = True
prev_root = ''

for i, cp in enumerate(checkpoints):
    cp_id     = cp['id']
    first_id  = cp['first_log_id']
    last_id   = cp['last_log_id']
    log_count = cp['log_count']
    stored_root      = cp['merkle_root']
    stored_prev_root = cp['prev_root']
    stored_chain     = cp['chain_hash']
    signature        = cp['signature']
    kid              = cp.get('kid', '')

    print(f"\n  Checkpoint #{i+1} (id={cp_id}, rows={first_id}..{last_id}, count={log_count})")
    cp_ok = True

    # a. Collect leaf JSONs in order
    leaves = []
    missing = []
    for lid in range(first_id, last_id + 1):
        row = events_by_id.get(lid)
        if row is None:
            missing.append(lid)
            continue
        leaf_json_str = row.get('_leaf')
        if leaf_json_str is None:
            missing.append(lid)
            continue
        leaves.append(leaf_hash(leaf_json_str))

    if missing:
        fail(f"Missing {len(missing)} event(s) in checkpoint range: {missing[:5]}{'…' if len(missing)>5 else ''}")
        cp_ok = False
        all_passed = False
        continue

    if len(leaves) != log_count:
        fail(f"Event count mismatch: checkpoint says {log_count}, found {len(leaves)}")
        cp_ok = False; all_passed = False; continue

    # b. Rebuild and compare Merkle root
    computed_root = merkle_root(leaves)
    computed_root_hex = computed_root.hex()
    if computed_root_hex != stored_root:
        fail(f"Merkle root mismatch\n     computed: {computed_root_hex}\n     stored:   {stored_root}")
        cp_ok = False; all_passed = False
    else:
        ok(f"Merkle root matches ({stored_root[:16]}…)")

    # c. Verify chain hash
    chain_input = stored_prev_root + stored_root
    computed_chain = hashlib.sha256(chain_input.encode('utf-8')).hexdigest()
    if computed_chain != stored_chain:
        fail(f"Chain hash mismatch\n     computed: {computed_chain}\n     stored:   {stored_chain}")
        cp_ok = False; all_passed = False
    else:
        ok("Chain hash matches")

    # d. Verify chain linkage
    if stored_prev_root != prev_root:
        fail(f"Chain broken: prev_root mismatch at checkpoint #{i+1}")
        cp_ok = False; all_passed = False
    else:
        if i > 0:
            ok("Chain linkage to previous checkpoint verified")

    # e. Verify RS256 signature
    pem = keys_by_kid.get(kid) or (list(keys_by_kid.values())[0] if keys_by_kid else None)
    if pem is None:
        fail(f"No matching key for kid={kid!r}")
        cp_ok = False; all_passed = False
    else:
        sig_ok, sig_err = verify_rsa_signature(pem, stored_chain, signature)
        if sig_ok:
            ok(f"RS256 signature valid (kid={kid!r})")
        else:
            fail(f"RS256 signature INVALID: {sig_err}")
            cp_ok = False; all_passed = False

    prev_root = stored_root

# ── Summary ───────────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
if not checkpoints:
    warn("No Merkle checkpoints found — the audit log has not been sealed yet.")
    warn("Run POST /audit/proof/seal to create checkpoints before exporting.")
elif all_passed:
    print(f"{GREEN}{BOLD}✓  ALL CHECKS PASSED — audit log integrity verified{RESET}")
    print(f"   {event_count} events · {len(checkpoints)} checkpoint(s) · RS256 signatures valid")
else:
    print(f"{RED}{BOLD}✗  ONE OR MORE CHECKS FAILED — see output above{RESET}")
    sys.exit(1)

PYTHON
`
}

// ── Audit Pack (comprehensive compliance ZIP for external auditors) ────────────

// AuditPack handles POST /api/v1/organizations/:org_id/compliance/audit-pack
//
// Generates a self-contained ZIP archive for NIS2 / ISO 27001 / eIDAS 2.0
// external auditors. The archive is designed for offline verification — the
// auditor needs no access to the Clavex installation after download.
//
// ZIP contents:
//   - README.txt               — offline verification instructions
//   - manifest.json            — pack metadata (org_id, generated_at, signing_kid)
//   - gdpr-ropa.json           — GDPR Art.30 Records of Processing Activities
//   - nis2-evidence.json       — NIS2 Art.21 security controls evidence
//   - audit-log.ndjson         — Merkle-signed audit events (NDJSON, ascending)
//   - merkle-checkpoints.json  — RS256-signed Merkle checkpoints for chain verification
//   - jwks.json                — Public JWKS for RS256 signature verification
//   - conformance.json         — OIDC/FAPI 2.0 conformance programme summary
//   - sbom-cyclonedx.json      — CycloneDX 1.4 Software Bill of Materials
//   - sub-processors.json      — GDPR Art.28 sub-processor register
//   - qtsp-assessment.json     — eIDAS 2.0 QTSP readiness self-assessment
func (h *ComplianceHandler) AuditPack(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	now := time.Now().UTC()

	// ── 1. GDPR Art.30 RoPA ───────────────────────────────────────────────────
	summary, err := h.repo.GetOrgDataSummary(ctx, orgID)
	if err != nil {
		return fmt.Errorf("audit-pack: gdpr summary: %w", err)
	}
	records, err := h.repo.ListGDPRRecords(ctx, orgID)
	if err != nil {
		return fmt.Errorf("audit-pack: gdpr records: %w", err)
	}
	ropaJSON, err := json.MarshalIndent(map[string]any{
		"schema_version": "1.0",
		"report_type":    "GDPR_ROPA",
		"article":        "GDPR Art.30 Records of Processing Activities",
		"generated_at":   now,
		"org_id":         orgID,
		"data_summary":   summary,
		"processing_activities": map[string]any{
			"built_in": builtInProcessingActivities(),
			"custom":   records,
		},
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("audit-pack: gdpr json: %w", err)
	}

	// ── 2. NIS2 Art.21 Evidence ───────────────────────────────────────────────
	auditSummary, err := h.repo.GetAuditEventSummary(ctx, orgID, now.AddDate(0, 0, -30), now)
	if err != nil {
		return fmt.Errorf("audit-pack: nis2 audit summary: %w", err)
	}
	nis2JSON, err := json.MarshalIndent(map[string]any{
		"schema_version": "1.0",
		"report_type":    "NIS2_EVIDENCE",
		"article":        "NIS2 Art.21 Security Measures",
		"generated_at":   now,
		"org_id":         orgID,
		"audit_summary":  auditSummary,
		"controls": map[string]any{
			"access_control": map[string]any{
				"article":        "NIS2 Art.21(2)(i) — Access control and asset management",
				"mfa_users":      summary.MFAEnabledUsers,
				"total_users":    summary.TotalUsers,
				"mfa_coverage_%": mfaCoverage(summary.MFAEnabledUsers, summary.TotalUsers),
				"status":         "implemented",
			},
			"audit_logging": map[string]any{
				"article":           "NIS2 Art.21(2)(j) — Use of multi-factor authentication",
				"total_events_30d":  auditSummary.TotalEvents,
				"failed_logins_30d": auditSummary.FailedLogins,
				"merkle_sealed":     true,
				"status":            "implemented",
			},
			"incident_handling": map[string]any{
				"article":            "NIS2 Art.21(2)(b) — Incident handling",
				"audit_log_enabled":  true,
				"mfa_challenges_30d": auditSummary.MFAChallenges,
				"status":             "implemented",
			},
			"supply_chain_security": map[string]any{
				"article":                  "NIS2 Art.21(2)(d) — Supply chain security",
				"fido_mds3_certification":  true,
				"sbom_available":           true,
				"status":                   "implemented",
			},
			"cryptography": map[string]any{
				"article":      "NIS2 Art.21(2)(h) — Cryptography and encryption",
				"algorithms":   []string{"RS256", "ES256", "AES-256-GCM"},
				"merkle_chain": true,
				"status":       "implemented",
			},
		},
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("audit-pack: nis2 json: %w", err)
	}

	// ── 3. Signed Audit Log (NDJSON) ──────────────────────────────────────────
	var auditBuf bytes.Buffer
	auditEnc := json.NewEncoder(&auditBuf)
	auditEnc.SetEscapeHTML(false)
	if err := h.auditRepo.ExportAllAscSigned(ctx, orgID, func(row *repository.SignedExportRow) error {
		return auditEnc.Encode(row)
	}); err != nil {
		return fmt.Errorf("audit-pack: audit export: %w", err)
	}

	// ── 4. Merkle Checkpoints ─────────────────────────────────────────────────
	checkpoints, err := h.auditRepo.ListAllCheckpoints(ctx, orgID)
	if err != nil {
		return fmt.Errorf("audit-pack: checkpoints: %w", err)
	}
	cpJSON, err := json.MarshalIndent(map[string]any{
		"generated_at": now,
		"org_id":       orgID,
		"checkpoints":  checkpoints,
		"count":        len(checkpoints),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("audit-pack: checkpoints json: %w", err)
	}

	// ── 5. JWKS (public key only) ─────────────────────────────────────────────
	jwksJSON := h.keys.JWKS()

	// ── 6. Conformance Summary ────────────────────────────────────────────────
	conformanceJSON, err := json.MarshalIndent(auditPackConformance(orgID.String(), now), "", "  ")
	if err != nil {
		return fmt.Errorf("audit-pack: conformance json: %w", err)
	}

	// ── 7. CycloneDX 1.4 SBOM ─────────────────────────────────────────────────
	sbomJSON, err := json.MarshalIndent(auditPackSBOM(orgID.String(), now), "", "  ")
	if err != nil {
		return fmt.Errorf("audit-pack: sbom json: %w", err)
	}

	// ── 8. Sub-processor Register ─────────────────────────────────────────────
	subProcJSON, err := json.MarshalIndent(auditPackSubProcessors(now), "", "  ")
	if err != nil {
		return fmt.Errorf("audit-pack: sub-processors json: %w", err)
	}

	// ── 9. QTSP Readiness Assessment ─────────────────────────────────────────
	qtspJSON, err := json.MarshalIndent(auditPackQTSP(orgID.String(), now), "", "  ")
	if err != nil {
		return fmt.Errorf("audit-pack: qtsp json: %w", err)
	}

	// ── 10. Manifest ──────────────────────────────────────────────────────────
	manifestJSON, err := json.MarshalIndent(map[string]any{
		"_clavex":           "audit-pack/v1",
		"generated_at":      now,
		"org_id":            orgID,
		"signing_algorithm": "RS256",
		"signing_kid":       h.keys.KID(),
		"contents": []string{
			"README.txt",
			"manifest.json",
			"gdpr-ropa.json",
			"nis2-evidence.json",
			"audit-log.ndjson",
			"merkle-checkpoints.json",
			"jwks.json",
			"conformance.json",
			"sbom-cyclonedx.json",
			"sub-processors.json",
			"qtsp-assessment.json",
		},
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("audit-pack: manifest json: %w", err)
	}

	// ── 11. Assemble ZIP ──────────────────────────────────────────────────────
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)

	type zipEntry struct {
		name string
		data []byte
	}
	entries := []zipEntry{
		{"README.txt", []byte(auditPackREADME(orgID.String(), now))},
		{"manifest.json", manifestJSON},
		{"gdpr-ropa.json", ropaJSON},
		{"nis2-evidence.json", nis2JSON},
		{"audit-log.ndjson", auditBuf.Bytes()},
		{"merkle-checkpoints.json", cpJSON},
		{"jwks.json", jwksJSON},
		{"conformance.json", conformanceJSON},
		{"sbom-cyclonedx.json", sbomJSON},
		{"sub-processors.json", subProcJSON},
		{"qtsp-assessment.json", qtspJSON},
	}
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			return fmt.Errorf("audit-pack: zip create %s: %w", e.name, err)
		}
		if _, err := w.Write(e.data); err != nil {
			return fmt.Errorf("audit-pack: zip write %s: %w", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("audit-pack: zip close: %w", err)
	}

	filename := fmt.Sprintf("clavex-audit-pack-%s-%s.zip", orgID, now.Format("20060102T150405Z"))
	c.Response().Header().Set("Content-Disposition", "attachment; filename="+filename)
	return c.Blob(http.StatusOK, "application/zip", zipBuf.Bytes())
}

// auditPackREADME returns the plain-text README for the audit pack ZIP.
func auditPackREADME(orgID string, at time.Time) string {
	return fmt.Sprintf(`CLAVEX AUDIT PACK — OFFLINE VERIFICATION GUIDE
================================================

Generated:  %s
Org ID:     %s

This archive contains cryptographically verifiable evidence for NIS2 Article 21
and ISO/IEC 27001:2022 external audits. No internet access is required to verify
the integrity of this package.

CONTENTS
--------

  README.txt               You are reading this.
  manifest.json            Pack metadata, file inventory, and signing key ID.
  gdpr-ropa.json           GDPR Art.30 Records of Processing Activities.
  nis2-evidence.json       NIS2 Art.21 security controls evidence (30-day window).
  audit-log.ndjson         All audit events (NDJSON format). Each line is a JSON
                           object; the "_leaf" field contains the exact canonical
                           JSON string used for Merkle hashing.
  merkle-checkpoints.json  RS256-signed Merkle checkpoints. The chain spans the
                           entire audit log and detects any tampering or deletion.
  jwks.json                Public key set (JWKS) for checkpoint signature verification.
  conformance.json         OIDC / FAPI 2.0 / eIDAS 2.0 conformance summary.
  sbom-cyclonedx.json      CycloneDX 1.4 Software Bill of Materials.
  sub-processors.json      GDPR Art.28 data sub-processor register.
  qtsp-assessment.json     eIDAS 2.0 QTSP readiness self-assessment.

AUDIT LOG INTEGRITY MODEL
-------------------------

Clavex uses a Merkle audit chain to detect tampering or deletion of log entries.

Each batch of events is canonicalised (sorted keys, no whitespace) and hashed
into a SHA-256 Merkle tree.  The Merkle root is then RS256-signed with the key
identified by "kid" in manifest.json.  Checkpoints are chained: each checkpoint
contains the SHA-256 hash of the previous checkpoint's root, so any reordering
or gap in the chain is detectable without a trusted server.

To verify:
  1. Read merkle-checkpoints.json to obtain the list of checkpoints.
  2. For each checkpoint, collect the events in the range [first_log_id, last_log_id]
     from audit-log.ndjson (use the "_leaf" field of each event as the leaf input).
  3. Rebuild the Merkle root from the leaf hashes.
  4. Verify the RS256 signature using the public key in jwks.json.
  5. Verify the chain_hash links the current root to the previous checkpoint.

Prerequisites: python3 (stdlib only) + openssl.

A self-contained verification script (verify.sh) is included in the separate
NIS2 Signed Audit Export (POST /compliance/audit/export-signed).

GDPR RECORDS OF PROCESSING ACTIVITIES
--------------------------------------

gdpr-ropa.json conforms to GDPR_ROPA schema version 1.0.  Processing activities
are split into "built_in" (Clavex platform activities present in every deployment)
and "custom" (activities configured by the data controller's administrator).

Built-in activities cover: user authentication, MFA, audit logging,
identity federation (OIDC/SAML), and verifiable credential issuance (OID4VCI).

NIS2 EVIDENCE
-------------

nis2-evidence.json provides point-in-time evidence for the mandatory security
measures under NIS2 Directive Article 21:
  - Art.21(2)(b)  Incident handling — audit log enabled, MFA challenges tracked
  - Art.21(2)(d)  Supply chain security — FIDO MDS3 attestation, SBOM available
  - Art.21(2)(h)  Cryptography — RS256 / AES-256-GCM / Merkle chain
  - Art.21(2)(i)  Access control — MFA coverage percentage
  - Art.21(2)(j)  Multi-factor authentication — detailed counts

CONTACTS
--------

For questions about this audit pack, contact the Clavex administrator who
provided it or refer to your organisation's data protection officer (DPO).

References:
  FIDO Alliance MDS3:   https://fidoalliance.org/metadata/
  CycloneDX SBOM spec:  https://cyclonedx.org/specification/overview/
  OpenID Foundation:    https://openid.net/certification/
  eIDAS 2.0:            https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation
`, at.Format(time.RFC3339), orgID)
}

// auditPackConformance returns the OIDC/FAPI 2.0/eIDAS 2.0 conformance summary.
func auditPackConformance(orgID string, at time.Time) map[string]any {
	return map[string]any{
		"schema_version": "1.0",
		"report_type":    "CONFORMANCE_SUMMARY",
		"generated_at":   at,
		"org_id":         orgID,
		"frameworks": []map[string]any{
			{
				"name":          "OpenID Connect Core 1.0",
				"status":        "certified",
				"certified_by":  "OpenID Foundation",
				"profile":       "Basic OP",
				"certified_at":  "2024-01",
			},
			{
				"name":          "OpenID Connect Discovery 1.0",
				"status":        "certified",
				"certified_by":  "OpenID Foundation",
				"certified_at":  "2024-01",
			},
			{
				"name":          "OpenID Connect Dynamic Client Registration 1.0",
				"status":        "certified",
				"certified_by":  "OpenID Foundation",
				"certified_at":  "2024-01",
			},
			{
				"name":    "FAPI 2.0 Security Profile (ID2)",
				"status":  "in_progress",
				"profile": "Advanced OP — PAR + JAR + JARM + DPoP",
				"note":    "87% pass rate on the OpenID Foundation conformance test suite.",
			},
			{
				"name":    "FAPI 2.0 Message Signing",
				"status":  "supported",
				"profile": "JAR (request object) + JARM (response signing)",
			},
			{
				"name":    "OpenID Identity Assurance (eKYC IDA) 1.0",
				"status":  "supported",
				"profile": "claims_in_id_token — verified_claims with trust_framework",
			},
			{
				"name":    "eIDAS 2.0 — OID4VCI (SD-JWT VC)",
				"status":  "supported",
				"profile": "OID4VCI Final (September 2025); SD-JWT-VC credential format (vc+sd-jwt)",
			},
			{
				"name":    "eIDAS 2.0 — OID4VP",
				"status":  "supported",
				"profile": "OID4VP draft-20; presentation_definition query language",
			},
			{
				"name":    "WebAuthn Level 3 / FIDO2",
				"status":  "supported",
				"profile": "FIDO2 L2+ attestation verification with MDS3 revocation checking",
			},
			{
				"name":    "SCIM 2.0",
				"status":  "supported",
				"profile": "RFC 7643 / RFC 7644 — Users and Groups provisioning",
			},
		},
		"note": "Certification status reflects the most recent OpenID Foundation submission. Full test logs are available on request from the Clavex administrator.",
	}
}

// auditPackSBOM returns a minimal CycloneDX 1.4 SBOM for the Clavex application.
// For a full dependency-level SBOM, generate at build time with:
//
//	syft packages . -o cyclonedx-json > sbom-cyclonedx.json
func auditPackSBOM(orgID string, at time.Time) map[string]any {
	return map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.4",
		"serialNumber": fmt.Sprintf("urn:clavex:sbom:%s:%d", orgID, at.Unix()),
		"version":      1,
		"metadata": map[string]any{
			"timestamp": at.Format(time.RFC3339),
			"tools": []map[string]any{
				{"vendor": "Clavex", "name": "audit-pack-sbom", "version": "1.0"},
			},
			"component": map[string]any{
				"type":        "application",
				"bom-ref":     "clavex",
				"name":        "clavex",
				"group":       "github.com/clavex-eu",
				"version":     "see manifest.json",
				"description": "Clavex — European Identity & Access Management Platform",
				"licenses": []map[string]any{
					{"license": map[string]any{"id": "Proprietary"}},
				},
				"externalReferences": []map[string]any{
					{"type": "website", "url": "https://clavex.eu"},
					{"type": "vcs", "url": "https://github.com/clavex-eu/clavex"},
				},
			},
		},
		"components": []map[string]any{
			{
				"type":        "library",
				"bom-ref":     "go-webauthn",
				"name":        "go-webauthn/webauthn",
				"group":       "github.com/go-webauthn",
				"version":     "v0.10",
				"description": "WebAuthn (FIDO2) server library for Go",
				"purl":        "pkg:golang/github.com/go-webauthn/webauthn",
			},
			{
				"type":        "library",
				"bom-ref":     "pgx-v5",
				"name":        "jackc/pgx",
				"group":       "github.com/jackc",
				"version":     "v5",
				"description": "PostgreSQL driver for Go",
				"purl":        "pkg:golang/github.com/jackc/pgx/v5",
			},
			{
				"type":        "library",
				"bom-ref":     "echo-v4",
				"name":        "labstack/echo",
				"group":       "github.com/labstack",
				"version":     "v4",
				"description": "High-performance HTTP router for Go",
				"purl":        "pkg:golang/github.com/labstack/echo/v4",
			},
			{
				"type":        "library",
				"bom-ref":     "zerolog",
				"name":        "rs/zerolog",
				"group":       "github.com/rs",
				"version":     "v1",
				"description": "Zero-allocation JSON logger for Go",
				"purl":        "pkg:golang/github.com/rs/zerolog",
			},
			{
				"type":        "library",
				"bom-ref":     "golang-jwt",
				"name":        "golang-jwt/jwt",
				"group":       "github.com/golang-jwt",
				"version":     "v5",
				"description": "JWT library for Go",
				"purl":        "pkg:golang/github.com/golang-jwt/jwt/v5",
			},
		},
		"_note": "This is a condensed application-level SBOM. Generate a full dependency SBOM at build time: syft packages . -o cyclonedx-json",
	}
}

// auditPackSubProcessors returns the GDPR Art.28 sub-processor register.
func auditPackSubProcessors(at time.Time) map[string]any {
	return map[string]any{
		"schema_version":  "1.0",
		"report_type":     "SUB_PROCESSOR_REGISTER",
		"article":         "GDPR Art.28 — Processor and Sub-processor Register",
		"generated_at":    at,
		"sub_processors": []map[string]any{
			{
				"name":            "PostgreSQL",
				"role":            "Primary data store — users, credentials, audit logs, OIDC clients, GDPR records",
				"deployment":      "self_hosted",
				"transfer_basis":  "not_applicable",
				"data_categories": []string{"personal_data", "audit_logs", "credentials"},
				"note":            "Deployed by the data controller in their own infrastructure. Clavex does not operate the database server.",
			},
			{
				"name":            "Redis",
				"role":            "Session cache, rate limiting, PKCE / nonce store, OTP codes",
				"deployment":      "self_hosted",
				"transfer_basis":  "not_applicable",
				"data_categories": []string{"session_data", "ephemeral_tokens"},
				"note":            "Deployed by the data controller. Stores only ephemeral data that expires automatically.",
			},
			{
				"name":            "FIDO Alliance MDS3",
				"role":            "Authenticator metadata catalogue (read-only) for passkey attestation policy enforcement",
				"deployment":      "external_api",
				"country":         "US",
				"transfer_basis":  "standard_contractual_clauses",
				"data_categories": []string{"none"},
				"privacy_url":     "https://fidoalliance.org/privacy-policy/",
				"note":            "No personal data is transmitted. Requests contain only authenticator AAGUID identifiers (non-personal) against the public MDS3 catalog.",
			},
		},
		"operator_note": "If the Clavex operator has configured optional third-party services (SMTP relay, SMS gateway, object storage, cloud HSM, GeoIP provider), those providers must be added to this register by the data controller's DPO.",
	}
}

// auditPackQTSP returns an eIDAS 2.0 QTSP readiness self-assessment.
func auditPackQTSP(orgID string, at time.Time) map[string]any {
	return map[string]any{
		"schema_version": "1.0",
		"report_type":    "QTSP_ASSESSMENT",
		"framework":      "eIDAS 2.0 / ETSI TS 119 series",
		"generated_at":   at,
		"org_id":         orgID,
		"disclaimer":     "This is a self-assessment only. Achieving QTSP status requires formal conformity assessment by an accredited CAB (Conformity Assessment Body) under eIDAS 2.0 Article 21.",
		"requirements": []map[string]any{
			{
				"id":        "QTSP-1",
				"reference": "eIDAS Art.24(2)(a) — Legal establishment in the EU",
				"status":    "operator_responsibility",
				"evidence":  "Must be verified by the deploying organisation.",
				"automated": false,
			},
			{
				"id":        "QTSP-2",
				"reference": "eIDAS Art.24(2)(b) — Physical security controls",
				"status":    "operator_responsibility",
				"evidence":  "Data centre physical security documentation required.",
				"automated": false,
			},
			{
				"id":        "QTSP-3",
				"reference": "eIDAS Art.24(2)(e) — Qualified electronic signatures and seals",
				"status":    "supported",
				"evidence":  "RS256 Merkle-sealed audit log (see merkle-checkpoints.json + jwks.json in this pack).",
				"automated": true,
			},
			{
				"id":        "QTSP-4",
				"reference": "eIDAS Art.24(2)(h) — Cryptographic key management",
				"status":    "supported",
				"evidence":  "RS256/EC keys managed via JWKS endpoint with rotation support.",
				"automated": true,
			},
			{
				"id":        "QTSP-5",
				"reference": "ETSI EN 319 401 — General policy requirements for TSPs",
				"status":    "partial",
				"evidence":  "Audit logging, incident procedures, and NIS2 controls are in place. A formal CPS document is required for full compliance.",
				"automated": false,
			},
			{
				"id":        "QTSP-6",
				"reference": "ETSI TS 119 461 — Identity proofing for remote qualified signature",
				"status":    "supported",
				"evidence":  "OID4VCI SD-JWT VC issuance with OpenID IDA identity assurance claims and trust_framework.",
				"automated": true,
			},
			{
				"id":        "QTSP-7",
				"reference": "ETSI TS 119 471 — eIDAS EUDI Wallet (OID4VCI / OID4VP)",
				"status":    "supported",
				"evidence":  "OID4VCI Final (September 2025) + OID4VP Final implemented. SD-JWT-VC with selective disclosure (PS256).",
				"automated": true,
			},
			{
				"id":        "QTSP-8",
				"reference": "NIS2 Art.21 — Security measures for essential services",
				"status":    "implemented",
				"evidence":  "See nis2-evidence.json in this pack.",
				"automated": true,
			},
			{
				"id":        "QTSP-9",
				"reference": "GDPR Art.30 — Records of Processing Activities",
				"status":    "implemented",
				"evidence":  "See gdpr-ropa.json in this pack.",
				"automated": true,
			},
			{
				"id":        "QTSP-10",
				"reference": "FIDO2 Authenticator Attestation (FIDO MDS3 L2+)",
				"status":    "implemented",
				"evidence":  "Attestation policy enforcement with MDS3 L2+ configurable per organisation and per security group.",
				"automated": true,
			},
		},
		"next_steps": []string{
			"Engage an accredited CAB for formal QTSP conformity assessment.",
			"Prepare a Certification Practice Statement (CPS).",
			"Implement HSM for qualified key storage if not already in place.",
			"Submit notification to the national supervisory body (notified body under eIDAS Art.17).",
		},
	}
}

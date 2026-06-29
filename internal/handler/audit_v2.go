package handler

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	internaudit "github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/merkle"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// AuditHandlerV2 provides the structured audit log API:
//
//	GET    /audit                         — paginated query (cursor-based)
//	GET    /audit/export                  — bulk export (NDJSON or CSV)
//	GET    /audit/stream                  — live SSE / NDJSON stream
//	GET    /audit/retention               — get retention settings
//	PUT    /audit/retention               — update retention settings
//	GET    /audit/sinks                   — list sinks
//	POST   /audit/sinks                   — create sink
//	GET    /audit/sinks/:sink_id          — get sink
//	PATCH  /audit/sinks/:sink_id          — update sink
//	GET    /audit/snapshot                — time-travel entity snapshot
//	DELETE /audit/sinks/:sink_id          — delete sink
//	POST   /audit/sinks/:sink_id/test     — fire a test event through the sink
//	GET    /audit/proof                   — list Merkle checkpoints (immutability proof)
//	POST   /audit/proof/seal              — trigger immediate sealing of pending rows
type AuditHandlerV2 struct {
	repo       *repository.AuditRepository
	sealer     *merkle.Sealer          // may be nil when signing key is not configured
	dispatcher *internaudit.Dispatcher // may be nil; required for StreamLive
}

func NewAuditHandlerV2(pool *pgxpool.Pool) *AuditHandlerV2 {
	return &AuditHandlerV2{repo: repository.NewAuditRepository(pool)}
}

// NewAuditHandlerV2WithSealer creates a handler with Merkle sealing support.
func NewAuditHandlerV2WithSealer(pool *pgxpool.Pool, s *merkle.Sealer) *AuditHandlerV2 {
	return &AuditHandlerV2{repo: repository.NewAuditRepository(pool), sealer: s}
}

// WithDispatcher attaches the audit event dispatcher so StreamLive can subscribe.
func (h *AuditHandlerV2) WithDispatcher(d *internaudit.Dispatcher) *AuditHandlerV2 {
	h.dispatcher = d
	return h
}

// ── Query ─────────────────────────────────────────────────────────────────────

// List returns a cursor-paginated page of structured audit events.
//
// Query params:
//
//	action, resource_type, resource_id, actor_id, status, session_id
//	since, until   — RFC3339
//	cursor         — row ID returned by the previous response
//	limit          — 1-500, default 50
func (h *AuditHandlerV2) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	cursor, _ := strconv.ParseInt(c.QueryParam("cursor"), 10, 64)

	f := repository.AuditFilter{
		OrgID:        orgID,
		Action:       c.QueryParam("action"),
		ResourceType: c.QueryParam("resource_type"),
		ResourceID:   c.QueryParam("resource_id"),
		ActorID:      c.QueryParam("actor_id"),
		Status:       c.QueryParam("status"),
		SessionID:    c.QueryParam("session_id"),
		Cursor:       cursor,
		Limit:        limit,
	}
	if s := c.QueryParam("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "since must be RFC3339")
		}
		f.Since = &t
	}
	if u := c.QueryParam("until"); u != "" {
		t, err := time.Parse(time.RFC3339, u)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "until must be RFC3339")
		}
		f.Until = &t
	}

	page, err := h.repo.List(c.Request().Context(), f)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, page)
}

// ── Export ────────────────────────────────────────────────────────────────────

// Export streams all matching events as NDJSON or CSV.
// Query params: same as List, plus format=ndjson|csv (default ndjson).
func (h *AuditHandlerV2) Export(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	format := c.QueryParam("format")
	if format == "" {
		format = "ndjson"
	}
	if format != "ndjson" && format != "csv" {
		return echo.NewHTTPError(http.StatusBadRequest, "format must be ndjson or csv")
	}

	f := repository.AuditFilter{
		OrgID:        orgID,
		Action:       c.QueryParam("action"),
		ResourceType: c.QueryParam("resource_type"),
		ResourceID:   c.QueryParam("resource_id"),
		ActorID:      c.QueryParam("actor_id"),
		Status:       c.QueryParam("status"),
		SessionID:    c.QueryParam("session_id"),
	}
	if s := c.QueryParam("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "since must be RFC3339")
		}
		f.Since = &t
	}
	if u := c.QueryParam("until"); u != "" {
		t, err := time.Parse(time.RFC3339, u)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "until must be RFC3339")
		}
		f.Until = &t
	}

	ts := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("audit-%s-%s.%s", orgID.String()[:8], ts, format)

	switch format {
	case "ndjson":
		c.Response().Header().Set("Content-Type", "application/x-ndjson")
		c.Response().Header().Set("Content-Disposition", "attachment; filename="+filename)
		c.Response().WriteHeader(http.StatusOK)
		enc := json.NewEncoder(c.Response())
		return h.repo.ExportAll(c.Request().Context(), f, func(e *repository.AuditEvent) error {
			return enc.Encode(e)
		})

	default: // csv
		c.Response().Header().Set("Content-Type", "text/csv; charset=utf-8")
		c.Response().Header().Set("Content-Disposition", "attachment; filename="+filename)
		c.Response().WriteHeader(http.StatusOK)
		w := csv.NewWriter(c.Response())
		_ = w.Write([]string{
			"id", "event_id", "specversion", "source", "type", "time",
			"action", "status",
			"actor_email", "actor_id",
			"resource_type", "resource_id",
			"ip_address", "country_code", "session_id", "request_id",
		})
		return h.repo.ExportAll(c.Request().Context(), f, func(e *repository.AuditEvent) error {
			row := []string{
				strconv.FormatInt(e.ID, 10), e.EventID,
				e.SpecVersion, e.Source, e.Type,
				e.Time.Format(time.RFC3339),
				e.Action, e.Status,
				auditPtrStr(e.ActorEmail), auditPtrUUID(e.ActorID),
				auditPtrStr(e.ResourceType), auditPtrStr(e.ResourceID),
				auditPtrStr(e.IPAddress), auditPtrStr(e.CountryCode),
				auditPtrStr(e.SessionID), auditPtrStr(e.RequestID),
			}
			if writeErr := w.Write(row); writeErr != nil {
				return writeErr
			}
			w.Flush()
			return w.Error()
		})
	}
}

// ── Live stream ───────────────────────────────────────────────────────────────

// StreamLive opens a long-lived HTTP connection that pushes new audit events
// to the caller in real time using Server-Sent Events (SSE).
//
// Protocol: text/event-stream (SSE, RFC 8895)
//   - Each event: "data: <JSON>\n\n"
//   - Heartbeat comment ": heartbeat\n\n" every 30 s (keeps proxies from closing)
//
// SIEM integration example (Splunk / Elastic Logstash):
//
//	curl -N -H "Authorization: Bearer $TOKEN" \
//	  "https://clavex.example.com/api/v1/organizations/$ORG/audit/stream"
//
// The stream ends when:
//   - The client disconnects (context cancelled)
//   - The server shuts down
//
// Optional query params: action, resource_type, actor_id, status (same as List).
func (h *AuditHandlerV2) StreamLive(c echo.Context) error {
	if h.dispatcher == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "audit stream not available")
	}
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	// Optional server-side filters.
	filterAction := c.QueryParam("action")
	filterResourceType := c.QueryParam("resource_type")
	filterActorID := c.QueryParam("actor_id")
	filterStatus := c.QueryParam("status")

	// SSE headers — must be set before the first Write.
	c.Response().Header().Set("Content-Type", "text/event-stream")
	c.Response().Header().Set("Cache-Control", "no-cache")
	c.Response().Header().Set("Connection", "keep-alive")
	// Tell nginx/Caddy not to buffer this response.
	c.Response().Header().Set("X-Accel-Buffering", "no")
	c.Response().WriteHeader(http.StatusOK)
	c.Response().Flush()

	ch, cancel := h.dispatcher.Subscribe(orgID.String())
	defer cancel()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	ctx := c.Request().Context()
	w := c.Response()
	enc := json.NewEncoder(w)

	// Helper: write one SSE event line.
	writeEvent := func(e *repository.AuditEvent) error {
		if _, err := fmt.Fprint(w, "data: "); err != nil {
			return err
		}
		if err := enc.Encode(e); err != nil {
			return err
		}
		if _, err := fmt.Fprint(w, "\n"); err != nil {
			return err
		}
		w.Flush()
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			// Heartbeat keeps the TCP connection and any reverse proxies alive.
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return nil // client disconnected
			}
			w.Flush()

		case raw, ok := <-ch:
			if !ok {
				return nil // channel closed (server shutdown / cancel)
			}

			// Apply server-side filters — the dispatcher channel is org-scoped
			// already; here we filter further if the caller requested it.
			if filterAction != "" && raw.Data != nil {
				var d struct {
					Action string `json:"action"`
				}
				if json.Unmarshal(raw.Data, &d) == nil && d.Action != filterAction {
					continue
				}
			}

			// Convert the dispatcher Event to an AuditEvent DTO.
			ae := auditEventFromDispatcherEvent(raw, orgID, filterResourceType, filterActorID, filterStatus)
			if ae == nil {
				continue
			}
			if err := writeEvent(ae); err != nil {
				log.Debug().Err(err).Str("org_id", orgID.String()).Msg("audit stream: client write error")
				return nil
			}
		}
	}
}

// auditEventFromDispatcherEvent converts a raw audit.Event (from the dispatcher)
// into the AuditEvent DTO used by the API, applying optional field filters.
// Returns nil if the event should be skipped.
func auditEventFromDispatcherEvent(e *internaudit.Event, orgID uuid.UUID,
	filterResourceType, filterActorID, filterStatus string) *repository.AuditEvent {

	var data struct {
		Action       string  `json:"action"`
		Status       string  `json:"status"`
		ActorID      *string `json:"actor_id"`
		ActorEmail   *string `json:"actor_email"`
		ResourceType *string `json:"resource_type"`
		ResourceID   *string `json:"resource_id"`
		IPAddress    *string `json:"ip_address"`
		UserAgent    *string `json:"user_agent"`
		CountryCode  *string `json:"country_code"`
	}
	if e.Data != nil {
		_ = json.Unmarshal(e.Data, &data)
	}

	if filterResourceType != "" && (data.ResourceType == nil || *data.ResourceType != filterResourceType) {
		return nil
	}
	if filterStatus != "" && data.Status != filterStatus {
		return nil
	}
	if filterActorID != "" && (data.ActorID == nil || *data.ActorID != filterActorID) {
		return nil
	}

	ae := &repository.AuditEvent{
		EventID:      e.ID,
		SpecVersion:  e.SpecVersion,
		Source:       e.Source,
		Type:         e.Type,
		OrgID:        orgID,
		Action:       data.Action,
		Status:       data.Status,
		ActorEmail:   data.ActorEmail,
		ResourceType: data.ResourceType,
		ResourceID:   data.ResourceID,
		IPAddress:    data.IPAddress,
		UserAgent:    data.UserAgent,
		CountryCode:  data.CountryCode,
		Time:         e.Time,
	}
	if data.ActorID != nil {
		id, err := uuid.Parse(*data.ActorID)
		if err == nil {
			ae.ActorID = &id
		}
	}
	return ae
}

// ── Retention ─────────────────────────────────────────────────────────────────

func (h *AuditHandlerV2) GetRetention(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ret, err := h.repo.GetRetention(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, ret)
}

type updateRetentionReq struct {
	RetentionDays int         `json:"retention_days"`
	ExportEnabled bool        `json:"export_enabled"`
	ExportConfig  interface{} `json:"export_config,omitempty"`
}

func (h *AuditHandlerV2) UpdateRetention(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req updateRetentionReq
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.RetentionDays < 1 {
		return echo.NewHTTPError(http.StatusBadRequest, "retention_days must be >= 1")
	}
	ret := &repository.AuditRetention{
		OrgID:         orgID,
		RetentionDays: req.RetentionDays,
		ExportEnabled: req.ExportEnabled,
		ExportConfig:  req.ExportConfig,
	}
	if err := h.repo.UpsertRetention(c.Request().Context(), ret); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, ret)
}

// ── Sinks ─────────────────────────────────────────────────────────────────────

func (h *AuditHandlerV2) ListSinks(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	sinks, err := h.repo.ListSinks(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	for _, s := range sinks {
		auditRedactSinkConfig(s)
	}
	return c.JSON(http.StatusOK, sinks)
}

type createSinkReq struct {
	Name           string                 `json:"name"`
	SinkType       string                 `json:"sink_type"`
	IsActive       *bool                  `json:"is_active"`
	Config         map[string]interface{} `json:"config"`
	FilterActions  []string               `json:"filter_actions"`
	FilterStatuses []string               `json:"filter_statuses"`
}

func (h *AuditHandlerV2) CreateSink(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createSinkReq
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name == "" || req.SinkType == "" || req.Config == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "name, sink_type, and config are required")
	}
	validType := map[string]bool{"webhook": true, "http": true, "mqtt": true, "kafka": true, "splunk_hec": true, "sentinel": true, "elastic_ecs": true}
	if !validType[req.SinkType] {
		return echo.NewHTTPError(http.StatusBadRequest, "sink_type must be one of: webhook, http, mqtt, kafka, splunk_hec, sentinel, elastic_ecs")
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	s := &repository.AuditSink{
		OrgID:          orgID,
		Name:           req.Name,
		SinkType:       req.SinkType,
		IsActive:       isActive,
		Config:         req.Config,
		FilterActions:  req.FilterActions,
		FilterStatuses: req.FilterStatuses,
	}
	if err := h.repo.CreateSink(c.Request().Context(), s); err != nil {
		return err
	}
	auditRedactSinkConfig(s)
	return c.JSON(http.StatusCreated, s)
}

func (h *AuditHandlerV2) GetSink(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	sinkID, err := uuidParam(c, "sink_id")
	if err != nil {
		return err
	}
	s, err := h.repo.GetSink(c.Request().Context(), orgID, sinkID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "audit sink not found")
		}
		return err
	}
	auditRedactSinkConfig(s)
	return c.JSON(http.StatusOK, s)
}

func (h *AuditHandlerV2) UpdateSink(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	sinkID, err := uuidParam(c, "sink_id")
	if err != nil {
		return err
	}
	s, err := h.repo.GetSink(c.Request().Context(), orgID, sinkID)
	if err != nil {
		return err
	}
	var req createSinkReq
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name != "" {
		s.Name = req.Name
	}
	if req.Config != nil {
		auditMergeSinkConfig(s.Config, req.Config)
	}
	if req.IsActive != nil {
		s.IsActive = *req.IsActive
	}
	if req.FilterActions != nil {
		s.FilterActions = req.FilterActions
	}
	if req.FilterStatuses != nil {
		s.FilterStatuses = req.FilterStatuses
	}
	if err := h.repo.UpdateSink(c.Request().Context(), s); err != nil {
		return err
	}
	auditRedactSinkConfig(s)
	return c.JSON(http.StatusOK, s)
}

func (h *AuditHandlerV2) DeleteSink(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	sinkID, err := uuidParam(c, "sink_id")
	if err != nil {
		return err
	}
	return h.repo.DeleteSink(c.Request().Context(), orgID, sinkID)
}

// TestSink fires a synthetic test event through the sink and returns the result.
func (h *AuditHandlerV2) TestSink(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	sinkID, err := uuidParam(c, "sink_id")
	if err != nil {
		return err
	}
	s, err := h.repo.GetSink(c.Request().Context(), orgID, sinkID)
	if err != nil {
		return err
	}

	testEvt := auditBuildTestEvent(orgID, s)
	sink, buildErr := internaudit.BuildSink(internaudit.SinkConfig{
		ID:       s.ID,
		OrgID:    s.OrgID,
		SinkType: s.SinkType,
		Config:   s.Config,
	})
	if buildErr != nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   "cannot build sink: " + buildErr.Error(),
		})
	}
	sendErr := sink.Send(c.Request().Context(), testEvt)
	if sendErr != nil {
		return c.JSON(http.StatusOK, map[string]interface{}{"success": false, "error": sendErr.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"success": true})
}

// ── Merkle immutability proof ─────────────────────────────────────────────────

// ListProofs handles GET /audit/proof
//
// Returns the list of Merkle checkpoints for the org, in ascending order.
// Each checkpoint contains the signed Merkle root covering a batch of
// audit rows. Clients (or auditors) can use this to verify that no rows
// have been tampered with or deleted.
//
// Query params:
//
//	limit — max checkpoints to return (default 100, max 1000)
func (h *AuditHandlerV2) ListProofs(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	cps, err := h.repo.ListCheckpoints(c.Request().Context(), orgID, limit)
	if err != nil {
		return err
	}
	if cps == nil {
		cps = []*repository.AuditMerkleCheckpoint{}
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"checkpoints": cps,
		"count":       len(cps),
	})
}

// SealProof handles POST /audit/proof/seal
//
// Triggers immediate sealing of any pending audit rows for the org.
// Returns the number of new checkpoints created and the latest checkpoint.
// Requires the handler to be configured with a Sealer (signing key).
func (h *AuditHandlerV2) SealProof(c echo.Context) error {
	if h.sealer == nil {
		return c.JSON(http.StatusNotImplemented, map[string]interface{}{
			"error": "merkle_signing_not_configured",
			"message": "Audit Merkle proof sealing requires a signing key. " +
				"Set `auth.signing_key_file` in your config (or CLAVEX_AUTH_SIGNING_KEY_FILE env var) " +
				"to the path of an RSA private key PEM file. " +
				"A fresh key can be generated with: openssl genrsa -out keys/signing.pem 2048",
			"docs": "https://github.com/clavex-eu/clavex/blob/main/docs/audit-merkle.md#signing-key-configuration",
		})
	}
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	n, err := h.sealer.SealOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	latest, err := h.repo.LatestCheckpoint(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"sealed":            n,
		"latest_checkpoint": latest,
	})
}

// ── private helpers ───────────────────────────────────────────────────────────

// MerkleProofPublic is a public endpoint for external auditors.
// GET /api/v1/organizations/:org_id/audit/merkle-proof
//
// Returns the signed Merkle checkpoints for the org together with step-by-step
// verification instructions. No authentication is required — the checkpoints
// carry their own RS256 signatures that auditors can verify against the
// published JWKS endpoint.
//
// Query params:
//
//	limit — max checkpoints to return (default 100, max 1000)
func (h *AuditHandlerV2) MerkleProofPublic(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	cps, err := h.repo.ListCheckpoints(c.Request().Context(), orgID, limit)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if cps == nil {
		cps = []*repository.AuditMerkleCheckpoint{}
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"checkpoints": cps,
		"count":       len(cps),
		"verification_instructions": map[string]interface{}{
			"steps": []string{
				"1. Export the audit_log rows for the organisation in ascending id order.",
				"2. For each checkpoint, compute SHA-256 of the canonical JSON for each row in [first_log_id, last_log_id].",
				"3. Build the Merkle tree: pair-wise SHA-256(left||right), repeating the last node on odd levels.",
				"4. Compare the computed Merkle root (hex) against the checkpoint's merkle_root field.",
				"5. Verify the chain: SHA-256(prev_root || merkle_root) == chain_hash for each checkpoint.",
				"6. Verify the RS256 signature over chain_hash using the public key from the JWKS endpoint.",
				"7. Walk all checkpoints in order and confirm each prev_root equals the prior checkpoint's merkle_root.",
			},
			"canonical_row_json_fields": []string{"id", "event_id", "org_id", "action", "status", "created_at"},
			"signature_algorithm":       "RS256",
			"jwks_endpoint_template":    "https://<base-domain>/<org-slug>/.well-known/jwks.json",
		},
	})
}

// LatestProof returns the most recent Merkle checkpoint as a self-contained
// "proof bundle" that an auditor can save to disk and verify offline.
//
//	GET /api/v1/organizations/:org_id/audit/proof/latest
//
// Public endpoint — no authentication required. The signed checkpoint carries
// its own RS256 signature which auditors verify against the published JWKS:
//
//	clavexctl audit verify --proof proof.json [--jwks <jwks_url>]
func (h *AuditHandlerV2) LatestProof(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	cp, err := h.repo.LatestCheckpoint(c.Request().Context(), orgID)
	if err != nil {
		log.Error().Err(err).Msg("audit: LatestProof: db error")
		return echo.ErrInternalServerError
	}
	if cp == nil {
		return echo.NewHTTPError(http.StatusNotFound,
			"no Merkle checkpoints found — the audit log has not been sealed yet; "+
				"use POST /audit/proof/seal to trigger sealing")
	}

	// Look up the org slug so we can embed the JWKS URI in the bundle.
	slug, _ := h.repo.OrgSlug(c.Request().Context(), orgID)

	// Derive base URL from the request (works behind reverse proxies).
	scheme := "https"
	if proto := c.Request().Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if c.Request().TLS == nil {
		scheme = "http"
	}
	host := c.Request().Host
	if fwdHost := c.Request().Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	jwksURI := ""
	if slug != "" {
		jwksURI = fmt.Sprintf("%s://%s/%s/.well-known/jwks.json", scheme, host, slug)
	}

	type proofBundle struct {
		Clavex       string                            `json:"_clavex"`
		OrgID        string                            `json:"org_id"`
		OrgSlug      string                            `json:"org_slug,omitempty"`
		GeneratedAt  time.Time                         `json:"generated_at"`
		Checkpoint   *repository.AuditMerkleCheckpoint `json:"checkpoint"`
		JWKSUri      string                            `json:"jwks_uri,omitempty"`
		Verification map[string]interface{}            `json:"verification"`
	}

	verifyCmd := ""
	if jwksURI != "" {
		verifyCmd = fmt.Sprintf("clavexctl audit verify --proof proof.json --jwks %q", jwksURI)
	} else {
		verifyCmd = "clavexctl audit verify --proof proof.json --jwks <jwks_url>"
	}

	return c.JSON(http.StatusOK, proofBundle{
		Clavex:      "audit-proof-bundle/v1",
		OrgID:       orgID.String(),
		OrgSlug:     slug,
		GeneratedAt: time.Now().UTC(),
		Checkpoint:  cp,
		JWKSUri:     jwksURI,
		Verification: map[string]interface{}{
			"algorithm":           "RS256",
			"chain_input_formula": "SHA-256( hex(prev_root) || hex(merkle_root) ) → RS256 sign over raw digest bytes",
			"steps": []string{
				"1. Compute SHA-256(checkpoint.prev_root + checkpoint.merkle_root) and confirm it equals checkpoint.chain_hash (hex).",
				"2. Fetch the JWKS from jwks_uri and locate the key where kid == checkpoint.kid.",
				"3. Base64url-decode checkpoint.signature and hex-decode checkpoint.chain_hash.",
				"4. Verify the RS256 signature: rsa.VerifyPKCS1v15(pubKey, SHA256, chain_hash_bytes, sig_bytes).",
				"5. To also verify data integrity: export audit rows [first_log_id..last_log_id] ordered by id, " +
					"SHA-256 each canonical JSON row {id,event_id,org_id,action,status,created_at}, " +
					"build Merkle tree (pair SHA-256(left||right), repeat last on odd levels), " +
					"compare root with checkpoint.merkle_root.",
				"6. For chain continuity: this checkpoint's prev_root must match the prior checkpoint's merkle_root.",
			},
			"canonical_row_fields": []string{"id", "event_id", "org_id", "action", "status", "created_at"},
			"verify_command":       verifyCmd,
		},
	})
}

// LatestProofBySlug is the same as LatestProof but resolves the org by slug
// rather than UUID. This public endpoint is designed for external auditors
// who know only the public org slug and do not have an account:
//
//	GET /api/v1/organizations/by-slug/:slug/audit/proof/latest
//
// No authentication is required. The proof bundle is self-authenticating via
// its RS256 signature which verifiers check against the published JWKS.
func (h *AuditHandlerV2) LatestProofBySlug(c echo.Context) error {
	slug := c.Param("slug")
	if slug == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "slug is required")
	}

	ctx := c.Request().Context()

	// Resolve slug → org_id.
	orgID, err := h.repo.OrgIDFromSlug(ctx, slug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	// Reuse the LatestProof logic by substituting the param and delegating.
	c.SetParamNames("org_id")
	c.SetParamValues(orgID.String())
	return h.LatestProof(c)
}

var auditSecretKeys = map[string]bool{
	"secret": true, "password": true, "token": true, "workspace_key": true, "api_key": true,
}

func auditRedactSinkConfig(s *repository.AuditSink) {
	for k := range s.Config {
		if auditSecretKeys[k] {
			s.Config[k] = "***"
		}
	}
}

func auditMergeSinkConfig(base, patch map[string]interface{}) {
	for k, v := range patch {
		if sv, ok := v.(string); ok && sv == "***" {
			continue // preserve existing secret
		}
		base[k] = v
	}
}

func auditPtrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func auditPtrUUID(u *uuid.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func auditBuildTestEvent(orgID uuid.UUID, s *repository.AuditSink) *internaudit.Event {
	data, _ := json.Marshal(internaudit.EventData{
		Action:   "audit.sink.test",
		Status:   "success",
		Metadata: map[string]interface{}{"sink_name": s.Name, "sink_type": s.SinkType},
	})
	return &internaudit.Event{
		SpecVersion:     "1.0",
		ID:              uuid.NewString(),
		Source:          "https://clavex/test/" + orgID.String(),
		Type:            "com.clavex.audit.audit.sink.test",
		Time:            time.Now().UTC(),
		OrgID:           orgID.String(),
		DataContentType: "application/json",
		Data:            data,
	}
}

// ── Time-travel snapshot ──────────────────────────────────────────────────────

// Snapshot reconstructs the state of an audited entity at a specific point in
// time by replaying its audit events chronologically.
//
// Query params:
//
//	entity_type — resource_type value to filter on (e.g. "user", "client"); optional
//	entity_id   — resource_id value; required
//	at          — RFC3339 timestamp; defaults to now if omitted
//
// The response includes:
//   - state:      best-effort field reconstruction from mutation metadata
//   - change_log: mutation-only timeline with before/after/changed_fields
//   - events:     full audit trail for the entity up to `at`
func (h *AuditHandlerV2) Snapshot(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	entityID := c.QueryParam("entity_id")
	if entityID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "entity_id is required"})
	}
	entityType := c.QueryParam("entity_type")

	var at time.Time
	if raw := c.QueryParam("at"); raw != "" {
		at, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "at must be RFC3339 (e.g. 2026-03-15T14:00:00Z)"})
		}
	}

	snap, err := h.repo.SnapshotEntity(c.Request().Context(), orgID, entityType, entityID, at)
	if err != nil {
		log.Error().Err(err).Str("entity_id", entityID).Msg("audit snapshot failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to build snapshot"})
	}

	if len(snap.Events) == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "no audit events found for this entity"})
	}

	return c.JSON(http.StatusOK, snap)
}

package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// SSFHandler implements the OpenID Shared Signals Framework transmitter API.
//
// Public (tenant-scoped) routes:
//
//	GET /:org_slug/.well-known/ssf-configuration   — transmitter metadata
//	GET /:org_slug/ssf/poll                        — poll delivery (RFC 8936)
//
// Protected (orgScoped / API-key authenticated) routes:
//
//	POST   /:org_slug/ssf/stream          — create / replace stream config
//	GET    /:org_slug/ssf/stream          — get stream config
//	PATCH  /:org_slug/ssf/stream          — update stream config
//	DELETE /:org_slug/ssf/stream          — delete stream
//	GET    /:org_slug/ssf/stream/status   — get stream status
//	POST   /:org_slug/ssf/stream/verify   — trigger verification SET
type SSFHandler struct {
	orgs   *repository.OrgRepository
	repo   *repository.SSFStreamRepository
	keys   oidc.Signer
	issuer func(c echo.Context, orgSlug string) string
	disp   *ssf.Dispatcher // optional — for push delivery health status
}

func NewSSFHandler(pool *pgxpool.Pool, keys oidc.Signer, issuerFn func(echo.Context, string) string) *SSFHandler {
	return &SSFHandler{
		orgs:   repository.NewOrgRepository(pool),
		repo:   repository.NewSSFStreamRepository(pool),
		keys:   keys,
		issuer: issuerFn,
	}
}

// WithDispatcher attaches the SSF dispatcher so AdminListStreams can surface
// the last push delivery status per stream (from Redis).
func (h *SSFHandler) WithDispatcher(d *ssf.Dispatcher) *SSFHandler {
	h.disp = d
	return h
}

// ── Transmitter metadata ─────────────────────────────────────────────────────

// TransmitterMetadata serves the SSF transmitter configuration document.
// GET /:org_slug/.well-known/ssf-configuration
func (h *SSFHandler) TransmitterMetadata(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	base := h.issuer(c, orgSlug)
	meta := ssf.BuildTransmitterMetadata(base)
	return c.JSON(http.StatusOK, meta)
}

// ── Stream configuration endpoints ───────────────────────────────────────────

// createStreamRequest is the body for POST /ssf/stream.
// Per the SSF spec: the receiver requests a stream and specifies delivery.
type createStreamRequest struct {
	Delivery        ssf.Delivery `json:"delivery"          validate:"required"`
	EventsRequested []string     `json:"events_requested"`
	Description     string       `json:"description"`
}

// CreateStream registers a new SSF stream for the authenticated client.
// POST /:org_slug/ssf/stream
func (h *SSFHandler) CreateStream(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	var req createStreamRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	// Resolve delivery method from URI.
	method, endpointURL, apiErr := resolveDelivery(req.Delivery)
	if apiErr != nil {
		return apiErr
	}

	// Default to all supported events if none requested.
	eventsRequested := req.EventsRequested
	if len(eventsRequested) == 0 {
		eventsRequested = ssf.AllSupportedEvents
	}

	// Identify the calling client via the Bearer token's "aud" or use the
	// org_id UUID as a fallback client identifier when called from the admin API.
	clientID := resolveClientID(c, orgID)

	// Check for an existing stream for this client (upsert semantics).
	existing, err := h.repo.GetByClientID(ctx, orgID, clientID)
	if err != nil {
		log.Error().Err(err).Msg("ssf: get by client")
		return echo.ErrInternalServerError
	}

	var stream *models.SSFStream

	// Generate a signing secret for push delivery.
	var secretHash *string
	var rawSecret string
	if method == "push" {
		rawSecret, err = ssf.GenerateStreamSecret()
		if err != nil {
			return echo.ErrInternalServerError
		}
		h := ssf.HashStreamSecret(rawSecret)
		secretHash = &h
	}

	var epURL *string
	if endpointURL != "" {
		epURL = &endpointURL
	}
	var desc *string
	if req.Description != "" {
		desc = &req.Description
	}

	if existing != nil {
		// Update the existing stream.
		existing.DeliveryMethod = method
		existing.PushEndpoint = epURL
		existing.PushSecretHash = secretHash
		existing.EventsRequested = eventsRequested
		existing.Status = "enabled"
		existing.Description = desc
		stream, err = h.repo.Update(ctx, existing)
	} else {
		stream, err = h.repo.Create(ctx, &models.SSFStream{
			OrgID:           orgID,
			ClientID:        clientID,
			DeliveryMethod:  method,
			PushEndpoint:    epURL,
			PushSecretHash:  secretHash,
			EventsRequested: eventsRequested,
			Status:          "enabled",
			Description:     desc,
		})
	}
	if err != nil {
		log.Error().Err(err).Msg("ssf: create/update stream")
		return echo.ErrInternalServerError
	}

	resp := h.streamResponse(c, orgID, stream)
	// Include the raw push secret once (only on creation).
	if method == "push" && rawSecret != "" {
		resp["push_secret"] = rawSecret
	}
	return c.JSON(http.StatusOK, resp)
}

// GetStream returns the current stream configuration.
// GET /:org_slug/ssf/stream
func (h *SSFHandler) GetStream(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	stream, err := h.streamForClient(ctx, c, orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, h.streamResponse(c, orgID, stream))
}

// updateStreamRequest is the body for PATCH /ssf/stream.
type updateStreamRequest struct {
	EventsRequested []string `json:"events_requested"`
	Status          string   `json:"status"` // "enabled"|"paused"|"disabled"
	Description     *string  `json:"description"`
}

// UpdateStream modifies an existing stream's configuration.
// PATCH /:org_slug/ssf/stream
func (h *SSFHandler) UpdateStream(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	stream, err := h.streamForClient(ctx, c, orgID)
	if err != nil {
		return err
	}

	var req updateStreamRequest
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}

	if len(req.EventsRequested) > 0 {
		stream.EventsRequested = req.EventsRequested
	}
	if req.Status != "" {
		if req.Status != "enabled" && req.Status != "paused" && req.Status != "disabled" {
			return echo.NewHTTPError(http.StatusBadRequest, "status must be enabled, paused, or disabled")
		}
		stream.Status = req.Status
	}
	if req.Description != nil {
		stream.Description = req.Description
	}

	updated, err := h.repo.Update(ctx, stream)
	if err != nil {
		log.Error().Err(err).Msg("ssf: update stream")
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, h.streamResponse(c, orgID, updated))
}

// DeleteStream removes an SSF stream.
// DELETE /:org_slug/ssf/stream
func (h *SSFHandler) DeleteStream(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	stream, err := h.streamForClient(ctx, c, orgID)
	if err != nil {
		return err
	}
	if err := h.repo.Delete(ctx, orgID, stream.ID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrNotFound
		}
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Stream status endpoint ────────────────────────────────────────────────────

// GetStatus returns the current status of the stream.
// GET /:org_slug/ssf/stream/status
func (h *SSFHandler) GetStatus(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	stream, err := h.streamForClient(ctx, c, orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":    stream.Status,
		"stream_id": stream.ID.String(),
	})
}

// ── Verification SET endpoint ─────────────────────────────────────────────────

type verifyRequest struct {
	State string `json:"state"`
}

// Verify triggers a verification SET to be sent to the stream's push endpoint
// (RFC 8936 §2.4). For poll streams, the SET is enqueued.
// POST /:org_slug/ssf/stream/verify
func (h *SSFHandler) Verify(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	stream, err := h.streamForClient(ctx, c, orgID)
	if err != nil {
		return err
	}
	if stream.Status != "enabled" {
		return echo.NewHTTPError(http.StatusConflict, "stream is not enabled")
	}

	var req verifyRequest
	_ = c.Bind(&req)

	orgSlug := c.Param("org_slug")
	issuer := h.issuer(c, orgSlug)
	cfg := &ssf.SETConfig{
		Issuer:     issuer,
		PrivateKey: h.keys.PrivateKey(),
		KID:        h.keys.KID(),
	}

	compact, jti, err := ssf.BuildVerificationSET(cfg, stream.ClientID, req.State)
	if err != nil {
		log.Error().Err(err).Msg("ssf: build verification SET")
		return echo.ErrInternalServerError
	}

	if stream.DeliveryMethod == "poll" {
		if err := h.repo.EnqueueSET(ctx, stream.ID, jti, compact, ssf.VerificationEventType); err != nil {
			return echo.ErrInternalServerError
		}
		return c.JSON(http.StatusOK, map[string]string{"jti": jti, "status": "queued"})
	}

	// Push: deliver synchronously for verification (best-effort).
	if err := deliverSETPush(ctx, stream, compact); err != nil {
		log.Warn().Err(err).Str("stream_id", stream.ID.String()).Msg("ssf: push verification failed")
		return echo.NewHTTPError(http.StatusBadGateway, "push delivery failed: "+err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"jti": jti, "status": "delivered"})
}

// ── Poll endpoint (RFC 8936) ─────────────────────────────────────────────────

// Poll serves pending SETs to poll receivers.
// GET /:org_slug/ssf/poll
// Auth: Bearer <stream_access_token> — the token is the stream's client_id
// (this is the same access token the receiver used to create the stream).
func (h *SSFHandler) Poll(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	var req ssf.PollRequest
	_ = c.Bind(&req) // GET with JSON body is non-standard but RFC 8936 uses POST-like semantics
	if req.MaxEvents <= 0 {
		req.MaxEvents = 100
	}

	stream, err := h.streamForClient(ctx, c, orgID)
	if err != nil {
		return err
	}
	if stream.DeliveryMethod != "poll" {
		return echo.NewHTTPError(http.StatusBadRequest, "stream is not configured for poll delivery")
	}
	if stream.Status == "disabled" {
		return echo.NewHTTPError(http.StatusConflict, "stream is disabled")
	}

	// Acknowledge previously received SETs.
	if len(req.Ack) > 0 {
		if err := h.repo.AcknowledgeSETs(ctx, stream.ID, req.Ack); err != nil {
			log.Error().Err(err).Msg("ssf: acknowledge SETs")
		}
	}

	if stream.Status == "paused" {
		return c.JSON(http.StatusOK, ssf.PollResponse{Sets: map[string]string{}, MoreAvailable: false})
	}

	pending, err := h.repo.PollSETs(ctx, stream.ID, req.MaxEvents+1)
	if err != nil {
		log.Error().Err(err).Msg("ssf: poll sets")
		return echo.ErrInternalServerError
	}

	more := false
	if len(pending) > req.MaxEvents {
		more = true
		pending = pending[:req.MaxEvents]
	}

	sets := make(map[string]string, len(pending))
	for _, s := range pending {
		sets[s.JTI] = s.Payload
	}

	return c.JSON(http.StatusOK, ssf.PollResponse{Sets: sets, MoreAvailable: more})
}

// ── Admin list all streams ────────────────────────────────────────────────────

// streamWithHealth is the admin-API response shape for a stream, augmented
// with the last push delivery record retrieved from Redis.
type streamWithHealth struct {
	StreamID        string              `json:"stream_id"`
	ClientID        string              `json:"client_id"`
	DeliveryMethod  string              `json:"delivery_method"`
	PushEndpoint    *string             `json:"push_endpoint,omitempty"`
	EventsRequested []string            `json:"events_requested"`
	Status          string              `json:"status"`
	Description     *string             `json:"description,omitempty"`
	CreatedAt       string              `json:"created_at"`
	LastDelivery    *ssf.DeliveryRecord `json:"last_delivery,omitempty"`
}

// AdminListStreams returns all SSF streams for an organisation with push health.
// GET /api/v1/organizations/:org_id/ssf/streams
func (h *SSFHandler) AdminListStreams(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	streams, err := h.repo.ListByOrg(ctx, orgID)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ssf: admin list streams")
		return echo.ErrInternalServerError
	}
	out := make([]streamWithHealth, 0, len(streams))
	for _, s := range streams {
		item := streamWithHealth{
			StreamID:        s.ID.String(),
			ClientID:        s.ClientID,
			DeliveryMethod:  s.DeliveryMethod,
			PushEndpoint:    s.PushEndpoint,
			EventsRequested: s.EventsRequested,
			Status:          s.Status,
			Description:     s.Description,
			CreatedAt:       s.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if h.disp != nil && s.DeliveryMethod == "push" {
			item.LastDelivery = h.disp.LastDelivery(ctx, s.ID)
		}
		out = append(out, item)
	}
	return c.JSON(http.StatusOK, out)
}

// ── Internal helpers ─────────────────────────────────────────────────────────

// streamResponse converts a stream model into the API response shape.
func (h *SSFHandler) streamResponse(c echo.Context, orgID uuid.UUID, s *models.SSFStream) map[string]interface{} {
	orgSlug := c.Param("org_slug")
	issuer := h.issuer(c, orgSlug)

	deliveryMethod := ssf.PushMethodURI
	if s.DeliveryMethod == "poll" {
		deliveryMethod = ssf.PollMethodURI
	}
	delivery := map[string]interface{}{
		"method": deliveryMethod,
	}
	if s.PushEndpoint != nil {
		delivery["endpoint_url"] = *s.PushEndpoint
	}

	return map[string]interface{}{
		"stream_id":        s.ID.String(),
		"iss":              issuer,
		"aud":              []string{s.ClientID},
		"delivery":         delivery,
		"events_requested": s.EventsRequested,
		"events_delivered": s.EventsRequested,
		"status":           s.Status,
		"description":      s.Description,
	}
}

// streamForClient looks up the stream for the current authenticated client.
func (h *SSFHandler) streamForClient(ctx context.Context, c echo.Context, orgID uuid.UUID) (*models.SSFStream, error) {
	clientID := resolveClientID(c, orgID)
	stream, err := h.repo.GetByClientID(ctx, orgID, clientID)
	if err != nil {
		log.Error().Err(err).Msg("ssf: get stream for client")
		return nil, echo.ErrInternalServerError
	}
	if stream == nil {
		return nil, echo.ErrNotFound
	}
	return stream, nil
}

// resolveDelivery maps the delivery struct to (method, endpointURL, error).
func resolveDelivery(d ssf.Delivery) (method, endpointURL string, err error) {
	switch d.Method {
	case ssf.PushMethodURI, "push":
		if d.EndpointURL == "" {
			return "", "", echo.NewHTTPError(http.StatusBadRequest, "push delivery requires endpoint_url")
		}
		return "push", d.EndpointURL, nil
	case ssf.PollMethodURI, "poll":
		return "poll", "", nil
	case "":
		// Default to push when an endpoint_url is provided.
		if d.EndpointURL != "" {
			return "push", d.EndpointURL, nil
		}
		return "poll", "", nil
	default:
		return "", "", echo.NewHTTPError(http.StatusBadRequest, "unknown delivery method: "+d.Method)
	}
}

// resolveClientID extracts the client identifier from the Bearer token subject
// claim, or falls back to the orgID string for admin-API callers.
func resolveClientID(c echo.Context, orgID uuid.UUID) string {
	authHdr := c.Request().Header.Get("Authorization")
	if strings.HasPrefix(authHdr, "Bearer ") {
		tok := strings.TrimPrefix(authHdr, "Bearer ")
		// The client_id is the first part of the JWT (header.payload.sig).
		// We only need the payload's "client_id" or "sub" claim — decode without verification
		// since the middleware has already verified the signature.
		if id := extractClientIDFromJWT(tok); id != "" {
			return id
		}
	}
	// Fallback: use org_id as a stable client identifier for API key callers.
	return orgID.String()
}

// extractClientIDFromJWT extracts the "client_id" or "sub" claim from a JWT
// payload without re-verifying the signature (the auth middleware already did).
func extractClientIDFromJWT(compact string) string {
	parts := strings.SplitN(compact, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	// Very simple extraction — avoid bringing in a JSON lib for this.
	// Look for "client_id" or "sub" string values in the JSON.
	type miniClaims struct {
		ClientID string `json:"client_id"`
		Sub      string `json:"sub"`
	}
	var claims miniClaims
	if err := json.Unmarshal(payload, &claims); err == nil {
		if claims.ClientID != "" {
			return claims.ClientID
		}
		return claims.Sub
	}
	return ""
}

// deliverSETPush sends a SET to the stream's push endpoint using HTTP POST.
func deliverSETPush(ctx context.Context, stream *models.SSFStream, compact string) error {
	if stream.PushEndpoint == nil || *stream.PushEndpoint == "" {
		return fmt.Errorf("no push endpoint configured")
	}
	endpoint := *stream.PushEndpoint

	body := []byte(compact)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(compact))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")

	// Sign the delivery with HMAC-SHA256 if a secret is configured.
	if stream.PushSecretHash != nil {
		// We store the hash, not the raw secret, so we cannot re-derive the HMAC here.
		// Instead, the receiver validates using their stored raw secret. The signature
		// is already embedded in the SET JWT header/payload. The push_secret_hash
		// is only used during verification in the webhook-style flow.
		// For SSF push, the signed JWT itself is the authentication mechanism.
		_ = body
		_ = endpoint
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("push request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("push endpoint returned %d", resp.StatusCode)
	}
	return nil
}

package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/webhook"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// WebhookHandler manages webhook registrations for an organization.
type WebhookHandler struct {
	repo       *repository.WebhookRepository
	delivRepo  *repository.WebhookDeliveryRepository
	dispatcher *webhook.Dispatcher
}

func NewWebhookHandler(pool *pgxpool.Pool) *WebhookHandler {
	repo := repository.NewWebhookRepository(pool)
	delivRepo := repository.NewWebhookDeliveryRepository(pool)
	return &WebhookHandler{
		repo:       repo,
		delivRepo:  delivRepo,
		dispatcher: webhook.New(repo, delivRepo),
	}
}

// Dispatcher returns the shared dispatcher so server.go can pass it to other handlers.
func (h *WebhookHandler) Dispatcher() *webhook.Dispatcher {
	return h.dispatcher
}

type createWebhookRequest struct {
	URL         string   `json:"url"          validate:"required,url"`
	Events      []string `json:"events"       validate:"required,min=1"`
	// EventFilter lists specific event subtypes to subscribe to (e.g. "user.login.new_device").
	// An empty slice means "all events in Events[]".  Optional.
	EventFilter []string `json:"event_filter"`
}

// POST /api/v1/organizations/:org_id/webhooks
func (h *WebhookHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createWebhookRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	secret, err := generateSecret()
	if err != nil {
		return echo.ErrInternalServerError
	}

	w, err := h.repo.Create(c.Request().Context(), orgID, req.URL, req.Events, secret)
	if err != nil {
		return echo.ErrInternalServerError
	}
	// Persist event_filter if provided.
	if len(req.EventFilter) > 0 {
		w, _ = h.repo.Update(c.Request().Context(), w.ID, nil, nil, nil, req.EventFilter)
	}
	// Return the secret once — callers must store it immediately.
	type createResponse struct {
		ID       string   `json:"id"`
		URL      string   `json:"url"`
		Events   []string `json:"events"`
		Secret   string   `json:"secret"` // shown only at creation time
		IsActive bool     `json:"is_active"`
	}
	return c.JSON(http.StatusCreated, createResponse{
		ID:       w.ID.String(),
		URL:      w.URL,
		Events:   w.Events,
		Secret:   secret,
		IsActive: w.IsActive,
	})
}

// GET /api/v1/organizations/:org_id/webhooks
func (h *WebhookHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	p := models.PageParams{}
	if v := c.QueryParam("limit"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			p.Limit = n
		}
	}
	if v := c.QueryParam("after"); v != "" {
		if uid, e := uuid.Parse(v); e == nil {
			p.After = &uid
		} else {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid cursor")
		}
	}
	page, err := h.repo.ListByOrgPage(c.Request().Context(), orgID, p)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, page)
}

type updateWebhookRequest struct {
	URL         *string  `json:"url"          validate:"omitempty,url"`
	Events      []string `json:"events"       validate:"omitempty,min=1"`
	IsActive    *bool    `json:"is_active"`
	EventFilter []string `json:"event_filter"`
}

// PATCH /api/v1/organizations/:org_id/webhooks/:id
func (h *WebhookHandler) Update(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	var req updateWebhookRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	// Pass nil for eventFilter when not provided to leave it unchanged.
	var ef []string
	if req.EventFilter != nil {
		ef = req.EventFilter
	}
	w, err := h.repo.Update(c.Request().Context(), id, req.URL, req.Events, req.IsActive, ef)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, w)
}

// DELETE /api/v1/organizations/:org_id/webhooks/:id
func (h *WebhookHandler) Delete(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.Request().Context(), id); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// generateSecret returns a 32-byte random hex string suitable for HMAC signing.
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ── Delivery history ──────────────────────────────────────────────────────────

// GET /api/v1/organizations/:org_id/webhooks/:id/deliveries
func (h *WebhookHandler) Deliveries(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	webhookID, err := uuidParam(c, "id")
	if err != nil {
		return err
	}

	limit := 50
	if l := c.QueryParam("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil {
			limit = v
		}
	}

	deliveries, err := h.delivRepo.ListByWebhook(ctx, orgID, webhookID, limit)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if deliveries == nil {
		deliveries = []*models.WebhookDelivery{}
	}
	return c.JSON(http.StatusOK, deliveries)
}

// POST /api/v1/organizations/:org_id/webhooks/:id/deliveries/:delivery_id/retry
func (h *WebhookHandler) RetryDelivery(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	delivID, err := uuidParam(c, "delivery_id")
	if err != nil {
		return err
	}

	// Load the original delivery row
	orig, err := h.delivRepo.GetDelivery(ctx, orgID, delivID)
	if err != nil {
		return echo.ErrNotFound
	}

	// Load the webhook to get current URL + secret (may have been updated since original delivery)
	hook, err := h.delivRepo.GetWebhookForOrg(ctx, orgID, orig.WebhookID)
	if err != nil || !hook.IsActive {
		return echo.NewHTTPError(http.StatusConflict, "webhook not found or inactive")
	}

	// Fire the retry asynchronously via the dispatcher using the original payload
	go func() {
		h.dispatcher.RedeliverRaw(hook, orig.Payload, orig.DeliveryID, orig.Event)
	}()

	return c.JSON(http.StatusAccepted, map[string]string{
		"delivery_id": orig.DeliveryID,
		"status":      "queued",
	})
}

package handler

import (
	"net/http"
	"strconv"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/scimpush"
	"github.com/clavex-eu/clavex/internal/tracing"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
)

// ScimPushHandler manages outbound SCIM push configurations for an org.
type ScimPushHandler struct {
	repo         *repository.ScimPushRepository
	deliveryRepo *repository.ScimPushDeliveryRepository
	pusher       *scimpush.Pusher
}

func NewScimPushHandler(pool *pgxpool.Pool) *ScimPushHandler {
	return &ScimPushHandler{
		repo:         repository.NewScimPushRepository(pool),
		deliveryRepo: repository.NewScimPushDeliveryRepository(pool),
	}
}

func NewScimPushHandlerWithEnc(pool *pgxpool.Pool, enc *crypto.Encryptor) *ScimPushHandler {
	return &ScimPushHandler{
		repo:         repository.NewScimPushRepositoryWithEnc(pool, enc),
		deliveryRepo: repository.NewScimPushDeliveryRepository(pool),
	}
}

// WithPusher attaches the scimpush.Pusher used for delivery retries.
func (h *ScimPushHandler) WithPusher(p *scimpush.Pusher) *ScimPushHandler {
	h.pusher = p
	return h
}

type createScimPushRequest struct {
	Name          string   `json:"name"           validate:"required,min=1,max=120"`
	EndpointURL   string   `json:"endpoint_url"   validate:"required,url"`
	BearerToken   string   `json:"bearer_token"   validate:"required,min=8"`
	EnabledEvents []string `json:"enabled_events" validate:"required,min=1,dive,oneof=user.created user.updated user.deactivated group.created group.updated group.deleted"`
}

// POST /api/v1/organizations/:org_id/scim-push
func (h *ScimPushHandler) Create(c echo.Context) error {
	ctx, span := tracing.Tracer("clavex/handler").Start(c.Request().Context(), "handler.scim_push.create")
	defer span.End()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	span.SetAttributes(attribute.String("org_id", orgID.String()))
	var req createScimPushRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	cfg, err := h.repo.Create(ctx, orgID,
		req.Name, req.EndpointURL, req.BearerToken, req.EnabledEvents)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, err.Error())
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, cfg)
}

// GET /api/v1/organizations/:org_id/scim-push
func (h *ScimPushHandler) List(c echo.Context) error {
	ctx, span := tracing.Tracer("clavex/handler").Start(c.Request().Context(), "handler.scim_push.list")
	defer span.End()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	span.SetAttributes(attribute.String("org_id", orgID.String()))
	cfgs, err := h.repo.ListByOrg(ctx, orgID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, err.Error())
		return echo.ErrInternalServerError
	}
	if cfgs == nil {
		cfgs = []*models.ScimPushConfig{}
	}
	return c.JSON(http.StatusOK, cfgs)
}

type updateScimPushRequest struct {
	Name          *string  `json:"name"           validate:"omitempty,min=1,max=120"`
	EndpointURL   *string  `json:"endpoint_url"   validate:"omitempty,url"`
	BearerToken   *string  `json:"bearer_token"   validate:"omitempty,min=8"`
	EnabledEvents []string `json:"enabled_events" validate:"omitempty,min=1,dive,oneof=user.created user.updated user.deactivated group.created group.updated group.deleted"`
	IsActive      *bool    `json:"is_active"`
}

// PATCH /api/v1/organizations/:org_id/scim-push/:id
func (h *ScimPushHandler) Update(c echo.Context) error {
	ctx, span := tracing.Tracer("clavex/handler").Start(c.Request().Context(), "handler.scim_push.update")
	defer span.End()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	span.SetAttributes(
		attribute.String("org_id", orgID.String()),
		attribute.String("scim_push_id", id.String()),
	)
	var req updateScimPushRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	cfg, err := h.repo.Update(ctx, orgID, id, repository.UpdateScimPushParams{
		Name:          req.Name,
		EndpointURL:   req.EndpointURL,
		BearerToken:   req.BearerToken,
		EnabledEvents: req.EnabledEvents,
		IsActive:      req.IsActive,
	})
	if err != nil {
		span.SetStatus(otelcodes.Error, "not found")
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, cfg)
}

// DELETE /api/v1/organizations/:org_id/scim-push/:id
func (h *ScimPushHandler) Delete(c echo.Context) error {
	ctx, span := tracing.Tracer("clavex/handler").Start(c.Request().Context(), "handler.scim_push.delete")
	defer span.End()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	span.SetAttributes(
		attribute.String("org_id", orgID.String()),
		attribute.String("scim_push_id", id.String()),
	)
	if err := h.repo.Delete(ctx, orgID, id); err != nil {
		span.SetStatus(otelcodes.Error, "not found")
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Delivery log ─────────────────────────────────────────────────────────────

// ListDeliveries returns the recent delivery log for a SCIM push config.
// GET /api/v1/organizations/:org_id/scim-push/:id/deliveries?limit=50
func (h *ScimPushHandler) ListDeliveries(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	limit := 50
	if l := c.QueryParam("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	deliveries, err := h.deliveryRepo.ListDeliveries(c.Request().Context(), id, limit)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if deliveries == nil {
		deliveries = []*models.ScimPushDelivery{}
	}
	return c.JSON(http.StatusOK, deliveries)
}

// RetryDelivery replays a failed delivery by re-fetching the subject and calling Push.
// POST /api/v1/organizations/:org_id/scim-push/:id/deliveries/:did/retry
func (h *ScimPushHandler) RetryDelivery(c echo.Context) error {
	if h.pusher == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "pusher not configured")
	}
	didStr := c.Param("did")
	did, err := strconv.ParseInt(didStr, 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid delivery id")
	}
	ctx := c.Request().Context()
	delivery, err := h.deliveryRepo.GetDelivery(ctx, did)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "delivery not found")
	}
	// Look up config to get org_id.
	cfg, err := h.repo.GetByID(ctx, delivery.ConfigID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "config not found")
	}
	if delivery.SubjectID == nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "subject no longer available")
	}
	// Replay — push will record a fresh delivery entry.
	switch delivery.SubjectType {
	case "user":
		go h.pusher.PushByUserID(ctx, cfg.OrgID, delivery.Event, *delivery.SubjectID)
	case "group":
		go h.pusher.PushByGroupID(ctx, cfg.OrgID, delivery.Event, *delivery.SubjectID)
	default:
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "unknown subject type")
	}
	return c.JSON(http.StatusAccepted, map[string]string{"status": "retry_queued"})
}

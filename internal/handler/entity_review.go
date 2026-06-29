package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// EntityReviewHandler serves the Object Lifecycle Management entity review API.
type EntityReviewHandler struct {
	repo *repository.EntityReviewRepository
}

func NewEntityReviewHandler(pool *pgxpool.Pool) *EntityReviewHandler {
	return &EntityReviewHandler{repo: repository.NewEntityReviewRepository(pool)}
}

func (h *EntityReviewHandler) ListCampaigns(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	campaigns, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if campaigns == nil {
		campaigns = []*models.EntityReviewCampaign{}
	}
	for _, camp := range campaigns {
		counts, _ := h.repo.GetCampaignCounts(c.Request().Context(), camp.ID)
		camp.TotalItems = counts.Total
		camp.PendingItems = counts.Pending
		camp.ConfirmedItems = counts.Confirmed
		camp.DeprecatedItems = counts.Deprecated
	}
	return c.JSON(http.StatusOK, campaigns)
}

type createEntityReviewCampaignRequest struct {
	Name          string  `json:"name"`
	Description   *string `json:"description"`
	EntityType    string  `json:"entity_type"`
	FrequencyDays int     `json:"frequency_days"`
	StartsAt      *string `json:"starts_at"`
	EndsAt        string  `json:"ends_at"`
	ReminderDays  []int   `json:"reminder_days"`
	AutoDisable   *bool   `json:"auto_disable"`
	ReviewerID    string  `json:"reviewer_id"`
}

func (h *EntityReviewHandler) CreateCampaign(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createEntityReviewCampaignRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	if req.EntityType != "client" && req.EntityType != "group" && req.EntityType != "role" {
		return echo.NewHTTPError(http.StatusBadRequest, "entity_type must be client, group, or role")
	}
	if req.EndsAt == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ends_at is required")
	}
	if req.ReviewerID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "reviewer_id is required")
	}
	reviewerID, err := uuid.Parse(req.ReviewerID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid reviewer_id")
	}
	endsAt, err := time.Parse(time.RFC3339, req.EndsAt)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "ends_at must be RFC3339")
	}
	startsAt := time.Now().UTC()
	if req.StartsAt != nil && *req.StartsAt != "" {
		if t, parseErr := time.Parse(time.RFC3339, *req.StartsAt); parseErr == nil {
			startsAt = t
		}
	}
	autoDisable := true
	if req.AutoDisable != nil {
		autoDisable = *req.AutoDisable
	}
	freqDays := req.FrequencyDays
	if freqDays < 0 {
		freqDays = 0
	}
	callerID, _ := erCallerUserID(c)
	var createdBy *uuid.UUID
	if callerID != uuid.Nil {
		createdBy = &callerID
	}
	ctx := c.Request().Context()
	campaign, err := h.repo.Create(ctx, repository.CreateEntityReviewCampaignParams{
		OrgID:         orgID,
		Name:          req.Name,
		Description:   req.Description,
		EntityType:    req.EntityType,
		FrequencyDays: freqDays,
		StartsAt:      startsAt,
		EndsAt:        endsAt,
		ReminderDays:  req.ReminderDays,
		AutoDisable:   autoDisable,
		CreatedBy:     createdBy,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	if startsAt.Before(time.Now().Add(time.Minute)) {
		if err := h.generateItems(ctx, campaign, orgID, reviewerID); err != nil {
			c.Logger().Warnf("entity-review: generate items failed: %v", err)
		} else {
			_ = h.repo.UpdateStatus(ctx, orgID, campaign.ID, "active")
			campaign.Status = "active"
		}
	}
	return c.JSON(http.StatusCreated, campaign)
}

func (h *EntityReviewHandler) GetCampaign(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	campID, err := uuidParam(c, "campaign_id")
	if err != nil {
		return err
	}
	camp, err := h.repo.GetByID(c.Request().Context(), orgID, campID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "campaign not found")
	}
	counts, _ := h.repo.GetCampaignCounts(c.Request().Context(), campID)
	camp.TotalItems = counts.Total
	camp.PendingItems = counts.Pending
	camp.ConfirmedItems = counts.Confirmed
	camp.DeprecatedItems = counts.Deprecated
	return c.JSON(http.StatusOK, camp)
}

func (h *EntityReviewHandler) CancelCampaign(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	campID, err := uuidParam(c, "campaign_id")
	if err != nil {
		return err
	}
	if err := h.repo.UpdateStatus(c.Request().Context(), orgID, campID, "cancelled"); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

type activateEntityReviewRequest struct {
	ReviewerID string `json:"reviewer_id"`
}

func (h *EntityReviewHandler) ActivateCampaign(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	campID, err := uuidParam(c, "campaign_id")
	if err != nil {
		return err
	}
	var req activateEntityReviewRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	reviewerID, err := uuid.Parse(req.ReviewerID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid reviewer_id")
	}
	ctx := c.Request().Context()
	camp, err := h.repo.GetByID(ctx, orgID, campID)
	if err != nil || camp == nil {
		return echo.NewHTTPError(http.StatusNotFound, "campaign not found")
	}
	if camp.Status != "pending" {
		return echo.NewHTTPError(http.StatusConflict, "campaign is not in pending state")
	}
	if err := h.generateItems(ctx, camp, orgID, reviewerID); err != nil {
		return echo.ErrInternalServerError
	}
	if err := h.repo.UpdateStatus(ctx, orgID, campID, "active"); err != nil {
		return echo.ErrInternalServerError
	}
	camp.Status = "active"
	return c.JSON(http.StatusOK, camp)
}

func (h *EntityReviewHandler) ListItems(c echo.Context) error {
	campID, err := uuidParam(c, "campaign_id")
	if err != nil {
		return err
	}
	items, err := h.repo.ListItemsByCampaign(c.Request().Context(), campID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if items == nil {
		items = []*models.EntityReviewItem{}
	}
	return c.JSON(http.StatusOK, items)
}

type entityReviewDecisionRequest struct {
	Token    string  `json:"token"`
	Decision string  `json:"decision"`
	Comment  *string `json:"comment"`
}

func (h *EntityReviewHandler) Decide(c echo.Context) error {
	var req entityReviewDecisionRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "token is required")
	}
	if req.Decision != "confirmed" && req.Decision != "deprecated" {
		return echo.NewHTTPError(http.StatusBadRequest, "decision must be confirmed or deprecated")
	}
	comment := ""
	if req.Comment != nil {
		comment = *req.Comment
	}
	item, err := h.repo.DecideItem(c.Request().Context(), req.Token, req.Decision, comment)
	if err != nil || item == nil {
		return echo.NewHTTPError(http.StatusNotFound, "review item not found or already decided")
	}
	return c.JSON(http.StatusOK, item)
}

func (h *EntityReviewHandler) generateItems(ctx context.Context, camp *models.EntityReviewCampaign, orgID, reviewerID uuid.UUID) error {
	switch camp.EntityType {
	case "client":
		clients, err := h.repo.ListClientsForOrg(ctx, orgID)
		if err != nil {
			return err
		}
		for _, cl := range clients {
			_ = h.repo.UpsertItem(ctx, repository.CreateEntityReviewItemParams{
				CampaignID: camp.ID, OrgID: orgID,
				EntityType: "client", EntityID: cl.ID, EntityName: cl.Name, ReviewerID: reviewerID,
			})
		}
	case "group":
		groups, err := h.repo.ListGroupsForOrg(ctx, orgID)
		if err != nil {
			return err
		}
		for _, g := range groups {
			_ = h.repo.UpsertItem(ctx, repository.CreateEntityReviewItemParams{
				CampaignID: camp.ID, OrgID: orgID,
				EntityType: "group", EntityID: g.ID.String(), EntityName: g.Name, ReviewerID: reviewerID,
			})
		}
	case "role":
		roles, err := h.repo.ListRolesForOrg(ctx, orgID)
		if err != nil {
			return err
		}
		for _, r := range roles {
			_ = h.repo.UpsertItem(ctx, repository.CreateEntityReviewItemParams{
				CampaignID: camp.ID, OrgID: orgID,
				EntityType: "role", EntityID: r.ID.String(), EntityName: r.Name, ReviewerID: reviewerID,
			})
		}
	}
	return nil
}

func erCallerUserID(c echo.Context) (uuid.UUID, bool) {
	v := c.Get("user_id")
	if v == nil {
		return uuid.Nil, false
	}
	switch id := v.(type) {
	case uuid.UUID:
		return id, true
	case string:
		if u, err := uuid.Parse(id); err == nil {
			return u, true
		}
	}
	return uuid.Nil, false
}

package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// AccessReviewHandler manages access certification campaign APIs.
type AccessReviewHandler struct {
	repo     *repository.AccessReviewRepository
	smtpRepo *repository.SMTPRepository
	baseURL  string
}

func NewAccessReviewHandler(pool *pgxpool.Pool, baseURL string) *AccessReviewHandler {
	return &AccessReviewHandler{
		repo:     repository.NewAccessReviewRepository(pool),
		smtpRepo: repository.NewSMTPRepository(pool),
		baseURL:  baseURL,
	}
}

// ── List campaigns ────────────────────────────────────────────────────────────

// GET /api/v1/organizations/:org_id/access-reviews
func (h *AccessReviewHandler) List(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	campaigns, err := h.repo.ListCampaigns(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if campaigns == nil {
		campaigns = []*models.AccessReviewCampaign{}
	}
	return c.JSON(http.StatusOK, campaigns)
}

// ── Get campaign ──────────────────────────────────────────────────────────────

// GET /api/v1/organizations/:org_id/access-reviews/:campaign_id
func (h *AccessReviewHandler) Get(c echo.Context) error {
	orgID, campaignID, err := h.parseCampaignParams(c)
	if err != nil {
		return err
	}
	campaign, err := h.repo.GetCampaign(c.Request().Context(), orgID, campaignID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "campaign not found")
		}
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, campaign)
}

// ── Create campaign ───────────────────────────────────────────────────────────

type createCampaignRequest struct {
	Name         string    `json:"name"`
	Description  *string   `json:"description"`
	Frequency    string    `json:"frequency"`
	StartsAt     time.Time `json:"starts_at"`
	EndsAt       time.Time `json:"ends_at"`
	ReminderDays []int     `json:"reminder_days"`
	AutoRevoke   bool      `json:"auto_revoke"`
}

// POST /api/v1/organizations/:org_id/access-reviews
func (h *AccessReviewHandler) Create(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	var req createCampaignRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	freq := req.Frequency
	if freq == "" {
		freq = "quarterly"
	}
	validFrequencies := map[string]bool{"monthly": true, "quarterly": true, "annual": true, "one_time": true}
	if !validFrequencies[freq] {
		return echo.NewHTTPError(http.StatusBadRequest, "frequency must be monthly, quarterly, annual, or one_time")
	}
	if req.StartsAt.IsZero() || req.EndsAt.IsZero() {
		return echo.NewHTTPError(http.StatusBadRequest, "starts_at and ends_at are required")
	}
	if !req.EndsAt.After(req.StartsAt) {
		return echo.NewHTTPError(http.StatusBadRequest, "ends_at must be after starts_at")
	}
	reminderDays := req.ReminderDays
	if len(reminderDays) == 0 {
		reminderDays = []int{3, 1}
	}

	// Extract creator from the JWT claim stored by auth middleware.
	createdBy := extractCallerUserID(c)

	campaign, err := h.repo.CreateCampaign(c.Request().Context(), repository.CreateCampaignParams{
		OrgID:        orgID,
		Name:         req.Name,
		Description:  req.Description,
		Frequency:    freq,
		StartsAt:     req.StartsAt,
		EndsAt:       req.EndsAt,
		ReminderDays: reminderDays,
		AutoRevoke:   req.AutoRevoke,
		CreatedBy:    createdBy,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, campaign)
}

// ── Launch campaign ───────────────────────────────────────────────────────────

// POST /api/v1/organizations/:org_id/access-reviews/:campaign_id/launch
// Activates a pending campaign immediately, generates items, and sends initial emails.
func (h *AccessReviewHandler) Launch(c echo.Context) error {
	orgID, campaignID, err := h.parseCampaignParams(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	campaign, err := h.repo.GetCampaign(ctx, orgID, campaignID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "campaign not found")
		}
		return echo.ErrInternalServerError
	}
	if campaign.Status != "pending" {
		return echo.NewHTTPError(http.StatusConflict, "only pending campaigns can be launched")
	}

	// Activate
	if err := h.repo.UpdateCampaignStatus(ctx, orgID, campaignID, "active"); err != nil {
		return echo.ErrInternalServerError
	}
	campaign.Status = "active"

	// Generate items (user × role for the org)
	assignments, err := h.repo.ListUserRoleAssignmentsForOrg(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	// For admin-launched campaigns we need at least one reviewer.
	// Items with reviewer = campaign creator are generated; admins re-assign via API.
	var reviewerID uuid.UUID
	if cb := campaign.CreatedBy; cb != nil {
		reviewerID = *cb
	}
	if reviewerID == uuid.Nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "campaign has no created_by; cannot determine default reviewer")
	}

	params := make([]repository.CreateItemParams, 0, len(assignments))
	for _, a := range assignments {
		params = append(params, repository.CreateItemParams{
			CampaignID: campaignID,
			OrgID:      orgID,
			UserID:     a.UserID,
			RoleID:     a.RoleID,
			ReviewerID: reviewerID,
		})
	}
	if err := h.repo.BulkCreateItems(ctx, params); err != nil {
		return echo.ErrInternalServerError
	}

	// Fetch generated items (with denormalised fields) and send initial emails.
	items, err := h.repo.ListItems(ctx, campaignID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	go h.sendInitialEmails(items, campaign, orgID)

	campaign.TotalItems = len(items)
	campaign.PendingItems = len(items)
	return c.JSON(http.StatusOK, campaign)
}

func (h *AccessReviewHandler) sendInitialEmails(
	items []*models.AccessReviewItem,
	campaign *models.AccessReviewCampaign,
	orgID uuid.UUID,
) {
	ctx := context.Background() //nolint:all — background ctx intentional for goroutine
	m, err := mailer.ForOrg(ctx, h.smtpRepo, orgID)
	if err != nil {
		return
	}

	// Group by reviewer to send one email per reviewer.
	byReviewer := map[uuid.UUID][]*models.AccessReviewItem{}
	for _, item := range items {
		byReviewer[item.ReviewerID] = append(byReviewer[item.ReviewerID], item)
	}
	for _, batch := range byReviewer {
		subject := "[Action Required] Access Review: certify your team's access"
		body := buildInitialReviewEmailHTML(batch, campaign, h.baseURL)
		_ = m.Send(batch[0].ReviewerEmail, subject, body)
	}
}

// ── Cancel campaign ───────────────────────────────────────────────────────────

// DELETE /api/v1/organizations/:org_id/access-reviews/:campaign_id
func (h *AccessReviewHandler) Cancel(c echo.Context) error {
	orgID, campaignID, err := h.parseCampaignParams(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	campaign, err := h.repo.GetCampaign(ctx, orgID, campaignID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "campaign not found")
		}
		return echo.ErrInternalServerError
	}
	if campaign.Status == "completed" {
		return echo.NewHTTPError(http.StatusConflict, "completed campaigns cannot be cancelled")
	}
	if err := h.repo.UpdateCampaignStatus(ctx, orgID, campaignID, "cancelled"); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── List items (admin) ────────────────────────────────────────────────────────

// GET /api/v1/organizations/:org_id/access-reviews/:campaign_id/items
func (h *AccessReviewHandler) ListItems(c echo.Context) error {
	_, campaignID, err := h.parseCampaignParams(c)
	if err != nil {
		return err
	}
	items, err := h.repo.ListItems(c.Request().Context(), campaignID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if items == nil {
		items = []*models.AccessReviewItem{}
	}
	return c.JSON(http.StatusOK, items)
}

// ── Audit report ─────────────────────────────────────────────────────────────

type auditReportResponse struct {
	Campaign *models.AccessReviewCampaign `json:"campaign"`
	Items    []*models.AccessReviewItem   `json:"items"`
	Summary  map[string]int               `json:"summary"`
}

// GET /api/v1/organizations/:org_id/access-reviews/:campaign_id/report
func (h *AccessReviewHandler) Report(c echo.Context) error {
	orgID, campaignID, err := h.parseCampaignParams(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	campaign, err := h.repo.GetCampaign(ctx, orgID, campaignID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "campaign not found")
		}
		return echo.ErrInternalServerError
	}
	items, err := h.repo.ListItems(ctx, campaignID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	summary := map[string]int{
		"total": len(items), "pending": 0, "approved": 0, "revoked": 0, "auto_revoked": 0,
	}
	for _, item := range items {
		summary[item.Decision]++
	}
	return c.JSON(http.StatusOK, auditReportResponse{
		Campaign: campaign,
		Items:    items,
		Summary:  summary,
	})
}

// ── One-time decision endpoint (public, no JWT) ───────────────────────────────

// GET /:org_slug/access-review/decide?token=XXX&decision=approved|revoked
// This is the link sent in review emails. No authentication required —
// the token itself is the proof of authorization.
func (h *AccessReviewHandler) Decide(c echo.Context) error {
	token := c.QueryParam("token")
	decision := c.QueryParam("decision")

	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "token is required")
	}
	if decision != "approved" && decision != "revoked" {
		return echo.NewHTTPError(http.StatusBadRequest, "decision must be 'approved' or 'revoked'")
	}

	ctx := c.Request().Context()
	item, err := h.repo.GetItemByToken(ctx, token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "token not found or already used")
		}
		return echo.ErrInternalServerError
	}
	if item.Decision != "pending" {
		return echo.NewHTTPError(http.StatusConflict, "decision already recorded")
	}

	comment := c.QueryParam("comment")
	updated, err := h.repo.DecideItem(ctx, token, decision, comment)
	if err != nil {
		return echo.ErrInternalServerError
	}
	// Propagate reviewer fields from prefetched item (DecideItem only returns base fields).
	updated.UserEmail = item.UserEmail
	updated.UserName = item.UserName
	updated.RoleName = item.RoleName
	updated.ReviewerEmail = item.ReviewerEmail

	// Notify the reviewer by email.
	go func() {
		m, err := mailer.ForOrg(ctx, h.smtpRepo, updated.OrgID)
		if err != nil {
			return
		}
		body := worker.BuildDecisionConfirmationEmailHTML(updated)
		subject := "[Access Review] Decision recorded"
		_ = m.Send(updated.ReviewerEmail, subject, body)
	}()

	return c.JSON(http.StatusOK, map[string]string{
		"message":  "Decision recorded",
		"decision": updated.Decision,
		"user":     updated.UserName,
		"role":     updated.RoleName,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *AccessReviewHandler) parseCampaignParams(c echo.Context) (uuid.UUID, uuid.UUID, error) {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	campaignID, err := uuid.Parse(c.Param("campaign_id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "invalid campaign_id")
	}
	return orgID, campaignID, nil
}

// extractCallerUserID reads the authenticated user's UUID from the Echo context
// (set by the JWT middleware). Returns nil if not present.
func extractCallerUserID(c echo.Context) *uuid.UUID {
	sub, ok := c.Get("user_id").(string)
	if !ok || sub == "" {
		return nil
	}
	id, err := uuid.Parse(sub)
	if err != nil {
		return nil
	}
	return &id
}

func buildInitialReviewEmailHTML(
	items []*models.AccessReviewItem,
	campaign *models.AccessReviewCampaign,
	baseURL string,
) string {
	rows := ""
	for _, item := range items {
		approveURL := baseURL + "/access-review/decide?token=" + item.Token + "&decision=approved"
		revokeURL := baseURL + "/access-review/decide?token=" + item.Token + "&decision=revoked"
		rows += fmt.Sprintf(`
		<tr>
		  <td style="padding:8px;border-bottom:1px solid #eee">%s</td>
		  <td style="padding:8px;border-bottom:1px solid #eee">%s</td>
		  <td style="padding:8px;border-bottom:1px solid #eee">%s</td>
		  <td style="padding:8px;border-bottom:1px solid #eee">
		    <a href="%s" style="background:#16a34a;color:#fff;padding:5px 12px;border-radius:4px;text-decoration:none;margin-right:6px">Approve</a>
		    <a href="%s" style="background:#dc2626;color:#fff;padding:5px 12px;border-radius:4px;text-decoration:none">Revoke</a>
		  </td>
		</tr>`,
			item.UserName, item.UserEmail, item.RoleName,
			approveURL, revokeURL,
		)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;color:#111;max-width:700px;margin:0 auto">
<h2 style="border-bottom:2px solid #4f46e5;padding-bottom:8px">Access Review Campaign: %s</h2>
<p>You have been assigned as reviewer for the following access certifications.
   Please review each item and approve or revoke access before <strong>%s</strong>.</p>
<table style="width:100%%;border-collapse:collapse">
  <thead><tr style="background:#f3f4f6">
    <th style="padding:8px;text-align:left">User</th>
    <th style="padding:8px;text-align:left">Email</th>
    <th style="padding:8px;text-align:left">Role</th>
    <th style="padding:8px;text-align:left">Decision</th>
  </tr></thead>
  <tbody>%s</tbody>
</table>
<p style="color:#6b7280;font-size:12px;margin-top:24px">
  These links are single-use. If you have already decided, you may disregard this email.
</p>
</body></html>`,
		campaign.Name,
		campaign.EndsAt.Format("2 January 2006"),
		rows,
	)
}

package handler

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// acceptInvitationForm renders the public invitation-acceptance form. html/template
// context-escapes OrgID and Token, closing the reflected-XSS vector on the token.
var acceptInvitationForm = template.Must(template.New("accept-invitation").Parse(
	`<!DOCTYPE html><html><head><title>Accept Invitation</title></head><body>
<h2>Accept Invitation</h2>
<p>You have been invited to join {{.OrgID}}.</p>
<form method="POST">
<input type="hidden" name="token" value="{{.Token}}">
<label>First name: <input name="first_name" required></label><br>
<label>Last name: <input name="last_name" required></label><br>
<label>Password: <input type="password" name="password" required></label><br>
<button type="submit">Accept</button>
</form></body></html>`))

// InvitationHandler manages org invitations.
type InvitationHandler struct {
	invitations *repository.InvitationRepository
	orgs        *repository.OrgRepository
	smtp        *repository.SMTPRepository
}

func NewInvitationHandler(pool *pgxpool.Pool) *InvitationHandler {
	return &InvitationHandler{
		invitations: repository.NewInvitationRepository(pool),
		orgs:        repository.NewOrgRepository(pool),
		smtp:        repository.NewSMTPRepository(pool),
	}
}

// List returns all pending invitations for an org.
// GET /api/v1/organizations/:org_id/invitations
func (h *InvitationHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	invs, err := h.invitations.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, invs)
}

type createInvitationRequest struct {
	Email  string     `json:"email"   validate:"required,email"`
	RoleID *uuid.UUID `json:"role_id"`
}

// Create issues an invitation and sends an email.
// POST /api/v1/organizations/:org_id/invitations
func (h *InvitationHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	var req createInvitationRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}
	if err := validate.Struct(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	claims := middleware.GetClaims(c)
	var invitedBy *uuid.UUID
	if claims != nil && claims.Subject != "" {
		id, parseErr := uuid.Parse(claims.Subject)
		if parseErr == nil {
			invitedBy = &id
		}
	}

	inv, rawToken, err := h.invitations.Create(c.Request().Context(), orgID, strings.ToLower(req.Email), req.RoleID, invitedBy)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Attempt to send invitation email — non-fatal if SMTP not configured.
	go func() {
		org, oErr := h.orgs.GetByID(c.Request().Context(), orgID)
		if oErr != nil {
			return
		}
		m, mErr := mailer.ForOrg(c.Request().Context(), h.smtp, orgID)
		if mErr != nil {
			return
		}
		inviteURL := c.Scheme() + "://" + c.Request().Host + "/" + org.Slug + "/invite/accept?token=" + rawToken
		body := "<p>You have been invited to join <b>" + org.Name + "</b>.</p><p><a href=\"" + inviteURL + "\">Accept Invitation</a></p><p>This link expires at " + inv.ExpiresAt.Format("2006-01-02 15:04 UTC") + ".</p>"
		_ = m.Send(inv.Email, "You're invited to join "+org.Name, body)
	}()

	return c.JSON(http.StatusCreated, inv)
}

// Delete revokes an invitation.
// DELETE /api/v1/organizations/:org_id/invitations/:id
func (h *InvitationHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	invID, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.invitations.Delete(c.Request().Context(), invID, orgID); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "invitation not found")
	}
	return c.NoContent(http.StatusNoContent)
}

// ShowAcceptPage renders a simple HTML page for accepting an invitation.
// GET /:org_slug/invite/accept?token=...
func (h *InvitationHandler) ShowAcceptPage(c echo.Context) error {
	token := c.QueryParam("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing token")
	}
	inv, err := h.invitations.GetByToken(c.Request().Context(), token)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "invitation not found or expired")
	}
	if inv.AcceptedAt != nil {
		return echo.NewHTTPError(http.StatusGone, "invitation already accepted")
	}

	// Render a minimal HTML form. Use html/template so the reflected token and
	// org id are context-escaped (prevents reflected XSS, CWE-79).
	var buf strings.Builder
	if err := acceptInvitationForm.Execute(&buf, map[string]string{
		"OrgID": inv.OrgID.String(),
		"Token": token,
	}); err != nil {
		return echo.ErrInternalServerError
	}
	return c.HTML(http.StatusOK, buf.String())
}

type acceptInvitationRequest struct {
	Token     string  `form:"token"      json:"token"      validate:"required"`
	FirstName *string `form:"first_name" json:"first_name"`
	LastName  *string `form:"last_name"  json:"last_name"`
	Password  *string `form:"password"   json:"password"`
}

// Accept processes the invitation acceptance form.
// POST /:org_slug/invite/accept
func (h *InvitationHandler) Accept(c echo.Context) error {
	var req acceptInvitationRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}
	if err := validate.Struct(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	inv, err := h.invitations.GetByToken(c.Request().Context(), req.Token)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "invitation not found or expired")
	}
	if inv.AcceptedAt != nil {
		return echo.NewHTTPError(http.StatusGone, "invitation already accepted")
	}

	user, err := h.invitations.Accept(c.Request().Context(), inv, req.FirstName, req.LastName, req.Password)
	if err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Invitation accepted",
		"user_id": user.ID,
		"email":   user.Email,
	})
}

package handler

import (
	"html/template"
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// maxCustomLoginHTMLBytes caps the custom template at 256 KB — large enough
// for a full page with inline CSS/JS but small enough to prevent DB abuse.
const maxCustomLoginHTMLBytes = 256 * 1024

// LoginTemplateHandler manages the per-org custom Universal Login page.
type LoginTemplateHandler struct {
	orgs *repository.OrgRepository
}

func NewLoginTemplateHandler(pool *pgxpool.Pool) *LoginTemplateHandler {
	return &LoginTemplateHandler{orgs: repository.NewOrgRepository(pool)}
}

type loginTemplateResponse struct {
	HasCustomTemplate bool    `json:"has_custom_template"`
	// Preview is the first 512 bytes of the template, useful for the admin
	// console to show a snippet without transferring the full document.
	Preview           *string `json:"preview,omitempty"`
}

// GET /api/v1/organizations/:org_id/login-template
func (h *LoginTemplateHandler) Get(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	html, err := h.orgs.GetCustomLoginHTML(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	resp := loginTemplateResponse{HasCustomTemplate: html != nil && *html != ""}
	if html != nil && *html != "" {
		preview := *html
		if len(preview) > 512 {
			preview = preview[:512]
		}
		resp.Preview = &preview
	}
	return c.JSON(http.StatusOK, resp)
}

type setLoginTemplateRequest struct {
	// HTML is the full custom login template (Go html/template syntax).
	// Set to null or empty string to revert to the built-in login page.
	HTML *string `json:"html"`
}

// PUT /api/v1/organizations/:org_id/login-template
func (h *LoginTemplateHandler) Put(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	var body setLoginTemplateRequest
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	// Treat empty HTML as a delete.
	if body.HTML == nil || *body.HTML == "" {
		if err := h.orgs.SetCustomLoginHTML(c.Request().Context(), orgID, nil); err != nil {
			return echo.ErrInternalServerError
		}
		return c.JSON(http.StatusOK, loginTemplateResponse{HasCustomTemplate: false})
	}

	html := *body.HTML

	// Size guard.
	if len(html) > maxCustomLoginHTMLBytes {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge,
			"custom_login_html exceeds 256 KB limit")
	}

	// Validate: must be a parseable Go html/template.
	// This catches syntax errors immediately so the admin gets fast feedback
	// rather than silently breaking the login page.
	if _, parseErr := template.New("validate").Parse(html); parseErr != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity,
			"template parse error: "+parseErr.Error())
	}

	if err := h.orgs.SetCustomLoginHTML(c.Request().Context(), orgID, &html); err != nil {
		return echo.ErrInternalServerError
	}

	preview := html
	if len(preview) > 512 {
		preview = preview[:512]
	}
	resp := loginTemplateResponse{HasCustomTemplate: true, Preview: &preview}
	return c.JSON(http.StatusOK, resp)
}

// DELETE /api/v1/organizations/:org_id/login-template
func (h *LoginTemplateHandler) Delete(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	if err := h.orgs.SetCustomLoginHTML(c.Request().Context(), orgID, nil); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// GET /api/v1/organizations/:org_id/login-template/raw
// Returns the full custom HTML as text/html for preview in an iframe.
func (h *LoginTemplateHandler) GetRaw(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	html, err := h.orgs.GetCustomLoginHTML(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if html == nil || *html == "" {
		return echo.NewHTTPError(http.StatusNotFound, "no custom login template set")
	}

	c.Response().Header().Set("Content-Type", "text/plain; charset=utf-8")
	return c.String(http.StatusOK, *html)
}

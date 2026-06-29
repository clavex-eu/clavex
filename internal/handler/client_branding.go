package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ClientBrandingHandler manages per-OIDC-client branding overrides.
type ClientBrandingHandler struct {
	clientBranding *repository.ClientBrandingRepository
	orgBranding    *repository.BrandingRepository
	clients        *repository.ClientRepository
}

func NewClientBrandingHandler(pool *pgxpool.Pool) *ClientBrandingHandler {
	return &ClientBrandingHandler{
		clientBranding: repository.NewClientBrandingRepository(pool),
		orgBranding:    repository.NewBrandingRepository(pool),
		clients:        repository.NewClientRepository(pool),
	}
}

// Get returns the branding override for a specific OIDC client.
// GET /api/v1/organizations/:org_id/clients/:client_id/branding
func (h *ClientBrandingHandler) Get(c echo.Context) error {
	if _, err := uuid.Parse(c.Param("org_id")); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	clientID := c.Param("client_id")

	b, err := h.clientBranding.Get(c.Request().Context(), clientID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if b == nil {
		return c.JSON(http.StatusOK, &models.ClientBranding{ClientID: clientID})
	}
	return c.JSON(http.StatusOK, b)
}

// Put creates or updates per-client branding.
// PUT /api/v1/organizations/:org_id/clients/:client_id/branding
func (h *ClientBrandingHandler) Put(c echo.Context) error {
	if _, err := uuid.Parse(c.Param("org_id")); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	clientID := c.Param("client_id")

	var req models.ClientBranding
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	req.ClientID = clientID

	out, err := h.clientBranding.Upsert(c.Request().Context(), &req)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, out)
}

// Delete removes the per-client branding override (falls back to org branding).
// DELETE /api/v1/organizations/:org_id/clients/:client_id/branding
func (h *ClientBrandingHandler) Delete(c echo.Context) error {
	if _, err := uuid.Parse(c.Param("org_id")); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	clientID := c.Param("client_id")
	if err := h.clientBranding.Delete(c.Request().Context(), clientID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Cascade resolution ────────────────────────────────────────────────────────

// BrandingCascadeResponse is the merged branding returned by the public cascade endpoint.
type BrandingCascadeResponse struct {
	CompanyName  *string `json:"company_name,omitempty"`
	LogoURL      *string `json:"logo_url,omitempty"`
	FaviconURL   *string `json:"favicon_url,omitempty"`
	PrimaryColor string  `json:"primary_color"`
	BgColor      string  `json:"bg_color"`
	TextColor    string  `json:"text_color"`
	WelcomeTitle string  `json:"welcome_title"`
	Source       string  `json:"source"` // "client" | "org" | "default"
}

// ResolveBranding returns the effective branding for a login page using the
// cascade: client branding → org branding → built-in defaults.
// GET /api/v1/branding?client_id=&org_id=
func (h *ClientBrandingHandler) ResolveBranding(c echo.Context) error {
	ctx := c.Request().Context()
	clientID := c.QueryParam("client_id")
	orgIDStr := c.QueryParam("org_id")

	// Defaults
	resp := &BrandingCascadeResponse{
		PrimaryColor: "#4F46E5",
		BgColor:      "#F9FAFB",
		TextColor:    "#111827",
		WelcomeTitle: "Sign in to your account",
		Source:       "default",
	}

	// Layer 2: org branding
	if orgIDStr != "" {
		if orgID, err := uuid.Parse(orgIDStr); err == nil {
			if ob, err := h.orgBranding.Get(ctx, orgID); err == nil && ob != nil {
				resp.CompanyName = ob.CompanyName
				resp.LogoURL = ob.LogoURL
				resp.FaviconURL = ob.FaviconURL
				resp.PrimaryColor = ob.PrimaryColor
				resp.BgColor = ob.BgColor
				resp.TextColor = ob.TextColor
				resp.WelcomeTitle = ob.WelcomeTitle
				resp.Source = "org"
			}
		}
	}

	// Layer 1 (highest priority): client branding override
	if clientID != "" {
		if cb, err := h.clientBranding.Get(ctx, clientID); err == nil && cb != nil {
			if cb.CompanyName != nil {
				resp.CompanyName = cb.CompanyName
			}
			if cb.LogoURL != nil {
				resp.LogoURL = cb.LogoURL
			}
			if cb.PrimaryColor != nil {
				resp.PrimaryColor = *cb.PrimaryColor
			}
			resp.Source = "client"
		}
	}

	return c.JSON(http.StatusOK, resp)
}

package handler

import (
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// OrgHandler handles organization (tenant) CRUD.
type OrgHandler struct {
	pool    *pgxpool.Pool
	repo    *repository.OrgRepository
	posture *repository.SecurityPostureRepository
	flags   *repository.FeatureFlagRepository
}

func NewOrgHandler(pool *pgxpool.Pool) *OrgHandler {
	return &OrgHandler{
		pool:    pool,
		repo:    repository.NewOrgRepository(pool),
		posture: repository.NewSecurityPostureRepository(pool),
		flags:   repository.NewFeatureFlagRepository(pool),
	}
}

type createOrgRequest struct {
	Name    string  `json:"name"     validate:"required,min=1,max=120"`
	Slug    string  `json:"slug"     validate:"required,min=2,max=63,slug"`
	LogoURL *string `json:"logo_url" validate:"omitempty,url"`
}

func (h *OrgHandler) Create(c echo.Context) error {
	var req createOrgRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	org, err := h.repo.Create(c.Request().Context(), req.Name, req.Slug, req.LogoURL)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "organization slug already taken")
	}
	return c.JSON(http.StatusCreated, org)
}

func (h *OrgHandler) List(c echo.Context) error {
	orgs, err := h.repo.List(c.Request().Context())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, orgs)
}

func (h *OrgHandler) Get(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	org, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, org)
}

type updateOrgRequest struct {
	Name        *string `json:"name"              validate:"omitempty,min=1,max=120"`
	LogoURL     *string `json:"logo_url"          validate:"omitempty,url"`
	IsActive    *bool   `json:"is_active"`
	MFARequired *bool   `json:"mfa_required"`
	// AccessTokenTTL overrides the access token lifetime (seconds) for all clients in this org.
	// Pass 0 to clear the override and revert to the server default.
	AccessTokenTTL *int `json:"access_token_ttl"`
	// RefreshTokenTTL overrides the refresh token lifetime (seconds) for all clients in this org.
	// Pass 0 to clear the override and revert to the server default.
	RefreshTokenTTL *int `json:"refresh_token_ttl"`
}

func (h *OrgHandler) Update(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	var req updateOrgRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	org, err := h.repo.Update(c.Request().Context(), id, req.Name, req.LogoURL, req.IsActive, req.MFARequired, req.AccessTokenTTL, req.RefreshTokenTTL)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, org)
}

func (h *OrgHandler) Delete(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.Request().Context(), id); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// SecurityPosture returns the computed security posture score for an org.
// GET /api/v1/organizations/:id/security-posture
func (h *OrgHandler) SecurityPosture(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	p, err := h.posture.Compute(c.Request().Context(), id)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, p)
}

// SecurityPostureOrgAdmin returns the security posture for the calling org admin.
// GET /api/v1/organizations/:org_id/security-posture
func (h *OrgHandler) SecurityPostureOrgAdmin(c echo.Context) error {
	id, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	p, err := h.posture.Compute(c.Request().Context(), id)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, p)
}

// ── Provisioning (ISV bootstrap) ──────────────────────────────────────────────

type provisionSMTPRequest struct {
	Host        string  `json:"host"         validate:"required"`
	Port        int     `json:"port"         validate:"required,min=1,max=65535"`
	Username    *string `json:"username"`
	Password    string  `json:"password"`
	FromAddress string  `json:"from_address" validate:"required,email"`
	FromName    string  `json:"from_name"    validate:"required"`
	UseTLS      bool    `json:"use_tls"`
}

type provisionClientRequest struct {
	Name         string   `json:"name"          validate:"required"`
	RedirectURIs []string `json:"redirect_uris" validate:"required,min=1,dive,url"`
	IsPublic     bool     `json:"is_public"`
}

type provisionRequest struct {
	Name         string                  `json:"name"          validate:"required,min=1,max=120"`
	Slug         string                  `json:"slug"          validate:"required,min=2,max=63,slug"`
	AdminEmail   string                  `json:"admin_email"   validate:"required,email"`
	Plan         string                  `json:"plan"          validate:"required,oneof=community enterprise cloud"`
	TempPassword string                  `json:"temp_password"` // optional; generated if absent
	SMTP         *provisionSMTPRequest   `json:"smtp"`          // optional
	OIDCClient   *provisionClientRequest `json:"oidc_client"`   // optional
}

// Provision creates an org + admin user + rate limits + optional SMTP + OIDC client atomically.
// POST /api/v1/organizations/provision
func (h *OrgHandler) Provision(c echo.Context) error {
	var req provisionRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	params := repository.ProvisionParams{
		Name:         req.Name,
		Slug:         req.Slug,
		AdminEmail:   req.AdminEmail,
		Plan:         req.Plan,
		TempPassword: req.TempPassword,
	}

	if req.SMTP != nil {
		params.SMTP = &repository.ProvisionSMTP{
			Host:        req.SMTP.Host,
			Port:        req.SMTP.Port,
			Username:    req.SMTP.Username,
			Password:    req.SMTP.Password,
			FromAddress: req.SMTP.FromAddress,
			FromName:    req.SMTP.FromName,
			UseTLS:      req.SMTP.UseTLS,
		}
	}

	if req.OIDCClient != nil {
		params.OIDCClient = &repository.ProvisionClient{
			Name:         req.OIDCClient.Name,
			RedirectURIs: req.OIDCClient.RedirectURIs,
			IsPublic:     req.OIDCClient.IsPublic,
		}
	}

	result, err := repository.ProvisionOrg(c.Request().Context(), h.pool, params)
	if err != nil {
		// Slug conflict is the most common cause
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	}
	return c.JSON(http.StatusCreated, result)
}

// ── Email Policy ──────────────────────────────────────────────────────────────

type emailPolicyResponse struct {
	EmailBlocklist []string `json:"email_blocklist"`
	EmailAllowlist []string `json:"email_allowlist"`
}

// GetEmailPolicy returns the email domain blocklist/allowlist for an org.
// GET /api/v1/organizations/:id/email-policy
func (h *OrgHandler) GetEmailPolicy(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	blocklist, allowlist, err := h.repo.GetEmailPolicy(c.Request().Context(), id)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, emailPolicyResponse{
		EmailBlocklist: blocklist,
		EmailAllowlist: allowlist,
	})
}

type setEmailPolicyRequest struct {
	EmailBlocklist []string `json:"email_blocklist"`
	EmailAllowlist []string `json:"email_allowlist"`
}

// SetEmailPolicy updates the email domain blocklist/allowlist for an org.
// PUT /api/v1/organizations/:id/email-policy
func (h *OrgHandler) SetEmailPolicy(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	var req setEmailPolicyRequest
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}
	// Normalise: lowercase all entries.
	for i, d := range req.EmailBlocklist {
		req.EmailBlocklist[i] = strings.ToLower(strings.TrimSpace(d))
	}
	for i, d := range req.EmailAllowlist {
		req.EmailAllowlist[i] = strings.ToLower(strings.TrimSpace(d))
	}
	if err := h.repo.SetEmailPolicy(c.Request().Context(), id, req.EmailBlocklist, req.EmailAllowlist); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, emailPolicyResponse(req))
}

// ── Feature Flags ─────────────────────────────────────────────────────────────

type upsertFlagRequest struct {
	Key         string `json:"key"         validate:"required,min=1,max=64"`
	Description string `json:"description"`
	Value       bool   `json:"value"`
}

// ListFeatureFlags lists all feature flags for an org.
// GET /api/v1/organizations/:id/feature-flags
func (h *OrgHandler) ListFeatureFlags(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	flags, err := h.flags.List(c.Request().Context(), id)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if flags == nil {
		flags = []*models.FeatureFlag{}
	}
	return c.JSON(http.StatusOK, flags)
}

// UpsertFeatureFlag creates or updates a feature flag.
// POST /api/v1/organizations/:id/feature-flags
func (h *OrgHandler) UpsertFeatureFlag(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	var req upsertFlagRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	f, err := h.flags.Upsert(c.Request().Context(), id, req.Key, req.Description, req.Value)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, f)
}

// DeleteFeatureFlag removes a feature flag and all its overrides.
// DELETE /api/v1/organizations/:id/feature-flags/:key
func (h *OrgHandler) DeleteFeatureFlag(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	key := c.Param("key")
	if key == "" {
		return echo.ErrBadRequest
	}
	if err := h.flags.Delete(c.Request().Context(), id, key); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ListFlagOverrides lists all overrides for a flag.
// GET /api/v1/organizations/:id/feature-flags/:key/overrides
func (h *OrgHandler) ListFlagOverrides(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	key := c.Param("key")
	flagID, err := h.flags.GetFlagID(c.Request().Context(), id, key)
	if err != nil {
		return echo.ErrNotFound
	}
	overrides, err := h.flags.ListOverrides(c.Request().Context(), flagID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, overrides)
}

type setOverrideRequest struct {
	TargetType string `json:"target_type" validate:"required,oneof=user role"`
	TargetID   string `json:"target_id"   validate:"required,uuid"`
	Value      bool   `json:"value"`
}

// SetFlagOverride creates or updates a per-user or per-role flag override.
// PUT /api/v1/organizations/:id/feature-flags/:key/overrides
func (h *OrgHandler) SetFlagOverride(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	key := c.Param("key")
	flagID, err := h.flags.GetFlagID(c.Request().Context(), id, key)
	if err != nil {
		return echo.ErrNotFound
	}
	var req setOverrideRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	targetID, err := uuid.Parse(req.TargetID)
	if err != nil {
		return echo.ErrBadRequest
	}
	if err := h.flags.SetOverride(c.Request().Context(), flagID, req.TargetType, targetID, req.Value); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

type deleteOverrideRequest struct {
	TargetType string `json:"target_type" validate:"required,oneof=user role"`
	TargetID   string `json:"target_id"   validate:"required,uuid"`
}

// DeleteFlagOverride removes a specific per-user or per-role flag override.
// DELETE /api/v1/organizations/:id/feature-flags/:key/overrides
func (h *OrgHandler) DeleteFlagOverride(c echo.Context) error {
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	key := c.Param("key")
	flagID, err := h.flags.GetFlagID(c.Request().Context(), id, key)
	if err != nil {
		return echo.ErrNotFound
	}
	var req deleteOverrideRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	targetID, err := uuid.Parse(req.TargetID)
	if err != nil {
		return echo.ErrBadRequest
	}
	if err := h.flags.DeleteOverride(c.Request().Context(), flagID, req.TargetType, targetID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Org-admin variants (use :org_id instead of :id) ──────────────────────────

func (h *OrgHandler) GetEmailPolicyOrgAdmin(c echo.Context) error {
	return orgAdminDelegate(c, "org_id", h.GetEmailPolicy)
}
func (h *OrgHandler) SetEmailPolicyOrgAdmin(c echo.Context) error {
	return orgAdminDelegate(c, "org_id", h.SetEmailPolicy)
}
func (h *OrgHandler) ListFeatureFlagsOrgAdmin(c echo.Context) error {
	return orgAdminDelegate(c, "org_id", h.ListFeatureFlags)
}
func (h *OrgHandler) UpsertFeatureFlagOrgAdmin(c echo.Context) error {
	return orgAdminDelegate(c, "org_id", h.UpsertFeatureFlag)
}
func (h *OrgHandler) DeleteFeatureFlagOrgAdmin(c echo.Context) error {
	return orgAdminDelegate(c, "org_id", h.DeleteFeatureFlag)
}
func (h *OrgHandler) ListFlagOverridesOrgAdmin(c echo.Context) error {
	return orgAdminDelegate(c, "org_id", h.ListFlagOverrides)
}
func (h *OrgHandler) SetFlagOverrideOrgAdmin(c echo.Context) error {
	return orgAdminDelegate(c, "org_id", h.SetFlagOverride)
}
func (h *OrgHandler) DeleteFlagOverrideOrgAdmin(c echo.Context) error {
	return orgAdminDelegate(c, "org_id", h.DeleteFlagOverride)
}

// orgAdminDelegate rewrites the path parameter so shared handlers that use
// uuidParam(c,"id") work when the actual param name is "org_id".
//
// The names and values must be captured BEFORE mutating either: echo's
// ParamValues() returns pvalues[:len(pnames)], so growing pnames first would
// make ParamValues() expose an empty trailing slot and the appended value would
// land beyond pnames — leaving "id" mapped to an empty string (→ 400).
func orgAdminDelegate(c echo.Context, srcParam string, fn echo.HandlerFunc) error {
	val := c.Param(srcParam)
	names := append([]string{}, c.ParamNames()...)
	values := append([]string{}, c.ParamValues()...)
	names = append(names, "id")
	values = append(values, val)
	c.SetParamNames(names...)
	c.SetParamValues(values...)
	return fn(c)
}

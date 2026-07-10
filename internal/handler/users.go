package handler

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/clavex-eu/clavex/internal/breach"
	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/risk"
	"github.com/clavex-eu/clavex/internal/shield"
	"github.com/clavex-eu/clavex/internal/scimpush"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/clavex-eu/clavex/internal/webhook"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var validate = validator.New()

func init() {
	// redirect_uri accepts regular HTTP(S)/custom-scheme URIs and single-subdomain
	// wildcard patterns such as https://*.vercel.app/callback.
	_ = validate.RegisterValidation("redirect_uri", func(fl validator.FieldLevel) bool {
		raw := fl.Field().String()
		if strings.Contains(raw, "*") {
			// Replace * with a valid label to let url.ParseRequestURI accept it.
			candidate := strings.Replace(raw, "*.", "wildcard.", 1)
			u, err := url.ParseRequestURI(candidate)
			if err != nil {
				return false
			}
			// Ensure * is only in the first label of the hostname.
			p, _ := url.Parse(raw)
			parts := strings.SplitN(p.Hostname(), ".", 2)
			return len(parts) == 2 && parts[0] == "*" &&
				(u.Scheme == "https" || u.Scheme == "http")
		}
		u, err := url.ParseRequestURI(raw)
		return err == nil && u.Scheme != ""
	})

	// slug accepts lowercase alphanumeric segments joined by single hyphens,
	// e.g. "my-org". No leading/trailing hyphen, no consecutive hyphens.
	_ = validate.RegisterValidation("slug", func(fl validator.FieldLevel) bool {
		return slugPattern.MatchString(fl.Field().String())
	})
}

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// UserHandler handles user CRUD and self-service endpoints.
type UserHandler struct {
	repo         *repository.UserRepository
	orgs         *repository.OrgRepository
	smtp         *repository.SMTPRepository
	pwPolicy     *repository.PasswordPolicyRepository
	store        *session.Store
	dispatcher   *webhook.Dispatcher
	ssfDisp      *ssf.Dispatcher
	scimPusher   *scimpush.Pusher
	breach       *breach.Checker
	breachRepo   *repository.BreachRepository
	loginHistory *repository.LoginHistoryRepository
	scorer       *risk.Scorer
	shieldClient *shield.Client
	feedClient   *shield.FeedClient
	asyncActions AsyncActionRunner
}

// AsyncActionRunner is the minimal interface for firing async action hooks on
// user lifecycle events (created / updated / deleted).
type AsyncActionRunner interface {
	RunAsync(orgID uuid.UUID, eventType string, data map[string]any)
}

func NewUserHandler(pool *pgxpool.Pool, rdb redis.UniversalClient, dispatcher *webhook.Dispatcher) *UserHandler {
	return &UserHandler{
		repo:       repository.NewUserRepository(pool),
		orgs:       repository.NewOrgRepository(pool),
		smtp:       repository.NewSMTPRepository(pool),
		pwPolicy:   repository.NewPasswordPolicyRepository(pool),
		store:      session.NewStore(rdb),
		dispatcher: dispatcher,
		scimPusher:   scimpush.New(repository.NewScimPushRepository(pool)),
		breach:       breach.New(),
		breachRepo:   repository.NewBreachRepository(pool),
		loginHistory: repository.NewLoginHistoryRepository(pool),
		scorer:       risk.NewScorer(repository.NewLoginHistoryRepository(pool), nil, nil),
	}
}

// WithSSFDispatcher attaches an SSF dispatcher so the handler can fire security events.
func (h *UserHandler) WithSSFDispatcher(d *ssf.Dispatcher) *UserHandler {
	h.ssfDisp = d
	return h
}

// WithShieldClient enables Clavex Shield threat-intelligence for the risk scorer.
func (h *UserHandler) WithShieldClient(c *shield.Client) *UserHandler {
	h.shieldClient = c
	h.scorer = risk.NewScorer(h.loginHistory, c, h.feedClient)
	return h
}

// WithFeedClient attaches the Clavex Shield distributed threat feed client.
func (h *UserHandler) WithFeedClient(f *shield.FeedClient) *UserHandler {
	h.feedClient = f
	h.scorer = risk.NewScorer(h.loginHistory, h.shieldClient, f)
	return h
}

// WithAsyncActionRunner attaches an Actions V2 runner so user lifecycle events
// (created / updated / deleted) fire async HTTP hooks.
func (h *UserHandler) WithAsyncActionRunner(r AsyncActionRunner) *UserHandler {
	h.asyncActions = r
	return h
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

type createUserRequest struct {
	Email     string   `json:"email"      validate:"required,email"`
	FirstName *string  `json:"first_name"`
	LastName  *string  `json:"last_name"`
	Password  *string  `json:"password"`
	RoleIDs   []string `json:"role_ids"`
}

func (h *UserHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createUserRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	// Email policy check: enforce org-level blocklist/allowlist before creating the user.
	if blocklist, allowlist, pErr := h.orgs.GetEmailPolicy(c.Request().Context(), orgID); pErr == nil {
		if reason := checkEmailPolicy(req.Email, blocklist, allowlist); reason != "" {
			return echo.NewHTTPError(http.StatusUnprocessableEntity, reason)
		}
	}
	user, err := h.repo.Create(c.Request().Context(), orgID, req.Email, req.FirstName, req.LastName)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "user already exists")
	}
	if req.Password != nil && *req.Password != "" {
		if err := h.repo.SetPassword(c.Request().Context(), user.ID, *req.Password); err != nil {
			return echo.ErrInternalServerError
		}
	}
	for _, ridStr := range req.RoleIDs {
		roleID, err := uuid.Parse(ridStr)
		if err != nil {
			continue
		}
		_ = h.repo.AssignRole(c.Request().Context(), user.ID, roleID)
	}
	// Auto-enroll: if the org has domain-based enrollment configured and the
	// caller did not explicitly specify roles, auto-assign the configured role.
	if len(req.RoleIDs) == 0 {
		applyAutoEnrollRole(c.Request().Context(), h.orgs, h.repo, orgID, user)
	}
	h.dispatcher.Dispatch(orgID, webhook.EventUserCreated, user)
	go h.scimPusher.Push(c.Request().Context(), orgID, scimpush.EventUserCreated, user)
	if h.asyncActions != nil {
		h.asyncActions.RunAsync(orgID, "user.created", map[string]any{
			"user_id": user.ID.String(), "email": user.Email, "org_id": orgID.String(),
		})
	}
	return c.JSON(http.StatusCreated, user)
}

func (h *UserHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	p := models.PageParams{
		Query: c.QueryParam("q"),
	}

	if limitStr := c.QueryParam("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil {
			p.Limit = n
		}
	}

	if afterStr := c.QueryParam("after"); afterStr != "" {
		if uid, err := uuid.Parse(afterStr); err == nil {
			p.After = &uid
		} else {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid cursor: 'after' must be a UUID")
		}
	}

	page, err := h.repo.ListByOrgPage(c.Request().Context(), orgID, p)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, page)
}

// assertRoleInOrg returns a 404 unless the role exists and belongs to orgID.
// Prevents cross-tenant role operations performed purely by role_id.
func (h *UserHandler) assertRoleInOrg(ctx context.Context, roleID, orgID uuid.UUID) error {
	role, err := h.repo.GetRoleByID(ctx, roleID)
	if err != nil || role == nil || role.OrgID != orgID {
		return echo.ErrNotFound
	}
	return nil
}

func (h *UserHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	user, err := h.repo.GetForOrg(c.Request().Context(), id, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, user)
}

type updateUserRequest struct {
	FirstName       *string `json:"first_name"`
	LastName        *string `json:"last_name"`
	IsActive        *bool   `json:"is_active"`
	MFARequired     *bool   `json:"mfa_required"`
	Password        *string `json:"password"`
	IsEmailVerified *bool   `json:"is_email_verified"`
}

func (h *UserHandler) Update(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	// Tenant guard: reject (404) if the target user is not in this org before any
	// mutation (Update/SetPassword/SetEmailVerified all operate by id alone).
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	var req updateUserRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	user, err := h.repo.Update(c.Request().Context(), id, req.FirstName, req.LastName, req.IsActive, req.MFARequired)
	if err != nil {
		return echo.ErrNotFound
	}
	if req.Password != nil && *req.Password != "" {
		if err := h.repo.SetPassword(c.Request().Context(), id, *req.Password); err != nil {
			return echo.ErrInternalServerError
		}
	}
	if req.IsEmailVerified != nil && *req.IsEmailVerified {
		if err := h.repo.SetEmailVerified(c.Request().Context(), id); err != nil {
			return echo.ErrInternalServerError
		}
		user.IsEmailVerified = true
	}
	h.dispatcher.Dispatch(user.OrgID, webhook.EventUserUpdated, user)
	go h.scimPusher.Push(c.Request().Context(), user.OrgID, scimpush.EventUserUpdated, user)
	if h.asyncActions != nil {
		h.asyncActions.RunAsync(user.OrgID, "user.updated", map[string]any{
			"user_id": user.ID.String(), "email": user.Email, "org_id": user.OrgID.String(),
		})
	}
	if h.ssfDisp != nil {
		org, _ := h.orgs.GetByID(c.Request().Context(), user.OrgID)
		orgSlug := ""
		if org != nil {
			orgSlug = org.Slug
		}
		// CAEP: credential-change — RS must discard existing tokens for this user.
		if req.Password != nil && *req.Password != "" {
			h.ssfDisp.Dispatch(user.OrgID, orgSlug, user.ID.String(),
				ssf.EventCredentialChange,
				ssf.CredentialChangeBody("password", "update"))
		}
		// RISC: account-disabled / account-enabled when is_active changes.
		if req.IsActive != nil {
			eventType := ssf.EventAccountEnabled
			body := map[string]interface{}{"reason": "admin"}
			if !*req.IsActive {
				eventType = ssf.EventAccountDisabled
			}
			h.ssfDisp.Dispatch(user.OrgID, orgSlug, user.ID.String(), eventType, body)
		}
	}
	return c.JSON(http.StatusOK, user)
}

func (h *UserHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	// Fetch (org-scoped) before delete: gives us org_id for the webhook payload and
	// rejects (404) a cross-tenant user id.
	user, err := h.repo.GetForOrg(c.Request().Context(), id, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	if err := h.repo.Delete(c.Request().Context(), id); err != nil {
		return echo.ErrInternalServerError
	}
	h.dispatcher.Dispatch(user.OrgID, webhook.EventUserDeleted, map[string]string{"id": id.String(), "org_id": user.OrgID.String()})
	go h.scimPusher.Push(c.Request().Context(), user.OrgID, scimpush.EventUserDeactivated, user)
	if h.asyncActions != nil {
		h.asyncActions.RunAsync(user.OrgID, "user.deleted", map[string]any{
			"user_id": user.ID.String(), "email": user.Email, "org_id": user.OrgID.String(),
		})
	}
	// SSF: fire account-purged event.
	if h.ssfDisp != nil {
		org, _ := h.orgs.GetByID(c.Request().Context(), user.OrgID)
		orgSlug := ""
		if org != nil {
			orgSlug = org.Slug
		}
		h.ssfDisp.Dispatch(user.OrgID, orgSlug, user.ID.String(), ssf.EventAccountPurged, nil)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *UserHandler) SendPasswordReset(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "id")
	if err != nil {
		return err
	}

	user, err := h.repo.GetForOrg(ctx, userID, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	// Generate a cryptographically secure token
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return echo.ErrInternalServerError
	}
	tokenStr := base64URLEncode(tokenBytes)

	if err := h.store.SavePWResetToken(ctx, tokenStr, user.ID.String()); err != nil {
		return echo.ErrInternalServerError
	}

	// Build reset URL. Prefer X-Forwarded-Proto for reverse-proxy setups.
	scheme := c.Request().Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if c.Request().TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	resetURL := fmt.Sprintf("%s://%s/%s/reset-password?token=%s", scheme, c.Request().Host, org.Slug, tokenStr)

	// Best-effort email delivery — do not fail the API call if SMTP is not configured
	if m, err := mailer.ForOrg(ctx, h.smtp, orgID); err == nil {
		_ = m.SendPasswordReset(user.Email, org.Name, resetURL)
	}

	return c.NoContent(http.StatusNoContent)
}

// PatchAttributes replaces a user's metadata key-value map.
// PUT /api/v1/organizations/:org_id/users/:id/attributes
func (h *UserHandler) PatchAttributes(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	var attrs map[string]interface{}
	if err := c.Bind(&attrs); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if attrs == nil {
		attrs = map[string]interface{}{}
	}
	if err := h.repo.SetMetadata(c.Request().Context(), id, attrs); err != nil {
		return echo.ErrNotFound
	}
	user, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, user)
}

// AddChildRole creates a composite role membership.
// PUT /api/v1/organizations/:org_id/roles/:role_id/children/:child_id
func (h *UserHandler) AddChildRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	parentID, err := uuidParam(c, "role_id")
	if err != nil {
		return err
	}
	childID, err := uuidParam(c, "child_id")
	if err != nil {
		return err
	}
	if parentID == childID {
		return echo.NewHTTPError(http.StatusBadRequest, "a role cannot be a child of itself")
	}
	ctx := c.Request().Context()
	if err := h.assertRoleInOrg(ctx, parentID, orgID); err != nil {
		return err
	}
	if err := h.assertRoleInOrg(ctx, childID, orgID); err != nil {
		return err
	}
	if err := h.repo.AddChildRole(c.Request().Context(), parentID, childID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// RemoveChildRole removes a composite role membership.
// DELETE /api/v1/organizations/:org_id/roles/:role_id/children/:child_id
func (h *UserHandler) RemoveChildRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	parentID, err := uuidParam(c, "role_id")
	if err != nil {
		return err
	}
	childID, err := uuidParam(c, "child_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	if err := h.assertRoleInOrg(ctx, parentID, orgID); err != nil {
		return err
	}
	if err := h.assertRoleInOrg(ctx, childID, orgID); err != nil {
		return err
	}
	if err := h.repo.RemoveChildRole(c.Request().Context(), parentID, childID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ListChildRoles returns the direct child roles of a composite role.
// GET /api/v1/organizations/:org_id/roles/:role_id/children
func (h *UserHandler) ListChildRoles(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	roleID, err := uuidParam(c, "role_id")
	if err != nil {
		return err
	}
	if err := h.assertRoleInOrg(c.Request().Context(), roleID, orgID); err != nil {
		return err
	}
	roles, err := h.repo.ListChildRoles(c.Request().Context(), roleID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, roles)
}

// SetRequiredActions replaces the required_actions for a user.
// PUT /api/v1/organizations/:org_id/users/:id/required-actions
type setRequiredActionsRequest struct {
	Actions []string `json:"actions" validate:"required"`
}

func (h *UserHandler) SetRequiredActions(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	var req setRequiredActionsRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	// Validate allowed action values
	allowed := map[string]bool{"VERIFY_EMAIL": true, "UPDATE_PASSWORD": true, "CONFIGURE_TOTP": true, "ENROLL_PASSKEY": true}
	for _, a := range req.Actions {
		if !allowed[a] {
			return echo.NewHTTPError(http.StatusBadRequest, "unknown required action: "+a)
		}
	}
	if err := h.repo.SetRequiredActions(c.Request().Context(), id, req.Actions); err != nil {
		return echo.ErrNotFound
	}
	user, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, user)
}

// ── Role management ───────────────────────────────────────────────────────────

type createRoleRequest struct {
	Name        string  `json:"name"        validate:"required,min=1,max=64"`
	Description *string `json:"description"`
}

func (h *UserHandler) CreateRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createRoleRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	role, err := h.repo.CreateRole(c.Request().Context(), orgID, req.Name, req.Description)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "role already exists")
	}
	return c.JSON(http.StatusCreated, role)
}

func (h *UserHandler) ListRoles(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	roles, err := h.repo.ListRoles(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, roles)
}

func (h *UserHandler) DeleteRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	roleID, err := uuidParam(c, "role_id")
	if err != nil {
		return err
	}
	if err := h.assertRoleInOrg(c.Request().Context(), roleID, orgID); err != nil {
		return err
	}
	if err := h.repo.DeleteRole(c.Request().Context(), roleID); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *UserHandler) AssignRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	roleID, err := uuidParam(c, "role_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	// Both the target user and the role must belong to this org, else a tenant
	// admin could grant an arbitrary (cross-org) role to an arbitrary user.
	if _, err := h.repo.GetForOrg(ctx, userID, orgID); err != nil {
		return echo.ErrNotFound
	}
	if err := h.assertRoleInOrg(ctx, roleID, orgID); err != nil {
		return err
	}
	if err := h.repo.AssignRole(ctx, userID, roleID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *UserHandler) UnassignRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	roleID, err := uuidParam(c, "role_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	if _, err := h.repo.GetForOrg(ctx, userID, orgID); err != nil {
		return echo.ErrNotFound
	}
	if err := h.assertRoleInOrg(ctx, roleID, orgID); err != nil {
		return err
	}
	if err := h.repo.UnassignRole(ctx, userID, roleID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Self-service ──────────────────────────────────────────────────────────────

func (h *UserHandler) Me(c echo.Context) error {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	user, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, user)
}

func (h *UserHandler) UpdateMe(c echo.Context) error {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	var req updateUserRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	user, err := h.repo.Update(c.Request().Context(), id, req.FirstName, req.LastName, req.IsActive, nil)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, user)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password"     validate:"required,min=10"`
}

func (h *UserHandler) ChangePassword(c echo.Context) error {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}

	var req changePasswordRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	user, err := h.repo.GetByIDWithHash(c.Request().Context(), id)
	if err != nil {
		return echo.ErrNotFound
	}
	if user.PasswordHash == nil || !h.repo.CheckPassword(*user.PasswordHash, req.CurrentPassword) {
		return echo.NewHTTPError(http.StatusUnauthorized, "current password is incorrect")
	}

	// Breached password check — load org to get policy.
	if user.OrgID != uuid.Nil {
		if policy, err := h.pwPolicy.Get(c.Request().Context(), user.OrgID); err == nil {
			if err := h.checkBreachedPassword(c, req.NewPassword, policy.BreachedPasswordAction,
				user.OrgID, &id, user.Email,
			); err != nil {
				return err
			}
		}
	}

	if err := h.repo.SetPassword(c.Request().Context(), id, req.NewPassword); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// checkBreachedPassword checks a password against the HIBP corpus and returns
// an error (HTTP 422) if the policy is "block" and the password is breached.
// Errors from the HIBP API are silently ignored (fail-open).
// When orgID/userID/email are non-zero, the result is recorded in breach_events.
func (h *UserHandler) checkBreachedPassword(
	c echo.Context,
	password, action string,
	orgID uuid.UUID, userID *uuid.UUID, email string,
) error {
	if action == "" || action == "off" {
		return nil
	}
	result, err := h.breach.Check(password)
	if err != nil {
		// Network/API failure — fail open, never block the user.
		return nil
	}

	if !result.Pwned {
		// Check sub_address: password equals email local-part (with or without +tag).
		if email != "" && isSubAddressPassword(password, email) {
			if h.breachRepo != nil && orgID != uuid.Nil {
				_ = h.breachRepo.RecordEvent(c.Request().Context(), repository.RecordEventParams{
					OrgID: orgID, UserID: userID, Email: email,
					BreachCategory: "sub_address", HIBPCount: 0,
					ActionTaken: action, Context: "password_change",
				})
			}
			if action == "block" {
				return echo.NewHTTPError(http.StatusUnprocessableEntity,
					"this password matches part of your email address and cannot be used")
			}
		}
		return nil
	}

	// Determine category: common_password if count >= 1000, otherwise exact_match.
	category := "exact_match"
	if result.Count >= 1000 {
		category = "common_password"
	}

	if h.breachRepo != nil && orgID != uuid.Nil {
		_ = h.breachRepo.RecordEvent(c.Request().Context(), repository.RecordEventParams{
			OrgID: orgID, UserID: userID, Email: email,
			BreachCategory: category, HIBPCount: result.Count,
			ActionTaken: action, Context: "password_change",
		})
	}

	if action == "block" || action == "force_reset" {
		return echo.NewHTTPError(http.StatusUnprocessableEntity,
			fmt.Sprintf("this password has appeared in %d data breach(es) and cannot be used", result.Count))
	}
	return nil
}

// isSubAddressPassword returns true when password equals the email local-part,
// optionally stripping a +tag sub-address (RFC 5321 §4.5.3).
func isSubAddressPassword(password, email string) bool {
	if len(password) < 3 {
		return false
	}
	var local string
	for i := range email {
		if email[i] == '@' {
			local = email[:i]
			break
		}
	}
	if local == "" {
		return false
	}
	// Strip +tag.
	stripped := local
	for i := range local {
		if local[i] == '+' {
			stripped = local[:i]
			break
		}
	}
	return password == local || password == stripped
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// RiskScore handles GET /api/v1/organizations/:org_id/users/:user_id/risk-score
//
// Returns a composite identity risk score (0-100) and the contributing signals.
// Clients can use this to decide whether to trigger step-up MFA or block access.
//
//	{
//	  "score": 35,
//	  "level": "high",
//	  "reason": ["recent_failures:5_in_24h", "new_country:RU"]
//	}
func (h *UserHandler) RiskScore(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	score, err := h.scorer.Compute(c.Request().Context(), orgID, userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not compute risk score")
	}
	return c.JSON(http.StatusOK, score)
}

// RiskDashboard handles GET /api/v1/organizations/:org_id/risk-dashboard
// Returns org-level aggregated risk data: top risky users, geo breakdown,
// 24-hour trend, and impossible travel alerts.
func (h *UserHandler) RiskDashboard(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	summary, err := h.scorer.OrgSummary(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not compute risk dashboard")
	}
	return c.JSON(http.StatusOK, summary)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func uuidParam(c echo.Context, name string) (uuid.UUID, error) {
	raw := c.Param(name)
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, name+" must be a valid UUID")
	}
	return id, nil
}

func bindAndValidate(c echo.Context, req interface{}) error {
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := validate.Struct(req); err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	}
	return nil
}

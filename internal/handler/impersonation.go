package handler

import (
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ImpersonationHandler issues short-lived impersonation tokens.
type ImpersonationHandler struct {
	cfg   *config.Config
	users *repository.UserRepository
	audit *repository.AuditRepository
}

func NewImpersonationHandler(cfg *config.Config, pool *pgxpool.Pool) *ImpersonationHandler {
	return &ImpersonationHandler{
		cfg:   cfg,
		users: repository.NewUserRepository(pool),
		audit: repository.NewAuditRepository(pool),
	}
}

type impersonateClaims struct {
	jwt.RegisteredClaims
	OrgID          string `json:"org_id"`
	Email          string `json:"email"`
	Impersonated   bool   `json:"impersonated"`
	ImpersonatedBy string `json:"impersonated_by"`
}

// Impersonate returns a short-lived admin JWT that appears as the target user.
// The caller must be a superadmin.
//
// POST /api/v1/superadmin/impersonate/:user_id
func (h *ImpersonationHandler) Impersonate(c echo.Context) error {
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}

	callerClaims := middleware.GetClaims(c)
	if callerClaims == nil {
		return echo.ErrUnauthorized
	}

	// Load target user
	target, err := h.users.GetByID(c.Request().Context(), userID)
	if err != nil || target == nil || !target.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	orgID := target.OrgID
	now := time.Now()
	ttl := 15 * time.Minute

	claims := impersonateClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   target.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.New().String(),
		},
		OrgID:          orgID.String(),
		Email:          target.Email,
		Impersonated:   true,
		ImpersonatedBy: callerClaims.Subject,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(h.cfg.Auth.AdminSecret))
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Audit
	callerUserID, _ := uuid.Parse(callerClaims.Subject)
	resourceType := "user"
	resourceID := target.ID.String()
	ip := c.RealIP()
	ua := c.Request().UserAgent()
	actorEmail := callerClaims.Email
	_ = h.audit.Record(c.Request().Context(), &models.AuditLog{
		OrgID:        &orgID,
		UserID:       &callerUserID,
		ActorEmail:   &actorEmail,
		Action:       "admin.impersonate",
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Status:       "success",
		IPAddress:    &ip,
		UserAgent:    &ua,
	})

	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":            signed,
		"expires_in":       int(ttl.Seconds()),
		"user_id":          target.ID,
		"impersonating":    target.Email,
		"impersonated_by":  callerClaims.Subject,
		"warning":          "This token grants full access as the impersonated user. Handle with care.",
	})
}

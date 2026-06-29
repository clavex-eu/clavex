package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// SessionHandler exposes admin endpoints for listing and revoking active sessions.
type SessionHandler struct {
	tokens  *repository.RefreshTokenRepository
	users   *repository.UserRepository
	orgs    *repository.OrgRepository
	ssfDisp *ssf.Dispatcher
}

func NewSessionHandler(pool *pgxpool.Pool) *SessionHandler {
	return &SessionHandler{
		tokens: repository.NewRefreshTokenRepository(pool),
		users:  repository.NewUserRepository(pool),
		orgs:   repository.NewOrgRepository(pool),
	}
}

// WithSSFDispatcher attaches an SSF dispatcher so the handler can push
// CAEP session-revoked / RISC sessions-revoked events to registered streams.
func (h *SessionHandler) WithSSFDispatcher(d *ssf.Dispatcher) *SessionHandler {
	h.ssfDisp = d
	return h
}

// ListOrgSessions returns all active sessions for an organisation.
// GET /api/v1/organizations/:org_id/sessions
func (h *SessionHandler) ListOrgSessions(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	sessions, err := h.tokens.ListActiveByOrg(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, sessions)
}

// ListUserSessions returns the active sessions for a specific user.
// GET /api/v1/organizations/:org_id/users/:user_id/sessions
func (h *SessionHandler) ListUserSessions(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	sessions, err := h.tokens.ListActiveByUser(c.Request().Context(), orgID, userID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, sessions)
}

// RevokeSession revokes a single refresh token by its UUID.
// DELETE /api/v1/organizations/:org_id/sessions/:id
func (h *SessionHandler) RevokeSession(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid session id")
	}
	// Load the org's sessions first: this both finds the user to notify AND
	// confirms the session belongs to this org. Without the membership check a
	// session UUID from another tenant could be revoked (cross-tenant forced logout).
	sessions, _ := h.tokens.ListActiveByOrg(c.Request().Context(), orgID)
	var userID uuid.UUID
	found := false
	for _, s := range sessions {
		if s.ID == id {
			found = true
			if s.UserID != nil {
				userID = *s.UserID
			}
			break
		}
	}
	if !found {
		return echo.ErrNotFound
	}
	if err := h.tokens.RevokeByID(c.Request().Context(), id); err != nil {
		return err
	}
	// CAEP: session-revoked — RS can drop the access token immediately.
	if h.ssfDisp != nil && userID != uuid.Nil {
		org, _ := h.orgs.GetByID(c.Request().Context(), orgID)
		orgSlug := ""
		if org != nil {
			orgSlug = org.Slug
		}
		h.ssfDisp.Dispatch(orgID, orgSlug, userID.String(),
			ssf.EventSessionRevoked,
			ssf.SessionRevokedBody("admin"))
	}
	return c.NoContent(http.StatusNoContent)
}

// RevokeAllUserSessions revokes every active session for a user.
// DELETE /api/v1/organizations/:org_id/users/:user_id/sessions
func (h *SessionHandler) RevokeAllUserSessions(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	if err := h.tokens.RevokeAllByUser(c.Request().Context(), orgID, userID); err != nil {
		return err
	}
	// RISC: sessions-revoked — RS must treat all access tokens as invalid immediately.
	if h.ssfDisp != nil {
		org, _ := h.orgs.GetByID(c.Request().Context(), orgID)
		orgSlug := ""
		if org != nil {
			orgSlug = org.Slug
		}
		h.ssfDisp.Dispatch(orgID, orgSlug, userID.String(),
			ssf.EventSessionsRevoked,
			ssf.SessionsRevokedBody("admin"))
	}
	return c.NoContent(http.StatusNoContent)
}

// RevokeAllUserSessionsExcept revokes all sessions for a user except the given one.
// DELETE /api/v1/organizations/:org_id/users/:user_id/sessions/others?except=<session_id>
func (h *SessionHandler) RevokeAllUserSessionsExcept(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	exceptStr := c.QueryParam("except")
	exceptID, err := uuid.Parse(exceptStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "except must be a valid session UUID")
	}
	if err := h.tokens.RevokeAllByUserExcept(c.Request().Context(), orgID, userID, exceptID); err != nil {
		return err
	}
	// RISC: sessions-revoked — notify receivers about bulk revocation.
	if h.ssfDisp != nil {
		org, _ := h.orgs.GetByID(c.Request().Context(), orgID)
		orgSlug := ""
		if org != nil {
			orgSlug = org.Slug
		}
		h.ssfDisp.Dispatch(orgID, orgSlug, userID.String(),
			ssf.EventSessionsRevoked,
			ssf.SessionsRevokedBody("admin"))
	}
	return c.NoContent(http.StatusNoContent)
}

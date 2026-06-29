package handler

// revnet.go — Cross-installation Revocation Network inbound handler.
//
// Federated partner installations POST a signed CAEP credential-change SET to
//   POST /api/v1/inbound/ssf/revocation
// This endpoint:
//  1. Authenticates the request via the Bearer token (looked up by SHA-256 hash
//     in federated_installations.inbound_token_hash).
//  2. Delegates SET verification and local revocation to federation.VerifyAndApply.
//  3. Returns 202 Accepted on success (no body) or a JSON error.
//
// Route registration (in cmd/server/main.go or your router file):
//   e.POST("/api/v1/inbound/ssf/revocation", revnetHandler.Inbound)

import (
	"io"
	"net/http"

	"github.com/clavex-eu/clavex/internal/federation"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// RevNetHandler handles inbound federated revocation SETs.
type RevNetHandler struct {
	repo *repository.OID4WRepository
}

// NewRevNetHandler creates a RevNetHandler.
func NewRevNetHandler(pool *pgxpool.Pool) *RevNetHandler {
	return &RevNetHandler{repo: repository.NewOID4WRepository(pool)}
}

// Inbound handles POST /api/v1/inbound/ssf/revocation.
func (h *RevNetHandler) Inbound(c echo.Context) error {
	ctx := c.Request().Context()

	// Authenticate: look up the federated installation by the bearer token hash.
	tokenHash, ok := federation.ParseTokenHash(c.Request().Header.Get("Authorization"))
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing or malformed bearer token"})
	}

	sender, err := h.repo.GetFederatedInstallationByTokenHash(ctx, tokenHash)
	if err != nil || sender == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unknown sender"})
	}

	// Read the raw compact JWT body.
	body, err := io.ReadAll(io.LimitReader(c.Request().Body, 64*1024))
	if err != nil || len(body) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "empty body"})
	}

	// Verify and apply the revocation.
	event, err := federation.VerifyAndApply(ctx, h.repo, sender.OrgID, sender, string(body))
	if err != nil {
		log.Warn().Err(err).
			Str("sender", sender.EntityID).
			Msg("revnet: inbound SET rejected")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "SET verification failed"})
	}

	log.Info().
		Str("sender", event.SenderEntityID).
		Str("vct", event.VCT).
		Str("reason", event.Reason).
		Str("user_sub", event.UserSub).
		Msg("revnet: inbound revocation applied")

	return c.NoContent(http.StatusAccepted)
}

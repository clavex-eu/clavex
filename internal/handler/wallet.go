package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// WalletHandler serves the end-user wallet APIs under /api/v1/me/credentials.
// These endpoints are protected by RequireUserJWT and return data scoped to the
// authenticated user. They back the embeddable <ClavexWallet /> React component.
type WalletHandler struct {
	oid4w *repository.OID4WRepository
}

// NewWalletHandler creates a new WalletHandler.
func NewWalletHandler(oid4w *repository.OID4WRepository) *WalletHandler {
	return &WalletHandler{oid4w: oid4w}
}

// walletCredentialResponse is the JSON shape returned per credential.
// We never expose the raw SD-JWT or hash — only metadata the holder already
// possesses (vct, dates, revocation status).
type walletCredentialResponse struct {
	ID               uuid.UUID  `json:"id"`
	VCT              string     `json:"vct"`
	IssuedAt         string     `json:"issued_at"`
	ExpiresAt        *string    `json:"expires_at,omitempty"`
	IsRevoked        bool       `json:"is_revoked"`
	RevocationReason *string    `json:"revocation_reason,omitempty"`
}

func toWalletResponse(ic models.IssuedCredential) walletCredentialResponse {
	r := walletCredentialResponse{
		ID:               ic.ID,
		VCT:              ic.VCT,
		IssuedAt:         ic.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		IsRevoked:        ic.IsRevoked,
		RevocationReason: ic.RevocationReason,
	}
	if ic.ExpiresAt != nil {
		s := ic.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
		r.ExpiresAt = &s
	}
	return r
}

// ListCredentials handles GET /api/v1/me/credentials.
// Returns the server-side issuance record for every credential issued to the
// authenticated user in their current organisation. The wallet uses this to
// reconcile local storage (the actual VCs) with the server's revocation state.
func (h *WalletHandler) ListCredentials(c echo.Context) error {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	orgID, err := uuid.Parse(claims.OrgID)
	if err != nil {
		return echo.ErrUnauthorized
	}

	issued, err := h.oid4w.ListMyCredentials(c.Request().Context(), orgID, userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not list credentials")
	}

	out := make([]walletCredentialResponse, 0, len(issued))
	for _, ic := range issued {
		out = append(out, toWalletResponse(ic))
	}
	return c.JSON(http.StatusOK, echo.Map{"credentials": out})
}

package handler

import (
	"errors"
	"net/http"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// Registered only below the authenticated, org-scoped users administration group.
type WalletIdentityHandler struct {
	pool *pgxpool.Pool
	cfg  baseURLProvider
}

func NewWalletIdentityHandler(pool *pgxpool.Pool, cfg baseURLProvider) *WalletIdentityHandler {
	return &WalletIdentityHandler{pool: pool, cfg: cfg}
}

func walletIdentityAccountParams(c echo.Context) (uuid.UUID, uuid.UUID, error) {
	if middleware.GetClaims(c) == nil {
		return uuid.Nil, uuid.Nil, echo.ErrUnauthorized
	}
	org, err := uuidParam(c, "org_id")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	claims := middleware.GetClaims(c)
	if (!claims.IsAdmin && !claims.IsSuperAdmin) || (!claims.IsSuperAdmin && claims.OrgID != org.String()) {
		return uuid.Nil, uuid.Nil, echo.ErrForbidden
	}
	user, err := uuidParam(c, "user_id")
	return org, user, err
}

func (h *WalletIdentityHandler) Create(c echo.Context) error {
	org, user, err := walletIdentityAccountParams(c)
	if err != nil {
		return err
	}
	actor, err := uuid.Parse(middleware.GetClaims(c).Subject)
	if err != nil {
		return echo.ErrForbidden
	}
	var req struct {
		oid4w.WalletIdentityProfile
		VerifiedIdentifier       string `json:"verified_identifier"`
		AdministrativelyReviewed bool   `json:"administratively_reviewed"`
	}
	if err := c.Bind(&req); err != nil || !req.AdministrativelyReviewed {
		return echo.NewHTTPError(http.StatusBadRequest, "explicit administrative review is required")
	}
	if err := req.Validate(); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	digest, err := req.Digest(org.String(), req.VerifiedIdentifier)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid external identifier")
	}
	ctx := c.Request().Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return echo.ErrInternalServerError
	}
	defer tx.Rollback(ctx)
	repo := repository.NewWalletIdentityRepository(tx)
	slug, settings, err := repo.LockActiveOrg(ctx, org)
	if err != nil {
		return echo.ErrNotFound
	}
	if err := repo.LockActiveUser(ctx, org, user); err != nil {
		return echo.ErrNotFound
	}
	var verifier uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM identity.users WHERE id=$1 AND is_active FOR SHARE`, actor).Scan(&verifier); err != nil {
		return echo.ErrForbidden
	}
	if req.Format == "dc+sd-jwt" && req.Issuer == h.cfg.BaseURL()+"/"+slug {
		return echo.NewHTTPError(http.StatusBadRequest, "local subjects are matched directly")
	}
	profiles, err := oid4w.WalletIdentityProfiles(settings)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	allowed := false
	for _, p := range profiles {
		if p.Format == req.Format && p.Issuer == req.Issuer && p.CredentialType == req.CredentialType && sameIdentityPath(p.ClaimPath, req.ClaimPath) {
			allowed = true
		}
	}
	if !allowed {
		return echo.NewHTTPError(http.StatusBadRequest, "identity profile is not configured for this organisation")
	}
	id, err := repo.Create(ctx, repository.WalletIdentityLink{OrgID: org, UserID: user, Format: req.Format, Issuer: req.Issuer, CredentialType: req.CredentialType, ClaimPath: req.ClaimPath, SubjectDigest: digest, VerifiedBy: &actor})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return echo.NewHTTPError(http.StatusConflict, "identity is already linked")
		}
		return echo.ErrInternalServerError
	}
	if err := tx.Commit(ctx); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, map[string]interface{}{"id": id, "verification_method": "administrative_review"})
}

func sameIdentityPath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (h *WalletIdentityHandler) List(c echo.Context) error {
	org, user, err := walletIdentityAccountParams(c)
	if err != nil {
		return err
	}
	if _, err := repository.NewUserRepository(h.pool).GetForOrg(c.Request().Context(), user, org); err != nil {
		return echo.ErrNotFound
	}
	links, err := repository.NewWalletIdentityRepository(h.pool).List(c.Request().Context(), org, user)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, links)
}

func (h *WalletIdentityHandler) Revoke(c echo.Context) error {
	org, user, err := walletIdentityAccountParams(c)
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "link_id")
	if err != nil {
		return err
	}
	ok, err := repository.NewWalletIdentityRepository(h.pool).Revoke(c.Request().Context(), org, user, id)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if !ok {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

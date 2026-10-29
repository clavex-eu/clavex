package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
)

// A dot cannot occur in ordinary base64url OIDC refresh tokens.
const walletRefreshPrefix = "vci_rt."
const walletGrantLifetime = 7 * 24 * time.Hour
const walletAccessLifetime = 5 * time.Minute
const deferredPollInterval = 5

func walletToken(prefix string) (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

func walletTokenError(c echo.Context, code string) error {
	return c.JSON(http.StatusBadRequest, map[string]string{"error": code})
}

func walletGrantError(c echo.Context, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return walletTokenError(c, "invalid_grant")
	}
	return echo.ErrServiceUnavailable
}

func walletTokenParameters(c echo.Context, scope string) error {
	if v := c.FormValue("scope"); v != "" && v != scope {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid_scope")
	}
	for _, name := range []string{"authorization_details", "resource", "audience"} {
		if c.FormValue(name) != "" {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid_request")
		}
	}

	return nil
}

func writeWalletParameterError(c echo.Context, err error) error {
	var e *echo.HTTPError
	if errors.As(err, &e) {
		if code, ok := e.Message.(string); ok {
			return walletTokenError(c, code)
		}
	}
	return echo.ErrServiceUnavailable
}

// Validate possession on every bound request. Resource proofs additionally
// require ath; all JTI checks fail closed when Redis is unavailable.
func (h *OID4VCIHandler) walletSender(c echo.Context, g *repository.WalletIssuanceGrant, rawAccess string, initial bool) error {
	proofs := c.Request().Header.Values("DPoP")
	if len(proofs) > 1 {
		return echo.ErrUnauthorized
	}
	proof, err := oidc.ParseDPoPProof(c.Request().Header.Get("DPoP"), c.Request().Method, htuFromRequest(c, h.cfg.BaseURL()))
	if err != nil {
		return echo.ErrUnauthorized
	}
	if initial {
		if proof != nil {
			g.DPoPJKT = proof.JKT
		}
		if cert := oidc.CertFromConnectionState(c.Request().TLS); cert != nil {
			g.MTLSX5TS256 = cert.X5TS256
		}
	} else {
		if (proof == nil) != (g.DPoPJKT == "") || proof != nil && proof.JKT != g.DPoPJKT {
			return echo.ErrUnauthorized
		}
		if g.MTLSX5TS256 != "" {
			cert := oidc.CertFromConnectionState(c.Request().TLS)
			if cert == nil || cert.X5TS256 != g.MTLSX5TS256 {
				return echo.ErrUnauthorized
			}
		}
	}
	if rawAccess != "" {
		scheme, _, _ := strings.Cut(c.Request().Header.Get("Authorization"), " ")
		if g.DPoPJKT != "" {
			if !strings.EqualFold(scheme, "DPoP") {
				return echo.ErrUnauthorized
			}
			digest := sha256.Sum256([]byte(rawAccess))
			if proof == nil || proof.ATH != base64.RawURLEncoding.EncodeToString(digest[:]) {
				return echo.ErrUnauthorized
			}
		} else if !strings.EqualFold(scheme, "Bearer") {
			return echo.ErrUnauthorized
		}
	}
	if proof != nil {
		if h.rdb == nil {
			return echo.ErrServiceUnavailable
		}
		// The shared parser accepts iat within +/- max age. Retain the JTI
		// through that entire possible validity window, including future iat.
		fresh, err := h.rdb.SetNX(c.Request().Context(), "vci:dpop:"+g.OrgID.String()+":"+proof.JKT+":"+hashToken(proof.JTI), 1, 2*oidc.DPoPProofMaxAge).Result()
		if err != nil {
			return echo.ErrServiceUnavailable
		}
		if !fresh {
			return echo.ErrUnauthorized
		}
	}
	return nil
}

func (h *OID4VCIHandler) startWalletGrant(c echo.Context, org *models.Organization, offer *models.CredentialOffer, nonce string) error {
	if err := walletTokenParameters(c, oid4w.CredentialConfigID(offer.VCT)); err != nil {
		return writeWalletParameterError(c, err)
	}
	client, authErr := h.authenticateWalletClient(c, org)
	if authErr != nil {
		return walletClientError(c, authErr)
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()
	cfg, err := h.repo.GetCredentialConfigByVCT(ctx, org.ID, offer.VCT)
	if err != nil {
		return walletGrantError(c, err)
	}
	g := repository.WalletIssuanceGrant{OrgID: org.ID, OfferID: offer.ID, UserID: offer.UserID, ConfigurationID: cfg.ID, VCT: offer.VCT, ClientID: client.ID, ClientAuthMethod: client.Method, AttestationJKT: client.AttestationJKT, StatusParents: marshalStatusParents(client.Parents), DeferredAllowed: cfg.DeferredIssuance, ExpiresAt: time.Now().Add(walletGrantLifetime)}
	if !g.DeferredAllowed {
		g.ExpiresAt = offer.ExpiresAt
	}
	if err := h.walletSender(c, &g, "", true); err != nil {
		if errors.Is(err, echo.ErrServiceUnavailable) {
			return err
		}
		return walletTokenError(c, "invalid_dpop_proof")
	}
	repo, tx, err := h.repo.BeginIssuance(ctx)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	defer tx.Rollback(ctx)
	raw, hash, err := walletToken("vci_at_")
	if err != nil {
		return echo.ErrInternalServerError
	}
	if err := repo.SetOfferAccessToken(ctx, offer.ID, hash); err != nil {
		return walletGrantError(c, err)
	}
	current, err := repo.GetOfferByID(ctx, offer.ID)
	if err != nil {
		return walletGrantError(c, err)
	}
	if err := repo.CheckWalletEligibility(ctx, &g, current); err != nil {
		return walletGrantError(c, err)
	}
	created, err := repo.CreateWalletGrant(ctx, g)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	response, err := h.walletTokenResponse(ctx, repo, created, raw, hash)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	response["c_nonce"], response["c_nonce_expires_in"] = nonce, int(vciNonceTTL.Seconds())
	if err := tx.Commit(ctx); err != nil {
		return echo.ErrServiceUnavailable
	}
	return c.JSON(http.StatusOK, response)
}

func (h *OID4VCIHandler) walletTokenResponse(ctx context.Context, repo *repository.OID4WRepository, g *repository.WalletIssuanceGrant, raw, hash string) (map[string]any, error) {
	if g.AuthorizationCodeID != nil {
		token, err := h.walletAuthorizationJWT(ctx, g)
		if err != nil {
			return nil, err
		}
		raw = token
		hash = hashToken(raw)
	}
	expires := time.Now().Add(walletAccessLifetime)
	if expires.After(g.ExpiresAt) {
		expires = g.ExpiresAt
	}
	if err := repo.AddWalletToken(ctx, g, hash, "access", expires); err != nil {
		return nil, err
	}
	tokenType := "Bearer"
	if g.DPoPJKT != "" {
		tokenType = "DPoP"
	}
	response := map[string]any{"access_token": raw, "token_type": tokenType, "expires_in": int(time.Until(expires).Seconds()), "credential_identifiers": []string{oid4w.CredentialConfigID(g.VCT)}}
	if g.DeferredAllowed {
		refresh, rh, err := walletToken(walletRefreshPrefix)
		if err != nil {
			return nil, err
		}
		if err := repo.AddWalletToken(ctx, g, rh, "refresh", g.ExpiresAt); err != nil {
			return nil, err
		}
		response["refresh_token"] = refresh
	}
	return response, nil
}

func (h *OID4VCIHandler) refreshWalletGrant(c echo.Context, org *models.Organization) error {
	ctx := c.Request().Context()
	raw := c.FormValue("refresh_token")
	if !strings.HasPrefix(raw, walletRefreshPrefix) || len(raw) > 256 {
		return walletTokenError(c, "invalid_grant")
	}
	hash := hashToken(raw)
	g, _, _, err := h.repo.WalletGrantForToken(ctx, hash, "refresh")
	if err != nil {
		return walletGrantError(c, err)
	}
	if g.OrgID != org.ID {
		return walletTokenError(c, "invalid_grant")
	}
	scope := oid4w.CredentialConfigID(g.VCT)
	if g.AuthorizationCodeID != nil {
		scope = g.AuthorizationScope
	}
	if err := walletTokenParameters(c, scope); err != nil {
		return writeWalletParameterError(c, err)
	}
	client, authErr := h.authenticateWalletClient(c, org)
	if authErr != nil {
		return walletClientError(c, authErr)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !walletClientMatches(g, client) {
		return walletTokenError(c, "invalid_grant")
	}
	if err := oid4w.CheckStatusParents(ctx, g.OrgID.String(), org.Settings, g.StatusParents); err != nil {
		if errors.Is(err, oid4w.ErrRevoked) || errors.Is(err, oid4w.ErrSuspended) {
			return walletTokenError(c, "invalid_grant")
		}
		return echo.ErrServiceUnavailable
	}
	if err := h.walletSender(c, g, "", false); err != nil {
		if errors.Is(err, echo.ErrServiceUnavailable) {
			return err
		}
		return walletTokenError(c, "invalid_dpop_proof")
	}
	repo, tx, err := h.repo.BeginIssuance(ctx)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	defer tx.Rollback(ctx)
	g, err = repo.LockWalletGrant(ctx, g.OfferID, org.ID)
	if err != nil {
		return walletGrantError(c, err)
	}
	if g == nil {
		return walletTokenError(c, "invalid_grant")
	}
	_, expires, used, err := repo.WalletGrantForToken(ctx, hash, "refresh")
	if err != nil {
		return walletGrantError(c, err)
	}
	if g.RevokedAt != nil || g.ClosedAt != nil || !g.DeferredAllowed || !time.Now().Before(expires) {
		return walletTokenError(c, "invalid_grant")
	}
	if used != nil {
		if err := repo.RevokeWalletGrant(ctx, g.ID); err != nil {
			return echo.ErrServiceUnavailable
		}
		if err := tx.Commit(ctx); err != nil {
			return echo.ErrServiceUnavailable
		}
		return walletTokenError(c, "invalid_grant")
	}
	offer, err := repo.LockWalletOffer(ctx, g.OfferID, org.ID)
	if err != nil {
		return walletGrantError(c, err)
	}
	if err := repo.CheckWalletEligibility(ctx, g, offer); err != nil {
		return walletGrantError(c, err)
	}
	if offer.Status == "pending" {
		if !time.Now().Before(offer.ExpiresAt) {
			return walletTokenError(c, "invalid_grant")
		}
	} else if offer.Status == "used" {
		ok, err := repo.DeferredRetrievable(ctx, offer.ID)
		if err != nil {
			return echo.ErrServiceUnavailable
		}
		if !ok {
			return walletTokenError(c, "invalid_grant")
		}
	} else {
		return walletTokenError(c, "invalid_grant")
	}
	settings, err := repo.LockWalletStatusPolicy(ctx, g.OrgID)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	if err := oid4w.CheckStatusParents(ctx, g.OrgID.String(), settings, g.StatusParents); err != nil {
		if errors.Is(err, oid4w.ErrRevoked) || errors.Is(err, oid4w.ErrSuspended) {
			return walletTokenError(c, "invalid_grant")
		}
		return echo.ErrServiceUnavailable
	}
	if err := repo.ConsumeWalletRefresh(ctx, hash); err != nil {
		return walletGrantError(c, err)
	}
	access, ah, err := walletToken("vci_at_")
	if err != nil {
		return echo.ErrInternalServerError
	}
	response, err := h.walletTokenResponse(ctx, repo, g, access, ah)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return echo.ErrServiceUnavailable
	}
	return c.JSON(http.StatusOK, response)
}

func (h *OID4VCIHandler) validateWalletResource(c echo.Context, raw string) error {
	g, _, _, err := h.repo.WalletGrantForToken(c.Request().Context(), hashToken(raw), "access")
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	} // legacy bearer: no refresh or sender binding was granted
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	settings, policyErr := h.repo.LockWalletStatusPolicy(c.Request().Context(), g.OrgID)
	if policyErr != nil {
		return echo.ErrServiceUnavailable
	}
	if err := oid4w.CheckStatusParents(c.Request().Context(), g.OrgID.String(), settings, g.StatusParents); err != nil {
		if errors.Is(err, oid4w.ErrRevoked) || errors.Is(err, oid4w.ErrSuspended) {
			return echo.ErrUnauthorized
		}
		return echo.ErrServiceUnavailable
	}
	if err := h.walletSender(c, g, raw, false); err != nil {
		if errors.Is(err, echo.ErrServiceUnavailable) {
			return err
		}
		return echo.NewHTTPError(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}
	return nil
}

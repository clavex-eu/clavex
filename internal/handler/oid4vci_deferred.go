package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
)

func (h *OID4VCIHandler) retrieveDeferredCredential(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()
	raw := extractBearerToken(c)
	if raw == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}
	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}
	offer, err := h.repo.GetOfferByAccessToken(ctx, hashToken(raw))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return echo.ErrServiceUnavailable
	}
	if err != nil || offer.OrgID != org.ID {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}
	if err := h.validateWalletResource(c, raw); err != nil {
		return err
	}
	var request deferredCredentialRequest
	if err := h.bindCredentialRequest(c, &request); err != nil || request.TransactionID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request"})
	}
	if request.CredentialResponseEncryption != nil && !strings.HasPrefix(c.Request().Header.Get(echo.HeaderContentType), "application/jwt") {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "deferred encryption parameters require an encrypted request"})
	}
	repo, tx, err := h.repo.BeginIssuance(ctx)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	defer tx.Rollback(ctx)
	grant, err := repo.LockWalletGrant(ctx, offer.ID, org.ID)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	// Recheck token validity after waiting for a concurrent rotation/revocation.
	current, err := repo.GetOfferByAccessToken(ctx, hashToken(raw))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return echo.ErrServiceUnavailable
	}
	if err != nil || current.ID != offer.ID {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}
	current, err = repo.LockWalletOffer(ctx, offer.ID, org.ID)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	if grant != nil {
		if err := repo.CheckWalletEligibility(ctx, grant, current); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return echo.ErrServiceUnavailable
			}
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_request_denied"})
		}
	}
	delivered, err := repo.LockDeferredDelivery(ctx, request.TransactionID, org.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_transaction_id"})
		}
		return echo.ErrServiceUnavailable
	}
	dc, err := repo.GetDeferredCredential(ctx, request.TransactionID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return echo.ErrServiceUnavailable
	}
	if err != nil || dc.OrgID != org.ID || dc.OfferID != offer.ID || dc.CredentialConfigurationID != offer.VCT || delivered || !time.Now().Before(dc.ExpiresAt) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_transaction_id"})
	}
	cfg, err := repo.GetCredentialConfigByVCT(ctx, org.ID, dc.CredentialConfigurationID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrServiceUnavailable
		}
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_request_denied"})
	}
	if grant == nil {
		if err := repo.LockWalletEligibility(ctx, org.ID, current.UserID, "", cfg.ID, current.VCT); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return echo.ErrServiceUnavailable
			}
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_request_denied"})
		}
	}
	switch dc.Status {
	case "pending":
		return finishCredentialResponseStatus(c, tx, map[string]any{"transaction_id": dc.TransactionID, "interval": deferredPollInterval}, request.CredentialResponseEncryption, http.StatusAccepted)
	case "completed":
		if dc.CredentialJWT == nil {
			return echo.ErrServiceUnavailable
		}
		scoped := *h
		scoped.repo = repo
		if err := scoped.checkDeferredCredentialStatus(ctx, org, cfg, *dc.CredentialJWT); err != nil {
			if errors.Is(err, errWalletStatusRejected) {
				return c.JSON(400, map[string]string{"error": "credential_request_denied"})
			}
			return echo.ErrServiceUnavailable
		}
		if err := repo.ConsumeDeferredDelivery(ctx, dc.TransactionID, org.ID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_transaction_id"})
			}
			return echo.ErrServiceUnavailable
		}
		if err := repo.CloseWalletGrant(ctx, offer.ID); err != nil {
			return echo.ErrServiceUnavailable
		}
		return finishCredentialResponse(c, tx, map[string]any{"credentials": []map[string]any{{"credential": *dc.CredentialJWT}}}, request.CredentialResponseEncryption)
	case "failed":
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_request_denied"})
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_transaction_id"})
	}
}

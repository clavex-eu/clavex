package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
)

func (h *OID4VCIHandler) beginCredentialIssuance(ctx context.Context, offer *models.CredentialOffer, tokenHash string) (*OID4VCIHandler, pgx.Tx, error) {
	repo, tx, err := h.repo.BeginIssuance(ctx)
	if err != nil {
		return nil, nil, err
	}
	if offer != nil {
		if err := repo.LockIssuanceOffer(ctx, offer.ID, offer.OrgID, tokenHash); err != nil {
			_ = tx.Rollback(ctx)
			return nil, nil, err
		}
	}
	copy := *h
	copy.repo = repo
	copy.mdocIssuers = repository.NewMdocIssuerRepository(tx)
	return &copy, tx, nil
}

func writeIssuanceError(c echo.Context, err error) error {
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_credential_request", "error_description": "issuance authorization has expired or was already consumed"})
	}
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "error_description": "issuance is already in progress"})
	}
	return echo.ErrInternalServerError
}

// Prepare encryption before committing; never return a credential whose records
// or offer consumption failed to commit. Redis nonce consumption is separate:
// failures require fresh proofs on retry rather than reusing a challenge.
func finishCredentialResponse(c echo.Context, tx pgx.Tx, body any, encryption *credentialResponseEncryptionReq) error {
	return finishCredentialResponseStatus(c, tx, body, encryption, http.StatusOK)
}

func finishCredentialResponseStatus(c echo.Context, tx pgx.Tx, body any, encryption *credentialResponseEncryptionReq, status int) error {
	data, err := json.Marshal(body)
	if err != nil {
		return echo.ErrInternalServerError
	}
	contentType := echo.MIMEApplicationJSON
	if encryption != nil {
		token, err := encryptCredentialResponse(data, encryption)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_encryption_parameters", "error_description": "invalid credential response encryption parameters"})
		}
		data = []byte(token)
		contentType = "application/jwt"
	}
	if err := tx.Commit(c.Request().Context()); err != nil {
		return echo.ErrInternalServerError
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Blob(status, contentType, data)
}

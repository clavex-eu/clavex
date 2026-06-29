package handler

// OrgSigningKeyHandler provides the BYOK (Bring Your Own Key) API for
// per-organisation signing key management.
//
// API:
//   GET    /api/v1/organizations/:id/signing-key        — current key info
//   PUT    /api/v1/organizations/:id/signing-key        — generate or import key
//   DELETE /api/v1/organizations/:id/signing-key        — remove (revert to global)

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// OrgSigningKeyHandler manages per-org RSA signing keys.
type OrgSigningKeyHandler struct {
	signers *oidc.OrgSignerCache
	keyRepo *repository.SigningKeyRepository
	orgRepo *repository.OrgRepository
}

// NewOrgSigningKeyHandler creates the handler.
func NewOrgSigningKeyHandler(pool *pgxpool.Pool, signers *oidc.OrgSignerCache) *OrgSigningKeyHandler {
	return &OrgSigningKeyHandler{
		signers: signers,
		keyRepo: repository.NewSigningKeyRepository(pool),
		orgRepo: repository.NewOrgRepository(pool),
	}
}

// signingKeyInfo is the read model returned by GET and PUT.
type signingKeyInfo struct {
	KID       string    `json:"kid"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
}

// Get handles GET /api/v1/organizations/:id/signing-key.
// Returns 404 if the org has no own key (it is using the global one).
func (h *OrgSigningKeyHandler) Get(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid organization id")
	}

	row, err := h.keyRepo.GetActiveForOrg(ctx, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound,
				"organization has no custom signing key (using global)")
		}
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, signingKeyInfo{
		KID:       row.KID,
		Algorithm: row.Algorithm,
		CreatedAt: row.CreatedAt,
	})
}

// upsertKeyRequest is the body for PUT.
type upsertKeyRequest struct {
	// Action: "generate" (default when body is empty or action unset).
	Action string `json:"action"`
	// PEM: PKCS#8 or PKCS#1 RSA private key in PEM format.
	PEM string `json:"pem"`
	// JWK: JSON-encoded RSA private JWK (RFC 7517).
	JWK string `json:"jwk"`
}

// Upsert handles PUT /api/v1/organizations/:id/signing-key.
//
//   - Empty body or {"action":"generate"} → generates a new RSA-2048 key server-side.
//   - {"pem":"-----BEGIN PRIVATE KEY-----…"} → imports PKCS#8 or PKCS#1 PEM.
//   - {"jwk":"{…}"} → imports RSA private key in JWK JSON format.
func (h *OrgSigningKeyHandler) Upsert(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid organization id")
	}

	if _, err := h.orgRepo.GetByID(ctx, orgID); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	var req upsertKeyRequest
	if c.Request().ContentLength > 0 {
		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
		}
	}

	var kid string

	switch {
	case req.PEM != "":
		der, parseErr := decodePKCS8PEM(req.PEM)
		if parseErr != nil {
			return echo.NewHTTPError(http.StatusUnprocessableEntity, parseErr.Error())
		}
		kid, err = h.signers.ImportForOrg(ctx, orgID, der)

	case req.JWK != "":
		der, parseErr := decodeJWKPrivate([]byte(req.JWK))
		if parseErr != nil {
			return echo.NewHTTPError(http.StatusUnprocessableEntity, parseErr.Error())
		}
		kid, err = h.signers.ImportForOrg(ctx, orgID, der)

	default:
		// action="generate" (or empty body)
		kid, err = h.signers.GenerateForOrg(ctx, orgID)
	}

	if err != nil {
		return echo.ErrInternalServerError
	}

	row, dbErr := h.keyRepo.GetActiveForOrg(ctx, orgID)
	if dbErr != nil {
		return c.JSON(http.StatusOK, map[string]string{"kid": kid})
	}
	return c.JSON(http.StatusOK, signingKeyInfo{
		KID:       row.KID,
		Algorithm: row.Algorithm,
		CreatedAt: row.CreatedAt,
	})
}

// Delete handles DELETE /api/v1/organizations/:id/signing-key.
// Hard-deletes all org signing keys; the org reverts to the global key.
func (h *OrgSigningKeyHandler) Delete(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid organization id")
	}

	if err := h.signers.RemoveForOrg(ctx, orgID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── key decode helpers ────────────────────────────────────────────────────────

// decodePKCS8PEM parses a PEM-encoded PKCS#8 ("PRIVATE KEY") or PKCS#1
// ("RSA PRIVATE KEY") block and returns the raw PKCS#8 DER bytes.
func decodePKCS8PEM(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, echo.NewHTTPError(http.StatusUnprocessableEntity, "no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8 — use as-is
		return block.Bytes, nil
	case "RSA PRIVATE KEY": // PKCS#1 — re-wrap in PKCS#8
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKCS8PrivateKey(key)
	default:
		return nil, echo.NewHTTPError(http.StatusUnprocessableEntity,
			"unsupported PEM block type: "+block.Type)
	}
}

// decodeJWKPrivate parses a JSON RSA private JWK and returns PKCS#8 DER bytes.
func decodeJWKPrivate(raw []byte) ([]byte, error) {
	key, err := jwk.ParseKey(raw)
	if err != nil {
		return nil, err
	}
	var rsaKey rsa.PrivateKey
	if err := key.Raw(&rsaKey); err != nil {
		return nil, err
	}
	if bits := rsaKey.N.BitLen(); bits < 2048 {
		return nil, echo.NewHTTPError(http.StatusUnprocessableEntity,
			"RSA key too short; minimum 2048 bits")
	}
	return x509.MarshalPKCS8PrivateKey(&rsaKey)
}

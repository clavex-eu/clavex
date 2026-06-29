package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// MdocIssuerHandler manages per-org Document Signer (DS) key + certificate pairs
// used to issue ISO 18013-5 mdoc credentials via OID4VCI.
type MdocIssuerHandler struct {
	repo *repository.MdocIssuerRepository
	orgs *repository.OrgRepository
}

func NewMdocIssuerHandler(pool *pgxpool.Pool) *MdocIssuerHandler {
	return &MdocIssuerHandler{
		repo: repository.NewMdocIssuerRepository(pool),
		orgs: repository.NewOrgRepository(pool),
	}
}

// ── Request/response types ────────────────────────────────────────────────────

type createMdocIssuerRequest struct {
	DisplayName       string  `json:"display_name"          validate:"required"`
	DocType           string  `json:"doc_type"              validate:"required"`
	// DSPrivateKeyPEM: provide an existing PEM key, or omit to auto-generate.
	DSPrivateKeyPEM   string  `json:"ds_private_key_pem"`
	DSCertificatePEM  string  `json:"ds_certificate_pem"`
	IACACertificatePEM *string `json:"iaca_certificate_pem"`
	ValidityHours     int     `json:"validity_hours"`
}

// Generate handles POST /api/v1/organizations/:org_id/mdoc/issuers/generate
//
// Auto-generates a self-signed ECDSA P-256 DS key + certificate pair and stores
// it as the active issuer for the requested docType.  Useful for test/sandbox
// environments — in production upload a DS cert signed by your IACA CA.
func (h *MdocIssuerHandler) Generate(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		DisplayName string `json:"display_name" validate:"required"`
		DocType     string `json:"doc_type"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.DocType == "" {
		req.DocType = mdoc.DocTypeMdl
	}

	org, err := h.orgs.GetByID(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	dsKeyPEM, dsCertPEM, err := mdoc.GenerateMdocIssuerKeys(org.Name, req.DocType)
	if err != nil {
		return echo.ErrInternalServerError
	}

	issuer, err := h.repo.Create(
		c.Request().Context(),
		orgID,
		req.DisplayName,
		req.DocType,
		dsKeyPEM,
		dsCertPEM,
		nil,
		720,
	)
	if err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"issuer":          issuer,
		"ds_certificate":  dsCertPEM,
		// Expose the IACA cert (same as DS cert for self-signed) so the admin can
		// add it to the wallet's trusted list or the org's iaca_roots.
		"iaca_certificate": dsCertPEM,
	})
}

// Create handles POST /api/v1/organizations/:org_id/mdoc/issuers
//
// Upload an existing DS key + certificate (e.g., issued by your org's IACA CA).
func (h *MdocIssuerHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createMdocIssuerRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.DSPrivateKeyPEM == "" || req.DSCertificatePEM == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ds_private_key_pem and ds_certificate_pem are required")
	}
	if req.DocType == "" {
		req.DocType = mdoc.DocTypeMdl
	}
	if req.ValidityHours <= 0 {
		req.ValidityHours = 720
	}

	issuer, err := h.repo.Create(
		c.Request().Context(),
		orgID,
		req.DisplayName,
		req.DocType,
		req.DSPrivateKeyPEM,
		req.DSCertificatePEM,
		req.IACACertificatePEM,
		req.ValidityHours,
	)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, issuer)
}

// List handles GET /api/v1/organizations/:org_id/mdoc/issuers
func (h *MdocIssuerHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	issuers, err := h.repo.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if issuers == nil {
		issuers = []*models.OrgMdocIssuer{}
	}
	return c.JSON(http.StatusOK, issuers)
}

// Delete handles DELETE /api/v1/organizations/:org_id/mdoc/issuers/:issuer_id
func (h *MdocIssuerHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	issuerID, err := uuidParam(c, "issuer_id")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.Request().Context(), issuerID, orgID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

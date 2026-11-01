package handler

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	secretcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/walletsigning"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// MdocIssuerHandler manages per-org Document Signer (DS) key + certificate pairs
// used to issue ISO 18013-5 mdoc credentials via OID4VCI.
type MdocIssuerHandler struct {
	repo  *repository.MdocIssuerRepository
	orgs  *repository.OrgRepository
	enc   *secretcrypto.Encryptor
	vault *walletsigning.Registry
}

func NewMdocIssuerHandler(pool *pgxpool.Pool) *MdocIssuerHandler {
	return &MdocIssuerHandler{
		repo: repository.NewMdocIssuerRepository(pool),
		orgs: repository.NewOrgRepository(pool),
	}
}

// WithSigningStorage enables encrypted local keys and operator-scoped Vault references.
func (h *MdocIssuerHandler) WithSigningStorage(enc *secretcrypto.Encryptor, vault *walletsigning.Registry) *MdocIssuerHandler {
	h.enc = enc
	h.vault = vault
	return h
}

// VaultProfiles exposes only labels and references authorised for this tenant.
func (h *MdocIssuerHandler) VaultProfiles(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	if h.vault.Err() != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "wallet Vault profile configuration unavailable")
	}
	return c.JSON(http.StatusOK, h.vault.Choices(orgID))
}

// ── Request/response types ────────────────────────────────────────────────────

type createMdocIssuerRequest struct {
	ReplaceExisting bool   `json:"replace_existing"`
	VaultSignerRef  string `json:"vault_signer_ref"`
	DisplayName     string `json:"display_name"          validate:"required"`
	DocType         string `json:"doc_type"              validate:"required"`
	// Provide either one PEM key or an authorised Vault signer reference.
	DSPrivateKeyPEM    string  `json:"ds_private_key_pem"`
	DSCertificatePEM   string  `json:"ds_certificate_pem"`
	IACACertificatePEM *string `json:"iaca_certificate_pem"`
	ValidityHours      int     `json:"validity_hours"`
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
		DisplayName     string `json:"display_name" validate:"required"`
		ReplaceExisting bool   `json:"replace_existing"`
		DocType         string `json:"doc_type"`
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

	encrypted, err := walletsigning.EncryptKey(h.enc, dsKeyPEM)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "wallet key encryption unavailable")
	}
	issuer, err := h.repo.CreateWithSigner(
		c.Request().Context(),
		orgID,
		req.DisplayName,
		req.DocType,
		&encrypted,
		dsCertPEM,
		nil,
		720, "", req.ReplaceExisting,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusConflict, "an active signer already exists; confirm replacement explicitly")
	}
	if err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"issuer":         mdocPublicView(issuer),
		"ds_certificate": dsCertPEM,
		// This self-signed DS leaf is exclusively for sandbox use.
		"sandbox": true,
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
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.DocType = strings.TrimSpace(req.DocType)
	if (req.DSPrivateKeyPEM == "") == (req.VaultSignerRef == "") || req.DSCertificatePEM == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "provide a DS certificate and exactly one of private key or Vault profile")
	}
	if strings.TrimSpace(req.DisplayName) == "" || utf8.RuneCountInString(req.DisplayName) > 200 || len(req.DocType) > 512 || req.DocType == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid display name or document type")
	}
	leaf, _, err := walletsigning.Certificates(req.DSCertificatePEM, req.IACACertificatePEM, false)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	var storedKey *string
	if req.VaultSignerRef != "" {
		signer, resolveErr := h.vault.Resolve(orgID, req.VaultSignerRef, leaf.PublicKey)
		if resolveErr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Vault profile unavailable for this organisation")
		}
		challenge := sha256.Sum256([]byte("Clavex mdoc DS signing configuration check"))
		if _, err = signer.Sign(rand.Reader, challenge[:], crypto.SHA256); err != nil {
			return echo.NewHTTPError(http.StatusBadGateway, "Vault signing check failed; configuration was not saved")
		}
	} else {
		if _, err = walletsigning.LocalKey(req.DSCertificatePEM, req.DSPrivateKeyPEM); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		encrypted, encryptErr := walletsigning.EncryptKey(h.enc, req.DSPrivateKeyPEM)
		if encryptErr != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "wallet key encryption unavailable")
		}
		storedKey = &encrypted
	}

	if req.DocType == "" {
		req.DocType = mdoc.DocTypeMdl
	}
	if req.ValidityHours == 0 {
		req.ValidityHours = 720
	}
	if req.ValidityHours < 1 || req.ValidityHours > 8760 {
		return echo.NewHTTPError(http.StatusBadRequest, "validity_hours must be between 1 and 8760")
	}

	issuer, err := h.repo.CreateWithSigner(
		c.Request().Context(),
		orgID,
		req.DisplayName,
		req.DocType,
		storedKey,
		req.DSCertificatePEM,
		req.IACACertificatePEM,
		req.ValidityHours,
		req.VaultSignerRef,
		req.ReplaceExisting,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.NewHTTPError(http.StatusConflict, "an active signer already exists; confirm replacement explicitly")
	}
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, mdocPublicView(issuer))
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
	views := make([]mdocIssuerView, 0, len(issuers))
	for _, issuer := range issuers {
		views = append(views, mdocPublicView(issuer))
	}
	return c.JSON(http.StatusOK, views)
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

// Explicit response projection: neither stored private keys nor provider tokens
// can be serialised, including for legacy or malformed database records.
type mdocIssuerView struct {
	ID               string     `json:"id"`
	DisplayName      string     `json:"display_name"`
	DocType          string     `json:"doc_type"`
	IsActive         bool       `json:"is_active"`
	ValidityHours    int        `json:"validity_hours"`
	Backend          string     `json:"key_backend"`
	VaultSignerRef   string     `json:"vault_signer_ref,omitempty"`
	Certificate      string     `json:"ds_certificate_pem,omitempty"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	NotAfter         *time.Time `json:"not_after,omitempty"`
	Fingerprint      string     `json:"sha256_fingerprint,omitempty"`
	CertificateError bool       `json:"certificate_error"`
}

func mdocPublicView(rec *models.OrgMdocIssuer) mdocIssuerView {
	out := mdocIssuerView{ID: rec.ID.String(), DisplayName: rec.DisplayName, DocType: rec.DocType, IsActive: rec.IsActive, ValidityHours: rec.ValidityHours, Backend: "local", VaultSignerRef: rec.VaultSignerRef}
	if rec.VaultSignerRef != "" {
		out.Backend = "vault_transit"
	}
	_, _, validationErr := walletsigning.Certificates(rec.DSCertificatePEM, rec.IACACertificatePEM, true)
	out.CertificateError = validationErr != nil
	leaf, err := walletsigning.PublicCertificate(rec.DSCertificatePEM)
	if err != nil {
		out.CertificateError = true
		return out
	}
	out.Certificate = rec.DSCertificatePEM
	out.NotBefore = &leaf.NotBefore
	out.NotAfter = &leaf.NotAfter
	fp := sha256.Sum256(leaf.Raw)
	out.Fingerprint = hex.EncodeToString(fp[:])
	return out
}

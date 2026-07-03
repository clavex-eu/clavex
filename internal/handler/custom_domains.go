package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/domainverify"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// CustomDomainHandler manages CRUD for per-org custom domains.
type CustomDomainHandler struct {
	repo        *repository.CustomDomainRepository
	enc         *crypto.Encryptor
	resolver    domainverify.Resolver
	cnameTarget string // expected CNAME target, e.g. "ingress.cloud.clavex.eu"
}

func NewCustomDomainHandler(pool *pgxpool.Pool, enc *crypto.Encryptor) *CustomDomainHandler {
	return &CustomDomainHandler{
		repo:        repository.NewCustomDomainRepository(pool),
		enc:         enc,
		resolver:    net.DefaultResolver,
		cnameTarget: strings.TrimSuffix(os.Getenv("CLAVEX_CLOUD_CNAME_TARGET"), "."),
	}
}

// List returns all custom domains for an org.
// GET /api/v1/organizations/:org_id/custom-domains
func (h *CustomDomainHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	domains, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	if domains == nil {
		domains = []*repository.CustomDomain{}
	}
	return c.JSON(http.StatusOK, domains)
}

// Create registers a new custom domain for an org (status=pending).
// POST /api/v1/organizations/:org_id/custom-domains
func (h *CustomDomainHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	var body struct {
		Domain string `json:"domain"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	domain := strings.ToLower(strings.TrimSpace(body.Domain))
	if domain == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "domain is required")
	}
	// Basic sanity: must look like a hostname (no scheme, no path).
	if strings.ContainsAny(domain, "/:?#") {
		return echo.NewHTTPError(http.StatusBadRequest, "domain must be a plain hostname without scheme or path")
	}

	d, err := h.repo.Create(c.Request().Context(), orgID, domain)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return echo.NewHTTPError(http.StatusConflict, "domain is already registered")
		}
		return err
	}
	return c.JSON(http.StatusCreated, d)
}

// Delete removes a custom domain.
// DELETE /api/v1/organizations/:org_id/custom-domains/:domain_id
func (h *CustomDomainHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	domainID, err := uuidParam(c, "domain_id")
	if err != nil {
		return err
	}

	if err := h.repo.Delete(c.Request().Context(), domainID, orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "custom domain not found")
		}
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// Verify checks that the customer's domain CNAMEs to the Clavex target and, on
// success, marks it active so the ingress reconciler picks it up. On failure it
// records the failed status and returns the expected target for the UI to show.
// POST /api/v1/organizations/:org_id/custom-domains/:domain_id/verify
func (h *CustomDomainHandler) Verify(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	domainID, err := uuidParam(c, "domain_id")
	if err != nil {
		return err
	}

	domains, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	var dom *repository.CustomDomain
	for _, d := range domains {
		if d.ID == domainID {
			dom = d
			break
		}
	}
	if dom == nil {
		return echo.NewHTTPError(http.StatusNotFound, "custom domain not found")
	}

	if h.cnameTarget == "" {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "domain verification not configured")
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()
	resolved, lookupErr := h.resolver.LookupCNAME(ctx, dom.Domain)
	if lookupErr != nil || !domainverify.Matches(resolved, h.cnameTarget) {
		_ = h.repo.SetFailed(c.Request().Context(), domainID)
		return c.JSON(http.StatusOK, map[string]any{
			"status":         "failed",
			"expected_cname": h.cnameTarget,
			"resolved_cname": strings.TrimSuffix(resolved, "."),
			"message":        "domain does not yet CNAME to " + h.cnameTarget + " — add the record and retry",
		})
	}

	if err := h.repo.Activate(c.Request().Context(), domainID, nil); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]any{
		"status":  "active",
		"message": "domain verified — TLS will be provisioned shortly",
	})
}

type uploadCertRequest struct {
	CertPEM string `json:"cert_pem"` // leaf + intermediate chain
	KeyPEM  string `json:"key_pem"`  // private key (PKCS#8/PKCS#1/EC)
}

// validateBYOCert checks that cert+key form a valid pair, the leaf covers the
// domain, and the cert is currently within its validity window. Returns the
// certificate expiry (NotAfter). Pure — no I/O — so it is unit-testable.
func validateBYOCert(certPEM, keyPEM, domain string) (time.Time, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return time.Time{}, errors.New("certificate and private key do not match or are malformed")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, errors.New("could not parse leaf certificate")
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return time.Time{}, errors.New("certificate does not cover domain " + domain)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return time.Time{}, errors.New("certificate is not yet valid")
	}
	if now.After(leaf.NotAfter) {
		return time.Time{}, errors.New("certificate has expired")
	}
	return leaf.NotAfter, nil
}

// UploadCert stores a customer-supplied TLS certificate for a domain (BYO).
// POST /api/v1/organizations/:org_id/custom-domains/:domain_id/certificate
func (h *CustomDomainHandler) UploadCert(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	domainID, err := uuidParam(c, "domain_id")
	if err != nil {
		return err
	}

	// Resolve the domain and confirm it belongs to this org.
	domains, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	var dom *repository.CustomDomain
	for _, d := range domains {
		if d.ID == domainID {
			dom = d
			break
		}
	}
	if dom == nil {
		return echo.NewHTTPError(http.StatusNotFound, "custom domain not found")
	}

	var req uploadCertRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON")
	}
	if strings.TrimSpace(req.CertPEM) == "" || strings.TrimSpace(req.KeyPEM) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "cert_pem and key_pem are required")
	}

	expiry, err := validateBYOCert(req.CertPEM, req.KeyPEM, dom.Domain)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Encrypt the private key at rest with the app KEK before storage.
	keyEnc, err := h.enc.EncryptBytes([]byte(req.KeyPEM))
	if err != nil {
		return echo.ErrInternalServerError
	}
	if err := h.repo.SetBYOCert(c.Request().Context(), domainID, orgID, req.CertPEM, keyEnc, &expiry); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "custom domain not found")
		}
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]any{
		"message":     "certificate stored; ingress will apply it shortly",
		"cert_source": "byo",
		"cert_expiry": expiry,
	})
}

// RevertCert removes a BYO certificate and returns the domain to ACME issuance.
// DELETE /api/v1/organizations/:org_id/custom-domains/:domain_id/certificate
func (h *CustomDomainHandler) RevertCert(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	domainID, err := uuidParam(c, "domain_id")
	if err != nil {
		return err
	}
	if err := h.repo.RevertToACME(c.Request().Context(), domainID, orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "custom domain not found")
		}
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ensure uuid.Nil is not flagged as unused
var _ = uuid.Nil

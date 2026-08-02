package handler

// DevicePKIHandler implements the Device CA API used to authenticate IoT
// device fleets to an external MQTT broker via mTLS. It is the X.509
// counterpart to PAMSSHCARotationHandler/PAMHandler's ssh-ca endpoints.
//
// Endpoints:
//
//	Admin (org-scoped admin session, "security" permission), under
//	/api/v1/organizations/:org_id/devices:
//	  GET    /ca                              — get Device CA config (no token)
//	  PUT    /ca                               — upsert Device CA config
//	  DELETE /ca
//	  POST   /:device_id/enrollment-secrets     — pre-register a device + issue a one-time bootstrap secret
//	  POST   /enrollment-secrets/:secret_id/revoke — revoke an unused (still-pending) bootstrap secret
//	  POST   /:device_id/certificates/:serial/revoke — revoke one issued certificate (device compromised)
//	  POST   /:device_id/revoke                 — revoke the whole device (all active certs + any pending secret)
//
//	Device-facing (authenticated by the bootstrap secret itself, no admin
//	session — registered without the admin JWT/CSRF middleware), under the
//	same path prefix:
//	  POST   /enroll                            — one-time enrollment: bootstrap secret + CSR -> first certificate
//
// The renewal endpoint (device authenticates with its current mTLS cert) is
// served on a dedicated mTLS listener — see DeviceRenewHandler.

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/devicepki"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// DevicePKIHandler serves the Device CA endpoints.
type DevicePKIHandler struct {
	repo *repository.DevicePKIRepository
	enc  *crypto.Encryptor
	svc  *devicepki.Service
}

// NewDevicePKIHandler builds the handler. disp may be nil (rotation webhooks skipped).
func NewDevicePKIHandler(pool *pgxpool.Pool, enc *crypto.Encryptor, disp devicepki.Dispatcher) *DevicePKIHandler {
	repo := repository.NewDevicePKIRepository(pool)
	return &DevicePKIHandler{
		repo: repo,
		enc:  enc,
		svc:  devicepki.NewService(repo, enc, disp),
	}
}

// ── Device CA config ──────────────────────────────────────────────────────

type deviceCAUpsertBody struct {
	VaultAddr                 string `json:"vault_addr"`
	VaultToken                string `json:"vault_token"` // plaintext — encrypted before storage
	VaultMount                string `json:"vault_mount"`
	VaultRole                 string `json:"vault_role"`
	CertTTLSeconds            int    `json:"cert_ttl_seconds"`
	RenewalWindowSeconds      int    `json:"renewal_window_seconds"`
	BootstrapSecretTTLSeconds int    `json:"bootstrap_secret_ttl_seconds"`
}

// GetDeviceCA handles GET /devices/ca.
func (h *DevicePKIHandler) GetDeviceCA(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	cfg, err := h.repo.GetDeviceCAConfig(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get Device CA config")
	}
	if cfg == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Device CA not configured")
	}
	return c.JSON(http.StatusOK, cfg)
}

// UpsertDeviceCA handles PUT /devices/ca. On first configuration of a mount,
// it provisions the Vault PKI mount, generates the root CA and the device
// signing role, and caches the CA certificate — mirroring how PAM's SSH CA
// caches its public key on save, but device CA additionally has to CREATE the
// mount (SSH CA's UpsertSSHCA assumes an already-provisioned mount).
func (h *DevicePKIHandler) UpsertDeviceCA(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	var body deviceCAUpsertBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if body.VaultAddr == "" || body.VaultToken == "" || body.VaultRole == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "vault_addr, vault_token, vault_role are required")
	}
	if body.VaultMount == "" {
		body.VaultMount = "pki-device-" + orgID.String()[:8]
	}
	if body.CertTTLSeconds <= 0 {
		body.CertTTLSeconds = 604800
	}
	if body.RenewalWindowSeconds <= 0 {
		body.RenewalWindowSeconds = 172800
	}
	if body.BootstrapSecretTTLSeconds <= 0 {
		body.BootstrapSecretTTLSeconds = 259200
	}

	encToken, err := h.enc.Encrypt(body.VaultToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to encrypt vault token")
	}
	if err := h.repo.UpsertDeviceCAConfig(c.Request().Context(), orgID,
		body.VaultAddr, encToken, body.VaultMount, body.VaultRole,
		body.CertTTLSeconds, body.RenewalWindowSeconds, body.BootstrapSecretTTLSeconds,
	); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save Device CA config")
	}

	if err := h.svc.EnsureMountProvisioned(c.Request().Context(), orgID, body.VaultAddr, body.VaultToken, body.VaultMount, body.VaultRole, body.CertTTLSeconds); err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "saved config but failed to provision Vault PKI mount: "+err.Error())
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// DeleteDeviceCA handles DELETE /devices/ca.
func (h *DevicePKIHandler) DeleteDeviceCA(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	if err := h.repo.DeleteDeviceCAConfig(c.Request().Context(), orgID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete Device CA config")
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Enrollment secrets (admin) ────────────────────────────────────────────

type createEnrollmentSecretBody struct {
	FleetID string `json:"fleet_id"`
}

// CreateEnrollmentSecret handles POST /devices/:device_id/enrollment-secrets.
// Pre-registers the device (status 'pending') if it doesn't exist yet, and
// issues a fresh one-time bootstrap secret for it. The raw secret is returned
// exactly once, for injection into the physical provisioning process.
func (h *DevicePKIHandler) CreateEnrollmentSecret(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	deviceExternalID := c.Param("device_id")
	if deviceExternalID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "device_id required")
	}
	var body createEnrollmentSecretBody
	_ = c.Bind(&body)

	ctx := c.Request().Context()
	cfg, err := h.repo.GetDeviceCAConfig(ctx, orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load Device CA config")
	}
	if cfg == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Device CA not configured")
	}

	var fleetID *string
	if body.FleetID != "" {
		fleetID = &body.FleetID
	}
	dev, err := h.repo.UpsertPendingDevice(ctx, orgID, deviceExternalID, fleetID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to register device")
	}

	createdBy := "admin"
	secret, raw, err := h.repo.CreateEnrollmentSecret(ctx, orgID, dev.ID,
		secondsToDuration(cfg.BootstrapSecretTTLSeconds), createdBy)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create enrollment secret")
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"enrollment_secret_id": secret.ID,
		"device_id":            deviceExternalID,
		"bootstrap_secret":     raw,
		"expires_at":           secret.ExpiresAt,
	})
}

// RevokeEnrollmentSecret handles POST /devices/enrollment-secrets/:secret_id/revoke.
func (h *DevicePKIHandler) RevokeEnrollmentSecret(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	secretID, err := uuidParam(c, "secret_id")
	if err != nil {
		return err
	}
	if err := h.repo.RevokeEnrollmentSecret(c.Request().Context(), orgID, secretID); err != nil {
		if errors.Is(err, repository.ErrEnrollmentSecretNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "no pending enrollment secret with that id")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to revoke enrollment secret")
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Revocation (admin) ────────────────────────────────────────────────────

type revokeReasonBody struct {
	Reason string `json:"reason"`
}

// RevokeCertificate handles POST /devices/:device_id/certificates/:serial/revoke.
func (h *DevicePKIHandler) RevokeCertificate(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	serial := c.Param("serial")
	if serial == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "serial required")
	}
	var body revokeReasonBody
	_ = c.Bind(&body)

	revokedBy := adminActor(c)
	if err := h.svc.RevokeCertificateBySerial(c.Request().Context(), orgID, serial, body.Reason, revokedBy); err != nil {
		return deviceCAError(err)
	}
	return c.NoContent(http.StatusNoContent)
}

// RevokeDevice handles POST /devices/:device_id/revoke — the whole-device
// compromise path: revokes every active certificate and flags the device
// itself revoked.
func (h *DevicePKIHandler) RevokeDevice(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	deviceExternalID := c.Param("device_id")
	if deviceExternalID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "device_id required")
	}
	var body revokeReasonBody
	_ = c.Bind(&body)

	ctx := c.Request().Context()
	dev, err := h.repo.GetDeviceByExternalID(ctx, orgID, deviceExternalID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to look up device")
	}
	if dev == nil {
		return echo.NewHTTPError(http.StatusNotFound, "device not found")
	}

	revokedBy := adminActor(c)
	if err := h.svc.RevokeDevice(ctx, orgID, dev.ID, body.Reason, revokedBy); err != nil {
		return deviceCAError(err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Enrollment (device-facing, no admin auth) ─────────────────────────────

type deviceEnrollBody struct {
	DeviceID        string `json:"device_id"`
	BootstrapSecret string `json:"bootstrap_secret"`
	// CSRPEM is the PEM-encoded PKCS#10 CSR. CSRBase64 is accepted as an
	// alternative for clients that prefer not to embed PEM newlines in JSON.
	CSRPEM    string `json:"csr_pem"`
	CSRBase64 string `json:"csr_base64"`
}

// Enroll handles POST /devices/enroll. Authenticated entirely by the one-time
// bootstrap secret (no admin session, no org membership) — this is the
// endpoint IoT devices call exactly once, at physical provisioning time.
func (h *DevicePKIHandler) Enroll(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	var body deviceEnrollBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if body.DeviceID == "" || body.BootstrapSecret == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "device_id and bootstrap_secret are required")
	}
	csrPEM := []byte(body.CSRPEM)
	if len(csrPEM) == 0 && body.CSRBase64 != "" {
		decoded, derr := base64.StdEncoding.DecodeString(body.CSRBase64)
		if derr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid csr_base64")
		}
		csrPEM = decoded
	}
	if len(csrPEM) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "csr_pem or csr_base64 is required")
	}

	result, err := h.svc.Enroll(c.Request().Context(), orgID, body.DeviceID, body.BootstrapSecret, csrPEM)
	if err != nil {
		return deviceCAError(err)
	}
	return c.JSON(http.StatusCreated, map[string]any{
		"certificate_pem": result.CertificatePEM,
		"issuing_ca_pem":  result.IssuingCAPEM,
		"serial_number":   result.SerialNumber,
		"not_after":       result.NotAfter,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────

func adminActor(c echo.Context) string {
	if claims := middleware.GetClaims(c); claims != nil {
		return claims.Subject
	}
	return "admin"
}

func secondsToDuration(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

func deviceCAError(err error) error {
	switch {
	case errors.Is(err, devicepki.ErrNotConfigured):
		return echo.NewHTTPError(http.StatusNotFound, "Device CA not configured")
	case errors.Is(err, devicepki.ErrInvalidCSR):
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	case errors.Is(err, devicepki.ErrCNMismatch):
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	case errors.Is(err, devicepki.ErrDeviceNotActive):
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	case errors.Is(err, devicepki.ErrCertificateInvalid):
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	case errors.Is(err, devicepki.ErrVaultMountCapability):
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, repository.ErrDeviceNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "device not found")
	case errors.Is(err, repository.ErrEnrollmentSecretNotFound):
		return echo.NewHTTPError(http.StatusForbidden, "no pending enrollment secret for this device")
	case errors.Is(err, repository.ErrEnrollmentSecretExpired):
		return echo.NewHTTPError(http.StatusForbidden, "enrollment secret expired")
	case errors.Is(err, repository.ErrEnrollmentSecretMismatch):
		return echo.NewHTTPError(http.StatusForbidden, "enrollment secret does not match")
	default:
		return echo.NewHTTPError(http.StatusBadGateway, "device CA operation failed: "+err.Error())
	}
}

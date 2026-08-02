package handler

// DeviceRenewHandler serves the device certificate renewal endpoint on the
// dedicated Device CA mTLS listener (see internal/server: a separate
// *http.Server/port from the main API listener, with
// tls.ClientAuth=RequireAndVerifyClientCert and a ClientCAs pool that is the
// UNION of every org's Device CA certificate — a single port serves every
// tenant). The device authenticates with its current, still-valid
// certificate at the TLS layer; no bootstrap secret or operator is involved,
// so this can run unattended indefinitely (like ACME/kubelet renewal).
//
// Because the listener's ClientCAs pool is a union across all tenants,
// generic Go TLS chain verification alone only proves "signed by SOME org's
// Device CA" — it does NOT prove the cert's claimed tenant (from its CN) is
// the same org that actually signed it. Renew re-verifies the presented
// certificate's chain against the SPECIFIC org named in its own CN before
// doing anything else. This is required defence-in-depth, not optional.

import (
	"encoding/base64"
	"net/http"

	"github.com/clavex-eu/clavex/internal/devicepki"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/clavex-eu/clavex/internal/crypto"
)

// DeviceRenewHandler serves POST /renew on the dedicated Device CA mTLS
// listener.
type DeviceRenewHandler struct {
	svc *devicepki.Service
}

// NewDeviceRenewHandler builds the handler.
func NewDeviceRenewHandler(pool *pgxpool.Pool, enc *crypto.Encryptor, disp devicepki.Dispatcher) *DeviceRenewHandler {
	repo := repository.NewDevicePKIRepository(pool)
	return &DeviceRenewHandler{svc: devicepki.NewService(repo, enc, disp)}
}

type deviceRenewBody struct {
	CSRPEM    string `json:"csr_pem"`
	CSRBase64 string `json:"csr_base64"`
}

// Renew handles POST /renew.
func (h *DeviceRenewHandler) Renew(c echo.Context) error {
	req := c.Request()
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return echo.NewHTTPError(http.StatusUnauthorized, "client certificate required")
	}
	presented := req.TLS.PeerCertificates[0]

	deviceExternalID, tenantIDStr, ok := devicepki.ParseCN(presented.Subject.CommonName)
	if !ok || deviceExternalID == "" || tenantIDStr == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "certificate CN is not in <deviceID>@<tenantID> form")
	}
	orgID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "certificate CN tenant id is not a valid org id")
	}

	ctx := req.Context()
	if err := h.svc.VerifyPresentedCertForOrg(ctx, orgID, presented); err != nil {
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	}

	var body deviceRenewBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
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

	presentedSerial := devicepki.FormatSerial(presented.SerialNumber)
	result, err := h.svc.Renew(ctx, orgID, presentedSerial, presented.Subject.CommonName, csrPEM)
	if err != nil {
		return deviceCAError(err)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"certificate_pem": result.CertificatePEM,
		"issuing_ca_pem":  result.IssuingCAPEM,
		"serial_number":   result.SerialNumber,
		"not_after":       result.NotAfter,
	})
}

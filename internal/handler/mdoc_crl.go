package handler

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
)

var crlFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MdocIACACRL serves a previously provisioned, signed public CRL. Expired or
// invalid CRLs are unavailable; this endpoint never signs or renews them.
func (h *OID4VCIHandler) MdocIACACRL(c echo.Context) error {
	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}
	fingerprint := c.Param("fingerprint")
	if !crlFingerprint.MatchString(fingerprint) {
		return echo.ErrNotFound
	}
	der, err := h.mdocCRLs.Get(c.Request().Context(), org.ID, fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return echo.ErrNotFound
	}
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	c.Response().Header().Set("Cache-Control", "no-cache")
	return c.Blob(http.StatusOK, "application/pkix-crl", der)
}

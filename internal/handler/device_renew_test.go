package handler

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clavex-eu/clavex/internal/devicepki"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// These cover only the validation performed BEFORE the handler reaches the
// DB-backed devicepki.Service call (missing cert / malformed CN / bad tenant
// id) — everything past that point requires a real Vault + Postgres and is
// exercised by the sshca/pam_ssh_ca-style integration tests, not here. A
// zero-value *devicepki.Service is safe to embed because none of these paths
// call into it.

func newDeviceRenewContext(peerCert *x509.Certificate) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodPost, "/renew", nil)
	if peerCert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerCert}}
	}
	rec := httptest.NewRecorder()
	return echo.New().NewContext(req, rec), rec
}

func TestDeviceRenew_NoClientCertificate(t *testing.T) {
	h := &DeviceRenewHandler{svc: &devicepki.Service{}}
	c, _ := newDeviceRenewContext(nil)

	err := h.Renew(c)
	assert.Equal(t, http.StatusUnauthorized, httpCode(err))
}

func TestDeviceRenew_MalformedCN(t *testing.T) {
	h := &DeviceRenewHandler{svc: &devicepki.Service{}}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "no-at-sign-here"}}
	c, _ := newDeviceRenewContext(cert)

	err := h.Renew(c)
	assert.Equal(t, http.StatusBadRequest, httpCode(err))
}

func TestDeviceRenew_EmptyDeviceOrTenant(t *testing.T) {
	h := &DeviceRenewHandler{svc: &devicepki.Service{}}

	cases := []string{"@org-1", "device-1@", "@"}
	for _, cn := range cases {
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
		c, _ := newDeviceRenewContext(cert)
		err := h.Renew(c)
		assert.Equal(t, http.StatusBadRequest, httpCode(err), "for CN %q", cn)
	}
}

func TestDeviceRenew_TenantNotAValidUUID(t *testing.T) {
	h := &DeviceRenewHandler{svc: &devicepki.Service{}}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "device-1@not-a-uuid"}}
	c, _ := newDeviceRenewContext(cert)

	err := h.Renew(c)
	assert.Equal(t, http.StatusBadRequest, httpCode(err))
}

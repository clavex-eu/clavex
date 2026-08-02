package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/devicepki"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestDeviceCAErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{devicepki.ErrNotConfigured, http.StatusNotFound},
		{devicepki.ErrInvalidCSR, http.StatusBadRequest},
		{devicepki.ErrCNMismatch, http.StatusBadRequest},
		{devicepki.ErrDeviceNotActive, http.StatusForbidden},
		{devicepki.ErrCertificateInvalid, http.StatusForbidden},
		{devicepki.ErrVaultMountCapability, http.StatusUnprocessableEntity},
		{repository.ErrDeviceNotFound, http.StatusNotFound},
		{repository.ErrEnrollmentSecretNotFound, http.StatusForbidden},
		{repository.ErrEnrollmentSecretExpired, http.StatusForbidden},
		{repository.ErrEnrollmentSecretMismatch, http.StatusForbidden},
		{errors.New("vault unreachable"), http.StatusBadGateway},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.code, httpCode(deviceCAError(tc.err)), "for error %v", tc.err)
	}
}

func TestAdminActor(t *testing.T) {
	e := echo.New()

	t.Run("no claims falls back to admin", func(t *testing.T) {
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRecorder())
		assert.Equal(t, "admin", adminActor(c))
	})

	t.Run("claims present uses subject", func(t *testing.T) {
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRecorder())
		claims := &middleware.Claims{}
		claims.Subject = "admin-user-42"
		c.Set("claims", claims)
		assert.Equal(t, "admin-user-42", adminActor(c))
	})
}

func TestSecondsToDuration(t *testing.T) {
	assert.Equal(t, 72*time.Hour, secondsToDuration(259200))
	assert.Equal(t, time.Duration(0), secondsToDuration(0))
}

package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/devicepki"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceRotationErrorMapping(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, httpCode(deviceRotationError(devicepki.ErrNotConfigured)))
	assert.Equal(t, http.StatusUnprocessableEntity, httpCode(deviceRotationError(devicepki.ErrVaultMountCapability)))
	assert.Equal(t, http.StatusConflict, httpCode(deviceRotationError(repository.ErrActiveDeviceCARotationExists)))
	assert.Equal(t, http.StatusConflict, httpCode(deviceRotationError(repository.ErrInvalidDeviceCARotationTransition)))
	assert.Equal(t, http.StatusBadGateway, httpCode(deviceRotationError(errors.New("vault down"))))
}

func TestDeviceEmitRotationAction_Provenance(t *testing.T) {
	orgID := uuid.New()
	e := echo.New()

	t.Run("agent token records agent_id/delegated_by", func(t *testing.T) {
		au := &fakeAuditor{}
		h := &DevicePKIRotationHandler{auditor: au}
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRecorder())
		c.Set(ctxAgentID, "fleet-agent")
		c.Set(ctxDelegatedBy, uuid.New().String())

		h.emitRotationAction(c, context.Background(), orgID, "device_ca.rotation.completed", "rid")

		require.Len(t, au.params, 1)
		meta := au.params[0].Metadata
		assert.Equal(t, "fleet-agent", meta["agent_id"])
		assert.Equal(t, "agent_token", meta["via"])
	})

	t.Run("admin session records manual force + identity", func(t *testing.T) {
		au := &fakeAuditor{}
		h := &DevicePKIRotationHandler{auditor: au}
		adminID := uuid.New()
		claims := &middleware.Claims{}
		claims.Subject = adminID.String()
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRecorder())
		c.Set("claims", claims)

		h.emitRotationAction(c, context.Background(), orgID, "device_ca.rotation.marked_ready", "rid")

		require.Len(t, au.params, 1)
		p := au.params[0]
		assert.Equal(t, "admin_console", p.Metadata["via"])
		assert.Equal(t, true, p.Metadata["forced"])
		require.NotNil(t, p.ActorID)
		assert.Equal(t, adminID, *p.ActorID)
	})
}

func runDeviceRotationMiddleware(h *DevicePKIRotationHandler, bearer, orgID string) (bool, error) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	c := e.NewContext(req, httptest.NewRecorder())
	c.SetParamNames("org_id")
	c.SetParamValues(orgID)

	called := false
	next := func(c echo.Context) error { called = true; return c.NoContent(http.StatusOK) }
	err := h.RequireAgentScope(ScopeDeviceCARotationManage)(next)(c)
	return called, err
}

func TestDeviceRequireAgentScope(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	orgID := uuid.New()
	future := time.Now().Add(time.Hour)

	baseClaims := func() map[string]any {
		return map[string]any{
			"token_type":   "agent",
			"org_id":       orgID.String(),
			"scope":        "mcp:read " + ScopeDeviceCARotationManage,
			"agent_id":     "mqtt-broker-agent",
			"delegated_by": uuid.New().String(),
		}
	}
	okHandler := func() *DevicePKIRotationHandler {
		return &DevicePKIRotationHandler{
			signer:    stubSigner{pub: &priv.PublicKey},
			agentRepo: fakeAgentLookup{rec: &models.AgentToken{IsRevoked: false}},
		}
	}

	t.Run("valid token with scope passes", func(t *testing.T) {
		tok := mintToken(t, priv, baseClaims(), future)
		called, err := runDeviceRotationMiddleware(okHandler(), tok, orgID.String())
		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("missing scope is 403", func(t *testing.T) {
		c := baseClaims()
		c["scope"] = "mcp:read mcp:write"
		tok := mintToken(t, priv, c, future)
		called, err := runDeviceRotationMiddleware(okHandler(), tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, httpCode(err))
	})

	t.Run("wrong org is 403", func(t *testing.T) {
		tok := mintToken(t, priv, baseClaims(), future)
		called, err := runDeviceRotationMiddleware(okHandler(), tok, uuid.New().String())
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, httpCode(err))
	})

	t.Run("non-agent token is 403", func(t *testing.T) {
		c := baseClaims()
		c["token_type"] = "access"
		tok := mintToken(t, priv, c, future)
		called, err := runDeviceRotationMiddleware(okHandler(), tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, httpCode(err))
	})

	t.Run("revoked token is 401", func(t *testing.T) {
		h := &DevicePKIRotationHandler{
			signer:    stubSigner{pub: &priv.PublicKey},
			agentRepo: fakeAgentLookup{rec: &models.AgentToken{IsRevoked: true}},
		}
		tok := mintToken(t, priv, baseClaims(), future)
		called, err := runDeviceRotationMiddleware(h, tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, httpCode(err))
	})

	t.Run("wrong signature is 401", func(t *testing.T) {
		tok := mintToken(t, otherPriv, baseClaims(), future)
		called, err := runDeviceRotationMiddleware(okHandler(), tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, httpCode(err))
	})

	t.Run("expired token is 401", func(t *testing.T) {
		tok := mintToken(t, priv, baseClaims(), time.Now().Add(-time.Hour))
		called, err := runDeviceRotationMiddleware(okHandler(), tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, httpCode(err))
	})

	t.Run("no bearer is 401", func(t *testing.T) {
		called, err := runDeviceRotationMiddleware(okHandler(), "", orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, httpCode(err))
	})
}

// sanity: distinct scope constants (a copy-paste bug wiring the wrong scope
// string would silently let SSH CA agent tokens manage the Device CA rotation
// or vice versa).
func TestDeviceCARotationScope_DistinctFromSSHCA(t *testing.T) {
	assert.NotEqual(t, ScopeSSHCARotationManage, ScopeDeviceCARotationManage)
}

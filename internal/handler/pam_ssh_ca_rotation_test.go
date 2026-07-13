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

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/sshca"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAuditor struct{ params []audit.EmitParams }

func (f *fakeAuditor) Emit(_ context.Context, p audit.EmitParams) { f.params = append(f.params, p) }

func TestRotationErrorMapping(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, httpCode(rotationError(sshca.ErrNotConfigured)))
	assert.Equal(t, http.StatusUnprocessableEntity, httpCode(rotationError(sshca.ErrVaultMountCapability)))
	assert.Equal(t, http.StatusConflict, httpCode(rotationError(repository.ErrActiveRotationExists)))
	assert.Equal(t, http.StatusConflict, httpCode(rotationError(repository.ErrInvalidRotationTransition)))
	assert.Equal(t, http.StatusBadGateway, httpCode(rotationError(errors.New("vault down"))))
}

func TestEmitRotationAction_Provenance(t *testing.T) {
	orgID := uuid.New()
	e := echo.New()

	t.Run("agent token records agent_id/delegated_by", func(t *testing.T) {
		au := &fakeAuditor{}
		h := &PAMSSHCARotationHandler{auditor: au}
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRecorder())
		c.Set(ctxAgentID, "keel-fleet")
		c.Set(ctxDelegatedBy, uuid.New().String())

		h.emitRotationAction(c, context.Background(), orgID, "pam.ssh_ca.rotation.completed", "rid")

		require.Len(t, au.params, 1)
		meta := au.params[0].Metadata
		assert.Equal(t, "keel-fleet", meta["agent_id"])
		assert.Equal(t, "agent_token", meta["via"])
	})

	t.Run("admin session records manual force + identity", func(t *testing.T) {
		au := &fakeAuditor{}
		h := &PAMSSHCARotationHandler{auditor: au}
		adminID := uuid.New()
		claims := &middleware.Claims{}
		claims.Subject = adminID.String()
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRecorder())
		c.Set("claims", claims)

		h.emitRotationAction(c, context.Background(), orgID, "pam.ssh_ca.rotation.marked_ready", "rid")

		require.Len(t, au.params, 1)
		p := au.params[0]
		assert.Equal(t, "admin_console", p.Metadata["via"])
		assert.Equal(t, true, p.Metadata["forced"])
		assert.Equal(t, "manually forced via admin console", p.Metadata["note"])
		require.NotNil(t, p.ActorID)
		assert.Equal(t, adminID, *p.ActorID)
	})
}

type stubSigner struct{ pub *rsa.PublicKey }

func (s stubSigner) PublicKey() *rsa.PublicKey { return s.pub }

type fakeAgentLookup struct {
	rec *models.AgentToken
	err error
}

func (f fakeAgentLookup) GetByJTI(_ context.Context, _ string) (*models.AgentToken, error) {
	return f.rec, f.err
}

func mintToken(t *testing.T, priv *rsa.PrivateKey, claims map[string]any, exp time.Time) string {
	t.Helper()
	b := jwtlib.NewBuilder().IssuedAt(time.Now()).Expiration(exp).JwtID(uuid.NewString())
	for k, v := range claims {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	require.NoError(t, err)
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(jwa.PS256, priv))
	require.NoError(t, err)
	return string(signed)
}

// runMiddleware invokes RequireAgentScope with the given bearer token and org
// path param; returns whether next ran and the error (if any).
func runMiddleware(h *PAMSSHCARotationHandler, bearer, orgID string) (bool, error) {
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
	err := h.RequireAgentScope(ScopeSSHCARotationManage)(next)(c)
	return called, err
}

func httpCode(err error) int {
	if he, ok := err.(*echo.HTTPError); ok {
		return he.Code
	}
	return 0
}

func TestRequireAgentScope(t *testing.T) {
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
			"scope":        "mcp:read " + ScopeSSHCARotationManage,
			"agent_id":     "keel-fleet",
			"delegated_by": uuid.New().String(),
		}
	}
	okHandler := func() *PAMSSHCARotationHandler {
		return &PAMSSHCARotationHandler{
			signer:    stubSigner{pub: &priv.PublicKey},
			agentRepo: fakeAgentLookup{rec: &models.AgentToken{IsRevoked: false}},
		}
	}

	t.Run("valid token with scope passes", func(t *testing.T) {
		tok := mintToken(t, priv, baseClaims(), future)
		called, err := runMiddleware(okHandler(), tok, orgID.String())
		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("missing scope is 403", func(t *testing.T) {
		c := baseClaims()
		c["scope"] = "mcp:read mcp:write"
		tok := mintToken(t, priv, c, future)
		called, err := runMiddleware(okHandler(), tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, httpCode(err))
	})

	t.Run("wrong org is 403", func(t *testing.T) {
		tok := mintToken(t, priv, baseClaims(), future)
		called, err := runMiddleware(okHandler(), tok, uuid.New().String())
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, httpCode(err))
	})

	t.Run("non-agent token is 403", func(t *testing.T) {
		c := baseClaims()
		c["token_type"] = "access"
		tok := mintToken(t, priv, c, future)
		called, err := runMiddleware(okHandler(), tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, httpCode(err))
	})

	t.Run("revoked token is 401", func(t *testing.T) {
		h := &PAMSSHCARotationHandler{
			signer:    stubSigner{pub: &priv.PublicKey},
			agentRepo: fakeAgentLookup{rec: &models.AgentToken{IsRevoked: true}},
		}
		tok := mintToken(t, priv, baseClaims(), future)
		called, err := runMiddleware(h, tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, httpCode(err))
	})

	t.Run("unknown jti is 401", func(t *testing.T) {
		h := &PAMSSHCARotationHandler{
			signer:    stubSigner{pub: &priv.PublicKey},
			agentRepo: fakeAgentLookup{rec: nil},
		}
		tok := mintToken(t, priv, baseClaims(), future)
		called, err := runMiddleware(h, tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, httpCode(err))
	})

	t.Run("wrong signature is 401", func(t *testing.T) {
		tok := mintToken(t, otherPriv, baseClaims(), future)
		called, err := runMiddleware(okHandler(), tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, httpCode(err))
	})

	t.Run("expired token is 401", func(t *testing.T) {
		tok := mintToken(t, priv, baseClaims(), time.Now().Add(-time.Hour))
		called, err := runMiddleware(okHandler(), tok, orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, httpCode(err))
	})

	t.Run("no bearer is 401", func(t *testing.T) {
		called, err := runMiddleware(okHandler(), "", orgID.String())
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, httpCode(err))
	})
}

func TestScopeContains(t *testing.T) {
	assert.True(t, scopeContains("a b c", "b"))
	assert.True(t, scopeContains("pam:ssh_ca:rotation:manage", "pam:ssh_ca:rotation:manage"))
	assert.False(t, scopeContains("a b", "c"))
	assert.False(t, scopeContains("", "c"))
	assert.False(t, scopeContains("manage", "pam:ssh_ca:rotation:manage"))
}

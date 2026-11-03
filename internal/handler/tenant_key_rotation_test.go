package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestTenantImmediateRotationAndBYOKProtection(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	cache := oidc.NewOrgSignerCacheFromKEK(f.pool, [32]byte{47}, f.h.keys)
	before, err := cache.Resolve(ctx, f.org.ID)
	require.NoError(t, err)
	h := NewKeyRotationHandler(&config.Config{}, f.pool).WithOrgRotators(cache, nil)
	call := func(fn echo.HandlerFunc, kind string) *httptest.ResponseRecorder {
		e := echo.New()
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
		c.SetParamNames("org_id", "kind")
		c.SetParamValues(f.org.ID.String(), kind)
		if err := fn(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		return rec
	}
	require.Equal(t, 200, call(h.Rotate, "oidc").Code)
	after, err := cache.Resolve(ctx, f.org.ID)
	require.NoError(t, err)
	require.NotEqual(t, before.KID(), after.KID())
	require.Contains(t, string(after.JWKS()), before.KID())
	require.Equal(t, 409, call(h.Rotate, "pqc").Code, "disabled backend must not expose a fake operation")
	_, err = f.pool.Exec(ctx, `UPDATE signing_keys SET key_source='imported' WHERE org_id=$1 AND status='active' AND pqc_algorithm IS NULL`, f.org.ID)
	require.NoError(t, err)
	require.Equal(t, 409, call(h.Rotate, "oidc").Code)
	unchanged, err := cache.Resolve(ctx, f.org.ID)
	require.NoError(t, err)
	require.Equal(t, after.KID(), unchanged.KID())
	require.Equal(t, 400, call(h.Rotate, "enc").Code)
}

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// ── DB-backed Verify ──────────────────────────────────────────────────────────

type fakeResolver struct {
	cname string
	err   error
}

func (f fakeResolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	return f.cname, f.err
}

func hdlrPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed Verify test")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path = identity, sessions, audit, public`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func verifyReq(t *testing.T, h *CustomDomainHandler, orgID, domainID uuid.UUID) map[string]any {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id", "domain_id")
	c.SetParamValues(orgID.String(), domainID.String())
	require.NoError(t, h.Verify(c))
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

func TestVerify_CNAMEMatchActivates(t *testing.T) {
	pool := hdlrPool(t)
	ctx := context.Background()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "ver-"+uuid.NewString(), "ver-"+uuid.NewString(), nil)
	require.NoError(t, err)
	repo := repository.NewCustomDomainRepository(pool)
	dom, err := repo.Create(ctx, org.ID, "auth-"+uuid.NewString()+".acme.test")
	require.NoError(t, err)

	h := NewCustomDomainHandler(pool, nil)
	h.cnameTarget = "ingress.cloud.clavex.eu"
	h.resolver = fakeResolver{cname: "ingress.cloud.clavex.eu."}

	out := verifyReq(t, h, org.ID, dom.ID)
	require.Equal(t, "active", out["status"])

	got, err := repo.GetByDomain(ctx, dom.Domain)
	require.NoError(t, err)
	require.Equal(t, "active", got.Status)
}

func TestVerify_CNAMEMismatchFails(t *testing.T) {
	pool := hdlrPool(t)
	ctx := context.Background()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "ver2-"+uuid.NewString(), "ver2-"+uuid.NewString(), nil)
	require.NoError(t, err)
	repo := repository.NewCustomDomainRepository(pool)
	dom, err := repo.Create(ctx, org.ID, "auth-"+uuid.NewString()+".acme.test")
	require.NoError(t, err)

	h := NewCustomDomainHandler(pool, nil)
	h.cnameTarget = "ingress.cloud.clavex.eu"
	h.resolver = fakeResolver{err: errors.New("no such host")}

	out := verifyReq(t, h, org.ID, dom.ID)
	require.Equal(t, "failed", out["status"])
	require.Equal(t, "ingress.cloud.clavex.eu", out["expected_cname"])

	got, err := repo.GetByDomain(ctx, dom.Domain)
	require.NoError(t, err)
	require.Equal(t, "failed", got.Status)
}

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/db"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/redisconn"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

// Opt-in test-only entry point for a self-hosted OIDF suite. It is absent from
// production binaries and never changes the default status transport. The only
// outbound exception is the explicit loopback suite HTTPS port; signer, exact
// URI delegation, status and account checks still execute normally.
func TestWalletConformanceLab(t *testing.T) {
	path := os.Getenv("WALLET_CONFORMANCE_CONFIG")
	if path == "" {
		t.Skip("explicit isolated conformance configuration required")
	}
	suite, err := url.Parse(os.Getenv("WALLET_CONFORMANCE_SUITE"))
	require.NoError(t, err)
	require.Equal(t, "https", suite.Scheme)
	require.Equal(t, "localhost", suite.Hostname())
	require.NotEmpty(t, suite.Port())
	cfg, err := config.LoadFrom(path)
	require.NoError(t, err)
	host, _, err := net.SplitHostPort(cfg.HTTP.Addr)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	manager, err := db.Open(cfg.Database)
	require.NoError(t, err)
	defer manager.Close()
	rdb, err := redisconn.Open(cfg.Redis)
	require.NoError(t, err)
	defer rdb.Close()
	keys, err := oidc.LoadKeySet(cfg.Auth.SigningKeyFile)
	require.NoError(t, err)
	cert, err := os.ReadFile(os.Getenv("WALLET_CONFORMANCE_TLS_CERT"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(cert))
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != suite.Host {
			return nil, fmt.Errorf("test transport target is not the explicit suite")
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", suite.Port()))
	}}
	resolver := oid4w.NewStatusResolverWithHTTPClient(&http.Client{Transport: transport})
	server := New(cfg, manager.Pool, rdb, keys)
	server.echo.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.SetRequest(c.Request().WithContext(oid4w.WithStatusResolver(c.Request().Context(), resolver)))
			if os.Getenv("WALLET_CONFORMANCE_DYNAMIC_STATUS") == "1" && strings.HasSuffix(c.Request().URL.Path, "/wallet/response") {
				require.True(t, cfg.OID4VP.RequireTrustedIssuer, "dynamic lab references still require a pinned credential issuer")
				require.NoError(t, registerLabStatusReferences(c, cfg, manager.Pool, suite))
			}
			return next(c)
		}
	})
	require.NoError(t, server.echo.Start(cfg.HTTP.Addr))
}

// The suite allocates a random list URI immediately before each presentation.
// This is fixture setup, only in this opt-in test server: register that exact
// URI after verifying the credential and holder proof with already pinned keys.
// No self-asserted key, issuer, private target or wildcard delegation is added.
func registerLabStatusReferences(c echo.Context, cfg *config.Config, pool *pgxpool.Pool, suite *url.URL) error {
	ctx := c.Request().Context()
	raw, state := c.FormValue("vp_token"), c.FormValue("state")
	if raw == "" || state == "" {
		return nil
	}
	repo := repository.NewOID4WRepository(pool)
	session, err := repo.GetPresentationSession(ctx, state)
	if err != nil {
		return nil
	}
	query, err := oid4w.ParseDCQL(session.DCQLQuery)
	if err != nil {
		return nil
	}
	presentations, err := query.ParsePresentations(raw)
	if err != nil {
		return nil
	}
	trusted := parseTrustedIssuers(cfg.OID4VP.TrustedCredentialIssuers)
	org, err := repository.NewOrgRepository(pool).GetByID(ctx, session.OrgID)
	if err != nil {
		return err
	}
	sources, err := oid4w.StatusSources(org.Settings)
	if err != nil {
		return err
	}
	for _, credential := range query.Credentials {
		if credential.Format != "dc+sd-jwt" {
			continue
		}
		for _, presentation := range presentations[credential.ID] {
			result, err := oid4w.VerifyDCQLPresentation(ctx, presentation, credential.Single, session.Nonce, session.ClientID, trusted, true, nil)
			if err != nil || result.Identity == nil || len(result.Identity.Status) == 0 {
				continue
			}
			ref, err := oid4w.ParseStatusClaim(result.Identity.Status)
			if err != nil {
				continue
			}
			uri, err := url.Parse(ref.StatusList.URI)
			if err != nil || uri.Scheme != "https" || uri.Host != suite.Host || !strings.HasPrefix(uri.Path, "/test/") {
				continue
			}
			key, ok := trusted[result.Identity.Issuer]
			if !ok {
				continue
			}
			public, err := jwk.FromRaw(key)
			if err != nil {
				return err
			}
			jwks, err := json.Marshal(map[string]any{"keys": []any{public}})
			if err != nil {
				return err
			}
			exists := false
			for _, source := range sources {
				for _, allowed := range source.ListURIs {
					if allowed == uri.String() && source.CredentialIssuer == result.Identity.Issuer {
						exists = true
					}
				}
			}
			if !exists {
				zero := 0
				sources = append(sources, oid4w.StatusSource{Format: credential.Format, CredentialIssuer: result.Identity.Issuer, CredentialType: result.Identity.CredentialType, StatusIssuer: result.Identity.Issuer, ListURIs: []string{uri.String()}, JWKS: jwks, CacheSeconds: &zero})
			}
		}
	}
	if len(sources) == 0 {
		return nil
	}
	encoded, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `UPDATE identity.organizations SET settings=jsonb_set(settings,'{wallet_status_sources}',$2::jsonb) WHERE id=$1`, session.OrgID, encoded)
	return err
}

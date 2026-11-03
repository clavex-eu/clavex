package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func TestDCRDisplayMetadataPersistsAndRendersOnLogin(t *testing.T) {
	f := vciFixture(t)
	h, _, _ := confidentialWallet(t, f)
	payload := map[string]any{"client_name": "Example RP", "redirect_uris": []string{"https://rp.example/callback"}, "logo_uri": "https://rp.example/logo.png", "policy_uri": "https://rp.example/privacy", "tos_uri": "https://rp.example/terms"}
	rec := f.request(t, h.Register, "", payload)
	require.Equal(t, 201, rec.Code, rec.Body.String())
	var registered map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &registered))
	for _, field := range []string{"logo_uri", "policy_uri", "tos_uri"} {
		require.Equal(t, payload[field], registered[field])
	}
	id := registered["client_id"].(string)
	client, err := h.clients.GetByClientID(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, payload["logo_uri"], *client.LogoURL)
	require.Equal(t, payload["policy_uri"], client.Metadata["policy_uri"])
	// Exercise actual Authorize rendering, including client lookup and tenant branding.
	q := url.Values{"client_id": {id}, "redirect_uri": {"https://rp.example/callback"}, "scope": {"openid"}, "response_type": {"code"}}
	req := httptest.NewRequest(http.MethodGet, "https://issuer.example/"+f.org.Slug+"/authorize?"+q.Encode(), nil)
	response := httptest.NewRecorder()
	e := echo.New()
	c := e.NewContext(req, response)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	if err := h.Authorize(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	require.Equal(t, 200, response.Code, response.Body.String())
	html := response.Body.String()
	require.Contains(t, html, f.org.Name)
	require.Contains(t, html, "Example RP")
	for _, field := range []string{"logo_uri", "policy_uri", "tos_uri"} {
		require.Contains(t, html, payload[field])
	}
	require.Contains(t, html, `rel="noopener noreferrer"`)
	require.Contains(t, html, `referrerpolicy="no-referrer"`)
	// Error re-render retains the requesting application's context.
	var sessionID string
	marker := `name="login_session_id" value="`
	start := strings.Index(html, marker)
	require.GreaterOrEqual(t, start, 0)
	sessionID = strings.Split(html[start+len(marker):], `"`)[0]
	form := url.Values{"login_session_id": {sessionID}, "email": {"not-present@example.test"}, "password": {"invalid"}}
	req = httptest.NewRequest(http.MethodPost, "https://issuer.example/"+f.org.Slug+"/authorize", strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	response = httptest.NewRecorder()
	c = e.NewContext(req, response)
	if err := h.AuthorizeSubmit(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	require.Equal(t, 200, response.Code, response.Body.String())
	for _, field := range []string{"logo_uri", "policy_uri", "tos_uri"} {
		require.Contains(t, response.Body.String(), payload[field])
	}
}

func TestDCRDisplayMetadataRejectsUnsafeURLsAndEscapesClientName(t *testing.T) {
	f := vciFixture(t)
	h, _, _ := confidentialWallet(t, f)
	for _, field := range []string{"logo_uri", "policy_uri", "tos_uri"} {
		for _, value := range []string{"javascript:alert(1)", "data:text/html,example", "//example.test/logo", "https://user:pass@example.test/", "https://example.test/\n"} {
			rec := f.request(t, h.Register, "", map[string]any{"redirect_uris": []string{"https://rp.example/callback"}, field: value})
			require.Equal(t, 400, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), "invalid_client_metadata")
		}
	}
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	bad := "javascript:alert(1)"
	client := &models.OIDCClient{Name: `<script>alert(1)</script>`, LogoURL: &bad, Metadata: map[string]interface{}{"policy_uri": bad, "tos_uri": bad}}
	require.NoError(t, renderLoginWithCaptcha(c, "Tenant", nil, nil, "session", "tenant", "", "", false, "", "", false, "", "", nil, client))
	require.NotContains(t, rec.Body.String(), bad)
	require.NotContains(t, rec.Body.String(), client.Name)
	require.Contains(t, rec.Body.String(), "&lt;script&gt;")
}

func TestDiscoveryCredentialScopesAreActiveAndTenantScoped(t *testing.T) {
	f := vciFixture(t)
	h, _, _ := confidentialWallet(t, f)
	ctx := context.Background()
	inactive, err := f.h.repo.CreateCredentialConfig(ctx, f.org.ID, "https://issuer.example/inactive", "Inactive", nil, nil, 3600, "inactive", nil)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.credential_configs SET is_active=false WHERE id=$1`, inactive.ID)
	require.NoError(t, err)
	other := vciFixture(t)
	otherCfg, err := other.h.repo.CreateCredentialConfig(ctx, other.org.ID, "https://issuer.example/other-only", "Other", nil, nil, 3600, "other", nil)
	require.NoError(t, err)
	rec := f.request(t, h.Discovery, "", nil)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var discovery struct {
		Scopes []string `json:"scopes_supported"`
		ACR    []string `json:"acr_values_supported"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &discovery))
	require.Contains(t, discovery.Scopes, "openid")
	require.Contains(t, discovery.Scopes, oid4w.CredentialConfigID(f.cfg.VCT))
	require.NotContains(t, discovery.Scopes, oid4w.CredentialConfigID(inactive.VCT))
	require.NotContains(t, discovery.Scopes, oid4w.CredentialConfigID(otherCfg.VCT))
	require.Equal(t, []string{"0"}, discovery.ACR)
}

func TestHybridACRReportsActualContextWithoutUpgradingRequestedAssurance(t *testing.T) {
	f := vciFixture(t)
	h, id, _ := confidentialWallet(t, f)
	for _, requested := range []string{"", "0", "1 2"} {
		c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "https://issuer.example/", nil), httptest.NewRecorder())
		raw, err := h.hybridIDToken(c, "authorization-code", "nonce", f.org.Slug, id, "user", time.Now().Unix(), requested)
		require.NoError(t, err)
		parsed, err := jwt.Parse([]byte(raw), jwt.WithKey(jwa.PS256, f.h.keys.PublicKey()), jwt.WithValidate(true))
		require.NoError(t, err)
		acr, present := parsed.Get("acr")
		if requested == "" {
			require.False(t, present)
		} else {
			require.True(t, present)
			require.Equal(t, "0", acr)
		}
	}
}

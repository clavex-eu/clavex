package handler

import (
	"context"
	"encoding/json"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestUserInfoUsesTenantSigner(t *testing.T) {
	f := vciFixture(t)
	h, clientID, _ := confidentialWallet(t, f)
	ctx := context.Background()
	h.WithOrgSigners(oidc.NewOrgSignerCacheFromKEK(f.pool, [32]byte{42}, f.h.keys))
	user, err := h.users.Create(ctx, f.org.ID, "userinfo-"+uuid.NewString()+"@example.test", nil, nil)
	require.NoError(t, err)
	issuer := h.issuerFromRequest(echo.New().NewContext(httptest.NewRequest(http.MethodGet, "https://issuer.example/", nil), httptest.NewRecorder()), f.org.Slug)
	tc := h.newTC(issuer)
	require.NoError(t, h.applyOrgOverrides(ctx, tc, f.org, nil))
	require.NotEqual(t, h.tc.Keys.KID(), tc.Keys.KID(), "fixture requires distinct global and tenant signers")
	issue := func(keys oidc.Signer, iss string) string {
		config := *tc
		config.Keys = keys
		config.Issuer = iss
		token, _, err := config.IssueAccessToken(clientID, "openid email", &oidc.UserClaims{UserID: user.ID.String(), OrgID: f.org.ID.String(), Email: user.Email}, nil, nil)
		require.NoError(t, err)
		return token
	}
	cases := []struct {
		name, token string
		status      int
	}{
		{"tenant token", issue(tc.Keys, issuer), http.StatusOK},
		{"global key with matching issuer", issue(h.tc.Keys, issuer), http.StatusUnauthorized},
		{"tenant key with wrong issuer", issue(tc.Keys, issuer+"-other"), http.StatusUnauthorized},
	}
	other, err := h.orgs.Create(ctx, "Other tenant", "other-"+uuid.NewString(), nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := f.pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, other.ID)
		require.NoError(t, err)
	})
	cases = append(cases, struct {
		name, token string
		status      int
	}{"other tenant key with matching issuer", issue(h.orgSigners.For(ctx, other.ID), issuer), http.StatusUnauthorized})
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://issuer.example/"+f.org.Slug+"/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rec := httptest.NewRecorder()
			e := echo.New()
			c := e.NewContext(req, rec)
			c.SetParamNames("org_slug")
			c.SetParamValues(f.org.Slug)
			if err := h.UserInfo(c); err != nil {
				e.HTTPErrorHandler(err, c)
			}
			require.Equal(t, tt.status, rec.Code, rec.Body.String())
			if tt.status == http.StatusOK {
				var body map[string]any
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
				require.Equal(t, user.ID.String(), body["sub"])
			}
		})
	}
}

// The same token must never inherit an active introspection result cached for
// another issuer, and revocation must invalidate the issuing tenant's cache.
func TestTenantTokenIntrospectionAndRevocation(t *testing.T) {
	f := vciFixture(t)
	h, clientID, secret := confidentialWallet(t, f)
	ctx := context.Background()
	h.WithOrgSigners(oidc.NewOrgSignerCacheFromKEK(f.pool, [32]byte{43}, f.h.keys))
	tc := h.newTC("https://issuer.example/" + f.org.Slug)
	require.NoError(t, h.applyOrgOverrides(ctx, tc, f.org, nil))
	token, jti, err := tc.IssueAccessToken(clientID, "openid", nil, nil, nil)
	require.NoError(t, err)
	other, err := h.orgs.Create(ctx, "Other introspection tenant", "introspect-"+uuid.NewString(), nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := f.pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, other.ID)
		require.NoError(t, err)
	})
	call := func(slug, path string, fn echo.HandlerFunc) *httptest.ResponseRecorder {
		body := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
		req := httptest.NewRequest(http.MethodPost, "https://issuer.example/"+slug+"/"+path, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, secret)
		rec := httptest.NewRecorder()
		e := echo.New()
		c := e.NewContext(req, rec)
		c.SetParamNames("org_slug")
		c.SetParamValues(slug)
		if err := fn(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		return rec
	}
	active := func(slug string) bool {
		var body struct {
			Active bool `json:"active"`
		}
		rec := call(slug, "introspect", h.Introspect)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return body.Active
	}
	require.True(t, active(f.org.Slug))
	require.True(t, active(f.org.Slug), "cached own-tenant introspection must stay active")
	require.False(t, active(other.Slug), "another issuer must not reuse the cached active response")
	call(f.org.Slug, "revoke", h.Revoke)
	revoked, err := h.store.IsRevoked(ctx, jti)
	require.NoError(t, err)
	require.True(t, revoked)
	require.False(t, active(f.org.Slug), "revocation must invalidate the correct tenant cache")
}

func TestTenantHybridAndJARMUseAdvertisedSigner(t *testing.T) {
	f := vciFixture(t)
	h, client, _ := confidentialWallet(t, f)
	ctx := context.Background()
	h.WithOrgSigners(oidc.NewOrgSignerCacheFromKEK(f.pool, [32]byte{45}, f.h.keys))
	e := echo.New()
	makeContext := func() (echo.Context, *httptest.ResponseRecorder) {
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodGet, "https://issuer.example/"+f.org.Slug+"/authorize", nil), rec)
		c.SetParamNames("org_slug")
		c.SetParamValues(f.org.Slug)
		return c, rec
	}
	c, _ := makeContext()
	issuer := h.issuerFromRequest(c, f.org.Slug)
	tc, err := h.verificationTC(ctx, issuer, f.org.Slug)
	require.NoError(t, err)
	hybrid, err := h.hybridIDToken(c, "code", "nonce", f.org.Slug, client, uuid.NewString(), time.Now().Unix(), "")
	require.NoError(t, err)
	validate := func(raw string) {
		msg, err := jws.Parse([]byte(raw))
		require.NoError(t, err)
		require.Equal(t, tc.Keys.KID(), msg.Signatures()[0].ProtectedHeaders().KeyID())
		_, err = jwt.Parse([]byte(raw), jwt.WithKey(jwa.PS256, tc.Keys.PublicKey()), jwt.WithIssuer(issuer), jwt.WithValidate(true))
		require.NoError(t, err)
		_, err = jwt.Parse([]byte(raw), jwt.WithKey(jwa.PS256, h.tc.Keys.PublicKey()))
		require.Error(t, err)
	}
	validate(hybrid)
	c, rec := makeContext()
	require.NoError(t, h.redirectWithCode(c, "https://wallet.example/callback", "code", "state", f.org.Slug, client, "query.jwt", "", ""))
	dest, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	validate(dest.Query().Get("response"))
	c, rec = makeContext()
	require.NoError(t, h.redirectWithError(c, &oidc.AuthorizeError{OrgSlug: f.org.Slug, ClientID: client, RedirectURI: "https://wallet.example/callback", ResponseMode: "query.jwt", Code: "access_denied", State: "state"}))
	dest, err = url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	validate(dest.Query().Get("response"))
}

func TestVCICredentialAcceptsTenantTokensAcrossRotation(t *testing.T) {
	f := vciFixture(t)
	h, client, _ := confidentialWallet(t, f)
	ctx := context.Background()
	cache := oidc.NewOrgSignerCacheFromKEK(f.pool, [32]byte{46}, f.h.keys)
	h.WithOrgSigners(cache)
	tc := h.newTC("https://issuer.example/" + f.org.Slug)
	require.NoError(t, h.applyOrgOverrides(ctx, tc, f.org, nil))
	user, err := h.users.Create(ctx, f.org.ID, "tenant-vci@example.test", nil, nil)
	require.NoError(t, err)
	token, _, err := tc.IssueAccessToken(client, oid4w.CredentialConfigID(f.cfg.VCT), &oidc.UserClaims{UserID: user.ID.String(), OrgID: f.org.ID.String()}, nil, nil)
	require.NoError(t, err)
	check := func(raw string, status int) {
		nonce, err := f.h.issueCredentialNonce(ctx, f.org.Slug)
		require.NoError(t, err)
		proof := vciTestProof(t, vciTestHolder(t), tc.Issuer, nonce, nil)
		rec := f.request(t, f.h.Credential, raw, map[string]any{"credential_configuration_id": oid4w.CredentialConfigID(f.cfg.VCT), "proofs": map[string]any{"jwt": []string{proof}}})
		require.Equal(t, status, rec.Code, rec.Body.String())
	}
	check(token, 200)
	_, err = cache.RotateForOrg(ctx, f.org.ID)
	require.NoError(t, err)
	check(token, 200)
	tc.Keys = h.tc.Keys
	wrong, _, err := tc.IssueAccessToken(client, oid4w.CredentialConfigID(f.cfg.VCT), &oidc.UserClaims{UserID: user.ID.String()}, nil, nil)
	require.NoError(t, err)
	check(wrong, 401)
}

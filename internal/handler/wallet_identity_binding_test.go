package handler

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func accountVP(t *testing.T, signer *rsa.PrivateKey, issuer, subject, vct, nonce, audience string, claims map[string]any, bound bool) string {
	t.Helper()
	holder := vciTestHolder(t)
	var key jwk.Key
	if bound {
		var err error
		key, err = jwk.FromRaw(&holder.PublicKey)
		require.NoError(t, err)
	}
	credential, _, err := oid4w.IssueSDJWT(oid4w.SDJWTParams{Issuer: issuer, Subject: subject, VCT: vct, TTL: time.Hour, Signer: signer, KID: "test", HolderKey: key, DisclosableClaims: claims})
	require.NoError(t, err)
	if !bound {
		return credential
	}
	hash := sha256.Sum256([]byte(credential))
	kb, err := jwt.NewBuilder().IssuedAt(time.Now()).Audience([]string{audience}).Claim("nonce", nonce).Claim("sd_hash", base64.RawURLEncoding.EncodeToString(hash[:])).Build()
	require.NoError(t, err)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "kb+jwt"))
	signed, err := jwt.Sign(kb, jwt.WithKey(jwa.ES256, holder, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return credential + string(signed)
}

func bindingQuery(vct string, bearer bool) map[string]interface{} {
	c := map[string]any{"id": "identity", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{vct}}}
	if bearer {
		c["require_cryptographic_holder_binding"] = false
	}
	return map[string]interface{}{"credentials": []any{c}}
}

type cibaWalletFixture struct {
	vciIssuanceFixture
	h        *OID4VPHandler
	ciba     *repository.CIBARepository
	user     *models.User
	clientID string
}

func newCibaWalletFixture(t *testing.T) cibaWalletFixture {
	t.Helper()
	f := vciFixture(t)
	ctx := context.Background()
	// These pre-existing tests isolate account binding with synthetic credentials
	// that predate status support. Status tests exercise the strict default separately.
	_, err := f.pool.Exec(ctx, `UPDATE identity.organizations SET settings='{"wallet_status_required":false}' WHERE id=$1`, f.org.ID)
	require.NoError(t, err)

	u, err := f.h.users.Create(ctx, f.org.ID, "account@example.test", nil, nil)
	require.NoError(t, err)
	client, _, err := repository.NewClientRepository(f.pool).Create(ctx, f.org.ID, "ciba-"+uuid.NewString(), "CIBA", []string{"https://client.example/callback"}, nil, nil, nil, nil, true)
	require.NoError(t, err)
	ciba := repository.NewCIBARepository(f.pool)
	h := NewOID4VPHandler(f.pool, f.h.keys, f.h.cfg, nil, false, ciba, "", "") // conformance flag must never bypass CIBA trust
	return cibaWalletFixture{vciIssuanceFixture: f, h: h, ciba: ciba, user: u, clientID: client.ClientID}
}

func (f cibaWalletFixture) request(t *testing.T, bearer bool) (*models.PresentationSession, string) {
	t.Helper()
	ctx := context.Background()
	auth, err := f.ciba.Create(ctx, repository.CIBACreateParams{OrgID: f.org.ID, ClientID: f.clientID, UserID: &f.user.ID, Scope: "openid", ExpiresIn: time.Minute})
	require.NoError(t, err)
	responseURI := "https://issuer.example/" + f.org.Slug + "/wallet/response"
	se, err := f.h.repo.CreatePresentationSession(ctx, f.org.ID, uuid.NewString(), nil, bindingQuery(f.cfg.VCT, bearer), responseURI, nil, nil, uuid.NewString(), time.Now().Add(time.Minute), &auth, "redirect_uri:"+responseURI)
	require.NoError(t, err)
	return se, auth
}

func (f cibaWalletFixture) submit(t *testing.T, se *models.PresentationSession, raw string, jsonBody bool) *httptest.ResponseRecorder {
	t.Helper()
	envelope, err := json.Marshal(map[string][]string{"identity": {raw}})
	require.NoError(t, err)
	e := echo.New()
	rec := httptest.NewRecorder()
	var req *http.Request
	if jsonBody {
		body, err := json.Marshal(map[string]any{"state": se.RequestID, "vp_token": string(envelope)})
		require.NoError(t, err)
		req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	} else {
		form := url.Values{"state": {se.RequestID}, "vp_token": {string(envelope)}}
		req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	}
	c := e.NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	if err := f.h.Response(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec
}

func TestCIBAWalletLocalAccountBindingAndReplay(t *testing.T) {
	f := newCibaWalletFixture(t)
	se, auth := f.request(t, false)
	raw := accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://issuer.example/"+f.org.Slug, f.user.ID.String(), f.cfg.VCT, se.Nonce, se.ClientID, map[string]any{"name": "same name"}, true)
	rec := f.submit(t, se, raw, true)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	approved, err := f.ciba.Get(context.Background(), auth)
	require.NoError(t, err)
	require.Equal(t, "approved", approved.Status)
	require.Equal(t, f.user.ID, *approved.UserID)
	require.Equal(t, "local_signed_subject", approved.VPClaims["_clavex_account_binding"].(map[string]any)["method"])
	rec = f.submit(t, se, raw, false)
	require.NotEqual(t, 200, rec.Code)
}

func TestCIBAWalletRejectsOtherMissingAndBearerSubjects(t *testing.T) {
	f := newCibaWalletFixture(t)
	for _, tc := range []struct {
		name, subject string
		bound         bool
	}{
		{"another person", uuid.NewString(), true}, {"missing subject", "", true}, {"bearer", f.user.ID.String(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			se, auth := f.request(t, !tc.bound)
			raw := accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://issuer.example/"+f.org.Slug, tc.subject, f.cfg.VCT, se.Nonce, se.ClientID, map[string]any{"email": f.user.Email}, tc.bound)
			rec := f.submit(t, se, raw, false)
			require.NotEqual(t, 200, rec.Code, rec.Body.String())
			pending, err := f.ciba.Get(context.Background(), auth)
			require.NoError(t, err)
			require.Equal(t, "pending", pending.Status)
			require.Equal(t, f.user.ID, *pending.UserID)
		})
	}
	se, auth := f.request(t, false)
	raw := accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://unconfigured.example", f.user.ID.String(), f.cfg.VCT, se.Nonce, se.ClientID, nil, true)
	rec := f.submit(t, se, raw, false)
	require.NotEqual(t, 200, rec.Code)
	pending, err := f.ciba.Get(context.Background(), auth)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Status)
}

func TestCIBAWalletRejectsDisabledUserClientAndExpiredRequest(t *testing.T) {
	for _, scenario := range []string{"user", "client", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			f := newCibaWalletFixture(t)
			se, auth := f.request(t, false)
			var err error
			switch scenario {
			case "user":
				_, err = f.pool.Exec(context.Background(), `UPDATE users SET is_active=false WHERE id=$1`, f.user.ID)
			case "client":
				_, err = f.pool.Exec(context.Background(), `UPDATE oidc_clients SET is_active=false WHERE client_id=$1`, f.clientID)
			case "expired":
				_, err = f.pool.Exec(context.Background(), `UPDATE ciba_requests SET expires_at=NOW()-INTERVAL '1 second' WHERE auth_req_id=$1`, auth)
			}
			require.NoError(t, err)
			raw := accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://issuer.example/"+f.org.Slug, f.user.ID.String(), f.cfg.VCT, se.Nonce, se.ClientID, nil, true)
			rec := f.submit(t, se, raw, false)
			require.NotEqual(t, 200, rec.Code)
			pending, err := f.ciba.Get(context.Background(), auth)
			require.NoError(t, err)
			require.Equal(t, "pending", pending.Status)
		})
	}
}

func TestCIBAWalletConcurrentAndTransactionalApproval(t *testing.T) {
	f := newCibaWalletFixture(t)
	se, auth := f.request(t, false)
	raw := accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://issuer.example/"+f.org.Slug, f.user.ID.String(), f.cfg.VCT, se.Nonce, se.ClientID, nil, true)
	name := "test_ciba_failure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ident := pgx.Identifier{"identity", name}.Sanitize()
	_, err := f.pool.Exec(context.Background(), fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.auth_req_id='%s' THEN RAISE EXCEPTION 'test CIBA failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE UPDATE ON identity.ciba_requests FOR EACH ROW EXECUTE FUNCTION %s()`, ident, auth, pgx.Identifier{name}.Sanitize(), ident))
	require.NoError(t, err)
	cleanup := func() {
		_, err := f.pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON identity.ciba_requests; DROP FUNCTION IF EXISTS %s()`, pgx.Identifier{name}.Sanitize(), ident))
		require.NoError(t, err)
	}
	t.Cleanup(cleanup)
	rec := f.submit(t, se, raw, false)
	require.Equal(t, 503, rec.Code)
	saved, err := f.h.repo.GetPresentationSession(context.Background(), se.RequestID)
	require.NoError(t, err)
	require.Equal(t, "pending", saved.Status)
	cleanup()
	var wg sync.WaitGroup
	var success atomic.Int32
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if f.submit(t, se, raw, false).Code == 200 {
				success.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, success.Load())
	approved, err := f.ciba.Get(context.Background(), auth)
	require.NoError(t, err)
	require.Equal(t, "approved", approved.Status)
}

func linkAPICall(t *testing.T, f cibaWalletFixture, method string, user uuid.UUID, link string, body any, claims *middleware.Claims) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, "/", strings.NewReader(string(encoded)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id", "user_id", "link_id")
	c.SetParamValues(f.org.ID.String(), user.String(), link)
	if claims != nil {
		c.Set("claims", claims)
	}
	h := NewWalletIdentityHandler(f.pool, f.vciIssuanceFixture.h.cfg)
	var handler echo.HandlerFunc
	switch method {
	case http.MethodPost:
		handler = h.Create
	case http.MethodDelete:
		handler = h.Revoke
	default:
		handler = h.List
	}
	if err := middleware.RequireResourcePermission("users")(handler)(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec
}

func TestCIBAWalletExternalLinkRequiresRegistrationAndRevocation(t *testing.T) {
	f := newCibaWalletFixture(t)
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer := "https://external-issuer.example"
	f.h.trustedIssuers = map[string]crypto.PublicKey{issuer: &key.PublicKey}
	profile := oid4w.WalletIdentityProfile{Format: "dc+sd-jwt", Issuer: issuer, CredentialType: f.cfg.VCT, ClaimPath: []string{"external_id"}}
	settings, err := json.Marshal(map[string]any{"wallet_identity_profiles": []any{profile}, "wallet_status_required": false, "wallet_certificate_revocation_required": false})
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE organizations SET settings=$1 WHERE id=$2`, settings, f.org.ID)
	require.NoError(t, err)
	proof := func(se *models.PresentationSession) string {
		return accountVP(t, key, issuer, "external-pairwise-sub", f.cfg.VCT, se.Nonce, se.ClientID, map[string]any{"external_id": "test-stable-identifier", "email": f.user.Email}, true)
	}
	se, auth := f.request(t, false)
	rec := f.submit(t, se, proof(se), false)
	require.NotEqual(t, 200, rec.Code)
	pending, err := f.ciba.Get(ctx, auth)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Status)
	claims := &middleware.Claims{IsAdmin: true, OrgID: f.org.ID.String()}
	claims.Subject = f.user.ID.String()
	body := map[string]any{"format": profile.Format, "issuer": issuer, "credential_type": f.cfg.VCT, "claim_path": profile.ClaimPath, "verified_identifier": "test-stable-identifier", "administratively_reviewed": true}
	body["administratively_reviewed"] = false
	rec = linkAPICall(t, f, http.MethodPost, f.user.ID, "", body, claims)
	require.Equal(t, 400, rec.Code, "registration must require explicit prior administrative review")
	body["administratively_reviewed"] = true
	body["claim_path"] = []string{"unconfigured_identifier"}
	rec = linkAPICall(t, f, http.MethodPost, f.user.ID, "", body, claims)
	require.Equal(t, 400, rec.Code, "administration must not invent a different identity profile")
	body["claim_path"] = profile.ClaimPath
	rec = linkAPICall(t, f, http.MethodPost, f.user.ID, "", body, claims)
	require.Equal(t, 201, rec.Code, rec.Body.String())
	var link struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &link))
	rec = linkAPICall(t, f, http.MethodPost, f.user.ID, "", body, claims)
	require.Equal(t, 409, rec.Code)
	rec = linkAPICall(t, f, http.MethodGet, f.user.ID, "", nil, claims)
	require.Equal(t, 200, rec.Code)
	require.NotContains(t, rec.Body.String(), "test-stable-identifier")
	require.NotContains(t, rec.Body.String(), "subject_digest")
	se, auth = f.request(t, false)
	rec = f.submit(t, se, proof(se), false)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	approved, err := f.ciba.Get(ctx, auth)
	require.NoError(t, err)
	require.Equal(t, link.ID, approved.VPClaims["_clavex_account_binding"].(map[string]any)["link_id"])
	other, err := f.vciIssuanceFixture.h.users.Create(ctx, f.org.ID, "other@example.test", nil, nil)
	require.NoError(t, err)
	otherFixture := f
	otherFixture.user = other
	se, _ = otherFixture.request(t, false)
	rec = otherFixture.submit(t, se, proof(se), false)
	require.NotEqual(t, 200, rec.Code, "registered identity must not approve another user")
	rec = linkAPICall(t, f, http.MethodDelete, f.user.ID, link.ID, nil, claims)
	require.Equal(t, 204, rec.Code)
	se, auth = f.request(t, false)
	rec = f.submit(t, se, proof(se), false)
	require.NotEqual(t, 200, rec.Code)
	pending, err = f.ciba.Get(ctx, auth)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Status)
}

func TestWalletIdentityAdministrationRequiresPrivilege(t *testing.T) {
	f := newCibaWalletFixture(t)
	rec := linkAPICall(t, f, http.MethodPost, f.user.ID, "", nil, nil)
	require.True(t, rec.Code == 401 || rec.Code == 403)
	claims := &middleware.Claims{IsAdmin: true, OrgID: f.org.ID.String(), Permissions: []string{"users:read"}}
	claims.Subject = f.user.ID.String()
	rec = linkAPICall(t, f, http.MethodPost, f.user.ID, "", nil, claims)
	require.Equal(t, 403, rec.Code)
	claims.Permissions = nil
	claims.OrgID = uuid.NewString()
	rec = linkAPICall(t, f, http.MethodGet, f.user.ID, "", nil, claims)
	require.Equal(t, 403, rec.Code)
}

func TestCIBAWalletMdocUsesRegisteredNamespacedIdentifier(t *testing.T) {
	f := newCibaWalletFixture(t)
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `UPDATE identity.organizations SET settings=settings || '{"wallet_certificate_revocation_required":false}'::jsonb WHERE id=$1`, f.org.ID)
	require.NoError(t, err)
	se, auth := f.request(t, false)
	query := map[string]interface{}{"credentials": []any{map[string]any{"id": "identity", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": mdoc.DocTypeEuPid}}}}
	encodedQuery, err := json.Marshal(query)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.presentation_sessions SET dcql_query=$1 WHERE request_id=$2`, encodedQuery, se.RequestID)
	require.NoError(t, err)
	se.DCQLQuery = query
	encoded, root := verifierMdoc(t, se, map[string]interface{}{"test_stable_id": "synthetic-subject-42"})
	_, err = f.h.iacaRepo.Create(ctx, f.org.ID, "Synthetic IACA", root, []string{mdoc.DocTypeEuPid}, nil)
	require.NoError(t, err)
	result, err := f.h.verifyMdocDCQLVPToken(ctx, encoded, se, se.ClientID)
	require.NoError(t, err)
	require.ErrorIs(t, f.h.completeBoundCIBA(ctx, se.RequestID, f.org.ID, result), errWalletIdentityMismatch)
	profile := oid4w.WalletIdentityProfile{Format: "mso_mdoc", Issuer: result.Identity.Issuer, CredentialType: mdoc.DocTypeEuPid, ClaimPath: []string{mdoc.NSEuPid, "test_stable_id"}}
	settings, err := json.Marshal(map[string]any{"wallet_identity_profiles": []any{profile}, "wallet_status_required": false, "wallet_certificate_revocation_required": false})
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.organizations SET settings=$1 WHERE id=$2`, settings, f.org.ID)
	require.NoError(t, err)
	digest, err := profile.Digest(f.org.ID.String(), "synthetic-subject-42")
	require.NoError(t, err)
	linkRepo := repository.NewWalletIdentityRepository(f.pool)
	_, err = linkRepo.Create(ctx, repository.WalletIdentityLink{OrgID: f.org.ID, UserID: f.user.ID, Format: profile.Format, Issuer: profile.Issuer, CredentialType: profile.CredentialType, ClaimPath: profile.ClaimPath, SubjectDigest: digest})
	require.NoError(t, err)
	copyResult := *result
	copyIdentity := *result.Identity
	copyIdentity.Issuer = "x509-spki-sha256:another-key"
	copyResult.Identity = &copyIdentity
	require.ErrorIs(t, f.h.completeBoundCIBA(ctx, se.RequestID, f.org.ID, &copyResult), errWalletIdentityMismatch)
	require.NoError(t, f.h.completeBoundCIBA(ctx, se.RequestID, f.org.ID, result))
	approved, err := f.ciba.Get(ctx, auth)
	require.NoError(t, err)
	require.Equal(t, "approved", approved.Status)
	require.Equal(t, f.user.ID, *approved.UserID)
}

func TestWalletIdentityDatabaseRejectsCrossTenantAccount(t *testing.T) {
	f := newCibaWalletFixture(t)
	other := newCibaWalletFixture(t)
	p := oid4w.WalletIdentityProfile{Format: "dc+sd-jwt", Issuer: "https://issuer.example", CredentialType: "identity", ClaimPath: []string{"stable_id"}}
	digest, err := p.Digest(f.org.ID.String(), "synthetic-id")
	require.NoError(t, err)
	_, err = repository.NewWalletIdentityRepository(f.pool).Create(context.Background(), repository.WalletIdentityLink{OrgID: f.org.ID, UserID: other.user.ID, Format: p.Format, Issuer: p.Issuer, CredentialType: p.CredentialType, ClaimPath: p.ClaimPath, SubjectDigest: digest})
	require.Error(t, err, "composite foreign key must enforce tenant/account scope independently of handlers")
}

func TestWalletStepUpRequiresSubjectAndConsumesOnce(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	// These pre-existing tests isolate account binding with synthetic credentials
	// that predate status support. Status tests exercise the strict default separately.
	_, err := f.pool.Exec(ctx, `UPDATE identity.organizations SET settings='{"wallet_status_required":false}' WHERE id=$1`, f.org.ID)
	require.NoError(t, err)

	user, err := f.h.users.Create(ctx, f.org.ID, "stepup@example.test", nil, nil)
	require.NoError(t, err)
	store := session.NewStore(f.h.rdb)
	h := NewWalletStepUpHandler(f.pool, store, f.h.keys, f.h.cfg)
	for _, sub := range []string{"", uuid.NewString(), user.ID.String()} {
		challenge := &session.WalletStepUpChallenge{ID: uuid.NewString(), OrgID: f.org.ID.String(), OrgSlug: f.org.Slug, UserID: user.ID.String(), Nonce: uuid.NewString(), Status: "pending", VCTs: []string{f.cfg.VCT}, IssuedAfter: time.Now().Add(-time.Hour), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
		require.NoError(t, store.SaveWalletStepUpChallenge(ctx, challenge))
		uri := "https://issuer.example/" + f.org.Slug + "/wallet/stepup/" + challenge.ID + "/response"
		raw := accountVP(t, f.h.keys.PrivateKey(), "https://issuer.example/"+f.org.Slug, sub, f.cfg.VCT, challenge.Nonce, "redirect_uri:"+uri, nil, true)
		envelope, err := json.Marshal(map[string][]string{"stepup_identity": {raw}})
		require.NoError(t, err)
		invoke := func() *httptest.ResponseRecorder {
			e := echo.New()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{"vp_token": {string(envelope)}}.Encode()))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			c := e.NewContext(req, rec)
			c.SetParamNames("org_slug", "challenge_id")
			c.SetParamValues(f.org.Slug, challenge.ID)
			if err := h.SubmitResponse(c); err != nil {
				e.HTTPErrorHandler(err, c)
			}
			return rec
		}
		rec := invoke()
		if sub == user.ID.String() {
			require.Equal(t, 200, rec.Code, rec.Body.String())
			rec = invoke()
			require.NotEqual(t, 200, rec.Code)
		} else {
			require.NotEqual(t, 200, rec.Code, rec.Body.String())
		}
		saved, err := store.GetWalletStepUpChallenge(ctx, challenge.ID)
		require.NoError(t, err)
		if sub == user.ID.String() {
			require.Equal(t, "completed", saved.Status)
			require.Error(t, store.FailWalletStepUpChallenge(ctx, challenge.ID))
			saved, err = store.GetWalletStepUpChallenge(ctx, challenge.ID)
			require.NoError(t, err)
			require.Equal(t, "completed", saved.Status)
		} else {
			require.NotEqual(t, "completed", saved.Status)
		}
	}
}

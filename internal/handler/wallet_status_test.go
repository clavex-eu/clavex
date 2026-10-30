package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func issueStatusCredential(t *testing.T, f vciIssuanceFixture, user *uuid.UUID) (string, *ecdsa.PrivateKey, *models.IssuedCredential) {
	t.Helper()
	ctx := context.Background()
	offer, err := f.h.repo.CreateCredentialOffer(ctx, f.org.ID, user, f.cfg.VCT, uuid.NewString(), nil, map[string]interface{}{"given_name": "Alice", "department": "test"}, time.Now().Add(time.Hour))
	require.NoError(t, err)
	token, hash := generateOpaqueToken()
	require.NoError(t, f.h.repo.SetOfferAccessToken(ctx, offer.ID, hash))
	nonce, err := f.h.issueCredentialNonce(ctx, f.org.Slug)
	require.NoError(t, err)
	holder := vciTestHolder(t)
	proof := vciTestProof(t, holder, "https://issuer.example/"+f.org.Slug, nonce, nil)
	rec := f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": []string{proof}}})
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var body struct {
		Credentials []struct {
			Credential string `json:"credential"`
		} `json:"credentials"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Credentials, 1)
	raw := body.Credentials[0].Credential
	record, err := f.h.repo.GetIssuedCredentialByHash(ctx, f.org.ID, oid4w.HashToken(raw))
	require.NoError(t, err)
	require.NotNil(t, record)
	require.NotNil(t, record.StatusListID)
	require.NotNil(t, record.StatusIndex)
	return raw, holder, record
}

func presentStatusCredential(t *testing.T, raw string, holder *ecdsa.PrivateKey, nonce, audience string, subset bool) string {
	t.Helper()
	issuer, disclosures, _, err := oid4w.ParseSDJWT(raw)
	require.NoError(t, err)
	if subset && len(disclosures) > 0 {
		disclosures = disclosures[:len(disclosures)-1]
	}
	parts := []string{issuer}
	parts = append(parts, disclosures...)
	compact := strings.Join(parts, "~") + "~"
	hash := sha256.Sum256([]byte(compact))
	tok, err := jwt.NewBuilder().IssuedAt(time.Now()).Audience([]string{audience}).Claim("nonce", nonce).Claim("sd_hash", base64.RawURLEncoding.EncodeToString(hash[:])).Build()
	require.NoError(t, err)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "kb+jwt"))
	kb, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, holder, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return compact + string(kb)
}

func statusEndpoint(t *testing.T, f vciIssuanceFixture, fn echo.HandlerFunc, orgSlug, orgID, id string, body string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), rec)
	c.SetParamNames("org_slug", "org_id", "list_id", "cred_id")
	c.SetParamValues(orgSlug, orgID, id, id)
	if err := fn(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec
}

func TestWalletStatusLocalIssuancePublicationCIBARevocationAndDisclosureChanges(t *testing.T) {
	f := newCibaWalletFixture(t)
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `UPDATE identity.organizations SET settings='{}' WHERE id=$1`, f.org.ID)
	require.NoError(t, err) // strict authentication default
	raw, holder, record := issueStatusCredential(t, f.vciIssuanceFixture, &f.user.ID)
	issuer, disclosures, _, err := oid4w.ParseSDJWT(raw)
	require.NoError(t, err)
	claims, err := oid4w.VerifyAndExtractClaims(issuer, disclosures, f.vciIssuanceFixture.h.keys.PublicKey())
	require.NoError(t, err)
	encoded, err := json.Marshal(claims["status"])
	require.NoError(t, err)
	ref, err := oid4w.ParseStatusClaim(encoded)
	require.NoError(t, err)
	require.Equal(t, *record.StatusIndex, ref.StatusList.IDX)
	publish := func() *httptest.ResponseRecorder {
		return statusEndpoint(t, f.vciIssuanceFixture, f.vciIssuanceFixture.h.StatusList, f.org.Slug, f.org.ID.String(), record.StatusListID.String(), "")
	}
	rec := publish()
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Equal(t, "application/statuslist+jwt", rec.Header().Get(echo.HeaderContentType))
	require.NoError(t, oid4w.CheckStatus(rec.Body.String(), ref, f.vciIssuanceFixture.h.keys.PublicKey()))
	se, auth := f.request(t, false)
	rec = f.submit(t, se, presentStatusCredential(t, raw, holder, se.Nonce, se.ClientID, true), false)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	approved, err := f.ciba.Get(ctx, auth)
	require.NoError(t, err)
	require.Equal(t, "approved", approved.Status)
	require.Equal(t, "valid_local", approved.VPClaims["_clavex_credential_status"])
	rec = statusEndpoint(t, f.vciIssuanceFixture, f.vciIssuanceFixture.h.SuspendCredential, f.org.Slug, f.org.ID.String(), record.ID.String(), `{"reason":"temporary restriction"}`)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	rec = publish()
	require.Equal(t, 200, rec.Code)
	require.ErrorIs(t, oid4w.CheckStatus(rec.Body.String(), ref, f.vciIssuanceFixture.h.keys.PublicKey()), oid4w.ErrSuspended)
	se, _ = f.request(t, false)
	rec = f.submit(t, se, presentStatusCredential(t, raw, holder, se.Nonce, se.ClientID, true), false)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	rec = statusEndpoint(t, f.vciIssuanceFixture, f.vciIssuanceFixture.h.RestoreCredential, f.org.Slug, f.org.ID.String(), record.ID.String(), "")
	require.Equal(t, 200, rec.Code, rec.Body.String())
	se, _ = f.request(t, false)
	rec = f.submit(t, se, presentStatusCredential(t, raw, holder, se.Nonce, se.ClientID, true), false)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	rec = statusEndpoint(t, f.vciIssuanceFixture, f.vciIssuanceFixture.h.RevokeCredential, f.org.Slug, f.org.ID.String(), record.ID.String(), `{"reason":"synthetic test revocation"}`)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	rec = publish()
	require.Equal(t, 200, rec.Code)
	require.ErrorIs(t, oid4w.CheckStatus(rec.Body.String(), ref, f.vciIssuanceFixture.h.keys.PublicKey()), oid4w.ErrRevoked)
	se, auth = f.request(t, false)
	rec = f.submit(t, se, presentStatusCredential(t, raw, holder, se.Nonce, se.ClientID, false), false)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "credential_status_invalid")
	pending, err := f.ciba.Get(ctx, auth)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Status)
	rec = statusEndpoint(t, f.vciIssuanceFixture, f.vciIssuanceFixture.h.RestoreCredential, f.org.Slug, f.org.ID.String(), record.ID.String(), "")
	require.Equal(t, 409, rec.Code, rec.Body.String())
	se, _ = f.request(t, false)
	rec = f.submit(t, se, presentStatusCredential(t, raw, holder, se.Nonce, se.ClientID, true), false)
	require.Equal(t, 400, rec.Code, rec.Body.String())
}

func TestWalletStatusAdministrativeAndPublicationTenantIsolation(t *testing.T) {
	f := vciFixture(t)
	other := vciFixture(t)
	_, _, record := issueStatusCredential(t, f, nil)
	rec := statusEndpoint(t, f, f.h.StatusList, other.org.Slug, other.org.ID.String(), record.StatusListID.String(), "")
	require.Equal(t, 404, rec.Code)
	rec = statusEndpoint(t, f, f.h.RevokeCredential, other.org.Slug, other.org.ID.String(), record.ID.String(), "{}")
	require.Equal(t, 404, rec.Code)
	current, err := f.h.repo.GetIssuedCredentialByID(context.Background(), record.ID)
	require.NoError(t, err)
	require.False(t, current.IsRevoked)
	require.NoError(t, f.h.repo.RevokeIssuedCredential(context.Background(), record.ID, "test"))
	rec = statusEndpoint(t, f, f.h.RestoreCredential, other.org.Slug, other.org.ID.String(), record.ID.String(), "{}")
	require.Equal(t, 404, rec.Code)
	current, err = f.h.repo.GetIssuedCredentialByID(context.Background(), record.ID)
	require.NoError(t, err)
	require.True(t, current.IsRevoked)
}

func TestWalletStatusConcurrentIssuanceAllocatesDistinctSlots(t *testing.T) {
	f := vciFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); issueStatusCredential(t, f, nil) }()
	}
	wg.Wait()
	var count, slots, lists int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*),count(DISTINCT(status_list_id,status_index)),count(DISTINCT status_list_id) FROM identity.issued_credentials WHERE org_id=$1`, f.org.ID).Scan(&count, &slots, &lists))
	require.Equal(t, 8, count)
	require.Equal(t, 8, slots)
	require.Equal(t, 1, lists)
}

func TestWalletStatusRequiredMissingAndDeclaredUnresolvableAreDenied(t *testing.T) {
	f := newCibaWalletFixture(t)
	_, err := f.pool.Exec(context.Background(), `UPDATE identity.organizations SET settings='{}' WHERE id=$1`, f.org.ID)
	require.NoError(t, err)
	se, auth := f.request(t, false)
	raw := accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://issuer.example/"+f.org.Slug, f.user.ID.String(), f.cfg.VCT, se.Nonce, se.ClientID, nil, true)
	rec := f.submit(t, se, raw, false)
	require.Equal(t, 400, rec.Code)
	require.Contains(t, rec.Body.String(), "credential_status_invalid")
	request, err := f.ciba.Get(context.Background(), auth)
	require.NoError(t, err)
	require.Equal(t, "pending", request.Status)
	_, err = f.pool.Exec(context.Background(), `UPDATE identity.organizations SET settings='{"wallet_status_required":false}' WHERE id=$1`, f.org.ID)
	require.NoError(t, err)
	// A disclosure cannot replace the always-available status evidence. Even
	// the explicit missing-status compatibility mode must reject this form.
	se, _ = f.request(t, false)
	raw = accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://issuer.example/"+f.org.Slug, f.user.ID.String(), f.cfg.VCT, se.Nonce, se.ClientID, map[string]any{"status": oid4w.BuildStatusClaim("https://127.0.0.1/private", 0)}, true)
	rec = f.submit(t, se, raw, false)
	require.Equal(t, 400, rec.Code)
	// A signed non-local URI is never followed by the local-only resolver.
	var checks int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { checks++; w.WriteHeader(500) }))
	defer server.Close()
	repo, tx, err := f.vciIssuanceFixture.h.repo.BeginIssuance(context.Background())
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	identity := &oid4w.VerifiedCredentialIdentity{Format: "dc+sd-jwt", Issuer: "https://issuer.example/" + f.org.Slug, SignedByLocalIssuer: true, Status: json.RawMessage(`{"status_list":{"idx":0,"uri":"` + server.URL + `/private"}}`)}
	err = checkWalletStatus(context.Background(), repo, f.org.ID, identity.Issuer, nil, &oid4w.VerificationResult{Identity: identity, Claims: map[string]any{}}, true)
	require.ErrorIs(t, err, errWalletStatusUnavailable)
	require.Zero(t, checks)
}

func TestWalletStatusRevokedDeferredCredentialCannotBeDelivered(t *testing.T) {
	f := vciFixture(t)
	tokens := startWallet(t, f, deferredOffer(t, f, nil))
	txn, _ := requestDeferred(t, f, tokens)
	rec := approveWalletDeferred(t, f, txn)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	dc, err := f.h.repo.GetDeferredCredential(context.Background(), txn)
	require.NoError(t, err)
	credential, err := f.h.repo.GetIssuedCredentialByHash(context.Background(), f.org.ID, oid4w.HashToken(*dc.CredentialJWT))
	require.NoError(t, err)
	require.NotNil(t, credential)
	require.NoError(t, f.h.repo.RevokeIssuedCredential(context.Background(), credential.ID, "test"))
	rec = walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": txn}, tokens.Access, "", nil)
	require.Equal(t, 400, rec.Code)
	require.Contains(t, rec.Body.String(), "credential_request_denied")
	dc, err = f.h.repo.GetDeferredCredential(context.Background(), txn)
	require.NoError(t, err)
	require.Nil(t, dc.DeliveredAt)
}

func TestWalletStatusStepUpRevocationAndListRollover(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	user, err := f.h.users.Create(ctx, f.org.ID, "stepup-status@example.test", nil, nil)
	require.NoError(t, err)
	raw, holder, first := issueStatusCredential(t, f, &user.ID)
	_, err = f.pool.Exec(ctx, `UPDATE identity.credential_status_lists SET next_slot=65535 WHERE id=$1`, first.StatusListID)
	require.NoError(t, err)
	_, _, last := issueStatusCredential(t, f, &user.ID)
	require.Equal(t, 65535, *last.StatusIndex)
	_, _, rolled := issueStatusCredential(t, f, &user.ID)
	require.NotEqual(t, *last.StatusListID, *rolled.StatusListID)
	require.Zero(t, *rolled.StatusIndex)
	h := NewWalletStepUpHandler(f.pool, session.NewStore(f.h.rdb), f.h.keys, f.h.cfg)
	invoke := func() *httptest.ResponseRecorder {
		challenge := &session.WalletStepUpChallenge{ID: uuid.NewString(), OrgID: f.org.ID.String(), OrgSlug: f.org.Slug, UserID: user.ID.String(), Nonce: uuid.NewString(), Status: "pending", VCTs: []string{f.cfg.VCT}, IssuedAfter: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(time.Minute)}
		require.NoError(t, h.store.SaveWalletStepUpChallenge(ctx, challenge))
		aud := "redirect_uri:https://issuer.example/" + f.org.Slug + "/wallet/stepup/" + challenge.ID + "/response"
		vp := presentStatusCredential(t, raw, holder, challenge.Nonce, aud, true)
		envelope, err := json.Marshal(map[string][]string{"stepup_identity": {vp}})
		require.NoError(t, err)
		body, err := json.Marshal(map[string]string{"vp_token": string(envelope)})
		require.NoError(t, err)
		e := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		c := e.NewContext(req, rec)
		c.SetParamNames("org_slug", "challenge_id")
		c.SetParamValues(f.org.Slug, challenge.ID)
		if err := h.SubmitResponse(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		return rec
	}
	rec := invoke()
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.NoError(t, f.h.repo.RevokeIssuedCredential(ctx, first.ID, "test"))
	rec = invoke()
	require.Equal(t, 400, rec.Code)
	require.Contains(t, rec.Body.String(), "credential_status_invalid")
}

func TestWalletStatusSuspensionUpgradesLegacyListWithoutLosingRevocations(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	_, _, revoked := issueStatusCredential(t, f, nil)
	_, _, active := issueStatusCredential(t, f, nil)
	require.Equal(t, revoked.StatusListID, active.StatusListID)
	require.NoError(t, f.h.repo.RevokeIssuedCredential(ctx, revoked.ID, "legacy revocation"))
	legacy := oid4w.NewStatusList()
	require.NoError(t, legacy.Revoke(*revoked.StatusIndex))
	encoded, err := legacy.Encode()
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.credential_status_lists SET encoded=$2,bits=1 WHERE id=$1`, revoked.StatusListID, encoded)
	require.NoError(t, err)
	require.NoError(t, f.h.repo.SuspendIssuedCredential(ctx, active.ID, "temporary"))
	list, err := f.h.repo.GetStatusList(ctx, *active.StatusListID)
	require.NoError(t, err)
	require.Equal(t, 2, list.Bits)
	decoded, err := oid4w.DecodeStatusListWithBits(list.Encoded, list.Bits)
	require.NoError(t, err)
	first, err := decoded.Get(*revoked.StatusIndex)
	require.NoError(t, err)
	require.Equal(t, oid4w.StatusRevoked, first)
	second, err := decoded.Get(*active.StatusIndex)
	require.NoError(t, err)
	require.Equal(t, oid4w.StatusSuspended, second)
	require.NoError(t, f.h.repo.RestoreIssuedCredential(ctx, active.ID))
	require.Error(t, f.h.repo.RestoreIssuedCredential(ctx, revoked.ID))
}

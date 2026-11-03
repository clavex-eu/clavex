package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

type walletTokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Nonce   string `json:"c_nonce"`
	Type    string `json:"token_type"`
	Expires int    `json:"expires_in"`
}

func walletHTTP(t *testing.T, f vciIssuanceFixture, fn echo.HandlerFunc, path string, form url.Values, body any, access, proof string, connection *tls.ConnectionState) *httptest.ResponseRecorder {
	t.Helper()
	var data, contentType string
	if form != nil {
		data, contentType = form.Encode(), echo.MIMEApplicationForm
	} else {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		data, contentType = string(raw), echo.MIMEApplicationJSON
	}
	req := httptest.NewRequest(http.MethodPost, "/"+f.org.Slug+"/"+path, strings.NewReader(data))
	req.Header.Set(echo.HeaderContentType, contentType)
	if access != "" {
		scheme := "Bearer"
		if proof != "" {
			scheme = "DPoP"
		}
		req.Header.Set(echo.HeaderAuthorization, scheme+" "+access)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	req.TLS = connection
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	if err := fn(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec
}

func deferredOffer(t *testing.T, f vciIssuanceFixture, user *uuid.UUID) *models.CredentialOffer {
	t.Helper()
	_, err := f.pool.Exec(context.Background(), `UPDATE identity.credential_configs SET deferred_issuance=true WHERE id=$1`, f.cfg.ID)
	require.NoError(t, err)
	offer, err := f.h.repo.CreateCredentialOffer(context.Background(), f.org.ID, user, f.cfg.VCT, uuid.NewString(), nil, map[string]interface{}{"given_name": "Alice"}, time.Now().Add(time.Hour))
	require.NoError(t, err)
	return offer
}

func decodeWalletTokens(t *testing.T, rec *httptest.ResponseRecorder) walletTokens {
	t.Helper()
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var response walletTokens
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.NotEmpty(t, response.Access)
	require.NotEmpty(t, response.Refresh)
	require.Greater(t, response.Expires, 0)
	require.LessOrEqual(t, response.Expires, 300)
	return response
}

func startWallet(t *testing.T, f vciIssuanceFixture, offer *models.CredentialOffer) walletTokens {
	t.Helper()
	// Exercise the actual discovered OAuth endpoint, including anonymous refresh dispatch.
	h := &OIDCHandler{vciH: f.h}
	rec := walletHTTP(t, f, h.Token, "token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}}, nil, "", "", nil)
	return decodeWalletTokens(t, rec)
}

func refreshWallet(t *testing.T, f vciIssuanceFixture, refresh string) *httptest.ResponseRecorder {
	t.Helper()
	h := &OIDCHandler{vciH: f.h}
	return walletHTTP(t, f, h.Token, "token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, nil, "", "", nil)
}

func requestDeferred(t *testing.T, f vciIssuanceFixture, tokens walletTokens) (string, *ecdsa.PrivateKey) {
	t.Helper()
	holder := vciTestHolder(t)
	raw := vciTestProof(t, holder, "https://issuer.example/"+f.org.Slug, tokens.Nonce, nil)
	rec := walletHTTP(t, f, f.h.Credential, "oid4vci/credential", nil, map[string]any{"proofs": map[string]any{"jwt": []string{raw}}}, tokens.Access, "", nil)
	require.Equal(t, 202, rec.Code, rec.Body.String())
	var response struct {
		Transaction string `json:"transaction_id"`
		Interval    int    `json:"interval"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.NotEmpty(t, response.Transaction)
	require.Positive(t, response.Interval)
	return response.Transaction, holder
}

func approveWalletDeferred(t *testing.T, f vciIssuanceFixture, transaction string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
	c.SetParamNames("org_id", "txn_id")
	c.SetParamValues(f.org.ID.String(), transaction)
	if err := f.h.ApproveDeferredCredential(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec
}

func TestVCIRefreshDeferredBeyondAccessAndOfferExpiry(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	u, err := f.h.users.Create(ctx, f.org.ID, "deferred@example.test", nil, nil)
	require.NoError(t, err)
	offer := deferredOffer(t, f, &u.ID)
	tokens := startWallet(t, f, offer)
	transaction, holder := requestDeferred(t, f, tokens)
	poll := func(access string) *httptest.ResponseRecorder {
		return walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": transaction}, access, "", nil)
	}
	rec := poll(tokens.Access)
	require.Equal(t, 202, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), transaction)
	// Advance authorization state without sleeping or changing system time.
	_, err = f.pool.Exec(ctx, `UPDATE identity.wallet_issuance_tokens SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE token_hash=$1`, hashToken(tokens.Access))
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.credential_offers SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1`, offer.ID)
	require.NoError(t, err)
	rec = poll(tokens.Access)
	require.Equal(t, 401, rec.Code, "original offer hash must not bypass expiry in the access-token table")
	renewed := decodeWalletTokens(t, refreshWallet(t, f, tokens.Refresh))
	require.NotEqual(t, tokens.Access, renewed.Access)
	require.NotEqual(t, tokens.Refresh, renewed.Refresh)
	rec = poll(renewed.Access)
	require.Equal(t, 202, rec.Code, rec.Body.String())
	rec = walletHTTP(t, f, f.h.Credential, "oid4vci/credential", nil, map[string]any{}, renewed.Access, "", nil)
	require.NotEqual(t, 200, rec.Code, "refresh must not reopen issuance")
	rec = approveWalletDeferred(t, f, transaction)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	rec = poll(renewed.Access)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	dc, err := f.h.repo.GetDeferredCredential(ctx, transaction)
	require.NoError(t, err)
	require.NotNil(t, dc.DeliveredAt)
	var delivered struct {
		Credentials []struct {
			Credential string `json:"credential"`
		} `json:"credentials"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &delivered))
	require.Len(t, delivered.Credentials, 1)
	issuer, disclosures, _, err := oid4w.ParseSDJWT(delivered.Credentials[0].Credential)
	require.NoError(t, err)
	claims, err := oid4w.VerifyAndExtractClaims(issuer, disclosures, f.h.keys.PublicKey())
	require.NoError(t, err)
	require.Equal(t, u.ID.String(), claims["sub"])
	cnf, err := json.Marshal(claims["cnf"].(map[string]any)["jwk"])
	require.NoError(t, err)
	actual, err := jwk.ParseKey(cnf)
	require.NoError(t, err)
	expected, err := jwk.FromRaw(&holder.PublicKey)
	require.NoError(t, err)
	require.True(t, jwk.Equal(expected, actual))
	rec = poll(renewed.Access)
	require.Equal(t, 400, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid_transaction_id")
	rec = refreshWallet(t, f, renewed.Refresh)
	require.Equal(t, 400, rec.Code)
	var status string
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT status FROM identity.credential_offers WHERE id=$1`, offer.ID).Scan(&status))
	require.Equal(t, "used", status)
}

func TestVCIRefreshRotationReuseRevokesAllAccessTokens(t *testing.T) {
	f := vciFixture(t)
	offer := deferredOffer(t, f, nil)
	first := startWallet(t, f, offer)
	txn, _ := requestDeferred(t, f, first)
	second := decodeWalletTokens(t, refreshWallet(t, f, first.Refresh))
	poll := func(access string) *httptest.ResponseRecorder {
		return walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": txn}, access, "", nil)
	}
	require.Equal(t, 202, poll(first.Access).Code, "rotation preserves already issued access tokens until their own expiry")
	require.Equal(t, 202, poll(second.Access).Code)
	require.Equal(t, 400, refreshWallet(t, f, first.Refresh).Code)
	require.Equal(t, 401, poll(first.Access).Code, "reuse must also block the original offer-hash path")
	require.Equal(t, 401, poll(second.Access).Code)
	require.Equal(t, 400, refreshWallet(t, f, second.Refresh).Code)
}

func TestVCIRefreshConcurrentRotationHasOneWinnerAndRevokesFamily(t *testing.T) {
	f := vciFixture(t)
	tokens := startWallet(t, f, deferredOffer(t, f, nil))
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if refreshWallet(t, f, tokens.Refresh).Code == 200 {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
	g, _, _, err := f.h.repo.WalletGrantForToken(context.Background(), hashToken(tokens.Access), "access")
	require.NoError(t, err)
	require.NotNil(t, g.RevokedAt)
}

func TestVCIRefreshRejectsChangedAuthorization(t *testing.T) {
	for _, scenario := range []string{"grant_expiry", "refresh_expiry", "offer_expiry_before_request", "user_disabled", "org_disabled", "config_removed", "changed_subject", "transaction_failed", "transaction_expired"} {
		t.Run(scenario, func(t *testing.T) {
			f := vciFixture(t)
			ctx := context.Background()
			user, err := f.h.users.Create(ctx, f.org.ID, "subject@example.test", nil, nil)
			require.NoError(t, err)
			offer := deferredOffer(t, f, &user.ID)
			tokens := startWallet(t, f, offer)
			var txn string
			if strings.HasPrefix(scenario, "transaction_") {
				txn, _ = requestDeferred(t, f, tokens)
			}
			switch scenario {
			case "grant_expiry":
				_, err = f.pool.Exec(ctx, `UPDATE identity.wallet_issuance_grants SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE offer_id=$1`, offer.ID)
			case "refresh_expiry":
				_, err = f.pool.Exec(ctx, `UPDATE identity.wallet_issuance_tokens SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE token_hash=$1`, hashToken(tokens.Refresh))
			case "offer_expiry_before_request":
				_, err = f.pool.Exec(ctx, `UPDATE identity.credential_offers SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1`, offer.ID)
			case "user_disabled":
				_, err = f.pool.Exec(ctx, `UPDATE identity.users SET is_active=false WHERE id=$1`, user.ID)
			case "org_disabled":
				_, err = f.pool.Exec(ctx, `UPDATE identity.organizations SET is_active=false WHERE id=$1`, f.org.ID)
			case "config_removed":
				_, err = f.pool.Exec(ctx, `DELETE FROM identity.credential_configs WHERE id=$1`, f.cfg.ID)
			case "changed_subject":
				_, err = f.pool.Exec(ctx, `UPDATE identity.credential_offers SET user_id=NULL WHERE id=$1`, offer.ID)
			case "transaction_failed":
				_, err = f.pool.Exec(ctx, `UPDATE identity.deferred_credentials SET status='failed' WHERE transaction_id=$1`, txn)
			case "transaction_expired":
				_, err = f.pool.Exec(ctx, `UPDATE identity.deferred_credentials SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE transaction_id=$1`, txn)
			}
			require.NoError(t, err)
			rec := refreshWallet(t, f, tokens.Refresh)
			require.Equal(t, 400, rec.Code, rec.Body.String())
		})
	}
}

func walletDPoP(t *testing.T, key *ecdsa.PrivateKey, htu, access string, omitATH bool) string {
	t.Helper()
	public, err := jwk.FromRaw(&key.PublicKey)
	require.NoError(t, err)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, headers.Set(jws.JWKKey, public))
	b := jwt.NewBuilder().IssuedAt(time.Now()).JwtID(uuid.NewString()).Claim("htm", "POST").Claim("htu", htu)
	if access != "" && !omitATH {
		h := sha256.Sum256([]byte(access))
		b = b.Claim("ath", base64.RawURLEncoding.EncodeToString(h[:]))
	}
	tok, err := b.Build()
	require.NoError(t, err)
	raw, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return string(raw)
}

func TestVCIRefreshDPoPBindingAndResourceATH(t *testing.T) {
	f := vciFixture(t)
	offer := deferredOffer(t, f, nil)
	key := vciTestHolder(t)
	other := vciTestHolder(t)
	endpoint := "https://issuer.example/" + f.org.Slug + "/token"
	oidcH := &OIDCHandler{vciH: f.h}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}}
	proof := walletDPoP(t, key, endpoint, "", false)
	tokens := decodeWalletTokens(t, walletHTTP(t, f, oidcH.Token, "token", form, nil, "", proof, nil))
	require.Equal(t, "DPoP", tokens.Type)
	form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}}
	for _, p := range []string{"", proof, walletDPoP(t, other, endpoint, "", false)} {
		rec := walletHTTP(t, f, oidcH.Token, "token", form, nil, "", p, nil)
		require.Equal(t, 400, rec.Code, rec.Body.String())
	}
	renewed := decodeWalletTokens(t, walletHTTP(t, f, oidcH.Token, "token", form, nil, "", walletDPoP(t, key, endpoint, "", false), nil))
	resource := "https://issuer.example/" + f.org.Slug + "/oid4vci/credential"
	credentialProof := vciTestProof(t, vciTestHolder(t), "https://issuer.example/"+f.org.Slug, tokens.Nonce, nil)
	body := map[string]any{"proofs": map[string]any{"jwt": []string{credentialProof}}}
	for _, p := range []string{"", walletDPoP(t, key, resource, renewed.Access, true), walletDPoP(t, key, resource, "wrong-access-token", false)} {
		rec := walletHTTP(t, f, f.h.Credential, "oid4vci/credential", nil, body, renewed.Access, p, nil)
		require.Equal(t, 401, rec.Code, rec.Body.String())
	}
	valid := walletDPoP(t, key, resource, renewed.Access, false)
	rec := walletHTTP(t, f, f.h.Credential, "oid4vci/credential", nil, body, renewed.Access, valid, nil)
	require.Equal(t, 202, rec.Code, rec.Body.String())
	rec = walletHTTP(t, f, f.h.Credential, "oid4vci/credential", nil, body, renewed.Access, valid, nil)
	require.Equal(t, 401, rec.Code)
}

func TestVCIRefreshMTLSRequiresActualSameCertificate(t *testing.T) {
	f := vciFixture(t)
	offer := deferredOffer(t, f, nil)
	cert := &x509.Certificate{Raw: []byte("synthetic TLS client certificate")}
	connection := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}}
	tokens := decodeWalletTokens(t, walletHTTP(t, f, f.h.Token, "oid4vci/token", form, nil, "", "", connection))
	form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}}
	for _, conn := range []*tls.ConnectionState{nil, {PeerCertificates: []*x509.Certificate{{Raw: []byte("another client certificate")}}}} {
		rec := walletHTTP(t, f, f.h.Token, "oid4vci/token", form, nil, "", "", conn)
		require.Equal(t, 400, rec.Code, rec.Body.String())
	}
	renewed := decodeWalletTokens(t, walletHTTP(t, f, f.h.Token, "oid4vci/token", form, nil, "", "", connection))
	rec := walletHTTP(t, f, f.h.Credential, "oid4vci/credential", nil, map[string]any{}, renewed.Access, "", nil)
	require.Equal(t, 401, rec.Code)
}

func TestVCIRefreshRejectsOtherTenantClientAndScopeWithoutConsuming(t *testing.T) {
	f := vciFixture(t)
	other := vciFixture(t)
	offer := deferredOffer(t, f, nil)
	client, _, err := repository.NewClientRepository(f.pool).Create(context.Background(), f.org.ID, "wallet-"+uuid.NewString(), "Public wallet", []string{"https://wallet.example/cb"}, nil, nil, nil, nil, true)
	require.NoError(t, err)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}, "client_id": {client.ClientID}}
	tokens := decodeWalletTokens(t, walletHTTP(t, f, f.h.Token, "oid4vci/token", form, nil, "", "", nil))
	for _, change := range []url.Values{{"client_id": {"another"}}, {"scope": {"openid other_credential"}}, {"authorization_details": {`[{"type":"openid_credential"}]`}}} {
		q := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "client_id": {client.ClientID}}
		for k, v := range change {
			q[k] = v
		}
		rec := walletHTTP(t, f, f.h.Token, "oid4vci/token", q, nil, "", "", nil)
		expected := 400
		if _, changedClient := change["client_id"]; changedClient {
			expected = 401
		}
		require.Equal(t, expected, rec.Code, rec.Body.String())
	}
	q := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "client_id": {client.ClientID}}
	rec := walletHTTP(t, other, other.h.Token, "oid4vci/token", q, nil, "", "", nil)
	require.Equal(t, 400, rec.Code)
	renewed := decodeWalletTokens(t, walletHTTP(t, f, f.h.Token, "oid4vci/token", q, nil, "", "", nil))
	_, err = f.pool.Exec(context.Background(), `UPDATE identity.oidc_clients SET is_active=false WHERE client_id=$1`, client.ClientID)
	require.NoError(t, err)
	q.Set("refresh_token", renewed.Refresh)
	rec = walletHTTP(t, f, f.h.Token, "oid4vci/token", q, nil, "", "", nil)
	require.Equal(t, 401, rec.Code)
}

func TestVCIDeferredConcurrentDeliveryAndEligibility(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	user, err := f.h.users.Create(ctx, f.org.ID, "delivery@example.test", nil, nil)
	require.NoError(t, err)
	tokens := startWallet(t, f, deferredOffer(t, f, &user.ID))
	txn, _ := requestDeferred(t, f, tokens)
	rec := approveWalletDeferred(t, f, txn)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	poll := func() *httptest.ResponseRecorder {
		return walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": txn}, tokens.Access, "", nil)
	}
	_, err = f.pool.Exec(ctx, `UPDATE identity.users SET is_active=false WHERE id=$1`, user.ID)
	require.NoError(t, err)
	rec = poll()
	require.Equal(t, 400, rec.Code)
	require.Contains(t, rec.Body.String(), "credential_request_denied")
	_, err = f.pool.Exec(ctx, `UPDATE identity.users SET is_active=true WHERE id=$1`, user.ID)
	require.NoError(t, err)
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if poll().Code == 200 {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
}

func TestVCIRefreshRollbackPreservesUnspentToken(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	offer := deferredOffer(t, f, nil)
	tokens := startWallet(t, f, offer)
	name := "wallet_refresh_failure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	function := pgx.Identifier{"identity", name}.Sanitize()
	trigger := pgx.Identifier{name}.Sanitize()
	grant, _, _, err := f.h.repo.WalletGrantForToken(ctx, hashToken(tokens.Access), "access")
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.grant_id='%s' AND NEW.kind='access' THEN RAISE EXCEPTION 'synthetic refresh failure'; END IF; RETURN NEW; END $$`, function, grant.ID))
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON identity.wallet_issuance_tokens FOR EACH ROW EXECUTE FUNCTION %s()`, trigger, function))
	require.NoError(t, err)
	cleanup := func() {
		_, _ = f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON identity.wallet_issuance_tokens`, trigger))
		_, _ = f.pool.Exec(ctx, fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, function))
	}
	t.Cleanup(cleanup)
	rec := refreshWallet(t, f, tokens.Refresh)
	require.Equal(t, 503, rec.Code, rec.Body.String())
	_, _, used, err := f.h.repo.WalletGrantForToken(ctx, hashToken(tokens.Refresh), "refresh")
	require.NoError(t, err)
	require.Nil(t, used)
	cleanup()
	decodeWalletTokens(t, refreshWallet(t, f, tokens.Refresh))
}

func TestVCIRefreshDeletedUserCannotResurrectLegacyAccess(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	user, err := f.h.users.Create(ctx, f.org.ID, "deleted@example.test", nil, nil)
	require.NoError(t, err)
	offer := deferredOffer(t, f, &user.ID)
	tokens := startWallet(t, f, offer)
	txn, _ := requestDeferred(t, f, tokens)
	rec := approveWalletDeferred(t, f, txn)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	_, err = f.pool.Exec(ctx, `DELETE FROM identity.users WHERE id=$1`, user.ID)
	require.NoError(t, err)
	// Deletion cascades the grant and tokens, but leaves a generation marker on
	// the offer. Its old hash must not regain the meaning of a legacy bearer.
	rec = walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": txn}, tokens.Access, "", nil)
	require.Equal(t, 401, rec.Code, rec.Body.String())
	require.Equal(t, 400, refreshWallet(t, f, tokens.Refresh).Code)
}

func TestVCIDeferredTransactionIsolationAndDeliveryRollback(t *testing.T) {
	f := vciFixture(t)
	first := startWallet(t, f, deferredOffer(t, f, nil))
	txn, _ := requestDeferred(t, f, first)
	second := startWallet(t, f, deferredOffer(t, f, nil))
	otherTxn, _ := requestDeferred(t, f, second)
	rec := walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": otherTxn}, first.Access, "", nil)
	require.Equal(t, 400, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid_transaction_id")
	rec = approveWalletDeferred(t, f, txn)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	responseKey, publicJSON := responseEncryptionKey(t, "ECDH-ES")
	enc := &credentialResponseEncryptionReq{JWK: publicJSON, Enc: "unsupported-algorithm"}
	encryptedPoll := func(enc *credentialResponseEncryptionReq) *httptest.ResponseRecorder {
		body, err := json.Marshal(deferredCredentialRequest{TransactionID: txn, CredentialResponseEncryption: enc})
		require.NoError(t, err)
		sealed, err := jwe.Encrypt(body, jwe.WithKey(jwa.RSA_OAEP_256, f.h.keys.PublicKey()), jwe.WithContentEncryption(jwa.A256GCM))
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/"+f.org.Slug+"/oid4vci/deferred-credential", strings.NewReader(string(sealed)))
		req.Header.Set(echo.HeaderContentType, "application/jwt")
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+first.Access)
		e := echo.New()
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("org_slug")
		c.SetParamValues(f.org.Slug)
		if err := f.h.DeferredCredential(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		return rec
	}
	rec = walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, deferredCredentialRequest{TransactionID: txn, CredentialResponseEncryption: enc}, first.Access, "", nil)
	require.Equal(t, 400, rec.Code, "encryption parameters must be integrity protected in an encrypted request")
	rec = encryptedPoll(enc)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	var delivered bool
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT delivered_at IS NOT NULL FROM identity.deferred_credentials WHERE transaction_id=$1`, txn).Scan(&delivered))
	require.False(t, delivered, "failed response encryption must roll back transaction consumption")
	enc.Enc = "A256GCM"
	rec = encryptedPoll(enc)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Equal(t, "application/jwt", rec.Header().Get(echo.HeaderContentType))
	plain, err := jwe.Decrypt(rec.Body.Bytes(), jwe.WithKey(jwa.ECDH_ES, responseKey))
	require.NoError(t, err)
	require.Contains(t, string(plain), "credentials")
	rec = encryptedPoll(enc)
	require.Equal(t, 400, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid_transaction_id")
}

func TestVCIRefreshDPoPUnavailableReplayStoreFailsClosed(t *testing.T) {
	f := vciFixture(t)
	offer := deferredOffer(t, f, nil)
	key := vciTestHolder(t)
	endpoint := "https://issuer.example/" + f.org.Slug + "/oid4vci/token"
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}}
	tokens := decodeWalletTokens(t, walletHTTP(t, f, f.h.Token, "oid4vci/token", form, nil, "", walletDPoP(t, key, endpoint, "", false), nil))
	copy := *f.h
	copy.rdb = nil
	form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}}
	rec := walletHTTP(t, f, copy.Token, "oid4vci/token", form, nil, "", walletDPoP(t, key, endpoint, "", false), nil)
	require.Equal(t, 503, rec.Code, rec.Body.String())
	_, _, used, err := f.h.repo.WalletGrantForToken(context.Background(), hashToken(tokens.Refresh), "refresh")
	require.NoError(t, err)
	require.Nil(t, used)
}

func TestVCIRefreshInitialFailureDoesNotConsumePreauthorizedCode(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	offer := deferredOffer(t, f, nil)
	name := "wallet_initial_failure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	function := pgx.Identifier{"identity", name}.Sanitize()
	trigger := pgx.Identifier{name}.Sanitize()
	_, err := f.pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.offer_id='%s' THEN RAISE EXCEPTION 'synthetic grant failure'; END IF; RETURN NEW; END $$`, function, offer.ID))
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON identity.wallet_issuance_grants FOR EACH ROW EXECUTE FUNCTION %s()`, trigger, function))
	require.NoError(t, err)
	cleanup := func() {
		_, _ = f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON identity.wallet_issuance_grants`, trigger))
		_, _ = f.pool.Exec(ctx, fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, function))
	}
	t.Cleanup(cleanup)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}}
	rec := walletHTTP(t, f, f.h.Token, "oid4vci/token", form, nil, "", "", nil)
	require.Equal(t, 503, rec.Code, rec.Body.String())
	current, err := f.h.repo.GetOfferByID(ctx, offer.ID)
	require.NoError(t, err)
	require.Nil(t, current.AccessTokenHash)
	var generation int
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT wallet_grant_version FROM identity.credential_offers WHERE id=$1`, offer.ID).Scan(&generation))
	require.Zero(t, generation)
	cleanup()
	startWallet(t, f, offer)
}

func TestVCIRefreshDiscoveryAdvertisesWorkingAnonymousTokenEndpoint(t *testing.T) {
	f := vciFixture(t)
	cfg := &config.Config{}
	cfg.Auth.IssuerBase = "https://issuer.example"
	h := &OIDCHandler{vciH: f.h, orgs: f.h.orgs, cfg: cfg}
	rec := f.request(t, h.Discovery, "", nil)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var metadata map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &metadata))
	require.Equal(t, true, metadata["pre-authorized_grant_anonymous_access_supported"])
	require.Equal(t, "https://issuer.example/"+f.org.Slug+"/token", metadata["token_endpoint"])
	tokens := startWallet(t, f, deferredOffer(t, f, nil))
	decodeWalletTokens(t, refreshWallet(t, f, tokens.Refresh))
}

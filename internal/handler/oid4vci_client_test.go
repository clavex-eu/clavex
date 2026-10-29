package handler

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func confidentialWallet(t *testing.T, f vciIssuanceFixture) (*OIDCHandler, string, string) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Auth.IssuerBase = "https://issuer.example"
	cfg.Auth.AccessTokenTTL = 300
	cfg.Auth.RefreshTokenTTL = 3600
	h := NewOIDCHandler(cfg, f.pool, f.h.rdb, f.h.keys).WithOID4VCIHandler(f.h)
	client, secret, err := repository.NewClientRepository(f.pool).Create(context.Background(), f.org.ID, "wallet-"+uuid.NewString(), "wallet", []string{"https://wallet.example/callback"}, nil, []string{"authorization_code", "refresh_token"}, nil, nil, false)
	require.NoError(t, err)
	return h, client.ClientID, secret
}
func basicWallet(fn echo.HandlerFunc, id, secret string) echo.HandlerFunc {
	return func(c echo.Context) error { c.Request().SetBasicAuth(id, secret); return fn(c) }
}
func TestVCIConfidentialClientPreauthorizedRefreshAndIsolation(t *testing.T) {
	f := vciFixture(t)
	h, id, secret := confidentialWallet(t, f)
	offer := deferredOffer(t, f, nil)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}}
	rec := walletHTTP(t, f, basicWallet(h.Token, id, "wrong"), "token", form, nil, "", "", nil)
	require.Equal(t, 401, rec.Code, rec.Body.String())
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	tokens := decodeWalletTokens(t, rec)
	grant, _, _, err := f.h.repo.WalletGrantForToken(context.Background(), hashToken(tokens.Access), "access")
	require.NoError(t, err)
	require.Equal(t, "client_secret_basic", grant.ClientAuthMethod)
	txn, _ := requestDeferred(t, f, tokens)
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}}
	rec = walletHTTP(t, f, h.Token, "token", refresh, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	rec = walletHTTP(t, f, basicWallet(h.Token, id, "wrong"), "token", refresh, nil, "", "", nil)
	require.Equal(t, 401, rec.Code)
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", refresh, nil, "", "", nil)
	rotated := decodeWalletTokens(t, rec)
	require.Equal(t, 200, approveWalletDeferred(t, f, txn).Code)
	rec = walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": txn}, rotated.Access, "", nil)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	other := vciFixture(t)
	rec = walletHTTP(t, other, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	require.NotEqual(t, 200, rec.Code)
}
func createWalletCode(t *testing.T, f vciIssuanceFixture, id, scope string) (string, string) {
	t.Helper()
	ctx := context.Background()
	user, err := f.h.users.Create(ctx, f.org.ID, "code-"+uuid.NewString()+"@example.test", nil, nil)
	require.NoError(t, err)
	raw := uuid.NewString()
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	require.NoError(t, repository.NewAuthCodeRepository(f.pool).Create(ctx, repository.CreateAuthCodeParams{OrgID: f.org.ID, ClientID: id, UserID: user.ID, CodeHash: oidc.HashToken(raw), RedirectURI: "https://wallet.example/callback", Scope: scope, Nonce: "test-nonce", PKCEChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), PKCEMethod: "S256", ExpiresAt: time.Now().Add(time.Minute), AuthTime: time.Now().Unix()}))
	return raw, verifier
}
func TestVCIAuthorizationCodeDeferredRefreshAndJWTBinding(t *testing.T) {
	f := vciFixture(t)
	h, id, secret := confidentialWallet(t, f)
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `UPDATE identity.credential_configs SET deferred_issuance=true WHERE id=$1`, f.cfg.ID)
	require.NoError(t, err)
	scope := "openid " + oid4w.CredentialConfigID(f.cfg.VCT)
	raw, verifier := createWalletCode(t, f, id, scope)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {raw}, "redirect_uri": {"https://wallet.example/callback"}, "code_verifier": {"wrong"}}
	rec := walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	form.Set("code_verifier", verifier)
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	tokens := decodeWalletTokens(t, rec)
	access, err := jwt.Parse([]byte(tokens.Access), jwt.WithKey(jwa.PS256, f.h.keys.PublicKey()), jwt.WithValidate(true))
	require.NoError(t, err)
	_, ok := access.Get("clavex_wallet_grant")
	require.True(t, ok)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	var idToken string
	require.NoError(t, json.Unmarshal(body["id_token"], &idToken))
	parsedID, err := jwt.Parse([]byte(idToken), jwt.WithKey(jwa.PS256, f.h.keys.PublicKey()), jwt.WithValidate(true))
	require.NoError(t, err)
	atHash, ok := parsedID.Get("at_hash")
	require.True(t, ok)
	require.Equal(t, oidc.ComputeAtHash(tokens.Access), atHash)
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	require.Equal(t, 400, rec.Code)
	txn, _ := requestDeferred(t, f, tokens)
	// Expire only the database access token to exercise renewal without waiting.
	_, err = f.pool.Exec(ctx, `UPDATE identity.wallet_issuance_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1`, hashToken(tokens.Access))
	require.NoError(t, err)
	rec = walletHTTP(t, f, f.h.Credential, "oid4vci/credential", nil, map[string]any{"credential_configuration_id": oid4w.CredentialConfigID(f.cfg.VCT)}, tokens.Access, "", nil)
	require.Equal(t, 401, rec.Code, rec.Body.String())
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "scope": {scope}}
	rec = walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", refresh, nil, "", "", nil)
	rotated := decodeWalletTokens(t, rec)
	_, err = jwt.Parse([]byte(rotated.Access), jwt.WithKey(jwa.PS256, f.h.keys.PublicKey()), jwt.WithValidate(true))
	require.NoError(t, err)
	require.Equal(t, 200, approveWalletDeferred(t, f, txn).Code)
	rec = walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": txn}, rotated.Access, "", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	// A JWT cannot escape the consumed grant by falling back to the old generic
	// OIDC credential path, even after the grant/token rows disappear.
	_, err = f.pool.Exec(ctx, `DELETE FROM identity.wallet_issuance_grants WHERE offer_id=(SELECT offer_id FROM identity.deferred_credentials WHERE transaction_id=$1)`, txn)
	require.NoError(t, err)
	rec = walletHTTP(t, f, f.h.Credential, "oid4vci/credential", nil, map[string]any{"credential_configuration_id": oid4w.CredentialConfigID(f.cfg.VCT)}, rotated.Access, "", nil)
	require.Equal(t, 401, rec.Code, rec.Body.String())
}

func TestVCIPrivateKeyClientAssertionReplayAndStoreOutage(t *testing.T) {
	f := vciFixture(t)
	h, id, _ := confidentialWallet(t, f)
	ctx := context.Background()
	signer := f.h.keys
	public, err := jwk.FromRaw(signer.PublicKey())
	require.NoError(t, err)
	require.NoError(t, public.Set(jwk.KeyIDKey, "client-key"))
	jwks, err := json.Marshal(map[string]any{"keys": []any{public}})
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.oidc_clients SET token_endpoint_auth_method='private_key_jwt',jwks=$2 WHERE client_id=$1`, id, jwks)
	require.NoError(t, err)
	assertion := func() string {
		tok, err := jwt.NewBuilder().Issuer(id).Subject(id).Audience([]string{"https://issuer.example/" + f.org.Slug + "/token"}).IssuedAt(time.Now()).Expiration(time.Now().Add(time.Minute)).JwtID(uuid.NewString()).Build()
		require.NoError(t, err)
		headers := jws.NewHeaders()
		require.NoError(t, headers.Set(jws.KeyIDKey, "client-key"))
		raw, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, signer.CryptoSigner(), jws.WithProtectedHeaders(headers)))
		require.NoError(t, err)
		return string(raw)
	}
	offer := deferredOffer(t, f, nil)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}, "client_id": {id}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion()}}
	tokens := decodeWalletTokens(t, walletHTTP(t, f, h.Token, "token", form, nil, "", "", nil))
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "client_id": {id}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {form.Get("client_assertion")}}
	rec := walletHTTP(t, f, h.Token, "token", refresh, nil, "", "", nil)
	require.Equal(t, 401, rec.Code, rec.Body.String())
	refresh.Set("client_assertion", assertion())
	decodeWalletTokens(t, walletHTTP(t, f, h.Token, "token", refresh, nil, "", "", nil))
	// A separate closed Redis dependency verifies the actual shared assertion
	// validator fails closed rather than skipping replay protection on error.
	old := h.rdb
	closed := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 10 * time.Millisecond, MaxRetries: -1})
	require.NoError(t, closed.Close())
	h.rdb = closed
	refresh.Set("client_assertion", assertion())
	rec = walletHTTP(t, f, h.Token, "token", refresh, nil, "", "", nil)
	require.Equal(t, 503, rec.Code, rec.Body.String())
	h.rdb = old
}

func TestVCIClientSecretPostMethodCannotBeDowngraded(t *testing.T) {
	f := vciFixture(t)
	h, id, secret := confidentialWallet(t, f)
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `UPDATE identity.oidc_clients SET token_endpoint_auth_method='client_secret_post' WHERE client_id=$1`, id)
	require.NoError(t, err)
	offer := deferredOffer(t, f, nil)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}, "client_id": {id}, "client_secret": {secret}}
	rec := walletHTTP(t, f, basicWallet(h.Token, id, secret), "token", form, nil, "", "", nil)
	require.Equal(t, 401, rec.Code)
	tokens := decodeWalletTokens(t, walletHTTP(t, f, h.Token, "token", form, nil, "", "", nil))
	_, err = f.pool.Exec(ctx, `UPDATE identity.oidc_clients SET token_endpoint_auth_method='none',client_secret_hash=NULL WHERE client_id=$1`, id)
	require.NoError(t, err)
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "client_id": {id}}
	rec = walletHTTP(t, f, h.Token, "token", refresh, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
}

func TestVCIWalletAttestationInstanceAndParentLifecycle(t *testing.T) {
	f := vciFixture(t)
	h, id, _ := confidentialWallet(t, f)
	ctx := context.Background()
	provider, instance := vciTestHolder(t), vciTestHolder(t)
	providerPublic, err := jwk.FromRaw(&provider.PublicKey)
	require.NoError(t, err)
	require.NoError(t, providerPublic.Set(jwk.KeyIDKey, "provider"))
	keys, err := json.Marshal(map[string]any{"keys": []any{providerPublic}})
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.oidc_clients SET token_endpoint_auth_method='attest_jwt_client_auth',jwks=$2 WHERE client_id=$1`, id, keys)
	require.NoError(t, err)
	sourcePublic, err := jwk.FromRaw(f.h.keys.PublicKey())
	require.NoError(t, err)
	statusKeys, err := json.Marshal(map[string]any{"keys": []any{sourcePublic}})
	require.NoError(t, err)
	zero := 0
	source := oid4w.StatusSource{Format: "wallet-attestation+jwt", CredentialIssuer: "https://provider.example", CredentialType: "oauth-client-attestation+jwt", StatusIssuer: "https://status.example", ListURIs: []string{"https://status.example/wallets"}, JWKS: statusKeys, CacheSeconds: &zero}
	settings, err := json.Marshal(map[string]any{"wallet_attestation_status_required": true, "wallet_status_sources": []oid4w.StatusSource{source}})
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.organizations SET settings=$2 WHERE id=$1`, f.org.ID, settings)
	require.NoError(t, err)
	var state byte
	resolver := oid4w.NewStatusResolverWithHTTPClient(&http.Client{Transport: walletStatusTransport(func(*http.Request) (*http.Response, error) {
		list := oid4w.NewStatusListWithBits(2)
		require.NoError(t, list.Set(0, state))
		token, err := oid4w.IssueStatusListJWT(oid4w.StatusListJWTParams{Issuer: source.StatusIssuer, ListURI: source.ListURIs[0], StatusList: list, TTL: time.Minute, Signer: f.h.keys.CryptoSigner(), Algorithm: jwa.RS256})
		require.NoError(t, err)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/statuslist+jwt"}}, Body: io.NopCloser(strings.NewReader(token))}, nil
	})})
	withResolver := func(fn echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.SetRequest(c.Request().WithContext(oid4w.WithStatusResolver(c.Request().Context(), resolver)))
			return fn(c)
		}
	}
	assertion := func(instance *ecdsa.PrivateKey) string {
		pub, err := jwk.FromRaw(&instance.PublicKey)
		require.NoError(t, err)
		attest, err := jwt.NewBuilder().Issuer(source.CredentialIssuer).Subject(id).IssuedAt(time.Now()).Expiration(time.Now().Add(time.Hour)).Claim("cnf", map[string]any{"jwk": pub}).Claim("status", oid4w.BuildStatusClaim(source.ListURIs[0], 0)).Build()
		require.NoError(t, err)
		header := jws.NewHeaders()
		require.NoError(t, header.Set(jws.TypeKey, "oauth-client-attestation+jwt"))
		require.NoError(t, header.Set(jws.KeyIDKey, "provider"))
		raw, err := jwt.Sign(attest, jwt.WithKey(jwa.ES256, provider, jws.WithProtectedHeaders(header)))
		require.NoError(t, err)
		pop, err := jwt.NewBuilder().Issuer(id).Audience([]string{"https://issuer.example/" + f.org.Slug + "/token"}).IssuedAt(time.Now()).Expiration(time.Now().Add(time.Minute)).JwtID(uuid.NewString()).Build()
		require.NoError(t, err)
		ph := jws.NewHeaders()
		require.NoError(t, ph.Set(jws.TypeKey, "oauth-client-attestation-pop+jwt"))
		popRaw, err := jwt.Sign(pop, jwt.WithKey(jwa.ES256, instance, jws.WithProtectedHeaders(ph)))
		require.NoError(t, err)
		return string(raw) + "~" + string(popRaw)
	}
	offer := deferredOffer(t, f, nil)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}, "client_id": {id}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"}, "client_assertion": {assertion(instance)}}
	tokens := decodeWalletTokens(t, walletHTTP(t, f, withResolver(h.Token), "token", form, nil, "", "", nil))
	grant, _, _, err := f.h.repo.WalletGrantForToken(ctx, hashToken(tokens.Access), "access")
	require.NoError(t, err)
	require.NotEmpty(t, grant.AttestationJKT)
	require.Contains(t, string(grant.StatusParents), source.ListURIs[0])
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "client_id": {id}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"}, "client_assertion": {assertion(vciTestHolder(t))}}
	rec := walletHTTP(t, f, withResolver(h.Token), "token", refresh, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	refresh.Set("client_assertion", assertion(instance))
	renewed := decodeWalletTokens(t, walletHTTP(t, f, withResolver(h.Token), "token", refresh, nil, "", "", nil))
	// Capture the authenticated wallet parent in the pending deferred record.
	nonce, err := f.h.issueCredentialNonce(ctx, f.org.Slug)
	require.NoError(t, err)
	holder := vciTestHolder(t)
	proof := vciTestProof(t, holder, "https://issuer.example/"+f.org.Slug, nonce, nil)
	rec = walletHTTP(t, f, withResolver(f.h.Credential), "oid4vci/credential", nil, map[string]any{"proofs": map[string]any{"jwt": []string{proof}}}, renewed.Access, "", nil)
	require.Equal(t, 202, rec.Code, rec.Body.String())
	var deferred struct {
		TransactionID string `json:"transaction_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &deferred))
	dc, err := f.h.repo.GetDeferredCredential(ctx, deferred.TransactionID)
	require.NoError(t, err)
	require.Contains(t, string(dc.StatusParents), source.ListURIs[0])
	state = 1
	rec = walletHTTP(t, f, withResolver(f.h.DeferredCredential), "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": deferred.TransactionID}, renewed.Access, "", nil)
	require.Equal(t, 401, rec.Code, rec.Body.String())
	refresh.Set("refresh_token", renewed.Refresh)
	refresh.Set("client_assertion", assertion(instance))
	rec = walletHTTP(t, f, withResolver(h.Token), "token", refresh, nil, "", "", nil)
	require.Equal(t, 401, rec.Code, rec.Body.String())
}

func TestVCIMTLSClientRequiresVerifiedConnectionAndSameCertificate(t *testing.T) {
	f := vciFixture(t)
	h, id, _ := confidentialWallet(t, f)
	ctx := context.Background()
	cert := &x509.Certificate{Raw: []byte("synthetic verified TLS client certificate"), Subject: pkix.Name{CommonName: "test wallet"}}
	_, err := f.pool.Exec(ctx, `UPDATE identity.oidc_clients SET token_endpoint_auth_method='tls_client_auth',tls_client_auth_subject_dn=$2 WHERE client_id=$1`, id, cert.Subject.String())
	require.NoError(t, err)
	offer := deferredOffer(t, f, nil)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {offer.PreAuthCode}, "client_id": {id}}
	unverified := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := walletHTTP(t, f, h.Token, "token", form, nil, "", "", unverified)
	require.Equal(t, 401, rec.Code)
	connection := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	tokens := decodeWalletTokens(t, walletHTTP(t, f, h.Token, "token", form, nil, "", "", connection))
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "client_id": {id}}
	rec = walletHTTP(t, f, h.Token, "token", refresh, nil, "", "", nil)
	require.Equal(t, 401, rec.Code)
	other := &x509.Certificate{Raw: []byte("another verified certificate with same subject"), Subject: cert.Subject}
	another := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{other}, VerifiedChains: [][]*x509.Certificate{{other}}}
	rec = walletHTTP(t, f, h.Token, "token", refresh, nil, "", "", another)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	decodeWalletTokens(t, walletHTTP(t, f, h.Token, "token", refresh, nil, "", "", connection))
}

func TestVCIAuthorizationCodePublicDPoPBindingAndRAR(t *testing.T) {
	f := vciFixture(t)
	h, _, _ := confidentialWallet(t, f)
	ctx := context.Background()
	client, _, err := repository.NewClientRepository(f.pool).Create(ctx, f.org.ID, "public-wallet-"+uuid.NewString(), "public", []string{"https://wallet.example/callback"}, nil, []string{"authorization_code", "refresh_token"}, nil, nil, true)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.credential_configs SET deferred_issuance=true WHERE id=$1`, f.cfg.ID)
	require.NoError(t, err)
	raw, verifier := createWalletCode(t, f, client.ClientID, "openid")
	key := vciTestHolder(t)
	public, err := jwk.FromRaw(&key.PublicKey)
	require.NoError(t, err)
	thumb, err := public.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	details := []map[string]any{{"type": "openid_credential", "credential_configuration_id": oid4w.CredentialConfigID(f.cfg.VCT), "locations": []string{"https://issuer.example/" + f.org.Slug}}}
	encoded, err := json.Marshal(details)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE sessions.authorization_codes SET authorization_details=$2,dpop_jkt=$3 WHERE code_hash=$1`, oidc.HashToken(raw), encoded, base64.RawURLEncoding.EncodeToString(thumb))
	require.NoError(t, err)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {raw}, "client_id": {client.ClientID}, "redirect_uri": {"https://wallet.example/callback"}, "code_verifier": {verifier}, "authorization_details": {string(encoded)}}
	rec := walletHTTP(t, f, h.Token, "token", form, nil, "", "", nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	wrong := walletDPoP(t, vciTestHolder(t), "https://issuer.example/"+f.org.Slug+"/token", "", false)
	rec = walletHTTP(t, f, h.Token, "token", form, nil, "", wrong, nil)
	require.Equal(t, 400, rec.Code, rec.Body.String())
	valid := walletDPoP(t, key, "https://issuer.example/"+f.org.Slug+"/token", "", false)
	tokens := decodeWalletTokens(t, walletHTTP(t, f, h.Token, "token", form, nil, "", valid, nil))
	require.Equal(t, "DPoP", tokens.Type)
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "client_id": {client.ClientID}}
	valid = walletDPoP(t, key, "https://issuer.example/"+f.org.Slug+"/token", "", false)
	renewed := decodeWalletTokens(t, walletHTTP(t, f, h.Token, "token", refresh, nil, "", valid, nil))
	grant, _, _, err := f.h.repo.WalletGrantForToken(ctx, hashToken(renewed.Access), "access")
	require.NoError(t, err)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(thumb), grant.DPoPJKT)
}

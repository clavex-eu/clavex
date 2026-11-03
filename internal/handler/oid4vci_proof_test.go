package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func vciTestHolder(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func vciTestProof(t *testing.T, key *ecdsa.PrivateKey, issuer, nonce string, mutate func(map[string]any, jws.Headers)) string {
	t.Helper()
	public, err := jwk.FromRaw(&key.PublicKey)
	require.NoError(t, err)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "openid4vci-proof+jwt"))
	require.NoError(t, headers.Set(jws.JWKKey, public))
	claims := map[string]any{"aud": issuer, "iat": time.Now().Unix(), "nonce": nonce}
	if mutate != nil {
		mutate(claims, headers)
	}
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	signed, err := jws.Sign(body, jws.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return string(signed)
}

func TestVCIProofFormsAndEveryProofVerified(t *testing.T) {
	const issuer = "https://issuer.example/tenant"
	key := vciTestHolder(t)
	raw := vciTestProof(t, key, issuer, "challenge", nil)
	for _, req := range []credentialRequest{
		{Proof: &credentialProof{ProofType: "jwt", JWT: raw}},
		{Proofs: &credentialProofs{JWT: []string{raw}}},
	} {
		proofs, err := validateCredentialProofs(&req, issuer, "dc+sd-jwt", time.Now())
		require.NoError(t, err)
		require.Len(t, proofs, 1)
		pub, err := jwk.FromRaw(&key.PublicKey)
		require.NoError(t, err)
		require.True(t, jwk.Equal(pub, proofs[0].Key))
	}
	for _, req := range []credentialRequest{
		{}, {Proof: &credentialProof{}}, {Proofs: &credentialProofs{}},
		{Proof: &credentialProof{ProofType: "jwt", JWT: raw}, Proofs: &credentialProofs{JWT: []string{raw}}},
		{Proofs: &credentialProofs{JWT: []string{raw, "broken"}}},
		{Proofs: &credentialProofs{JWT: []string{raw, raw}}},
		{Proofs: &credentialProofs{JWT: make([]string, maxCredentialProofs+1)}},
	} {
		_, err := validateCredentialProofs(&req, issuer, "dc+sd-jwt", time.Now())
		require.Error(t, err)
	}
}

func TestVCIProofRejectsInvalidKeysClaimsAndSignatures(t *testing.T) {
	const issuer = "https://issuer.example/tenant"
	key := vciTestHolder(t)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any, jws.Headers)
	}{
		{"missing jwk", func(_ map[string]any, h jws.Headers) { require.NoError(t, h.Remove(jws.JWKKey)) }},
		{"kid only", func(_ map[string]any, h jws.Headers) {
			require.NoError(t, h.Remove(jws.JWKKey))
			require.NoError(t, h.Set(jws.KeyIDKey, "did:example:unknown#key"))
		}},
		{"private jwk", func(_ map[string]any, h jws.Headers) {
			k, err := jwk.FromRaw(key)
			require.NoError(t, err)
			require.NoError(t, h.Set(jws.JWKKey, k))
		}},
		{"different key", func(_ map[string]any, h jws.Headers) {
			k, err := jwk.FromRaw(&vciTestHolder(t).PublicKey)
			require.NoError(t, err)
			require.NoError(t, h.Set(jws.JWKKey, k))
		}},
		{"wrong type", func(_ map[string]any, h jws.Headers) { require.NoError(t, h.Set(jws.TypeKey, "JWT")) }},
		{"missing iat", func(c map[string]any, _ jws.Headers) { delete(c, "iat") }},
		{"string iat", func(c map[string]any, _ jws.Headers) { c["iat"] = "123" }},
		{"old iat", func(c map[string]any, _ jws.Headers) { c["iat"] = time.Now().Add(-time.Hour).Unix() }},
		{"future iat", func(c map[string]any, _ jws.Headers) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"missing aud", func(c map[string]any, _ jws.Headers) { delete(c, "aud") }},
		{"wrong tenant", func(c map[string]any, _ jws.Headers) { c["aud"] = "https://issuer.example/other" }},
		{"missing nonce", func(c map[string]any, _ jws.Headers) { delete(c, "nonce") }},
		{"expired", func(c map[string]any, _ jws.Headers) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := vciTestProof(t, key, issuer, "challenge", tc.mutate)
			_, err := validateCredentialProofs(&credentialRequest{Proofs: &credentialProofs{JWT: []string{raw}}}, issuer, "dc+sd-jwt", time.Now())
			require.Error(t, err)
		})
	}
	_, err := verifyCredentialProofKey(`eyJhbGciOiJub25lIiwidHlwIjoib3BlbmlkNHZjaS1wcm9vZitqd3QifQ.e30.`)
	require.Error(t, err)
}

func vciTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	address := os.Getenv("TEST_REDIS_URL")
	if address == "" {
		t.Skip("TEST_REDIS_URL not set")
	}
	opts, err := redis.ParseURL(address)
	require.NoError(t, err)
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	require.NoError(t, rdb.Ping(context.Background()).Err())
	return rdb
}

func TestVCINonceAtomicBatchAndReplay(t *testing.T) {
	h := &OID4VCIHandler{rdb: vciTestRedis(t)}
	ctx := context.Background()
	org := uuid.NewString()
	nonce, err := h.issueCredentialNonce(ctx, org)
	require.NoError(t, err)
	proofs := []verifiedCredentialProof{{Nonce: nonce}, {Nonce: nonce}}
	// A bad second challenge must not consume the first valid challenge.
	require.Error(t, h.consumeCredentialProofs(ctx, org, []verifiedCredentialProof{{Nonce: nonce}, {Nonce: "unknown"}}))
	require.Error(t, h.consumeCredentialProofs(ctx, "other-"+org, proofs))
	require.NoError(t, h.consumeCredentialProofs(ctx, org, proofs))
	require.Error(t, h.consumeCredentialProofs(ctx, org, proofs))

	nonce, err = h.issueCredentialNonce(ctx, org)
	require.NoError(t, err)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.consumeCredentialProofs(ctx, org, []verifiedCredentialProof{{Nonce: nonce}}) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())

	nonce, err = h.issueCredentialNonce(ctx, org)
	require.NoError(t, err)
	require.NoError(t, h.rdb.PExpire(ctx, credentialNonceKey(org, nonce), time.Millisecond).Err())
	require.Eventually(t, func() bool { return h.rdb.Exists(ctx, credentialNonceKey(org, nonce)).Val() == 0 }, time.Second, time.Millisecond)
	require.Error(t, h.consumeCredentialProofs(ctx, org, []verifiedCredentialProof{{Nonce: nonce}}))
}

func TestVCINonceStoreUnavailableFailsClosed(t *testing.T) {
	h := &OID4VCIHandler{}
	_, err := h.issueCredentialNonce(context.Background(), "org")
	require.Error(t, err)
	require.Error(t, h.consumeCredentialProofs(context.Background(), "org", []verifiedCredentialProof{{Nonce: "nonce"}}))
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	require.NoError(t, rdb.Close())
	h.rdb = rdb
	_, err = h.issueCredentialNonce(context.Background(), "org")
	require.Error(t, err)
	err = h.consumeCredentialProofs(context.Background(), "org", []verifiedCredentialProof{{Nonce: "nonce"}})
	require.Error(t, err)
	e := echo.New()
	rec := httptest.NewRecorder()
	require.NoError(t, writeCredentialProofError(e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec), err))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

type vciIssuanceFixture struct {
	h    *OID4VCIHandler
	pool *pgxpool.Pool
	org  *models.Organization
	cfg  *models.CredentialConfig
}

func vciFixture(t *testing.T) vciIssuanceFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = "identity,sessions,audit,public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	h := NewOID4VCIHandler(pool, nil, StaticBaseURL("https://issuer.example")).WithRedis(vciTestRedis(t))
	org, err := h.orgs.Create(context.Background(), "VCI review", "vci-"+uuid.NewString(), nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org.ID)
		require.NoError(t, err)
	})
	credCfg, err := h.repo.CreateCredentialConfig(context.Background(), org.ID, "https://issuer.example/identity", "Identity", nil, map[string]interface{}{"given_name": "given_name"}, 3600, "identity", nil)
	require.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "issuer.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600))
	h.keys, err = oidc.LoadKeySet(keyPath)
	require.NoError(t, err)
	return vciIssuanceFixture{h: h, pool: pool, org: org, cfg: credCfg}
}

func (f vciIssuanceFixture) offer(t *testing.T) (*models.CredentialOffer, string) {
	t.Helper()
	offer, err := f.h.repo.CreateCredentialOffer(context.Background(), f.org.ID, nil, f.cfg.VCT, uuid.NewString(), nil, map[string]interface{}{"given_name": "Alice"}, time.Now().Add(time.Hour))
	require.NoError(t, err)
	raw, hash := generateOpaqueToken()
	require.NoError(t, f.h.repo.SetOfferAccessToken(context.Background(), offer.ID, hash))
	return offer, raw
}

func (f vciIssuanceFixture) request(t *testing.T, fn echo.HandlerFunc, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(b)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e := echo.New()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	if err := fn(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec
}

func TestVCIPreauthorizedHTTPProofValidationAndBinding(t *testing.T) {
	f := vciFixture(t)
	_, token := f.offer(t)
	issuer := "https://issuer.example/" + f.org.Slug
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	holder := vciTestHolder(t)
	raw := vciTestProof(t, holder, issuer, nonce, nil)
	for _, body := range []any{
		map[string]any{},
		map[string]any{"proofs": map[string]any{"jwt": []string{vciTestProof(t, holder, issuer, nonce, func(_ map[string]any, h jws.Headers) { require.NoError(t, h.Remove(jws.JWKKey)) })}}},
		map[string]any{"proofs": map[string]any{"jwt": []string{raw, "broken"}}},
	} {
		rec := f.request(t, f.h.Credential, token, body)
		require.Equal(t, 400, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "invalid_proof")
	}
	second := vciTestHolder(t)
	rec := f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": []string{raw, vciTestProof(t, second, issuer, nonce, nil)}}})
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var response struct {
		Credentials []struct {
			Credential string `json:"credential"`
		} `json:"credentials"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Len(t, response.Credentials, 2)
	for i, k := range []*ecdsa.PrivateKey{holder, second} {
		issuerJWT, disclosures, _, err := oid4w.ParseSDJWT(response.Credentials[i].Credential)
		require.NoError(t, err)
		claims, err := oid4w.VerifyAndExtractClaims(issuerJWT, disclosures, f.h.keys.PublicKey())
		require.NoError(t, err)
		expected, err := jwk.FromRaw(&k.PublicKey)
		require.NoError(t, err)
		cnf := claims["cnf"].(map[string]any)
		b, err := json.Marshal(cnf["jwk"])
		require.NoError(t, err)
		actual, err := jwk.ParseKey(b)
		require.NoError(t, err)
		require.True(t, jwk.Equal(expected, actual))
	}
	// A fresh offer cannot reuse the consumed proof challenge.
	_, otherToken := f.offer(t)
	rec = f.request(t, f.h.Credential, otherToken, map[string]any{"proof": map[string]any{"proof_type": "jwt", "jwt": raw}})
	require.Equal(t, 400, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid_nonce")
}

func TestVCIDeferredHTTPPersistsVerifiedHolderKey(t *testing.T) {
	f := vciFixture(t)
	_, err := f.pool.Exec(context.Background(), `UPDATE credential_configs SET deferred_issuance=true WHERE id=$1`, f.cfg.ID)
	require.NoError(t, err)
	_, token := f.offer(t)
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	holder := vciTestHolder(t)
	raw := vciTestProof(t, holder, "https://issuer.example/"+f.org.Slug, nonce, nil)
	rec := f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": []string{raw}}})
	require.Equal(t, 202, rec.Code, rec.Body.String())
	var response struct {
		TransactionID string `json:"transaction_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	dc, err := f.h.repo.GetDeferredCredential(context.Background(), response.TransactionID)
	require.NoError(t, err)
	stored, err := deferredCredentialHolderKey(dc.HolderJWK)
	require.NoError(t, err)
	expected, err := jwk.FromRaw(&holder.PublicKey)
	require.NoError(t, err)
	require.True(t, jwk.Equal(expected, stored))
	listed, err := f.h.repo.ListDeferredCredentials(context.Background(), f.org.ID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	require.JSONEq(t, string(dc.HolderJWK), string(listed[0].HolderJWK))
	approve := func() *httptest.ResponseRecorder {
		e := echo.New()
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
		c.SetParamNames("org_id", "txn_id")
		c.SetParamValues(f.org.ID.String(), dc.TransactionID)
		if err := f.h.ApproveDeferredCredential(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		return rec
	}
	rec = approve()
	require.Equal(t, 200, rec.Code, rec.Body.String())
	dc, err = f.h.repo.GetDeferredCredential(context.Background(), dc.TransactionID)
	require.NoError(t, err)
	require.NotNil(t, dc.CredentialJWT)
	issuerJWT, disclosures, _, err := oid4w.ParseSDJWT(*dc.CredentialJWT)
	require.NoError(t, err)
	claims, err := oid4w.VerifyAndExtractClaims(issuerJWT, disclosures, f.h.keys.PublicKey())
	require.NoError(t, err)
	b, err := json.Marshal(claims["cnf"].(map[string]any)["jwk"])
	require.NoError(t, err)
	actual, err := jwk.ParseKey(b)
	require.NoError(t, err)
	require.True(t, jwk.Equal(expected, actual))
	// Existing requests cannot reconstruct holder keys from IDs or silently downgrade.
	_, err = f.pool.Exec(context.Background(), `UPDATE deferred_credentials SET status='pending',holder_jwk=NULL WHERE id=$1`, dc.ID)
	require.NoError(t, err)
	rec = approve()
	require.Equal(t, 409, rec.Code, rec.Body.String())
	private, err := jwk.FromRaw(holder)
	require.NoError(t, err)
	privJSON, err := json.Marshal(private)
	require.NoError(t, err)
	_, err = f.pool.Exec(context.Background(), `UPDATE deferred_credentials SET holder_jwk=$1 WHERE id=$2`, privJSON, dc.ID)
	require.Error(t, err, "database must reject private holder keys")
}

func TestVCIDeferredRejectsPrivateOrMissingKeys(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`{"kty":"oct","k":"c2VjcmV0"}`)} {
		_, err := deferredCredentialHolderKey(raw)
		require.Error(t, err)
	}
	private, err := jwk.FromRaw(vciTestHolder(t))
	require.NoError(t, err)
	b, err := json.Marshal(private)
	require.NoError(t, err)
	_, err = deferredCredentialHolderKey(b)
	require.Error(t, err)
}

// Check the proof parser cannot mistake an HMAC for an asymmetric holder proof.
func TestVCIProofRejectsSymmetricAlgorithm(t *testing.T) {
	h := jws.NewHeaders()
	require.NoError(t, h.Set(jws.TypeKey, "openid4vci-proof+jwt"))
	key, err := jwk.FromRaw([]byte("a sufficiently long symmetric secret"))
	require.NoError(t, err)
	require.NoError(t, h.Set(jws.JWKKey, key))
	proof, err := jws.Sign([]byte(`{"aud":"issuer","iat":1,"nonce":"n"}`), jws.WithKey(jwa.HS256, key, jws.WithProtectedHeaders(h)))
	require.NoError(t, err)
	_, err = verifyCredentialProofKey(string(proof))
	require.Error(t, err)
}

func TestVCIProofCertificateKeyAndAlgorithmPolicy(t *testing.T) {
	const issuer = "https://issuer.example/tenant"
	holder := vciTestHolder(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &holder.PublicKey, holder)
	require.NoError(t, err)
	raw := vciTestProof(t, holder, issuer, "challenge", func(_ map[string]any, h jws.Headers) {
		require.NoError(t, h.Remove(jws.JWKKey))
		var chain cert.Chain
		require.NoError(t, chain.AddString(base64.StdEncoding.EncodeToString(der)))
		require.NoError(t, h.Set(jws.X509CertChainKey, &chain))
	})
	proofs, err := validateCredentialProofs(&credentialRequest{Proofs: &credentialProofs{JWT: []string{raw}}}, issuer, "mso_mdoc", time.Now())
	require.NoError(t, err)
	pub, err := jwk.FromRaw(&holder.PublicKey)
	require.NoError(t, err)
	require.True(t, jwk.Equal(pub, proofs[0].Key))
	// The certificate supplies the holder key; it does not grant issuer trust.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	public, err := jwk.FromRaw(&rsaKey.PublicKey)
	require.NoError(t, err)
	for _, alg := range []jwa.SignatureAlgorithm{jwa.PS256, jwa.RS256} {
		h := jws.NewHeaders()
		require.NoError(t, h.Set(jws.TypeKey, "openid4vci-proof+jwt"))
		require.NoError(t, h.Set(jws.JWKKey, public))
		payload, err := json.Marshal(map[string]any{"aud": issuer, "iat": time.Now().Unix(), "nonce": "challenge"})
		require.NoError(t, err)
		signed, err := jws.Sign(payload, jws.WithKey(alg, rsaKey, jws.WithProtectedHeaders(h)))
		require.NoError(t, err)
		req := &credentialRequest{Proofs: &credentialProofs{JWT: []string{string(signed)}}}
		_, err = validateCredentialProofs(req, issuer, "dc+sd-jwt", time.Now())
		require.NoError(t, err)
		_, err = validateCredentialProofs(req, issuer, "mso_mdoc", time.Now())
		require.Error(t, err)
	}
}

// Produce a valid access token for HTTP tests without a live authorization server.
func vciTestAccessToken(t *testing.T, f vciIssuanceFixture, userID uuid.UUID) string {
	t.Helper()
	tok, err := jwt.NewBuilder().IssuedAt(time.Now()).Issuer("https://issuer.example/"+f.org.Slug).Subject(userID.String()).Claim("scope", oid4w.CredentialConfigID(f.cfg.VCT)).Expiration(time.Now().Add(time.Minute)).Build()
	require.NoError(t, err)
	raw, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, f.h.keys.PrivateKey()))
	require.NoError(t, err)
	return string(raw)
}

func TestVCIAuthorizationCodeHTTPValidatesEveryProofBeforeIssuance(t *testing.T) {
	f := vciFixture(t)
	user, err := f.h.users.Create(context.Background(), f.org.ID, "wallet@example.test", nil, nil)
	require.NoError(t, err)
	token := vciTestAccessToken(t, f, user.ID)
	issuer := "https://issuer.example/" + f.org.Slug
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	first := vciTestProof(t, vciTestHolder(t), issuer, nonce, nil)
	secondKey := vciTestHolder(t)
	wrongAudience := vciTestProof(t, secondKey, "https://issuer.example/other", nonce, nil)
	body := func(proofs ...string) any {
		return map[string]any{"credential_configuration_id": oid4w.CredentialConfigID(f.cfg.VCT), "proofs": map[string]any{"jwt": proofs}}
	}
	rec := f.request(t, f.h.Credential, token, body(first, wrongAudience))
	require.Equal(t, 400, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "invalid_proof")
	var issued int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM issued_credentials WHERE org_id=$1`, f.org.ID).Scan(&issued))
	require.Zero(t, issued)
	require.EqualValues(t, 1, f.h.rdb.Exists(context.Background(), credentialNonceKey(f.org.Slug, nonce)).Val())
	second := vciTestProof(t, secondKey, issuer, nonce, nil)
	rec = f.request(t, f.h.Credential, token, body(first, second))
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var response struct {
		Credentials []json.RawMessage `json:"credentials"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Len(t, response.Credentials, 2)
	rec = f.request(t, f.h.Credential, token, body(first, second))
	require.Equal(t, 400, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "invalid_nonce")
}

func TestVCILegacyBatchHTTPValidatesAllItemsBeforeIssuance(t *testing.T) {
	f := vciFixture(t)
	_, token := f.offer(t)
	issuer := "https://issuer.example/" + f.org.Slug
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	first := vciTestProof(t, vciTestHolder(t), issuer, nonce, nil)
	second := vciTestProof(t, vciTestHolder(t), issuer, nonce, nil)
	item := func(raw string) map[string]any {
		return map[string]any{"proofs": map[string]any{"jwt": []string{raw}}}
	}
	rec := f.request(t, f.h.BatchCredential, token, map[string]any{"credential_requests": []any{item(first), item("broken")}})
	require.Equal(t, 400, rec.Code, rec.Body.String())
	var issued int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM issued_credentials WHERE org_id=$1`, f.org.ID).Scan(&issued))
	require.Zero(t, issued)
	rec = f.request(t, f.h.BatchCredential, token, map[string]any{"credential_requests": []any{item(first), item(second)}})
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var response struct {
		Credentials []struct {
			Credential *string `json:"credential"`
		} `json:"credential_responses"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Len(t, response.Credentials, 2)
	for _, credential := range response.Credentials {
		require.NotNil(t, credential.Credential)
	}
}

func TestVCINonceEndpointAndLegacyTokenUseSharedStore(t *testing.T) {
	f := vciFixture(t)
	rec := f.request(t, f.h.Nonce, "", nil)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &fields))
	require.Len(t, fields, 1, "Final nonce response must not expose legacy token-response fields")
	var result struct {
		Nonce string `json:"c_nonce"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	require.NoError(t, f.h.consumeCredentialProofs(context.Background(), f.org.Slug, []verifiedCredentialProof{{Nonce: result.Nonce}}))
	offer, err := f.h.repo.CreateCredentialOffer(context.Background(), f.org.ID, nil, f.cfg.VCT, uuid.NewString(), nil, nil, time.Now().Add(time.Hour))
	require.NoError(t, err)
	e := echo.New()
	form := "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=" + offer.PreAuthCode
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec = httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	require.NoError(t, f.h.Token(c))
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	require.NoError(t, f.h.consumeCredentialProofs(context.Background(), f.org.Slug, []verifiedCredentialProof{{Nonce: result.Nonce}}))
	f.h.rdb = nil
	rec = f.request(t, f.h.Nonce, "", nil)
	require.Equal(t, 503, rec.Code, rec.Body.String())
}

// A tx_code object already means that the wallet must supply the transaction
// code. Final section 4.1.1 does not define a nested "required" property.
func TestVCIOfferTransactionCodeFinalShape(t *testing.T) {
	f := vciFixture(t)
	hash := hashTxCode("123456")
	offer, err := f.h.repo.CreateCredentialOffer(context.Background(), f.org.ID, nil, f.cfg.VCT, uuid.NewString(), &hash, nil, time.Now().Add(time.Hour))
	require.NoError(t, err)
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	c.SetParamNames("org_slug", "offer_id")
	c.SetParamValues(f.org.Slug, offer.ID.String())
	require.NoError(t, f.h.OfferJSON(c))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Grants map[string]struct {
			TxCode map[string]any `json:"tx_code"`
		} `json:"grants"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	txCode := body.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].TxCode
	require.Equal(t, "numeric", txCode["input_mode"])
	require.NotContains(t, txCode, "required")
}

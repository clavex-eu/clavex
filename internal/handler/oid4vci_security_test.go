package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func trustedAttesterSettings(t *testing.T, key *ecdsa.PrivateKey) map[string]interface{} {
	t.Helper()
	public, err := jwk.FromRaw(&key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, public.Set(jwk.KeyIDKey, "attester"))
	return map[string]interface{}{"credential_key_attesters": []any{map[string]any{"issuer": "https://attester.example", "jwks": map[string]any{"keys": []any{public}}}}}
}

func attestedProof(t *testing.T, holder, attester *ecdsa.PrivateKey, issuer, nonce string, mutate func(map[string]any, jws.Headers)) string {
	t.Helper()
	public, err := jwk.FromRaw(&holder.PublicKey)
	require.NoError(t, err)
	claims := map[string]any{"iss": "https://attester.example", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": nonce, "attested_keys": []any{public}}
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "key-attestation+jwt"))
	require.NoError(t, headers.Set(jws.KeyIDKey, "attester"))
	// Self-declared header keys must not establish trust.
	attesterPublic, err := jwk.FromRaw(&attester.PublicKey)
	require.NoError(t, err)
	require.NoError(t, headers.Set(jws.JWKKey, attesterPublic))
	if mutate != nil {
		mutate(claims, headers)
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	ka, err := jws.Sign(payload, jws.WithKey(jwa.ES256, attester, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return vciTestProof(t, holder, issuer, nonce, func(_ map[string]any, h jws.Headers) {
		require.NoError(t, h.Remove(jws.JWKKey))
		require.NoError(t, h.Set(jws.KeyIDKey, "0"))
		require.NoError(t, h.Set("key_attestation", string(ka)))
	})
}

func TestVCIAttestationTrustNonceAndHolderBinding(t *testing.T) {
	issuer, nonce := "https://issuer.example/org", "challenge"
	holder, attester := vciTestHolder(t), vciTestHolder(t)
	org := &models.Organization{Settings: trustedAttesterSettings(t, attester)}
	cfg := &models.CredentialConfig{RequireKeyAttestation: true}
	check := func(t *testing.T, raw string, org *models.Organization) error {
		req := &credentialRequest{Proofs: &credentialProofs{JWT: []string{raw}}}
		proofs, err := validateCredentialProofs(req, issuer, "dc+sd-jwt", time.Now())
		if err != nil {
			return err
		}
		return validateCredentialAttestations(org, cfg, req, proofs, time.Now())
	}
	raw := attestedProof(t, holder, attester, issuer, nonce, nil)
	require.NoError(t, check(t, raw, org))
	require.NoError(t, check(t, attestedProof(t, holder, attester, issuer, nonce, func(c map[string]any, _ jws.Headers) { delete(c, "iss") }), org))
	strict := &models.Organization{Settings: trustedAttesterSettings(t, attester)}
	strict.Settings["key_attestation_issuer_required"] = true
	require.Error(t, check(t, attestedProof(t, holder, attester, issuer, nonce, func(c map[string]any, _ jws.Headers) { delete(c, "iss") }), strict))
	require.Error(t, check(t, raw, &models.Organization{}))
	require.Error(t, check(t, vciTestProof(t, holder, issuer, nonce, nil), org))
	require.Error(t, check(t, attestedProof(t, holder, vciTestHolder(t), issuer, nonce, nil), org))
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any, jws.Headers)
	}{
		{"wrong issuer", func(c map[string]any, _ jws.Headers) { c["iss"] = "https://untrusted.example" }},
		{"wrong nonce", func(c map[string]any, _ jws.Headers) { c["nonce"] = "other" }},
		{"expired", func(c map[string]any, _ jws.Headers) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{"missing expiration", func(c map[string]any, _ jws.Headers) { delete(c, "exp") }},
		{"wrong type", func(_ map[string]any, h jws.Headers) { require.NoError(t, h.Set(jws.TypeKey, "JWT")) }},
		{"different holder", func(c map[string]any, _ jws.Headers) {
			key, err := jwk.FromRaw(&vciTestHolder(t).PublicKey)
			require.NoError(t, err)
			c["attested_keys"] = []any{key}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, check(t, attestedProof(t, holder, attester, issuer, nonce, tc.mutate), org))
		})
	}
}

func TestVCICredentialAuthorizationRequiresExplicitGrant(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scope   string
		details any
		allow   bool
	}{
		{"ordinary OIDC", "openid profile", nil, false},
		{"exact credential scope", "openid identity", nil, true},
		{"scope prefix", "identity_other", nil, false},
		{"RAR", "openid", []any{map[string]any{"type": "openid_credential", "credential_configuration_id": "identity"}}, true},
		{"RAR wrong config overrides scope", "identity", []any{map[string]any{"type": "openid_credential", "credential_configuration_id": "other"}}, false},
		{"RAR wrong issuer location", "identity", []any{map[string]any{"type": "openid_credential", "credential_configuration_id": "identity", "locations": []string{"https://other.example"}}}, false},
		{"unimplemented dataset selectors", "identity", []any{map[string]any{"type": "openid_credential", "credential_configuration_id": "identity", "credential_identifiers": []string{"restricted-dataset"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := jwt.NewBuilder().Claim("scope", tc.scope)
			if tc.details != nil {
				builder = builder.Claim("authorization_details", tc.details)
			}
			token, err := builder.Build()
			require.NoError(t, err)
			require.Equal(t, tc.allow, credentialConfigurationAuthorized(token, "identity", "https://issuer.example"))
		})
	}
}

func TestVCIConcurrentOfferDifferentNoncesOnlyOneIssuance(t *testing.T) {
	f := vciFixture(t)
	_, token := f.offer(t)
	issuer := "https://issuer.example/" + f.org.Slug
	var wg sync.WaitGroup
	var successes atomic.Int32
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
		require.NoError(t, err)
		raw := vciTestProof(t, vciTestHolder(t), issuer, nonce, nil)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": []string{raw}}})
			if rec.Code == 200 {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
	var count int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM issued_credentials WHERE org_id=$1`, f.org.ID).Scan(&count))
	require.Equal(t, 1, count)
}

func TestVCITransactionalBatchRollsBackOnSecondInsertFailure(t *testing.T) {
	f := vciFixture(t)
	offer, token := f.offer(t)
	name := "test_vci_fail_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{"identity", name}.Sanitize()
	sql := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
	 IF NEW.org_id='%s'::uuid AND (SELECT count(*) FROM identity.issued_credentials WHERE org_id=NEW.org_id)>0 THEN RAISE EXCEPTION 'test issuance failure'; END IF; RETURN NEW; END $$;
	 CREATE TRIGGER %s BEFORE INSERT ON identity.issued_credentials FOR EACH ROW EXECUTE FUNCTION %s()`, identifier, f.org.ID, pgx.Identifier{name}.Sanitize(), identifier)
	_, err := f.pool.Exec(context.Background(), sql)
	require.NoError(t, err)
	cleanup := func() {
		_, err := f.pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON identity.issued_credentials; DROP FUNCTION IF EXISTS %s()`, pgx.Identifier{name}.Sanitize(), identifier))
		require.NoError(t, err)
	}
	t.Cleanup(cleanup)
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	issuer := "https://issuer.example/" + f.org.Slug
	proofs := []string{vciTestProof(t, vciTestHolder(t), issuer, nonce, nil), vciTestProof(t, vciTestHolder(t), issuer, nonce, nil)}
	rec := f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": proofs}})
	require.Equal(t, 500, rec.Code, rec.Body.String())
	var count int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM issued_credentials WHERE org_id=$1`, f.org.ID).Scan(&count))
	require.Zero(t, count)
	stored, err := f.h.repo.GetOfferByID(context.Background(), offer.ID)
	require.NoError(t, err)
	require.Equal(t, "pending", stored.Status)
	cleanup()
	nonce, err = f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	rec = f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": []string{vciTestProof(t, vciTestHolder(t), issuer, nonce, nil)}}})
	require.Equal(t, 200, rec.Code, rec.Body.String())
}

func TestVCIConcurrentPreauthorizedTokenSingleUse(t *testing.T) {
	f := vciFixture(t)
	offer, err := f.h.repo.CreateCredentialOffer(context.Background(), f.org.ID, nil, f.cfg.VCT, uuid.NewString(), nil, nil, time.Now().Add(time.Hour))
	require.NoError(t, err)
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			e := echo.New()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code="+offer.PreAuthCode))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			c := e.NewContext(req, rec)
			c.SetParamNames("org_slug")
			c.SetParamValues(f.org.Slug)
			if err := f.h.Token(c); err != nil {
				e.HTTPErrorHandler(err, c)
			}
			if rec.Code == 200 {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
}

func TestVCIAttestationPolicyHTTPAndMetadata(t *testing.T) {
	f := vciFixture(t)
	require.NoError(t, f.h.repo.SetRequireKeyAttestation(context.Background(), f.cfg.ID, f.org.ID, true))
	_, token := f.offer(t)
	issuer := "https://issuer.example/" + f.org.Slug
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	holder, attester := vciTestHolder(t), vciTestHolder(t)
	rec := f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": []string{vciTestProof(t, holder, issuer, nonce, nil)}}})
	require.Equal(t, 400, rec.Code, rec.Body.String())
	settings, err := json.Marshal(trustedAttesterSettings(t, attester))
	require.NoError(t, err)
	_, err = f.pool.Exec(context.Background(), `UPDATE organizations SET settings=$1 WHERE id=$2`, settings, f.org.ID)
	require.NoError(t, err)
	rec = f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": []string{attestedProof(t, holder, attester, issuer, nonce, nil)}}})
	require.Equal(t, 200, rec.Code, rec.Body.String())
	metadata := func() *httptest.ResponseRecorder {
		e := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "application/json")
		c := e.NewContext(req, rec)
		c.SetParamNames("org_slug")
		c.SetParamValues(f.org.Slug)
		if err := f.h.IssuerMetadata(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		return rec
	}
	rec = metadata()
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var meta map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &meta))
	config := meta["credential_configurations_supported"].(map[string]any)[oid4w.CredentialConfigID(f.cfg.VCT)].(map[string]any)
	proofType := config["proof_types_supported"].(map[string]any)["jwt"].(map[string]any)
	required := proofType["key_attestations_required"].(map[string]any)
	encoded, err := json.Marshal(required["key_attestation_jwks"])
	require.NoError(t, err)
	set, err := jwk.Parse(encoded)
	require.NoError(t, err)
	require.Equal(t, 1, set.Len())
	actual, _ := set.Key(0)
	expected, err := jwk.FromRaw(&attester.PublicKey)
	require.NoError(t, err)
	require.True(t, jwk.Equal(actual, expected))
	_, err = f.pool.Exec(context.Background(), `UPDATE organizations SET settings='{}'::jsonb WHERE id=$1`, f.org.ID)
	require.NoError(t, err)
	rec = metadata()
	require.Equal(t, 503, rec.Code, rec.Body.String())
}

func TestVCIOrdinaryOIDCTokenAndExpiredOpaqueTokenCannotIssue(t *testing.T) {
	f := vciFixture(t)
	user, err := f.h.users.Create(context.Background(), f.org.ID, "ordinary@example.test", nil, nil)
	require.NoError(t, err)
	token, err := jwt.NewBuilder().IssuedAt(time.Now()).Issuer("https://issuer.example/"+f.org.Slug).Subject(user.ID.String()).Claim("scope", "openid profile").Expiration(time.Now().Add(time.Minute)).Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.PS256, f.h.keys.PrivateKey()))
	require.NoError(t, err)
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	body := map[string]any{"credential_configuration_id": oid4w.CredentialConfigID(f.cfg.VCT), "proofs": map[string]any{"jwt": []string{vciTestProof(t, vciTestHolder(t), "https://issuer.example/"+f.org.Slug, nonce, nil)}}}
	rec := f.request(t, f.h.Credential, string(signed), body)
	require.Equal(t, 403, rec.Code, rec.Body.String())
	offer, opaque := f.offer(t)
	_, err = f.pool.Exec(context.Background(), `UPDATE credential_offers SET access_token_expires_at=NOW()-INTERVAL '1 minute' WHERE id=$1`, offer.ID)
	require.NoError(t, err)
	rec = f.request(t, f.h.Credential, opaque, body)
	require.Equal(t, 401, rec.Code, rec.Body.String())
}

func TestVCIConcurrentDeferredApprovalCommitsOnce(t *testing.T) {
	f := vciFixture(t)
	_, err := f.pool.Exec(context.Background(), `UPDATE credential_configs SET deferred_issuance=true WHERE id=$1`, f.cfg.ID)
	require.NoError(t, err)
	_, token := f.offer(t)
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	raw := vciTestProof(t, vciTestHolder(t), "https://issuer.example/"+f.org.Slug, nonce, nil)
	rec := f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": []string{raw}}})
	require.Equal(t, 202, rec.Code, rec.Body.String())
	var response struct {
		TransactionID string `json:"transaction_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			e := echo.New()
			rec := httptest.NewRecorder()
			c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
			c.SetParamNames("org_id", "txn_id")
			c.SetParamValues(f.org.ID.String(), response.TransactionID)
			if err := f.h.ApproveDeferredCredential(c); err != nil {
				e.HTTPErrorHandler(err, c)
			}
			if rec.Code == 200 {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
	var count int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM issued_credentials WHERE org_id=$1`, f.org.ID).Scan(&count))
	require.Equal(t, 1, count)
}

func TestVCIIssuanceUsesOneDatabaseConnection(t *testing.T) {
	f := vciFixture(t)
	config := f.pool.Config()
	config.MaxConns = 1
	config.MinConns = 0
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	f.h = NewOID4VCIHandler(pool, f.h.keys, f.h.cfg).WithRedis(f.h.rdb)
	_, token := f.offer(t)
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	raw := vciTestProof(t, vciTestHolder(t), "https://issuer.example/"+f.org.Slug, nonce, nil)
	body, err := json.Marshal(map[string]any{"proofs": map[string]any{"jwt": []string{raw}}})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body))).WithContext(ctx)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	if err := f.h.Credential(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	require.Equal(t, 200, rec.Code, rec.Body.String())
}

func TestVCILegacyOfferCannotIssueAnotherTenantsUser(t *testing.T) {
	f := vciFixture(t)
	other, err := f.h.orgs.Create(context.Background(), "Other tenant", "vci-other-"+uuid.NewString(), nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := f.pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, other.ID)
		require.NoError(t, err)
	})
	u, err := f.h.users.Create(context.Background(), other.ID, "other-tenant@example.test", nil, nil)
	require.NoError(t, err)
	// A legacy malformed row must not bypass the handler's creation check.
	offer, err := f.h.repo.CreateCredentialOffer(context.Background(), f.org.ID, &u.ID, f.cfg.VCT, uuid.NewString(), nil, nil, time.Now().Add(time.Hour))
	require.NoError(t, err)
	token, hash := generateOpaqueToken()
	require.NoError(t, f.h.repo.SetOfferAccessToken(context.Background(), offer.ID, hash))
	nonce, err := f.h.issueCredentialNonce(context.Background(), f.org.Slug)
	require.NoError(t, err)
	raw := vciTestProof(t, vciTestHolder(t), "https://issuer.example/"+f.org.Slug, nonce, nil)
	rec := f.request(t, f.h.Credential, token, map[string]any{"proofs": map[string]any{"jwt": []string{raw}}})
	require.Equal(t, 400, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "credential_request_denied")
	var count int
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT count(*) FROM issued_credentials WHERE org_id=$1`, f.org.ID).Scan(&count))
	require.Zero(t, count)
}

func TestVCIAccessTokenLifetimeAndCertificateBinding(t *testing.T) {
	now := time.Now()
	short, err := jwt.NewBuilder().IssuedAt(now).Expiration(now.Add(5 * time.Minute)).Build()
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	require.True(t, credentialAccessTokenValid(short, req, now))
	long, err := jwt.NewBuilder().IssuedAt(now).Expiration(now.Add(time.Hour)).Build()
	require.NoError(t, err)
	require.False(t, credentialAccessTokenValid(long, req, now))
	cert := &x509.Certificate{Raw: []byte("test TLS peer certificate")}
	bound, err := jwt.NewBuilder().IssuedAt(now).Expiration(now.Add(time.Hour)).Claim("cnf", map[string]any{"x5t#S256": oidc.CertThumbprint(cert)}).Build()
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-Client-Cert", "an untrusted forwarded header")
	require.False(t, credentialAccessTokenValid(bound, req, now))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	require.True(t, credentialAccessTokenValid(bound, req, now))
	req.TLS.PeerCertificates = []*x509.Certificate{{Raw: []byte("other certificate")}}
	require.False(t, credentialAccessTokenValid(bound, req, now))
}

func TestVCIAttestedProofKeyIndex(t *testing.T) {
	issuer, nonce := "https://issuer.example/org", "challenge"
	holder, attester := vciTestHolder(t), vciTestHolder(t)
	raw := attestedProof(t, holder, attester, issuer, nonce, nil)
	for _, tc := range []struct {
		name  string
		edit  func(jws.Headers)
		valid bool
	}{
		{"index zero", func(jws.Headers) {}, true},
		{"embedded jwk without index", func(h jws.Headers) {
			require.NoError(t, h.Remove(jws.KeyIDKey))
			p, e := jwk.FromRaw(&holder.PublicKey)
			require.NoError(t, e)
			require.NoError(t, h.Set(jws.JWKKey, p))
		}, true},
		{"out of range", func(h jws.Headers) { require.NoError(t, h.Set(jws.KeyIDKey, "1")) }, false},
		{"negative", func(h jws.Headers) { require.NoError(t, h.Set(jws.KeyIDKey, "-1")) }, false},
		{"non canonical", func(h jws.Headers) { require.NoError(t, h.Set(jws.KeyIDKey, "00")) }, false},
		{"DID", func(h jws.Headers) { require.NoError(t, h.Set(jws.KeyIDKey, "did:example:key")) }, false},
		{"missing index", func(h jws.Headers) { require.NoError(t, h.Remove(jws.KeyIDKey)) }, false},
		{"missing attestation", func(h jws.Headers) { require.NoError(t, h.Remove("key_attestation")) }, false},
		{"malformed attestation", func(h jws.Headers) { require.NoError(t, h.Set("key_attestation", "invalid")) }, false},
		{"ambiguous jwk", func(h jws.Headers) {
			p, e := jwk.FromRaw(&holder.PublicKey)
			require.NoError(t, e)
			require.NoError(t, h.Set(jws.JWKKey, p))
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, e := jws.Parse([]byte(raw))
			require.NoError(t, e)
			h := msg.Signatures()[0].ProtectedHeaders()
			tc.edit(h)
			proof, e := jws.Sign(msg.Payload(), jws.WithKey(jwa.ES256, holder, jws.WithProtectedHeaders(h)))
			require.NoError(t, e)
			_, e = validateCredentialProofs(&credentialRequest{Proofs: &credentialProofs{JWT: []string{string(proof)}}}, issuer, "dc+sd-jwt", time.Now())
			if tc.valid {
				require.NoError(t, e)
			} else {
				require.Error(t, e)
			}
		})
	}
	// The selected key must be public even when an attester signs the payload.
	private, e := jwk.FromRaw(holder)
	require.NoError(t, e)
	raw = attestedProof(t, holder, attester, issuer, nonce, func(c map[string]any, _ jws.Headers) { c["attested_keys"] = []any{private} })
	_, e = validateCredentialProofs(&credentialRequest{Proofs: &credentialProofs{JWT: []string{raw}}}, issuer, "dc+sd-jwt", time.Now())
	require.Error(t, e)
}

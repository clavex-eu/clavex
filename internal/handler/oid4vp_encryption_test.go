package handler

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	secretcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func encryptionFixture(t *testing.T) cibaWalletFixture {
	t.Helper()
	f := newCibaWalletFixture(t)
	f.h.WithResponseEncryption(secretcrypto.NewEncryptor("response-test-encryption-key-shared-by-replicas"))
	f.h.trustedIssuers = map[string]crypto.PublicKey{"https://issuer.example/" + f.org.Slug: f.vciIssuanceFixture.h.keys.PublicKey()}
	return f
}

func encryptedSession(t *testing.T, f cibaWalletFixture, query map[string]interface{}, state *string) *models.PresentationSession {
	t.Helper()
	s, err := f.h.repo.CreatePresentationSession(context.Background(), f.org.ID, uuid.NewString(), nil, query, "https://issuer.example/"+f.org.Slug+"/wallet/response", nil, state, uuid.NewString(), time.Now().Add(time.Minute), nil, "x509_san_dns:issuer.example", "direct_post.jwt")
	require.NoError(t, err)
	return s
}

func readerPublicKey(t *testing.T, f cibaWalletFixture, s *models.PresentationSession) jwk.Key {
	t.Helper()
	metadata, err := f.h.responseClientMetadata(context.Background(), s)
	require.NoError(t, err)
	encoded, err := json.Marshal(metadata)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), `"d":`)
	require.Equal(t, []string{"A128GCM", "A256GCM"}, metadata["encrypted_response_enc_values_supported"])
	return metadata["jwks"].(map[string]any)["keys"].([]jwk.Key)[0]
}

func encryptWalletResponse(t *testing.T, key jwk.Key, enc jwa.ContentEncryptionAlgorithm, payload any) string {
	t.Helper()
	plain, err := json.Marshal(payload)
	require.NoError(t, err)
	raw, err := jwe.Encrypt(plain, jwe.WithKey(jwa.ECDH_ES, key), jwe.WithContentEncryption(enc))
	require.NoError(t, err)
	return string(raw)
}

func postEncryptedResponse(t *testing.T, f cibaWalletFixture, compact string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"response": {compact}}
	for k, v := range extra {
		form[k] = v
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	if err := f.h.Response(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec
}

func encryptedSDJWTPayload(t *testing.T, f cibaWalletFixture, s *models.PresentationSession) map[string]any {
	t.Helper()
	vp := accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://issuer.example/"+f.org.Slug, f.user.ID.String(), f.cfg.VCT, s.Nonce, s.ClientID, map[string]any{"name": "test"}, true)
	state := s.RequestID
	if s.State != nil {
		state = *s.State
	}
	return map[string]any{"state": state, "vp_token": map[string][]string{"identity": {vp}}}
}

func TestEncryptedVPResponseBothGCMsRestartReplayAndCustomState(t *testing.T) {
	for _, enc := range []jwa.ContentEncryptionAlgorithm{jwa.A128GCM, jwa.A256GCM} {
		t.Run(enc.String(), func(t *testing.T) {
			f := encryptionFixture(t)
			custom := "caller-correlation"
			s := encryptedSession(t, f, bindingQuery(f.cfg.VCT, false), &custom)
			key := readerPublicKey(t, f, s)
			saved, err := f.h.repo.GetPresentationSession(context.Background(), s.RequestID)
			require.NoError(t, err)
			require.NotEmpty(t, saved.ResponseKeyCiphertext)
			apiJSON, err := json.Marshal(saved)
			require.NoError(t, err)
			require.NotContains(t, string(apiJSON), "ciphertext")
			// Another handler/replica must recover the persisted request key, not generate a new one.
			other := NewOID4VPHandler(f.pool, f.h.keys, f.h.cfg, f.h.trustedIssuers, true, nil, "", "").WithResponseEncryption(secretcrypto.NewEncryptor("response-test-encryption-key-shared-by-replicas"))
			f.h = other
			recovered := readerPublicKey(t, f, saved)
			a, err := key.Thumbprint(crypto.SHA256)
			require.NoError(t, err)
			b, err := recovered.Thumbprint(crypto.SHA256)
			require.NoError(t, err)
			require.Equal(t, a, b)
			compact := encryptWalletResponse(t, key, enc, encryptedSDJWTPayload(t, f, s))
			rec := postEncryptedResponse(t, f, compact, nil)
			require.Equal(t, 200, rec.Code, rec.Body.String())
			stored, err := f.h.repo.GetPresentationSession(context.Background(), s.RequestID)
			require.NoError(t, err)
			require.Equal(t, "verified", stored.Status)
			require.Empty(t, stored.ResponseKeyCiphertext)
			rec = postEncryptedResponse(t, f, compact, nil)
			require.Equal(t, 400, rec.Code)
		})
	}
}

func TestEncryptedVPRejectsDowngradeTamperingCrossSessionAndWrongState(t *testing.T) {
	f := encryptionFixture(t)
	for _, name := range []string{"wrong-state", "wrong-key", "tampered", "mixed-outer", "wrong-tenant", "expired"} {
		t.Run(name, func(t *testing.T) {
			s := encryptedSession(t, f, bindingQuery(f.cfg.VCT, false), nil)
			key := readerPublicKey(t, f, s)
			payload := encryptedSDJWTPayload(t, f, s)
			if name == "wrong-state" {
				payload["state"] = "other"
			}
			if name == "wrong-key" {
				other := encryptedSession(t, f, bindingQuery(f.cfg.VCT, false), nil)
				key = readerPublicKey(t, f, other)
				require.NoError(t, key.Set(jwk.KeyIDKey, s.RequestID))
			}
			compact := encryptWalletResponse(t, key, jwa.A256GCM, payload)
			if name == "tampered" {
				parts := strings.Split(compact, ".")
				parts[3] = "AAAA" + parts[3][4:]
				compact = strings.Join(parts, ".")
			}
			var extra url.Values
			if name == "mixed-outer" {
				extra = url.Values{"vp_token": {"unprotected"}}
			}
			target := f
			if name == "wrong-tenant" {
				org, err := f.h.orgs.Create(context.Background(), "Other tenant", "other-"+uuid.NewString(), nil)
				require.NoError(t, err)
				target.org = org
				t.Cleanup(func() {
					_, err := f.pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org.ID)
					require.NoError(t, err)
				})
			}
			if name == "expired" {
				_, err := f.pool.Exec(context.Background(), `UPDATE presentation_sessions SET expires_at=NOW()-interval '1 minute' WHERE request_id=$1`, s.RequestID)
				require.NoError(t, err)
			}
			rec := postEncryptedResponse(t, target, compact, extra)
			require.Equal(t, 400, rec.Code, rec.Body.String())
			got, err := f.h.repo.GetPresentationSession(context.Background(), s.RequestID)
			require.NoError(t, err)
			require.Equal(t, "pending", got.Status, "Unauthenticated failures must not consume a valid session")
		})
	}
	s := encryptedSession(t, f, bindingQuery(f.cfg.VCT, false), nil)
	readerPublicKey(t, f, s)
	payload := encryptedSDJWTPayload(t, f, s)
	raw, err := json.Marshal(payload["vp_token"])
	require.NoError(t, err)
	rec := f.submit(t, s, rawStringPresentation(t, raw), false)
	require.Equal(t, 400, rec.Code)
	require.Contains(t, rec.Body.String(), "encrypted_response_required")
}

func rawStringPresentation(t *testing.T, envelope []byte) string {
	t.Helper()
	var v map[string][]string
	require.NoError(t, json.Unmarshal(envelope, &v))
	return v["identity"][0]
}

func TestEncryptedVPKeyConcurrentRequestFetchAndSignedMetadata(t *testing.T) {
	f := encryptionFixture(t)
	s := encryptedSession(t, f, bindingQuery(f.cfg.VCT, false), nil)
	var wg sync.WaitGroup
	results := make(chan []byte, 6)
	errs := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			copy := *s
			_, public, err := f.h.responseKey(context.Background(), &copy, true)
			if err != nil {
				errs <- err
				return
			}
			thumb, err := public.Thumbprint(crypto.SHA256)
			if err != nil {
				errs <- err
				return
			}
			results <- thumb
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	var expected []byte
	for v := range results {
		if expected == nil {
			expected = v
		}
		require.Equal(t, expected, v)
	}
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	c.SetParamNames("org_slug", "req_id")
	c.SetParamValues(f.org.Slug, s.RequestID)
	require.NoError(t, f.h.GetRequest(c))
	require.Equal(t, 200, rec.Code)
	token, err := jwt.Parse(rec.Body.Bytes(), jwt.WithVerify(false), jwt.WithValidate(false))
	require.NoError(t, err)
	mode, _ := token.Get("response_mode")
	require.Equal(t, "direct_post.jwt", mode)
	metadata, _ := token.Get("client_metadata")
	raw, err := json.Marshal(metadata)
	require.NoError(t, err)
	require.Contains(t, string(raw), "encrypted_response_enc_values_supported")
	require.Contains(t, string(raw), "ECDH-ES")
	require.NotContains(t, string(raw), `"d":`)
}

func TestEncryptedMdocResponseBindsRecipientKeyThumbprint(t *testing.T) {
	f := encryptionFixture(t)
	query := map[string]interface{}{"credentials": []any{map[string]any{"id": "identity", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": mdoc.DocTypeEuPid}, "claims": []any{map[string]any{"path": []string{mdoc.NSEuPid, "given_name"}}}}}}
	for _, wrongThumb := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "wrong-thumbprint"}[wrongThumb], func(t *testing.T) {
			s := encryptedSession(t, f, query, nil)
			key := readerPublicKey(t, f, s)
			signingSession := *s
			if wrongThumb {
				signingSession.ResponseKeyThumbprint = make([]byte, 32)
			}
			vp, root := verifierMdoc(t, &signingSession)
			_, err := f.h.iacaRepo.Create(context.Background(), f.org.ID, "Test reader encrypted mdoc", root, []string{mdoc.DocTypeEuPid}, nil)
			require.NoError(t, err)
			var value any
			require.NoError(t, json.Unmarshal([]byte(vp), &value))
			compact := encryptWalletResponse(t, key, jwa.A256GCM, map[string]any{"state": s.RequestID, "vp_token": value})
			rec := postEncryptedResponse(t, f, compact, nil)
			if wrongThumb {
				require.Equal(t, 400, rec.Code, rec.Body.String())
			} else {
				require.Equal(t, 200, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestEncryptedVPDefaultRequestAndExpiredKeyCleanup(t *testing.T) {
	f := encryptionFixture(t)
	body, err := json.Marshal(map[string]any{"dcql_query": bindingQuery(f.cfg.VCT, false)})
	require.NoError(t, err)
	e := echo.New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	c := e.NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	require.NoError(t, f.h.CreateRequest(c))
	require.Equal(t, 201, rec.Code, rec.Body.String())
	var created struct {
		RequestID string `json:"request_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	s, err := f.h.repo.GetPresentationSession(context.Background(), created.RequestID)
	require.NoError(t, err)
	require.Equal(t, "direct_post.jwt", s.ResponseMode)
	require.NotEmpty(t, s.ResponseKeyCiphertext)
	expired := encryptedSession(t, f, bindingQuery(f.cfg.VCT, false), nil)
	readerPublicKey(t, f, expired)
	_, err = f.pool.Exec(context.Background(), `UPDATE presentation_sessions SET expires_at=NOW()-interval '1 minute' WHERE request_id=$1`, expired.RequestID)
	require.NoError(t, err)
	require.NoError(t, f.h.repo.ClearExpiredPresentationKeys(context.Background()))
	got, err := f.h.repo.GetPresentationSession(context.Background(), expired.RequestID)
	require.NoError(t, err)
	require.Empty(t, got.ResponseKeyCiphertext)
	got, err = f.h.repo.GetPresentationSession(context.Background(), s.RequestID)
	require.NoError(t, err)
	require.NotEmpty(t, got.ResponseKeyCiphertext, "active request key retained")
}

func TestEncryptedCIBARequestKeepsAccountBinding(t *testing.T) {
	for _, foreignSubject := range []bool{false, true} {
		t.Run(map[bool]string{false: "bound", true: "foreign-subject"}[foreignSubject], func(t *testing.T) {
			f := encryptionFixture(t)
			ctx := context.Background()
			auth, err := f.ciba.Create(ctx, repository.CIBACreateParams{OrgID: f.org.ID, ClientID: f.clientID, UserID: &f.user.ID, Scope: "openid", ExpiresIn: time.Minute})
			require.NoError(t, err)
			oidc := &OIDCHandler{cfg: &config.Config{Auth: config.AuthConfig{IssuerBase: "https://issuer.example"}}, vpSessions: f.h.repo, oid4vpH: f.h}
			id, _, err := oidc.createCIBALinkedVPSession(ctx, f.org, auth, f.org.Slug, bindingQuery(f.cfg.VCT, false))
			require.NoError(t, err)
			s, err := f.h.repo.GetPresentationSession(ctx, id)
			require.NoError(t, err)
			require.Equal(t, "direct_post.jwt", s.ResponseMode)
			require.Equal(t, "x509_san_dns:issuer.example", s.ClientID)
			key := readerPublicKey(t, f, s)
			subject := f.user.ID.String()
			if foreignSubject {
				subject = uuid.NewString()
			}
			vp := accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://issuer.example/"+f.org.Slug, subject, f.cfg.VCT, s.Nonce, s.ClientID, nil, true)
			compact := encryptWalletResponse(t, key, jwa.A256GCM, map[string]any{"state": s.RequestID, "vp_token": map[string][]string{"identity": {vp}}})
			rec := postEncryptedResponse(t, f, compact, nil)
			got, err := f.ciba.Get(ctx, auth)
			require.NoError(t, err)
			if foreignSubject {
				require.Equal(t, 400, rec.Code, rec.Body.String())
				require.NotEqual(t, "approved", got.Status)
			} else {
				require.Equal(t, 200, rec.Code, rec.Body.String())
				require.Equal(t, "approved", got.Status)
				require.Equal(t, f.user.ID, *got.UserID)
			}
		})
	}
}

func TestEncryptedVPErrorAndUnsupportedContentEncryption(t *testing.T) {
	f := encryptionFixture(t)
	s := encryptedSession(t, f, bindingQuery(f.cfg.VCT, false), nil)
	key := readerPublicKey(t, f, s)
	compact := encryptWalletResponse(t, key, jwa.A128CBC_HS256, encryptedSDJWTPayload(t, f, s))
	rec := postEncryptedResponse(t, f, compact, nil)
	require.Equal(t, 400, rec.Code)
	compact = encryptWalletResponse(t, key, jwa.A128GCM, map[string]any{"state": s.RequestID, "error": "access_denied"})
	rec = postEncryptedResponse(t, f, compact, nil)
	require.Equal(t, 200, rec.Code)
	got, err := f.h.repo.GetPresentationSession(context.Background(), s.RequestID)
	require.NoError(t, err)
	require.Equal(t, "failed", got.Status)
	require.Empty(t, got.ResponseKeyCiphertext)
}

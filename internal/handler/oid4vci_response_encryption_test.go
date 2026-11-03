package handler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

func responseEncryptionKey(t *testing.T, alg string) (*ecdsa.PrivateKey, json.RawMessage) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := jwk.FromRaw(&key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.AlgorithmKey, alg))
	require.NoError(t, pub.Set(jwk.KeyUsageKey, "enc"))
	require.NoError(t, pub.Set(jwk.KeyIDKey, "wallet-response-key"))
	raw, err := json.Marshal(pub)
	require.NoError(t, err)
	return key, raw
}
func TestCredentialResponseEncryptionAdvertisedAndDecryptable(t *testing.T) {
	for _, conformance := range []bool{false, true} {
		metadata := oid4w.BuildIssuerMetadata("https://issuer.example", "tenant", nil, conformance)
		require.NotNil(t, metadata.CredentialResponseEncryption)
		require.False(t, metadata.CredentialResponseEncryption.EncryptionRequired)
		require.NotNil(t, metadata.CredentialRequestEncryption)
		for _, alg := range metadata.CredentialResponseEncryption.AlgValuesSupported {
			for _, enc := range metadata.CredentialResponseEncryption.EncValuesSupported {
				t.Run(alg+"/"+enc, func(t *testing.T) {
					key, pub := responseEncryptionKey(t, alg)
					for _, credential := range []string{"base64url-mdoc", "pid-sd-jwt~disclosure~", "competence-badge~disclosure~"} {
						plain, err := json.Marshal(map[string]any{"credentials": []map[string]string{{"credential": credential}}})
						require.NoError(t, err)
						encrypted, err := encryptCredentialResponse(plain, &credentialResponseEncryptionReq{JWK: pub, Enc: enc})
						require.NoError(t, err)
						decoded, err := jwe.Decrypt([]byte(encrypted), jwe.WithKey(jwa.KeyEncryptionAlgorithm(alg), key))
						require.NoError(t, err)
						require.JSONEq(t, string(plain), string(decoded))
						other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
						_, err = jwe.Decrypt([]byte(encrypted), jwe.WithKey(jwa.KeyEncryptionAlgorithm(alg), other))
						require.Error(t, err)
					}
				})
			}
		}
	}
}
func TestCredentialResponseEncryptionRejectsInvalidParameters(t *testing.T) {
	key, pub := responseEncryptionKey(t, "ECDH-ES")
	private, err := jwk.FromRaw(key)
	require.NoError(t, err)
	privateJSON, err := json.Marshal(private)
	require.NoError(t, err)
	for _, req := range []*credentialResponseEncryptionReq{
		{JWK: pub, Enc: "none"}, {JWK: pub, Enc: "A256GCM", Alg: "RSA1_5"}, {JWK: privateJSON, Enc: "A256GCM", Alg: "ECDH-ES"}, {JWK: pub, Enc: "A256GCM", Alg: "ECDH-ES+A128KW"}, {JWK: pub, Enc: "A256GCM", Zip: "GZIP"},
	} {
		_, err := encryptCredentialResponse([]byte(`{"credentials":[]}`), req)
		require.Error(t, err)
	}
}
func TestOrdinaryIssuerMetadataAndEncryptedCredentialHTTP(t *testing.T) {
	f := vciFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	require.NoError(t, f.h.IssuerMetadata(c))
	require.Equal(t, 200, rec.Code)
	var metadata oid4w.CredentialIssuerMetadata
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &metadata))
	require.NotNil(t, metadata.CredentialResponseEncryption)
	require.NotEmpty(t, metadata.CredentialRequestEncryption.JWKS.Keys)
	// Mirror the reference wallet's SupportedRequestEncryptionParameters
	// validation: alg/kid alone are insufficient without explicit use=enc.
	for _, rawKey := range metadata.CredentialRequestEncryption.JWKS.Keys {
		encoded, err := json.Marshal(rawKey)
		require.NoError(t, err)
		key, err := jwk.ParseKey(encoded)
		require.NoError(t, err)
		require.Equal(t, "enc", key.KeyUsage())
		require.NotEmpty(t, key.KeyID())
		require.Equal(t, string(jwa.RSA_OAEP_256), key.Algorithm().String())
		var fields map[string]any
		require.NoError(t, json.Unmarshal(encoded, &fields))
		require.NotContains(t, fields, "d")
	}

	for _, encryptedRequest := range []bool{false, true} {
		for _, zip := range []string{"", "DEF"} {
			_, token := f.offer(t)
			nonce, err := f.h.issueCredentialNonce(req.Context(), f.org.Slug)
			require.NoError(t, err)
			proof := vciTestProof(t, vciTestHolder(t), "https://issuer.example/"+f.org.Slug, nonce, nil)
			key, pub := responseEncryptionKey(t, "ECDH-ES")
			body := map[string]any{"proofs": map[string]any{"jwt": []string{proof}}, "credential_response_encryption": &credentialResponseEncryptionReq{JWK: pub, Enc: "A256GCM", Zip: zip}}
			if encryptedRequest {
				plain, err := json.Marshal(body)
				require.NoError(t, err)
				encrypted, err := jwe.Encrypt(plain, jwe.WithKey(jwa.RSA_OAEP_256, f.h.keys.PublicKey()), jwe.WithContentEncryption(jwa.A256GCM))
				require.NoError(t, err)
				request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encrypted))
				request.Header.Set("Content-Type", "application/jwt")
				request.Header.Set("Authorization", "Bearer "+token)
				rec = httptest.NewRecorder()
				c = echo.New().NewContext(request, rec)
				c.SetParamNames("org_slug")
				c.SetParamValues(f.org.Slug)
				require.NoError(t, f.h.Credential(c))
			} else {
				rec = f.request(t, f.h.Credential, token, body)
			}
			require.Equal(t, 200, rec.Code, rec.Body.String())
			require.Contains(t, rec.Header().Get("Content-Type"), "application/jwt")
			decoded, err := jwe.Decrypt(rec.Body.Bytes(), jwe.WithKey(jwa.ECDH_ES, key))
			require.NoError(t, err)
			var response struct {
				Credentials []struct {
					Credential string `json:"credential"`
				} `json:"credentials"`
			}
			require.NoError(t, json.Unmarshal(decoded, &response))
			require.Len(t, response.Credentials, 1)
			require.NotEmpty(t, response.Credentials[0].Credential)
		}

	}
}

func TestCredentialResponseDeflateIsExplicitAndAdvertised(t *testing.T) {
	meta := oid4w.BuildIssuerMetadata("https://issuer.example", "tenant", nil, false)
	require.Contains(t, meta.CredentialResponseEncryption.ZipValuesSupported, "DEF")
	plain := []byte(`{"credentials":[{"credential":"synthetic-credential-only"}]}`)
	for _, alg := range meta.CredentialResponseEncryption.AlgValuesSupported {
		for _, enc := range meta.CredentialResponseEncryption.EncValuesSupported {
			key, pub := responseEncryptionKey(t, alg)
			for _, zip := range []string{"", "DEF"} {
				encrypted, err := encryptCredentialResponse(plain, &credentialResponseEncryptionReq{JWK: pub, Enc: enc, Zip: zip})
				require.NoError(t, err)
				message, err := jwe.Parse([]byte(encrypted))
				require.NoError(t, err)
				require.Equal(t, zip, message.ProtectedHeaders().Compression().String())
				decoded, err := jwe.Decrypt([]byte(encrypted), jwe.WithKey(jwa.KeyEncryptionAlgorithm(alg), key))
				require.NoError(t, err)
				require.Equal(t, plain, decoded)
			}
		}
	}
}

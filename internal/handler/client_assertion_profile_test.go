package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"
)

func TestClientAssertionAuthenticationAtPARAndCIBA(t *testing.T) {
	f := vciFixture(t)
	h, id, _ := confidentialWallet(t, f)
	ctx := context.Background()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := jwk.FromRaw(priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "assertion-test"))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	keys, err := json.Marshal(set)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE oidc_clients SET token_endpoint_auth_method='private_key_jwt', jwks=$2 WHERE client_id=$1`, id, keys)
	require.NoError(t, err)
	issuer := "https://issuer.example/" + f.org.Slug
	for _, endpoint := range []string{"par", "bc-authorize"} {
		for _, tc := range []struct {
			name, profile, omit, formID string
			audience                    any
			valid                       bool
		}{
			{"standard", "standard", "", id, issuer + "/" + endpoint, true},
			{"missing iss", "standard", "iss", id, issuer, false},
			{"missing exp", "standard", "exp", id, issuer, false},
			{"mismatched form client", "standard", "", "another-client", issuer, false},
			{"final issuer", "fapi2_final", "", id, issuer, true},
			{"final endpoint", "fapi2_final", "", id, issuer + "/" + endpoint, false},
			{"final array", "fapi2_final", "", id, []string{issuer, "https://other.example"}, false},
		} {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				client, err := h.clients.Update(ctx, id, f.org.ID, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, &tc.profile)
				require.NoError(t, err)
				require.Equal(t, tc.profile, client.Metadata[models.ClientAssertionProfileMetadataKey])
				claims := map[string]any{"iss": id, "sub": id, "aud": tc.audience, "exp": time.Now().Add(time.Minute).Unix(), "jti": uuid.NewString()}
				delete(claims, tc.omit)
				payload, err := json.Marshal(claims)
				require.NoError(t, err)
				headers := jws.NewHeaders()
				require.NoError(t, headers.Set(jws.KeyIDKey, "assertion-test"))
				token, err := jws.Sign(payload, jws.WithKey(jwa.PS256, priv, jws.WithProtectedHeaders(headers)))
				require.NoError(t, err)
				form := url.Values{"client_id": {tc.formID}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {string(token)}}
				fn := h.PushedAuthorizationRequest
				if endpoint == "bc-authorize" {
					fn = h.BackchannelAuthorize
				}
				rec := walletHTTP(t, f, fn, endpoint, form, nil, "", "", nil)
				// Other required protocol parameters are deliberately absent. Authentication
				// must succeed before their validation, or fail specifically as invalid_client.
				var result map[string]any
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
				if tc.valid {
					require.NotEqual(t, "invalid_client", result["error"], rec.Body.String())
				} else {
					require.Equal(t, "invalid_client", result["error"], rec.Body.String())
				}
			})
		}
	}
	// A profile change must preserve unrelated metadata and remain tenant-scoped.
	_, err = f.pool.Exec(ctx, `UPDATE oidc_clients SET metadata=metadata || '{"other":"preserve"}'::jsonb WHERE client_id=$1`, id)
	require.NoError(t, err)
	profile := models.ClientAssertionProfileStandard
	repo := repository.NewClientRepository(f.pool)
	_, err = repo.Update(ctx, id, uuid.New(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, &profile)
	require.Error(t, err)
	client, err := repo.Update(ctx, id, f.org.ID, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, &profile)
	require.NoError(t, err)
	require.Equal(t, "preserve", client.Metadata["other"])
}

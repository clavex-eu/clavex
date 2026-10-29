package oid4w

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func finalQuery(vct string, binding *bool) map[string]interface{} {
	q := map[string]interface{}{
		"id": "identity", "format": "dc+sd-jwt",
		"meta":   map[string]interface{}{"vct_values": []string{vct}},
		"claims": []interface{}{map[string]interface{}{"path": []string{"email"}}},
	}
	if binding != nil {
		q["require_cryptographic_holder_binding"] = *binding
	}
	return map[string]interface{}{"credentials": []interface{}{q}}
}

func finalHolder(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func finalPresentation(t *testing.T, p SDJWTParams, holder crypto.Signer, alg jwa.SignatureAlgorithm, typ, hash string) string {
	t.Helper()
	holderJWK, err := jwk.FromRaw(holder.Public())
	require.NoError(t, err)
	p.HolderKey = holderJWK
	credential, _, err := IssueSDJWT(p)
	require.NoError(t, err)
	if hash == "correct" {
		h := sha256.Sum256([]byte(credential))
		hash = base64.RawURLEncoding.EncodeToString(h[:])
	}
	b := jwt.NewBuilder().IssuedAt(time.Now()).Audience([]string{"verifier"}).Claim("nonce", "session-nonce")
	if hash != "" {
		b = b.Claim("sd_hash", hash)
	}
	token, err := b.Build()
	require.NoError(t, err)
	headers := jws.NewHeaders()
	if typ != "" {
		require.NoError(t, headers.Set(jws.TypeKey, typ))
	}
	kb, err := jwt.Sign(token, jwt.WithKey(alg, holder, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return credential + string(kb)
}

func TestFinalDCQLRequiresHolderBindingByDefault(t *testing.T) {
	p := baseParams(t)
	holder := finalHolder(t)
	bound := finalPresentation(t, p, holder, jwa.ES256, "kb+jwt", "correct")
	trusted := map[string]crypto.PublicKey{p.Issuer: p.Signer.Public()}
	query := finalQuery(p.VCT, nil)
	result, err := VerifyDCQLPresentation(context.Background(), bound, query, "session-nonce", "verifier", trusted, true, nil)
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", result.Claims["email"])
	issuer, disclosures, _, err := ParseSDJWT(bound)
	require.NoError(t, err)
	withoutProof := issuer + "~" + strings.Join(disclosures, "~") + "~"
	_, err = VerifyDCQLPresentation(context.Background(), withoutProof, query, "session-nonce", "verifier", trusted, true, nil)
	require.ErrorContains(t, err, "holder binding")
	_, err = VerifyPresentation(withoutProof, PresentationDefinition{}, "different", "another-verifier", nil, p.Signer.Public().(*rsa.PublicKey))
	require.ErrorContains(t, err, "requires a key binding proof")
	_, err = VerifyDCQLPresentation(context.Background(), bound, query, "different-nonce", "verifier", trusted, true, nil)
	require.ErrorContains(t, err, "nonce mismatch")
	_, err = VerifyDCQLPresentation(context.Background(), bound, query, "session-nonce", "another-verifier", trusted, true, nil)
	require.ErrorContains(t, err, "aud mismatch")
}

func TestFinalDCQLExplicitBearerOptOut(t *testing.T) {
	p := baseParams(t)
	credential, _, err := IssueSDJWT(p)
	require.NoError(t, err)
	trusted := map[string]crypto.PublicKey{p.Issuer: p.Signer.Public()}
	_, err = VerifyDCQLPresentation(context.Background(), credential, finalQuery(p.VCT, nil), "nonce", "aud", trusted, true, nil)
	require.ErrorContains(t, err, "holder binding")
	binding := false
	_, err = VerifyDCQLPresentation(context.Background(), credential, finalQuery(p.VCT, &binding), "nonce", "aud", trusted, true, nil)
	require.NoError(t, err)
}

func TestFinalDCQLRejectsExpiredWrongTypeAndMissingClaims(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(*SDJWTParams)
	}{
		{"expired", "credential validity", func(p *SDJWTParams) { p.TTL = -time.Hour }},
		{"wrong type", "credential type", func(p *SDJWTParams) { p.VCT = "https://example.org/unrelated" }},
		{"missing claim", "required claim", func(p *SDJWTParams) { delete(p.DisclosableClaims, "email") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := baseParams(t)
			query := finalQuery(p.VCT, nil)
			tc.mutate(&p)
			vp := finalPresentation(t, p, finalHolder(t), jwa.ES256, "kb+jwt", "correct")
			_, err := VerifyDCQLPresentation(context.Background(), vp, query, "session-nonce", "verifier", map[string]crypto.PublicKey{p.Issuer: p.Signer.Public()}, true, nil)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestFinalKBJWTRequiresTypeAndHashAndSupportsPS256(t *testing.T) {
	p := baseParams(t)
	for _, tc := range []struct{ name, typ, hash, want string }{
		{"missing hash", "kb+jwt", "", "sd_hash is required"},
		{"wrong hash", "kb+jwt", "unrelated", "sd_hash mismatch"},
		{"missing type", "", "correct", "typ must be kb+jwt"},
		{"wrong type", "JWT", "correct", "typ must be kb+jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vp := finalPresentation(t, p, finalHolder(t), jwa.ES256, tc.typ, tc.hash)
			_, err := VerifyDCQLPresentation(context.Background(), vp, finalQuery(p.VCT, nil), "session-nonce", "verifier", map[string]crypto.PublicKey{p.Issuer: p.Signer.Public()}, true, nil)
			require.ErrorContains(t, err, tc.want)
		})
	}
	vp := finalPresentation(t, p, newTestKey(t), jwa.PS256, "kb+jwt", "correct")
	_, err := VerifyDCQLPresentation(context.Background(), vp, finalQuery(p.VCT, nil), "session-nonce", "verifier", map[string]crypto.PublicKey{p.Issuer: p.Signer.Public()}, true, nil)
	require.NoError(t, err)
}

func TestFinalDCQLResponseEnvelope(t *testing.T) {
	query := finalQuery("https://example.org/identity", nil)
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"identity":["presentation"]}`, true},
		{`{"unrelated":["presentation"]}`, false},
		{`{"identity":["one","two"]}`, false},
		{`{"identity":["one"],"extra":["two"]}`, false},
		{`{"identity":[]}`, false},
		{`presentation`, false},
	} {
		t.Run(tc.body, func(t *testing.T) {
			_, err := ExtractDCQLSDJWT(tc.body, query)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	data, _ := json.Marshal(query)
	var multiple map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &multiple))
	items := multiple["credentials"].([]interface{})
	items = append(items, map[string]interface{}{"id": "second", "format": "dc+sd-jwt"})
	multiple["credentials"] = items
	_, err := ExtractDCQLSDJWT(`{"identity":["one"]}`, multiple)
	require.ErrorContains(t, err, "one credential")
}

func TestFinalDCQLClaimSetsAndPaths(t *testing.T) {
	query := finalQuery("https://example.org/identity", nil)
	c := query["credentials"].([]interface{})[0].(map[string]interface{})
	c["claims"] = []interface{}{
		map[string]interface{}{"id": "email", "path": []interface{}{"email"}},
		map[string]interface{}{"id": "age", "path": []interface{}{"attributes", nil, "age_over_18"}},
	}
	c["claim_sets"] = [][]string{{"email"}, {"age"}}
	parsed, err := parseSDJWTDCQL(query)
	require.NoError(t, err)
	claims := map[string]any{"vct": "https://example.org/identity", "attributes": []any{map[string]any{"age_over_18": true}}}
	require.NoError(t, parsed.match(claims))
	delete(claims, "attributes")
	require.Error(t, parsed.match(claims))
}

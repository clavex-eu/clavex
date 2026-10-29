package oid4w

import (
	"bytes"
	"compress/zlib"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"
)

func packedList(t *testing.T, data []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func statusJWT(t *testing.T, key *rsa.PrivateKey, uri string, width int, data []byte, mutate func(map[string]any, jws.Headers)) string {
	t.Helper()
	claims := map[string]any{"iss": "https://issuer.example", "sub": uri, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "ttl": 60, "status_list": map[string]any{"bits": width, "lst": packedList(t, data)}}
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "statuslist+jwt"))
	if mutate != nil {
		mutate(claims, headers)
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	raw, err := jws.Sign(payload, jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return string(raw)
}

func TestStatusPackedWidthsAndUnknownValues(t *testing.T) {
	key := newTestKey(t)
	uri := "https://issuer.example/list/1"
	for _, tc := range []struct {
		width int
		data  []byte
		want  []error
	}{{1, []byte{0x09}, []error{ErrRevoked, nil, nil, ErrRevoked}}, {2, []byte{0x39}, []error{ErrRevoked, ErrSuspended, ErrUnknownStatus, nil}}, {4, []byte{0x21}, []error{ErrRevoked, ErrSuspended}}, {8, []byte{0, 1, 2, 255}, []error{nil, ErrRevoked, ErrSuspended, ErrUnknownStatus}}} {
		raw := statusJWT(t, key, uri, tc.width, tc.data, nil)
		list, err := ValidateStatusListToken(raw, BuildStatusClaim(uri, 0), "https://issuer.example", &key.PublicKey, time.Now(), 5*time.Minute)
		require.NoError(t, err)
		for i, want := range tc.want {
			require.True(t, errors.Is(list.Check(i), want), "width %d, index %d", tc.width, i)
		}
		require.Error(t, list.Check(len(tc.data)*(8/tc.width)))
		require.Error(t, list.Check(-1))
	}
	var zero ValidatedStatusList
	require.Error(t, zero.Check(0))
}

func TestStatusRejectsWrongIdentityHeadersTimesAndMalformedLists(t *testing.T) {
	key := newTestKey(t)
	uri := "https://issuer.example/list/1"
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any, jws.Headers)
	}{
		{"URI substitution", func(c map[string]any, _ jws.Headers) { c["sub"] = "https://issuer.example/list/other" }},
		{"issuer substitution", func(c map[string]any, _ jws.Headers) { c["iss"] = "https://other.example" }},
		{"cty instead of typ", func(_ map[string]any, h jws.Headers) {
			require.NoError(t, h.Remove(jws.TypeKey))
			require.NoError(t, h.Set(jws.ContentTypeKey, "statuslist+jwt"))
		}},
		{"missing iat", func(c map[string]any, _ jws.Headers) { delete(c, "iat") }},
		{"expired", func(c map[string]any, _ jws.Headers) { c["exp"] = time.Now().Add(-time.Second).Unix() }},
		{"future", func(c map[string]any, _ jws.Headers) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"stale", func(c map[string]any, _ jws.Headers) { c["iat"] = time.Now().Add(-time.Minute * 6).Unix() }},
		{"zero ttl", func(c map[string]any, _ jws.Headers) { c["ttl"] = 0 }},
		{"invalid width", func(c map[string]any, _ jws.Headers) { c["status_list"].(map[string]any)["bits"] = 3 }},
		{"null width", func(c map[string]any, _ jws.Headers) { c["status_list"].(map[string]any)["bits"] = nil }},
		{"invalid compressed stream", func(c map[string]any, _ jws.Headers) { c["status_list"].(map[string]any)["lst"] = "broken" }},
		{"decompression limit", func(c map[string]any, _ jws.Headers) {
			c["status_list"].(map[string]any)["lst"] = packedList(t, make([]byte, 1024*1024+1))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := statusJWT(t, key, uri, 1, []byte{0}, tc.mutate)
			_, err := ValidateStatusListToken(raw, BuildStatusClaim(uri, 0), "https://issuer.example", &key.PublicKey, time.Now(), 5*time.Minute)
			require.Error(t, err)
		})
	}
	raw := statusJWT(t, key, uri, 1, []byte{0}, nil)
	other := newTestKey(t)
	_, err := ValidateStatusListToken(raw, BuildStatusClaim(uri, 0), "https://issuer.example", &other.PublicKey, time.Now(), 5*time.Minute)
	require.Error(t, err)
	var absent *rsa.PublicKey
	_, err = ValidateStatusListToken(raw, BuildStatusClaim(uri, 0), "", absent, time.Now(), 5*time.Minute)
	require.Error(t, err)
}

func TestStatusReferencesAndLocalDecodersRejectInvalidInput(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `{"status_list":{"uri":"https://issuer.example/list"}}`, `{"status_list":{"idx":null,"uri":"https://issuer.example/list"}}`, `{"status_list":{"idx":-1,"uri":"https://issuer.example/list"}}`, `{"status_list":{"idx":1.5,"uri":"https://issuer.example/list"}}`, `{"status_list":{"idx":0,"uri":"http://127.0.0.1/private"}}`, `{"status_list":{"idx":0,"uri":"https://user:pass@issuer.example/list"}}`, `{"other":{}}`, `{"status_list":{"idx":0,"uri":"https://issuer.example/list"},"other":{}}`} {
		_, err := ParseStatusClaim([]byte(raw))
		require.Error(t, err, raw)
	}
	for _, data := range [][]byte{{}, make([]byte, 1), make([]byte, StatusListSize/8+1)} {
		_, err := DecodeStatusList(packedList(t, data))
		require.Error(t, err)
	}
	var zero StatusList
	_, err := zero.Get(0)
	require.Error(t, err)
}

func TestStatusListOptionalIssuerAndExpirationRemainBoundedByTrustAndAge(t *testing.T) {
	key := newTestKey(t)
	uri := "https://issuer.example/list/optional"
	raw := statusJWT(t, key, uri, 1, []byte{0}, func(c map[string]any, _ jws.Headers) { delete(c, "iss"); delete(c, "exp"); delete(c, "ttl") })
	now := time.Now()
	list, err := ValidateStatusListToken(raw, BuildStatusClaim(uri, 0), "https://issuer.example", &key.PublicKey, now, 5*time.Minute)
	require.NoError(t, err)
	require.LessOrEqual(t, list.FreshUntil.Sub(now), 5*time.Minute)
	_, err = ValidateStatusListToken(raw, BuildStatusClaim(uri, 0), "https://issuer.example", &key.PublicKey, now, 5*time.Minute, StatusValidationPolicy{RequireExpiration: true})
	require.Error(t, err)
	_, err = ValidateStatusListToken(raw, BuildStatusClaim(uri, 0), "https://issuer.example", &key.PublicKey, now, 5*time.Minute, StatusValidationPolicy{RequireIssuerClaim: true})
	require.Error(t, err)
	_, err = ValidateStatusListToken(raw, BuildStatusClaim(uri, 0), "https://issuer.example", &key.PublicKey, now.Add(6*time.Minute), 5*time.Minute)
	require.Error(t, err)
}

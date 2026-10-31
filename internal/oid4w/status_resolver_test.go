package oid4w

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"
)

type statusRoundTrip func(*http.Request) (*http.Response, error)

func (f statusRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func remoteSource(t *testing.T, key *rsa.PrivateKey) StatusSource {
	t.Helper()
	public, err := jwk.FromRaw(&key.PublicKey)
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]any{"keys": []any{public}})
	require.NoError(t, err)
	return StatusSource{Format: "dc+sd-jwt", CredentialIssuer: "https://issuer.example", CredentialType: "identity", StatusIssuer: "https://issuer.example", ListURIs: []string{"https://status.example/list/1"}, JWKS: raw}
}

func remoteResponse(raw string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/statuslist+jwt"}}, Body: io.NopCloser(strings.NewReader(raw)), ContentLength: int64(len(raw))}
}

func TestRemoteStatusCacheTenantPolicyAndExpiry(t *testing.T) {
	key := newTestKey(t)
	source := remoteSource(t, key)
	ref := BuildStatusClaim(source.ListURIs[0], 0)
	var calls int
	var revoked, unavailable bool
	now := time.Now()
	resolver := NewStatusResolverWithHTTPClient(&http.Client{Transport: statusRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, http.MethodGet, r.Method)
		require.Empty(t, r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("Cookie"))
		require.Equal(t, "identity", r.Header.Get("Accept-Encoding"))
		if unavailable {
			return nil, errors.New("synthetic outage")
		}
		state := byte(0)
		if revoked {
			state = 1
		}
		response := remoteResponse(statusJWT(t, key, ref.StatusList.URI, 1, []byte{state}, nil))
		response.Header.Set("Cache-Control", "max-age=10")
		return response, nil
	})})
	resolver.now = func() time.Time { return now }
	require.NoError(t, resolver.Check(context.Background(), "org-a", source, ref))
	require.NoError(t, resolver.Check(context.Background(), "org-a", source, ref))
	require.Equal(t, 1, calls)
	require.NoError(t, resolver.Check(context.Background(), "org-b", source, ref))
	require.Equal(t, 2, calls)
	changed := source
	other := remoteSource(t, newTestKey(t))
	changed.JWKS = other.JWKS
	require.ErrorIs(t, resolver.Check(context.Background(), "org-a", changed, ref), ErrStatusInvalid)
	require.Equal(t, 3, calls, "changed trust cannot reuse an old positive cache")
	now = now.Add(11 * time.Second)
	revoked = true
	require.ErrorIs(t, resolver.Check(context.Background(), "org-a", source, ref), ErrRevoked)
	now = now.Add(11 * time.Second)
	unavailable = true
	require.ErrorIs(t, resolver.Check(context.Background(), "org-a", source, ref), ErrStatusUnavailable, "no stale result may be served during outage")
}

func TestRemoteDailyListRevalidationAfterTTL(t *testing.T) {
	key := newTestKey(t)
	source := remoteSource(t, key)
	source.Format = "mso_mdoc"
	source.MaxAgeSeconds = 86400
	now := time.Now().Truncate(time.Second)
	raw := statusJWT(t, key, source.ListURIs[0], 1, []byte{0}, func(c map[string]any, _ jws.Headers) {
		c["iat"], c["exp"], c["ttl"] = now.Add(-8*time.Hour).Unix(), now.Add(time.Hour).Unix(), 5
	})
	calls := 0
	resolver := NewStatusResolverWithHTTPClient(&http.Client{Transport: statusRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return remoteResponse(raw), nil
	})})
	resolver.now = func() time.Time { return now }
	ref := BuildStatusClaim(source.ListURIs[0], 0)
	require.NoError(t, resolver.Check(context.Background(), "org", source, ref))
	require.NoError(t, resolver.Check(context.Background(), "org", source, ref))
	require.Equal(t, 1, calls)
	now = now.Add(6 * time.Second)
	require.NoError(t, resolver.Check(context.Background(), "org", source, ref))
	require.Equal(t, 2, calls, "an unchanged, still valid signed list can be freshly retrieved after TTL")
	// Selecting a longer age is explicit; other sources keep the five-minute default.
	source.MaxAgeSeconds = 0
	require.ErrorIs(t, resolver.Check(context.Background(), "org", source, ref), ErrStatusInvalid)
	source.MaxAgeSeconds = 86401
	require.Error(t, source.Validate())
}

func TestRemoteStatusSingleFlightAndHTTPConstraints(t *testing.T) {
	key := newTestKey(t)
	source := remoteSource(t, key)
	ref := BuildStatusClaim(source.ListURIs[0], 0)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	resolver := NewStatusResolverWithHTTPClient(&http.Client{Transport: statusRoundTrip(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return remoteResponse(statusJWT(t, key, ref.StatusList.URI, 1, []byte{0}, nil)), nil
	})})
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- resolver.Check(context.Background(), "same-org", source, ref) }()
	}
	<-entered
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, calls.Load())
	for _, tc := range []struct {
		name  string
		alter func(*http.Response)
	}{
		{"redirect", func(r *http.Response) { r.StatusCode = 302; r.Header.Set("Location", "https://127.0.0.1/private") }},
		{"encoding", func(r *http.Response) { r.Header.Set("Content-Encoding", "gzip") }},
		{"media type", func(r *http.Response) { r.Header.Set("Content-Type", "application/json") }},
		{"body size", func(r *http.Response) { r.ContentLength = 512*1024 + 1 }},
		{"stale HTTP", func(r *http.Response) { r.Header.Set("Cache-Control", "max-age=10"); r.Header.Set("Age", "11") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			r := NewStatusResolverWithHTTPClient(&http.Client{Transport: statusRoundTrip(func(*http.Request) (*http.Response, error) {
				requests++
				response := remoteResponse(statusJWT(t, key, ref.StatusList.URI, 1, []byte{0}, nil))
				tc.alter(response)
				return response, nil
			})})
			require.Error(t, r.Check(context.Background(), "org", source, ref))
			require.Equal(t, 1, requests)
		})
	}
}

func TestRemoteStatusTransportBlocksPrivateAndSpecialTargets(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "0.1.2.3", "240.1.2.3", "::1", "::ffff:127.0.0.1", "fd00::1", "fe80::1", "64:ff9b::a00:1", "2002:7f00:1::", "2001:db8::1"} {
		require.False(t, publicStatusIP(ip), ip)
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		require.True(t, publicStatusIP(ip), ip)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := statusHTTPClient()
	_, err := client.Get(server.URL)
	require.Error(t, err)
	require.Zero(t, calls.Load())
	// localhost resolves to loopback; protection must also run after DNS.
	_, err = client.Get(strings.Replace(server.URL, "127.0.0.1", "localhost", 1))
	require.Error(t, err)
	require.Zero(t, calls.Load())
}

func TestRemoteStatusNoStoreAndUnknownIndexDoNotPoisonOtherSlots(t *testing.T) {
	key := newTestKey(t)
	source := remoteSource(t, key)
	ref := BuildStatusClaim(source.ListURIs[0], 100)
	var calls int
	resolver := NewStatusResolverWithHTTPClient(&http.Client{Transport: statusRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return remoteResponse(statusJWT(t, key, ref.StatusList.URI, 1, []byte{0}, nil)), nil
	})})
	require.ErrorIs(t, resolver.Check(context.Background(), "org", source, ref), ErrUnknownStatus)
	ref.StatusList.IDX = 0
	require.NoError(t, resolver.Check(context.Background(), "org", source, ref))
	require.Equal(t, 1, calls)
	noStore := NewStatusResolverWithHTTPClient(&http.Client{Transport: statusRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		r := remoteResponse(statusJWT(t, key, ref.StatusList.URI, 1, []byte{0}, nil))
		r.Header.Set("Cache-Control", "no-store")
		return r, nil
	})})
	require.NoError(t, noStore.Check(context.Background(), "org", source, ref))
	require.NoError(t, noStore.Check(context.Background(), "org", source, ref))
	require.Equal(t, 3, calls)
	bad := source
	bad.ListURIs = []string{"http://127.0.0.1/private"}
	require.Error(t, bad.Validate())
	_, err := StatusSources(map[string]interface{}{"wallet_status_sources": []StatusSource{source, source}})
	require.Error(t, err)
	private, err := jwk.FromRaw(key)
	require.NoError(t, err)
	bad.JWKS, _ = json.Marshal(map[string]any{"keys": []any{private}})
	bad.ListURIs = source.ListURIs
	require.Error(t, bad.Validate())
}

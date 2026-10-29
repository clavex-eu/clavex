package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

type walletStatusTransport func(*http.Request) (*http.Response, error)

func (f walletStatusTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestWalletStatusRemoteDelegationAndTenantDecision(t *testing.T) {
	f := newCibaWalletFixture(t)
	ctx := context.Background()
	// The credential issuer has already been authenticated cryptographically;
	// status signing delegation does not itself grant issuer trust.
	key := f.vciIssuanceFixture.h.keys
	public, err := jwk.FromRaw(key.PublicKey())
	require.NoError(t, err)
	jwks, err := json.Marshal(map[string]interface{}{"keys": []any{public}})
	require.NoError(t, err)
	source := oid4w.StatusSource{Format: "dc+sd-jwt", CredentialIssuer: "https://external.example", CredentialType: "external-id", StatusIssuer: "https://status.example", ListURIs: []string{"https://status.example/list"}, JWKS: jwks}
	settings, err := json.Marshal(map[string]any{"wallet_status_sources": []oid4w.StatusSource{source}})
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.organizations SET settings=$2 WHERE id=$1`, f.org.ID, settings)
	require.NoError(t, err)
	list := oid4w.NewStatusListWithBits(2)
	token, err := oid4w.IssueStatusListJWT(oid4w.StatusListJWTParams{Issuer: source.StatusIssuer, ListID: uuid.New(), ListURI: source.ListURIs[0], StatusList: list, TTL: time.Minute, Signer: key.CryptoSigner(), Algorithm: jwa.RS256})
	require.NoError(t, err)
	calls := 0
	resolver := oid4w.NewStatusResolverWithHTTPClient(&http.Client{Transport: walletStatusTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, source.ListURIs[0], req.URL.String())
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/statuslist+jwt"}}, Body: io.NopCloser(strings.NewReader(token))}, nil
	})})
	ctx = oid4w.WithStatusResolver(ctx, resolver)
	ref, err := json.Marshal(oid4w.BuildStatusClaim(source.ListURIs[0], 0))
	require.NoError(t, err)
	result := &oid4w.VerificationResult{Claims: map[string]interface{}{}, Identity: &oid4w.VerifiedCredentialIdentity{Format: source.Format, Issuer: source.CredentialIssuer, CredentialType: source.CredentialType, IssuerTrusted: true, HolderBound: true, Status: ref, ExpiresAt: time.Now().Add(time.Hour)}}
	check := func() error {
		repo, tx, err := f.vciIssuanceFixture.h.repo.BeginIssuance(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		return checkWalletStatus(ctx, repo, f.org.ID, "https://issuer.example/"+f.org.Slug, nil, result, true)
	}
	require.NoError(t, check())
	require.Equal(t, "valid_remote", result.StatusAssessment)
	require.Equal(t, 1, calls)
	result.Identity.IssuerTrusted = false
	require.ErrorIs(t, check(), errWalletStatusRejected)
	result.Identity.IssuerTrusted = true
	result.Identity.CredentialType = "other"
	require.ErrorIs(t, check(), errWalletStatusUnavailable)
	result.Identity.CredentialType = source.CredentialType
	// Stale caller settings cannot retain a delegation removed transactionally.
	_, err = f.pool.Exec(ctx, `UPDATE identity.organizations SET settings='{}' WHERE id=$1`, f.org.ID)
	require.NoError(t, err)
	require.ErrorIs(t, check(), errWalletStatusUnavailable)
	require.Equal(t, 1, calls)
}

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
	"github.com/clavex-eu/clavex/internal/worker"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"
)

func TestWalletStatusAttestationParentPersistenceAndCascade(t *testing.T) {
	f := newCibaWalletFixture(t)
	ctx := context.Background()
	attester, holder := vciTestHolder(t), vciTestHolder(t)
	settings := trustedAttesterSettings(t, attester)
	key := f.vciIssuanceFixture.h.keys
	public, err := jwk.FromRaw(key.PublicKey())
	require.NoError(t, err)
	jwks, err := json.Marshal(map[string]any{"keys": []any{public}})
	require.NoError(t, err)
	zero := 0
	source := oid4w.StatusSource{Format: "key-attestation+jwt", CredentialIssuer: "https://attester.example", CredentialType: "key-attestation+jwt", StatusIssuer: "https://status.example", ListURIs: []string{"https://status.example/attestations"}, JWKS: jwks, CacheSeconds: &zero}
	settings["wallet_status_sources"] = []oid4w.StatusSource{source}
	settings["key_attestation_status_required"] = true
	encoded, err := json.Marshal(settings)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.organizations SET settings=$2 WHERE id=$1`, f.org.ID, encoded)
	require.NoError(t, err)
	f.org.Settings = settings
	var state byte
	outage := false
	resolver := oid4w.NewStatusResolverWithHTTPClient(&http.Client{Transport: walletStatusTransport(func(*http.Request) (*http.Response, error) {
		if outage {
			return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		list := oid4w.NewStatusListWithBits(2)
		require.NoError(t, list.Set(0, state))
		token, err := oid4w.IssueStatusListJWT(oid4w.StatusListJWTParams{Issuer: source.StatusIssuer, ListURI: source.ListURIs[0], ListID: uuid.New(), StatusList: list, TTL: time.Minute, Signer: key.CryptoSigner(), Algorithm: jwa.RS256})
		require.NoError(t, err)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/statuslist+jwt"}}, Body: io.NopCloser(strings.NewReader(token))}, nil
	})})
	ctx = oid4w.WithStatusResolver(ctx, resolver)
	nonce, err := f.vciIssuanceFixture.h.issueCredentialNonce(ctx, f.org.Slug)
	require.NoError(t, err)
	raw := attestedProof(t, holder, attester, "https://issuer.example/"+f.org.Slug, nonce, func(c map[string]any, _ jws.Headers) { c["status"] = oid4w.BuildStatusClaim(source.ListURIs[0], 0) })
	req := &credentialRequest{Proofs: &credentialProofs{JWT: []string{raw}}}
	proofs, err := validateCredentialProofs(req, "https://issuer.example/"+f.org.Slug, "dc+sd-jwt", time.Now())
	require.NoError(t, err)
	require.NoError(t, validateCredentialAttestations(f.org, f.cfg, req, proofs, time.Now(), ctx))
	require.Len(t, proofs[0].StatusParents, 1)
	h, tx, err := f.vciIssuanceFixture.h.beginCredentialIssuance(ctx, nil, "")
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	credential, err := h.signCredential(ctx, f.org, f.cfg, f.user, map[string]interface{}{"given_name": "Alice"}, proofs[0].Key)
	require.NoError(t, err)
	require.NoError(t, h.recordWalletCredential(ctx, f.org.ID, &f.user.ID, f.cfg.VCT, credential, "dc+sd-jwt", proofs[0].StatusParents))
	require.NoError(t, tx.Commit(ctx))
	record, err := f.vciIssuanceFixture.h.repo.GetIssuedCredentialByHash(ctx, f.org.ID, oid4w.HashToken(credential))
	require.NoError(t, err)
	var persisted string
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT status_parents::text FROM identity.issued_credentials WHERE id=$1`, record.ID).Scan(&persisted))
	require.NotContains(t, persisted, raw)
	require.Contains(t, persisted, source.ListURIs[0])
	poll := func() {
		_, err := f.pool.Exec(ctx, `UPDATE identity.issued_credentials SET parents_checked_at=NULL WHERE id=$1`, record.ID)
		require.NoError(t, err)
		require.NoError(t, worker.PollWalletStatusParents(ctx, f.pool))
	}
	check := func() error {
		scoped, tx, err := f.vciIssuanceFixture.h.beginCredentialIssuance(ctx, nil, "")
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		return scoped.checkDeferredCredentialStatus(ctx, f.org, f.cfg, credential)
	}
	require.NoError(t, check())
	state = 2
	require.ErrorIs(t, check(), errWalletStatusRejected)
	poll()
	current, err := f.vciIssuanceFixture.h.repo.GetIssuedCredentialByID(ctx, record.ID)
	require.NoError(t, err)
	require.True(t, current.IsSuspended)
	state = 0
	poll()
	current, err = f.vciIssuanceFixture.h.repo.GetIssuedCredentialByID(ctx, record.ID)
	require.NoError(t, err)
	require.False(t, current.IsSuspended)
	require.NoError(t, f.vciIssuanceFixture.h.repo.SuspendIssuedCredential(ctx, record.ID, "manual hold"))
	poll()
	current, err = f.vciIssuanceFixture.h.repo.GetIssuedCredentialByID(ctx, record.ID)
	require.NoError(t, err)
	require.True(t, current.IsSuspended, "valid parent must not clear an independent manual suspension")
	require.NoError(t, f.vciIssuanceFixture.h.repo.RestoreIssuedCredential(ctx, record.ID))
	outage = true
	require.ErrorIs(t, check(), errWalletStatusUnavailable)
	poll()
	current, err = f.vciIssuanceFixture.h.repo.GetIssuedCredentialByID(ctx, record.ID)
	require.NoError(t, err)
	require.False(t, current.IsRevoked)
	outage = false
	state = 1
	poll()
	current, err = f.vciIssuanceFixture.h.repo.GetIssuedCredentialByID(ctx, record.ID)
	require.NoError(t, err)
	require.True(t, current.IsRevoked)
	state = 0
	poll()
	current, err = f.vciIssuanceFixture.h.repo.GetIssuedCredentialByID(ctx, record.ID)
	require.NoError(t, err)
	require.True(t, current.IsRevoked, "parent recovery cannot restore revoked child")
}

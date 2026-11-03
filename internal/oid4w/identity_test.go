package oid4w

import (
	"bytes"
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWalletIdentityProfilesRejectAmbiguousAndDemographicSelectors(t *testing.T) {
	p := WalletIdentityProfile{Format: "dc+sd-jwt", Issuer: "https://issuer.example", CredentialType: "identity", ClaimPath: []string{"person", "stable_id"}}
	_, err := WalletIdentityProfiles(map[string]interface{}{"wallet_identity_profiles": []WalletIdentityProfile{p, p}})
	require.ErrorContains(t, err, "ambiguous")
	for _, path := range [][]string{{"email"}, {"person", "given_name"}, {"birth_date"}, {""}} {
		q := p
		q.ClaimPath = path
		require.Error(t, q.Validate())
	}
	id, err := p.Identifier(map[string]any{"person": map[string]any{"stable_id": "ABC-123"}})
	require.NoError(t, err)
	require.Equal(t, "ABC-123", id)
	_, err = p.Identifier(map[string]any{"person": map[string]any{"email": "ABC-123"}})
	require.Error(t, err)
	a, err := p.Digest("tenant-a", id)
	require.NoError(t, err)
	b, err := p.Digest("tenant-b", id)
	require.NoError(t, err)
	require.False(t, bytes.Equal(a, b))
	b, err = p.Digest("tenant-a", "abc-123")
	require.NoError(t, err)
	require.False(t, bytes.Equal(a, b), "identifiers must not be case folded")
}

func TestSDJWTRejectsDisclosuresOverwritingSignedIdentity(t *testing.T) {
	for _, name := range []string{"iss", "sub", "vct", "_sd", "_sd_alg"} {
		t.Run(name, func(t *testing.T) {
			p := baseParams(t)
			// Issuance rounds iat down to the hour. Keep this security fixture
			// valid across the next hour boundary so it reaches disclosure checks.
			p.TTL = 2 * time.Hour
			p.DisclosableClaims = map[string]any{name: "attacker"}
			raw, _, err := IssueSDJWT(p)
			require.NoError(t, err)
			issuer, disclosures, _, err := ParseSDJWT(raw)
			require.NoError(t, err)
			_, err = VerifyAndExtractClaims(issuer, disclosures, p.Signer.Public())
			require.ErrorContains(t, err, "duplicates")
			_, err = extractSDJWTClaimsNoSigCheck(issuer, disclosures)
			require.ErrorContains(t, err, "duplicates")
		})
	}
}

func TestVerifiedIdentityDistinguishesIssuerTrustFromLocalSignature(t *testing.T) {
	p := baseParams(t)
	bound := finalPresentation(t, p, finalHolder(t), "ES256", "kb+jwt", "correct")
	result, err := VerifyDCQLPresentation(context.Background(), bound, finalQuery(p.VCT, nil), "session-nonce", "verifier", map[string]crypto.PublicKey{p.Issuer: p.Signer.Public()}, true, nil)
	require.NoError(t, err)
	require.True(t, result.Identity.IssuerTrusted)
	require.True(t, result.Identity.HolderBound)
	require.False(t, result.Identity.SignedByLocalIssuer)
	require.Equal(t, p.Subject, result.Identity.Subject)
	result, err = VerifyDCQLPresentation(context.Background(), bound, finalQuery(p.VCT, nil), "session-nonce", "verifier", nil, false, nil)
	require.NoError(t, err)
	require.False(t, result.Identity.IssuerTrusted, "conformance bypass must not manufacture issuer trust")
}

package oid4w

import (
	"context"
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// A DCQL presentation whose issuer is not in the configured trust anchors must be
// rejected when RequireTrustedIssuer is on — otherwise its claims would be
// accepted with the issuer signature unverified (claim forgery).
func TestVerifyDCQLPresentation_RejectsUntrustedIssuerWhenRequired(t *testing.T) {
	p := baseParams(t)
	vpToken, _, err := IssueSDJWT(p) // issuer-signed SD-JWT, no KB-JWT
	require.NoError(t, err)

	localPub := p.Signer.Public().(*rsa.PublicKey)
	empty := map[string]crypto.PublicKey{} // issuer not trusted

	// requireTrusted = true → reject before trusting any claim.
	_, err = VerifyDCQLPresentation(context.Background(), vpToken, nil, "nonce", "aud", empty, true, localPub)
	require.Error(t, err)
	require.Contains(t, err.Error(), "trust anchors")

	// requireTrusted = false (conformance) → MUST NOT fail on the trust-anchor check.
	_, err2 := VerifyDCQLPresentation(context.Background(), vpToken, nil, "nonce", "aud", empty, false, localPub)
	if err2 != nil {
		require.NotContains(t, err2.Error(), "trust anchors")
	}
}

// A presentation without a KB-JWT (credential issued with no holder binding) must
// still verify after the VerifyPresentation hardening — the KB-JWT check only
// applies when one is present.
func TestVerifyPresentation_NoKBJWTStillAccepted(t *testing.T) {
	p := baseParams(t)
	vpToken, _, err := IssueSDJWT(p)
	require.NoError(t, err)

	localPub := p.Signer.Public().(*rsa.PublicKey)
	// Empty presentation definition: no field constraints to satisfy.
	_, err = VerifyPresentation(vpToken, PresentationDefinition{}, "unused-nonce", "unused-aud", nil, localPub)
	require.NoError(t, err)
}

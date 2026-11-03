package oid4w

import (
	"crypto"
	"fmt"
)

// Issuer-side validation of a stored credential, without treating it as a
// holder-authenticated presentation. This verifies the local signature/time.
func VerifyLocalIssuedCredential(raw string, key crypto.PublicKey) (*VerificationResult, error) {
	issuer, disclosures, kb, err := ParseSDJWT(raw)
	if err != nil {
		return nil, err
	}
	if kb != "" {
		return nil, fmt.Errorf("stored credential must not contain a holder presentation proof")
	}
	claims, err := VerifyAndExtractClaims(issuer, disclosures, key)
	if err != nil {
		return nil, err
	}
	identity, err := verifiedSDJWTIdentity(issuer, true, true, false)
	if err != nil {
		return nil, err
	}
	return &VerificationResult{Claims: claims, Identity: identity}, nil
}

func withCredentialStatus(params *SDJWTParams, status []StatusClaim) error {
	if len(status) == 0 {
		return nil
	}
	if len(status) != 1 {
		return fmt.Errorf("exactly one credential status reference is supported")
	}
	if _, exists := params.DisclosableClaims["status"]; exists {
		return fmt.Errorf("credential payload cannot supply the reserved status claim")
	}
	if params.PlainClaims == nil {
		params.PlainClaims = map[string]any{}
	}
	if _, exists := params.PlainClaims["status"]; exists {
		return fmt.Errorf("credential mapping cannot override status")
	}
	params.PlainClaims["status"] = status[0]
	return nil
}

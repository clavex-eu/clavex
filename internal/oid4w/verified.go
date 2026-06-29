package oid4w

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
)

// IssueVerifiedCredential builds and signs an SD-JWT-VC credential whose
// claims come from an arbitrary payload provided at offer creation time.
//
// This is the issuance path for Clavex Verified credential types:
//   - Training completion certificates
//   - Professional qualification attestations
//   - Competency badges
//
// Every top-level key in payload becomes a selectively-disclosable claim.
// A minimal set of non-disclosable claims (iss, sub, vct, iat, exp, org_id)
// is always present in the issuer JWT per SD-JWT-VC spec §3.2.
//
// The VCT URI follows the pattern established for all credential types:
//
//	https://<baseURL>/<org_slug>/credentials/<type>/v1
//
// (the exact VCT is taken from cfg.VCT as configured by the org admin).
func IssueVerifiedCredential(
	payload map[string]interface{},
	userSub string,
	org *models.Organization,
	cfg *models.CredentialConfig,
	keys oidc.Signer,
	baseURL string,
	holderKey jwk.Key,
) (string, []Disclosure, error) {
	if len(payload) == 0 {
		return "", nil, fmt.Errorf("IssueVerifiedCredential: payload must not be empty")
	}

	issuer := fmt.Sprintf("%s/%s", baseURL, org.Slug)

	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour // 1 year default for qualifications
	}

	params := SDJWTParams{
		Issuer:            issuer,
		Subject:           userSub,
		VCT:               cfg.VCT,
		DisclosableClaims: payload,
		PlainClaims: map[string]any{
			"org_id":           org.ID.String(),
			"issuer_name":      org.Name,
			"credential_class": cfg.Category,
		},
		TTL:       ttl,
		Signer:    keys.CryptoSigner(),
		Alg:       jwa.PS256,
		KID:       keys.KID(),
		X5C:       buildX5C(keys),
		HolderKey: holderKey,
	}

	// Delegated issuance (ARF EUDIW §6.3.4): embed the delegation proof so wallets
	// can verify the sub-issuer was authorised by the delegating issuer.
	if cfg.DelegatedBy != nil && *cfg.DelegatedBy != "" && cfg.DelegationJWT != nil && *cfg.DelegationJWT != "" {
		delClaim := DelegationClaimForSDJWT(*cfg.DelegatedBy, *cfg.DelegationJWT)
		if delClaim != nil {
			params.PlainClaims["del"] = delClaim
		}
	}

	return IssueSDJWT(params)
}

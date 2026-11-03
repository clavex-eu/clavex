package handler

import (
	"crypto"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// WithCredentialSigningPublicKey registers a dedicated local credential key,
// keeping the existing OIDC key available for previously issued credentials.
func (h *OID4VPHandler) WithCredentialSigningPublicKey(key crypto.PublicKey, validity ...time.Time) *OID4VPHandler {
	h.credentialSigningPublicKey = key
	if len(validity) == 2 {
		h.credentialKeyNotBefore, h.credentialKeyNotAfter = validity[0], validity[1]
	}
	return h
}

// Select only between server-configured keys and only for the expected tenant
// issuer. Embedded JWKs, x5c and unverified kid values never establish trust.
func (h *OID4VPHandler) localCredentialVerificationKey(presentation, issuer string) crypto.PublicKey {
	legacy := h.keys.PublicKey()
	if h.credentialSigningPublicKey == nil {
		return legacy
	}
	if (!h.credentialKeyNotBefore.IsZero() && time.Now().Before(h.credentialKeyNotBefore)) || (!h.credentialKeyNotAfter.IsZero() && !time.Now().Before(h.credentialKeyNotAfter)) {
		return legacy
	}
	raw, disclosures, _, err := oid4w.ParseSDJWT(presentation)
	if err != nil {
		return legacy
	}
	claims, err := oid4w.VerifyAndExtractClaims(raw, disclosures, h.credentialSigningPublicKey)
	if err == nil && claims["iss"] == issuer {
		token, parseErr := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
		if parseErr != nil || token.IssuedAt().IsZero() || token.Expiration().IsZero() {
			return legacy
		}
		if (!h.credentialKeyNotBefore.IsZero() && token.IssuedAt().Before(h.credentialKeyNotBefore)) || (!h.credentialKeyNotAfter.IsZero() && token.Expiration().After(h.credentialKeyNotAfter)) {
			return legacy
		}
		return h.credentialSigningPublicKey
	}
	return legacy
}

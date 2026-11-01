package handler

import (
	"crypto"

	"github.com/clavex-eu/clavex/internal/oid4w"
)

// WithCredentialSigningPublicKey registers a dedicated local credential key,
// keeping the existing OIDC key available for previously issued credentials.
func (h *OID4VPHandler) WithCredentialSigningPublicKey(key crypto.PublicKey) *OID4VPHandler {
	h.credentialSigningPublicKey = key
	return h
}

// Select only between server-configured keys and only for the expected tenant
// issuer. Embedded JWKs, x5c and unverified kid values never establish trust.
func (h *OID4VPHandler) localCredentialVerificationKey(presentation, issuer string) crypto.PublicKey {
	legacy := h.keys.PublicKey()
	if h.credentialSigningPublicKey == nil {
		return legacy
	}
	raw, disclosures, _, err := oid4w.ParseSDJWT(presentation)
	if err != nil {
		return legacy
	}
	claims, err := oid4w.VerifyAndExtractClaims(raw, disclosures, h.credentialSigningPublicKey)
	if err == nil && claims["iss"] == issuer {
		return h.credentialSigningPublicKey
	}
	return legacy
}

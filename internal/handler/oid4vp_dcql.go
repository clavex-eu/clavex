package handler

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
)

// Validate every supplied instance, including optional alternatives. No
// successful first credential can hide a bad subsequent credential.
func (h *OID4VPHandler) verifyDCQLResponse(ctx context.Context, raw string, session *models.PresentationSession, clientID string) (*oid4w.VerificationResult, error) {
	query, err := oid4w.ParseDCQL(session.DCQLQuery)
	if err != nil {
		return nil, err
	}
	envelope, err := query.ParsePresentations(raw)
	if err != nil {
		return nil, err
	}
	requireTrusted := h.requireTrustedIssuer || session.CIBAAuthReqID != nil
	verified := []oid4w.VerifiedDCQLCredential{}
	for _, credential := range query.Credentials {
		for index, presentation := range envelope[credential.ID] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var result *oid4w.VerificationResult
			switch credential.Format {
			case "dc+sd-jwt":
				org, orgErr := h.orgs.GetByID(ctx, session.OrgID)
				if orgErr != nil {
					return nil, orgErr
				}
				localIssuer := h.cfg.BaseURL() + "/" + org.Slug
				localKey := h.localCredentialVerificationKey(presentation, localIssuer)
				trusted := make(map[string]crypto.PublicKey, len(h.trustedIssuers)+1)
				for issuer, key := range h.trustedIssuers {
					trusted[issuer] = key
				}
				trusted[localIssuer] = localKey
				result, err = oid4w.VerifyDCQLPresentation(ctx, presentation, credential.Single, session.Nonce, clientID, trusted, requireTrusted, localKey)
			case "mso_mdoc":
				single := *session
				single.DCQLQuery = credential.Single
				wrapped, wrapErr := json.Marshal(map[string][]string{credential.ID: {presentation}})
				if wrapErr != nil {
					return nil, wrapErr
				}
				result, err = h.verifyMdocDCQLVPToken(ctx, string(wrapped), &single, clientID)
			default:
				return nil, fmt.Errorf("unsupported DCQL format")
			}
			if err != nil {
				return nil, fmt.Errorf("query %s instance %d: %w", credential.ID, index, err)
			}
			if result == nil || result.Identity == nil {
				return nil, fmt.Errorf("missing verified credential evidence")
			}
			verified = append(verified, oid4w.VerifiedDCQLCredential{QueryID: credential.ID, Instance: index, Result: result})
		}
	}
	return oid4w.ComposeDCQLResult(query, verified)
}

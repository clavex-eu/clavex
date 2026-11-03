package handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errWalletIdentityMismatch = errors.New("credential is not linked to the requested account")

func bindWalletAccount(ctx context.Context, repo *repository.WalletIdentityRepository, orgID, userID uuid.UUID, localIssuer string, settings map[string]interface{}, result *oid4w.VerificationResult) (map[string]any, error) {
	if result != nil && len(result.Credentials) > 0 {
		decisions := make([]map[string]any, 0, len(result.Credentials))
		for _, credential := range result.Credentials {
			if credential.Result == nil || len(credential.Result.Credentials) > 0 {
				return nil, errWalletIdentityMismatch
			}
			decision, err := bindWalletAccount(ctx, repo, orgID, userID, localIssuer, settings, credential.Result)
			if err != nil {
				return nil, err
			}
			decisions = append(decisions, map[string]any{"query_id": credential.QueryID, "instance": credential.Instance, "binding": decision})
		}
		return map[string]any{"method": "all_presented_credentials", "credentials": decisions}, nil
	}
	if result == nil || result.Identity == nil {
		return nil, errWalletIdentityMismatch
	}
	e := result.Identity
	if !e.HolderBound || e.CredentialType == "" {
		return nil, errWalletIdentityMismatch
	}
	if e.Format == "dc+sd-jwt" && e.Issuer == localIssuer {
		if !e.SignedByLocalIssuer || e.Subject != userID.String() {
			return nil, errWalletIdentityMismatch
		}
		return map[string]any{"method": "local_signed_subject"}, nil
	}
	if !e.IssuerTrusted {
		return nil, errWalletIdentityMismatch
	}
	profiles, err := oid4w.WalletIdentityProfiles(settings)
	if err != nil {
		return nil, fmt.Errorf("wallet identity profiles are misconfigured: %w", err)
	}
	for _, profile := range profiles {
		if profile.Format != e.Format || profile.Issuer != e.Issuer || profile.CredentialType != e.CredentialType {
			continue
		}
		claims := result.Claims
		if e.Format == "mso_mdoc" {
			claims = map[string]any{}
			namespaces, ok := result.Claims["_mdoc_namespaces"].(map[string]map[string]any)
			if !ok {
				return nil, errWalletIdentityMismatch
			}
			for ns, attrs := range namespaces {
				claims[ns] = attrs
			}
		}
		identifier, err := profile.Identifier(claims)
		if err != nil {
			return nil, errWalletIdentityMismatch
		}
		digest, err := profile.Digest(orgID.String(), identifier)
		if err != nil {
			return nil, errWalletIdentityMismatch
		}
		id, boundUser, err := repo.FindActive(ctx, orgID, e.Format, e.Issuer, e.CredentialType, profile.ClaimPath, digest)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errWalletIdentityMismatch
		}
		if err != nil {
			return nil, err
		}
		if boundUser != userID {
			return nil, errWalletIdentityMismatch
		}
		return map[string]any{"method": "registered_external_identifier", "link_id": id.String()}, nil
	}
	return nil, errWalletIdentityMismatch
}

// Account binding and both pending-state transitions commit together. Neither a
// successful presentation alone nor a conformance-only issuer bypass approves CIBA.
func (h *OID4VPHandler) completeBoundCIBA(ctx context.Context, sessionID string, orgID uuid.UUID, result *oid4w.VerificationResult) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if h.cibaRequests == nil {
		return errWalletIdentityMismatch
	}
	repo, tx, err := h.repo.BeginIssuance(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM identity.presentation_sessions WHERE request_id=$1 AND org_id=$2 AND status='pending' AND expires_at>NOW() FOR UPDATE NOWAIT`, sessionID, orgID).Scan(&id); err != nil {
		return err
	}
	session, err := repo.GetPresentationSession(ctx, sessionID)
	if err != nil || session.CIBAAuthReqID == nil {
		return errWalletIdentityMismatch
	}
	var authReqID string
	if err := tx.QueryRow(ctx, `SELECT auth_req_id FROM identity.ciba_requests WHERE auth_req_id=$1 AND org_id=$2 AND status='pending' AND expires_at>NOW() FOR UPDATE NOWAIT`, *session.CIBAAuthReqID, orgID).Scan(&authReqID); err != nil {
		return err
	}
	cibaRepo := repository.NewCIBARepository(tx)
	request, err := cibaRepo.Get(ctx, authReqID)
	if err != nil {
		return err
	}
	if request == nil || request.UserID == nil {
		return errWalletIdentityMismatch
	}
	identities := repository.NewWalletIdentityRepository(tx)
	slug, settings, err := identities.LockActiveOrg(ctx, orgID)
	if err != nil {
		return err
	}
	if err := identities.LockActiveUser(ctx, orgID, *request.UserID); err != nil {
		return err
	}
	if err := identities.LockActiveClient(ctx, orgID, request.ClientID); err != nil {
		return err
	}
	if err := checkWalletStatus(ctx, repo, orgID, h.cfg.BaseURL()+"/"+slug, settings, result, true); err != nil {
		return err
	}
	decision, err := bindWalletAccount(ctx, identities, orgID, *request.UserID, h.cfg.BaseURL()+"/"+slug, settings, result)
	if err != nil {
		return err
	}
	claims := make(map[string]interface{}, len(result.Claims)+1)
	for key, value := range result.Claims {
		claims[key] = value
	}
	claims["_clavex_account_binding"] = decision
	claims["_clavex_credential_status"] = result.StatusAssessment
	if result.CertificateStatusAssessment != "" {
		claims["_clavex_certificate_status"] = result.CertificateStatusAssessment
	}
	if err := repo.CompletePresentationSession(ctx, sessionID, claims); err != nil {
		return err
	}
	if err := cibaRepo.ApproveWithVPClaims(ctx, authReqID, *request.UserID, claims, cibaVPACR); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

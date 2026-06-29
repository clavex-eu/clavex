package worker

// PolicyEnforcer re-validates all WebAuthn credentials against their org's
// attestation policy after each MDS3 refresh cycle.
//
// # Zero-trust credential lifecycle
//
// When the FIDO Alliance updates MDS3, two things can happen that break
// previously-compliant devices:
//
//  1. A device is REVOKED (security vulnerability discovered).
//  2. A device's certification level is downgraded below the org's minimum.
//
// Without this enforcer an admin would have to manually detect the change and
// revoke affected sessions. The enforcer closes that gap:
//
//  1. Runs FindNonCompliantCredentials() — a single DB query that joins
//     mfa_credentials, users, webauthn_attestation_policies, and
//     fido_mds_entries to find every credential that now violates its org's policy.
//  2. Revokes all active refresh tokens for affected users (force re-authentication).
//  3. Fires a CAEP credential-change (revoke) SET via the SSF dispatcher so
//     registered resource servers invalidate access tokens immediately.
//  4. Fires a RISC sessions-revoked SET so downstream systems are notified.
//
// The enforcer is idempotent: revoking already-revoked tokens is a no-op.

import (
	"context"
	"fmt"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// PolicyEnforcerDeps holds external dependencies for the enforcer.
// All fields are required.
type PolicyEnforcerDeps struct {
	Pool        *pgxpool.Pool
	SSFDispatch *ssf.Dispatcher // may be nil — SSF events simply not sent
}

// EnforcePoliciesAfterMDSRefresh finds credentials that became non-compliant
// after the MDS3 catalog was updated and revokes their sessions.
//
// It is called synchronously by the MDS3 worker after each successful catalog
// upsert (including unchanged catalogues — the MDS3 entry statuses may have
// changed even if the blob content hash is the same).
//
// When SSFDispatch is non-nil, CAEP credential-change and RISC sessions-revoked
// SETs are dispatched to all registered push/poll streams for the affected org.
func EnforcePoliciesAfterMDSRefresh(ctx context.Context, deps PolicyEnforcerDeps) {
	mdsRepo := repository.NewMDSRepository(deps.Pool)
	tokenRepo := repository.NewRefreshTokenRepository(deps.Pool)

	nonCompliant, err := mdsRepo.FindNonCompliantCredentials(ctx)
	if err != nil {
		log.Error().Err(err).Msg("policy-enforcer: find non-compliant credentials failed")
		return
	}
	if len(nonCompliant) == 0 {
		log.Debug().Msg("policy-enforcer: all credentials comply with attestation policies")
		return
	}

	// Deduplicate by (org_id, user_id) — one user may have multiple non-compliant
	// credentials, but we only need to revoke their sessions once.
	type userKey struct {
		orgID  uuid.UUID
		userID uuid.UUID
	}
	revoked := make(map[userKey]bool)
	// Collect one entry per user to extract org slug for SSF dispatch.
	type userMeta struct {
		orgSlug string
		reasons []string
		aaguids []string
	}
	userMetas := make(map[userKey]*userMeta)

	for _, nc := range nonCompliant {
		k := userKey{orgID: nc.OrgID, userID: nc.UserID}
		if _, seen := userMetas[k]; !seen {
			userMetas[k] = &userMeta{orgSlug: nc.OrgSlug}
		}
		userMetas[k].reasons = append(userMetas[k].reasons, nc.Reason)
		userMetas[k].aaguids = append(userMetas[k].aaguids, nc.AAGUID)
	}

	for k, meta := range userMetas {
		if revoked[k] {
			continue
		}
		revoked[k] = true

		log.Warn().
			Str("org_id", k.orgID.String()).
			Str("org_slug", meta.orgSlug).
			Str("user_id", k.userID.String()).
			Strs("aaguids", meta.aaguids).
			Strs("reasons", meta.reasons).
			Msg("policy-enforcer: revoking sessions for non-compliant credential")

		// Revoke all refresh tokens (force re-authentication).
		if err := tokenRepo.RevokeAllByUser(ctx, k.orgID, k.userID); err != nil {
			log.Error().Err(err).
				Str("user_id", k.userID.String()).
				Msg("policy-enforcer: revoke sessions failed")
			continue
		}

		// Dispatch CAEP + RISC events to registered resource servers.
		if deps.SSFDispatch != nil {
			credType := credentialTypeFromReasons(meta.reasons)

			// CAEP credential-change (revoke): RS must immediately invalidate
			// any access token issued to this user.
			deps.SSFDispatch.Dispatch(
				k.orgID, meta.orgSlug, k.userID.String(),
				ssf.EventCredentialChange,
				ssfCredentialRevokedByPolicyBody(credType, meta.reasons),
			)

			// RISC sessions-revoked: belt-and-suspenders notification.
			deps.SSFDispatch.Dispatch(
				k.orgID, meta.orgSlug, k.userID.String(),
				ssf.EventSessionsRevoked,
				ssf.SessionsRevokedBody("mds3-policy-enforcement"),
			)
		}
	}

	log.Info().
		Int("affected_users", len(revoked)).
		Int("affected_credentials", len(nonCompliant)).
		Msg("policy-enforcer: MDS3 post-refresh enforcement complete")
}

// credentialTypeFromReasons returns the CAEP credential_type that best
// describes the affected credential (always FIDO2 for WebAuthn credentials).
func credentialTypeFromReasons(reasons []string) string {
	// All credentials processed here are WebAuthn; distinguish platform vs roaming
	// if possible. Without the authenticator_type from the credential row itself
	// we default to the generic "fido2-platform" label (most common in enterprise).
	_ = reasons
	return "fido2-platform"
}

// ssfCredentialRevokedByPolicyBody builds the CAEP credential-change event body
// for an MDS3-driven policy revocation.
//
// CAEP spec: openid-caep-specification-1_0 §3.3
func ssfCredentialRevokedByPolicyBody(credentialType string, reasons []string) map[string]interface{} {
	body := ssf.CredentialChangeBody(credentialType, "revoke")
	body["initiating_entity"] = "policy"
	body["reason_admin"] = map[string]interface{}{
		"en": fmt.Sprintf("Authenticator no longer satisfies attestation policy: %v", reasons),
	}
	return body
}

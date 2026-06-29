package federation

import (
	"context"
	"log/slog"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
)

// clientGetter is the subset of repository.ClientRepository used by AutoRegisterLookup.
type clientGetter interface {
	GetByClientID(ctx context.Context, clientID string) (*models.OIDCClient, error)
}

// AutoRegisterLookup wraps a ClientLookup and transparently performs automatic
// federation registration (OIDF 1.0 §10.2) the first time an unknown entity ID
// (https:// URL) is used as client_id in an authorization request.
//
// Flow:
//  1. Try the inner lookup (DB hit for already-registered clients).
//  2. On miss, if client_id starts with "https://" and trust anchors are
//     configured, fetch the RP's Entity Configuration, validate the trust
//     chain, and upsert a client row with client_id = entity_id.
//  3. Return the upserted (or refreshed) client on success; return the
//     original "not found" error so the caller emits "unauthorized_client".
type AutoRegisterLookup struct {
	inner    clientGetter
	resolver *Resolver
	clients  *repository.ClientRepository
	orgID    uuid.UUID
}

// NewAutoRegisterLookup creates an AutoRegisterLookup. Pass a nil resolver or
// one with no trust anchors to disable automatic registration (lookup falls
// through to the inner ClientLookup only).
func NewAutoRegisterLookup(
	inner clientGetter,
	resolver *Resolver,
	clients *repository.ClientRepository,
	orgID uuid.UUID,
) *AutoRegisterLookup {
	return &AutoRegisterLookup{
		inner:    inner,
		resolver: resolver,
		clients:  clients,
		orgID:    orgID,
	}
}

// GetByClientID implements the oidc.ClientLookup interface.
func (a *AutoRegisterLookup) GetByClientID(ctx context.Context, clientID string) (*models.OIDCClient, error) {
	client, err := a.inner.GetByClientID(ctx, clientID)
	if err == nil {
		return client, nil
	}

	// Automatic registration only applies to entity IDs (https:// URLs).
	if !strings.HasPrefix(clientID, "https://") {
		return nil, err
	}
	if a.resolver == nil || len(a.resolver.trustAnchors) == 0 {
		slog.Warn("federation auto-register skipped: no resolver/trust anchors configured",
			"client_id", clientID,
			"resolver_nil", a.resolver == nil)
		return nil, err
	}

	// Resolve trust chain and extract RP metadata.
	rpData, fedErr := a.resolver.ValidateByEntityID(ctx, clientID)
	if fedErr != nil {
		// Surface the federation failure in logs (the caller only sees the
		// generic "unauthorized_client"), so trust-chain/fetch problems are
		// diagnosable instead of silently swallowed.
		slog.Warn("federation auto-register failed",
			"client_id", clientID,
			"trust_anchors", a.resolver.trustAnchorList(),
			"error", fedErr)
		// Return the original error so the caller sees "unauthorized_client",
		// not a federation-specific message.
		return nil, err
	}

	// Upsert the client. For automatic registration the entity ID is the client_id.
	params := repository.FederationRegisterParams{
		OrgID:                   a.orgID,
		ClientID:                clientID, // entity ID IS the client_id
		EntityID:                rpData.EntityID,
		Name:                    rpData.Name,
		RedirectURIs:            rpData.RedirectURIs,
		PostLogoutRedirectURIs:  rpData.PostLogoutRedirectURIs,
		GrantTypes:              rpData.GrantTypes,
		ResponseTypes:           rpData.ResponseTypes,
		Scopes:                  rpData.Scopes,
		TokenEndpointAuthMethod: rpData.TokenEndpointAuthMethod,
		RegistrationType:        "automatic",
	}
	if rpData.LogoURI != "" {
		l := rpData.LogoURI
		params.LogoURL = &l
	}
	if rpData.JWKSUri != "" {
		u := rpData.JWKSUri
		params.JWKSUri = &u
	}
	if len(rpData.JWKS) > 0 {
		params.JWKS = []byte(rpData.JWKS)
	}

	registered, regErr := a.clients.RegisterFederated(ctx, params)
	if regErr != nil {
		// The trust chain resolved but persisting the client failed; the caller
		// only sees "unauthorized_client", so log the DB error to keep it
		// diagnosable.
		slog.Warn("federation auto-register persist failed",
			"client_id", clientID,
			"error", regErr)
		return nil, err
	}
	return registered, nil
}

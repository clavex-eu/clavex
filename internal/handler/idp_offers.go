package handler

// idp_offers.go — shared helper for creating OID4VCI pre-authorized credential
// offers automatically after a user logs in through an external IdP (SPID, CIE,
// FranceConnect, …).

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// createIdpCredentialOffers queries for all active credential configs linked to
// idpType and creates a pre-authorized OID4VCI credential offer for each one.
// Returns the list of openid-credential-offer:// URIs (one per config).
func createIdpCredentialOffers(
	ctx context.Context,
	oid4w *repository.OID4WRepository,
	baseURL string,
	orgID uuid.UUID,
	user *models.User,
	orgSlug string,
	idpType string,
) []string {
	configs, err := oid4w.GetCredentialConfigsBySourceIdp(ctx, orgID, idpType)
	if err != nil {
		log.Warn().Err(err).Str("org_id", orgID.String()).Str("idp_type", idpType).
			Msg("idp_offers: failed to query credential configs")
		return nil
	}
	if len(configs) == 0 {
		return nil
	}

	var uris []string
	for _, cfg := range configs {
		ttl := time.Duration(cfg.TTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 24 * time.Hour
		}

		preAuthCode, err := generateSecureCode()
		if err != nil {
			log.Warn().Err(err).Msg("idp_offers: failed to generate pre-auth code")
			continue
		}

		offer, err := oid4w.CreateCredentialOffer(
			ctx, orgID, &user.ID, cfg.VCT, preAuthCode, nil, nil, time.Now().Add(ttl),
		)
		if err != nil {
			log.Warn().Err(err).Str("vct", cfg.VCT).Str("idp_type", idpType).
				Msg("idp_offers: failed to create credential offer")
			continue
		}

		credentialOfferURL := fmt.Sprintf("%s/%s/oid4vci/offers/%s", baseURL, orgSlug, offer.ID)
		offerURI := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(credentialOfferURL)
		uris = append(uris, offerURI)

		log.Info().
			Str("offer_id", offer.ID.String()).
			Str("vct", cfg.VCT).
			Str("user_id", user.ID.String()).
			Str("idp_type", idpType).
			Msg("idp_offers: auto-created credential offer after IdP login")
	}
	return uris
}

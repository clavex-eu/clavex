package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type walletClientIdentity struct {
	ID, Method, AttestationJKT string
	Parents                    []oid4w.StatusParent
}

func (h *OID4VCIHandler) authenticateWalletClient(c echo.Context, org *models.Organization) (walletClientIdentity, error) {
	identity := walletClientIdentity{Method: "none"}
	id := c.FormValue("client_id")
	basicID, _, basic := c.Request().BasicAuth()
	if basic {
		if id != "" && id != basicID {
			return identity, echo.ErrUnauthorized
		}
		id = basicID
	} else if c.Request().Header.Get("Authorization") != "" {
		return identity, echo.ErrUnauthorized
	}
	assertionType := c.FormValue("client_assertion_type")
	assertion := c.FormValue("client_assertion")
	hasAttestation := c.Request().Header.Get("OAuth-Client-Attestation") != "" || c.Request().Header.Get("OAuth-Client-Attestation-PoP") != ""
	hasAssertion := assertionType != "" || assertion != "" || hasAttestation
	secret := c.FormValue("client_secret")
	if basic && (hasAssertion || secret != "") || hasAssertion && secret != "" {
		return identity, echo.ErrUnauthorized
	}
	// Assertion transports may omit client_id. Resolve it for policy selection
	// only; signature and PoP are still authenticated by the OIDC implementation.
	if hasAssertion && id == "" {
		raw := assertion
		if hasAttestation {
			raw = c.Request().Header.Get("OAuth-Client-Attestation")
		}
		raw, _, _ = strings.Cut(raw, "~")
		tok, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			return identity, echo.ErrUnauthorized
		}
		if hasAttestation || assertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation" {
			id = tok.Subject()
		} else {
			id = tok.Issuer()
		}
	}
	if id == "" {
		if basic || hasAssertion || secret != "" {
			return identity, echo.ErrUnauthorized
		}
		return identity, nil
	}
	if len(id) > 512 {
		return identity, echo.ErrUnauthorized
	}
	var client *models.OIDCClient
	if h.oidcHandler != nil {
		var err error
		client, err = h.oidcHandler.clients.GetByClientID(c.Request().Context(), id)
		if err != nil {
			return identity, echo.ErrUnauthorized
		}
	} else {
		// Public clients need no extra infrastructure; the existing registry lock
		// validates tenant/activity/method below at grant creation/refresh.
		method, err := h.repo.WalletClientMethod(c.Request().Context(), org.ID, id)
		if err != nil {
			return identity, echo.ErrUnauthorized
		}
		if method != "none" {
			return identity, echo.ErrServiceUnavailable
		}
		client = &models.OIDCClient{ClientID: id, OrgID: org.ID, IsActive: true, TokenEndpointAuthMethod: method}
	}
	if !client.IsActive || client.OrgID != org.ID {
		return identity, echo.ErrUnauthorized
	}
	identity.ID, identity.Method = id, client.TokenEndpointAuthMethod
	switch identity.Method {
	case "none":
		if basic || hasAssertion || secret != "" {
			return identity, echo.ErrUnauthorized
		}
		return identity, nil
	case "client_secret_basic":
		if !basic || hasAssertion || secret != "" {
			return identity, echo.ErrUnauthorized
		}
	case "client_secret_post":
		if basic || hasAssertion || secret == "" {
			return identity, echo.ErrUnauthorized
		}
	case "private_key_jwt":
		if basic || hasAttestation || assertion == "" || assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return identity, echo.ErrUnauthorized
		}
	case "attest_jwt_client_auth":
		if basic || (!hasAttestation && (assertion == "" || assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation")) {
			return identity, echo.ErrUnauthorized
		}
		if hasAttestation && (assertion != "" || assertionType != "") {
			return identity, echo.ErrUnauthorized
		}
	case "tls_client_auth":
		if basic || hasAssertion || secret != "" || c.Request().TLS == nil || len(c.Request().TLS.VerifiedChains) == 0 {
			return identity, echo.ErrUnauthorized
		}
	default:
		return identity, echo.ErrUnauthorized
	}
	if h.oidcHandler == nil {
		return identity, echo.ErrServiceUnavailable
	}
	if identity.Method == "private_key_jwt" || identity.Method == "attest_jwt_client_auth" {
		proofRaw := assertion
		if identity.Method == "attest_jwt_client_auth" {
			if hasAttestation {
				proofRaw = c.Request().Header.Get("OAuth-Client-Attestation-PoP")
			} else {
				_, proofRaw, _ = strings.Cut(assertion, "~")
			}
		}
		msg, err := jws.Parse([]byte(proofRaw))
		if err != nil || len(msg.Signatures()) != 1 {
			return identity, echo.ErrUnauthorized
		}
		header := msg.Signatures()[0].ProtectedHeaders()
		if len(header.Critical()) > 0 || (header.Algorithm() != jwa.RS256 && header.Algorithm() != jwa.PS256 && header.Algorithm() != jwa.ES256) {
			return identity, echo.ErrUnauthorized
		}
		if identity.Method == "attest_jwt_client_auth" && header.Type() != "oauth-client-attestation-pop+jwt" {
			return identity, echo.ErrUnauthorized
		}
		proof, err := jwt.Parse([]byte(proofRaw), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			return identity, echo.ErrUnauthorized
		}
		now := time.Now()
		// Attestation PoP uses iat and jti for freshness/replay protection;
		// exp is optional (OAuth attestation-based client authentication §5.2).
		// private_key_jwt retains its mandatory expiration time.
		exp := proof.Expiration()
		if proof.JwtID() == "" || len(proof.JwtID()) > 512 || proof.IssuedAt().IsZero() || proof.IssuedAt().After(now.Add(30*time.Second)) ||
			(identity.Method == "private_key_jwt" && exp.IsZero()) ||
			(!exp.IsZero() && (!exp.After(proof.IssuedAt()) || exp.Sub(proof.IssuedAt()) > 5*time.Minute)) {
			return identity, echo.ErrUnauthorized
		}
		if identity.Method == "attest_jwt_client_auth" {
			attestationRaw := c.Request().Header.Get("OAuth-Client-Attestation")
			if attestationRaw == "" {
				attestationRaw, _, _ = strings.Cut(assertion, "~")
			}
			message, err := jws.Parse([]byte(attestationRaw))
			if err != nil || len(message.Signatures()) != 1 {
				return identity, echo.ErrUnauthorized
			}
			head := message.Signatures()[0].ProtectedHeaders()
			if head.Type() != "oauth-client-attestation+jwt" || len(head.Critical()) > 0 || (head.Algorithm() != jwa.RS256 && head.Algorithm() != jwa.PS256 && head.Algorithm() != jwa.ES256) {
				return identity, echo.ErrUnauthorized
			}
			token, err := jwt.Parse([]byte(attestationRaw), jwt.WithVerify(false), jwt.WithValidate(false))
			if err != nil || token.Issuer() == "" || token.IssuedAt().IsZero() || token.Expiration().IsZero() || !token.Expiration().After(token.IssuedAt()) || token.IssuedAt().After(now.Add(30*time.Second)) {
				return identity, echo.ErrUnauthorized
			}
		}
		if h.rdb == nil {
			return identity, echo.ErrServiceUnavailable
		}
	}
	authenticated, _, jkt, err := h.oidcHandler.authenticateClient(c)
	if err != nil {
		return identity, err
	}
	if authenticated != identity.ID {
		return identity, echo.ErrUnauthorized
	}
	identity.AttestationJKT = jkt
	if identity.Method == "attest_jwt_client_auth" {
		raw := c.Request().Header.Get("OAuth-Client-Attestation")
		if raw == "" {
			raw, _, _ = strings.Cut(assertion, "~")
		}
		tok, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			return identity, echo.ErrUnauthorized
		}
		// This payload has just been cryptographically authenticated above. Persist
		// only the reference, never the client assertion or whole wallet attestation.
		if value, ok := tok.Get("status"); ok {
			status, err := json.Marshal(value)
			if err != nil {
				return identity, echo.ErrServiceUnavailable
			}
			identity.Parents = []oid4w.StatusParent{{Format: "wallet-attestation+jwt", Issuer: tok.Issuer(), Type: "oauth-client-attestation+jwt", Status: status}}
		}
	}
	return identity, nil
}
func walletClientError(c echo.Context, err error) error {
	var httpErr *echo.HTTPError
	if errors.Is(err, echo.ErrServiceUnavailable) || errors.As(err, &httpErr) && httpErr.Code >= 500 {
		return echo.ErrServiceUnavailable
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
}
func walletClientMatches(g *repository.WalletIssuanceGrant, client walletClientIdentity) bool {
	return g.ClientID == client.ID && g.ClientAuthMethod == client.Method && g.AttestationJKT == client.AttestationJKT
}

func (h *OID4VCIHandler) attachWalletGrantParents(ctx context.Context, org *models.Organization, offer *models.CredentialOffer, proofs []verifiedCredentialProof) error {
	grant, err := h.repo.LockWalletGrant(ctx, offer.ID, org.ID)
	if err != nil {
		return err
	}
	if grant == nil {
		return nil
	}
	parents, err := oid4w.ParseStatusParents(grant.StatusParents)
	if err != nil {
		return err
	}
	settings, err := h.repo.LockWalletStatusPolicy(ctx, org.ID)
	if err != nil {
		return err
	}
	if err := oid4w.CheckStatusParents(ctx, org.ID.String(), settings, grant.StatusParents); err != nil {
		return err
	}
	for i := range proofs {
		proofs[i].StatusParents = append(proofs[i].StatusParents, parents...)
	}
	return nil
}

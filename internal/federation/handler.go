package federation

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

// EncKeyProvider supplies the OP's request-object encryption public key as a
// raw JWK JSON object (use=enc). *oidc.EncKeySet satisfies it.
type EncKeyProvider interface {
	JWKObject() []byte
}

// Handler serves OpenID Federation 1.0 endpoints for a tenant.
type Handler struct {
	cfg     *config.Config
	keys    oidc.Signer
	clients *repository.ClientRepository
	orgs    *repository.OrgRepository
	fed     *repository.FederationRepository
	auditor *audit.Emitter
	encKeys EncKeyProvider // nil when request-object encryption is not enabled
}

// WithEncKeys attaches the request-object encryption key so the leaf-OP entity
// configuration publishes its public key (use=enc) and advertises encrypted
// request-object support.
func (h *Handler) WithEncKeys(p EncKeyProvider) *Handler {
	h.encKeys = p
	return h
}

// encJWK returns the request-object encryption public JWK, or nil when not enabled.
func (h *Handler) encJWK() []byte {
	if h.encKeys == nil {
		return nil
	}
	return h.encKeys.JWKObject()
}

// NewHandler creates a Handler for the given server config, pool and signing key set.
func NewHandler(cfg *config.Config, pool *pgxpool.Pool, keys oidc.Signer) *Handler {
	return &Handler{
		cfg:     cfg,
		keys:    keys,
		clients: repository.NewClientRepository(pool),
		orgs:    repository.NewOrgRepository(pool),
		fed:     repository.NewFederationRepository(pool),
	}
}

// WithAuditor injects an audit.Emitter so federation events are written to the
// Merkle-chained audit log (eIDAS 2.0 Art.22 / AgID compliance).
func (h *Handler) WithAuditor(a *audit.Emitter) *Handler {
	h.auditor = a
	return h
}

// fedAudit emits a federation audit event. resourceID is the entity URI.
func (h *Handler) fedAudit(c echo.Context, orgID uuid.UUID, action, resourceID, status string, meta map[string]any) {
	if h.auditor == nil {
		return
	}
	resType := "federation_entity"
	h.auditor.Emit(c.Request().Context(), audit.EmitParams{
		OrgID:        orgID,
		Action:       action,
		ResourceType: &resType,
		ResourceID:   &resourceID,
		Status:       status,
		Metadata:     meta,
	})
}

// EntityConfiguration handles GET /:org_slug/.well-known/openid-federation.
//
// When federation.trust_anchor_mode = true, Clavex acts as a Trust Anchor:
// the JWT includes TA-specific federation endpoint URIs and no authority_hints.
// Otherwise Clavex acts as a Leaf OP pointing to external trust anchors.
func (h *Handler) EntityConfiguration(c echo.Context) error {
	if !h.cfg.Federation.Enabled {
		return echo.NewHTTPError(http.StatusNotFound, "openid federation is not enabled")
	}

	orgSlug := c.Param("org_slug")
	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug)
	fc := h.cfg.Federation

	var token []byte
	var err error

	if fc.TrustAnchorMode {
		// ── Trust Anchor mode ─────────────────────────────────────────────────
		// Load trust mark issuer map from DB (best-effort; omit on error).
		tmIssuers := map[string][]string{}
		ctx := c.Request().Context()
		org, orgErr := h.orgs.GetBySlug(ctx, orgSlug)
		if orgErr == nil {
			types, tmErr := h.fed.ListTrustMarkTypes(ctx, org.ID)
			if tmErr == nil {
				entityID := fc.TrustAnchorEntityID
				if entityID == "" {
					entityID = issuer
				}
				for _, t := range types {
					tmIssuers[t.TrustMarkID] = []string{entityID}
				}
			}
		}

		taCfg := TrustAnchorConfig{
			Config: Config{
				OrganizationName: fc.OrganizationName,
				Contacts:         fc.Contacts,
				HomepageURI:      fc.HomepageURI,
				LogoURI:          fc.LogoURI,
			},
			EntityID:           fc.TrustAnchorEntityID,
			BaseURL:            issuer,
			TrustMarkIssuerMap: tmIssuers,
		}
		if fc.JWTLifetime > 0 {
			taCfg.Lifetime = fc.JWTLifetime
		}

		token, err = BuildTAEntityConfig(taCfg, h.keys.CryptoSigner(), jwa.PS256, h.keys.KID())
	} else {
		// ── Leaf OP mode ──────────────────────────────────────────────────────
		fedCfg := Config{
			OrganizationName: fc.OrganizationName,
			AuthorityHints:   fc.AuthorityHints,
			Contacts:         fc.Contacts,
			HomepageURI:      fc.HomepageURI,
			LogoURI:          fc.LogoURI,
		}
		if fc.JWTLifetime > 0 {
			fedCfg.Lifetime = fc.JWTLifetime
		}
		token, err = Build(fedCfg, issuer, h.keys.PrivateKey(), h.keys.KID(), h.encJWK())
	}

	if err != nil {
		c.Logger().Errorf("federation: build entity configuration for %s: %v", orgSlug, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: internal error")
	}

	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Blob(http.StatusOK, ContentType, token)
}

// Register handles POST /:org_slug/federation/register.
//
// Implements OpenID Federation 1.0 §9.6 explicit client registration:
//   1. Parse the RP's signed Entity Statement (compact JWS).
//   2. Fetch the RP's Entity Configuration to obtain its JWKS.
//   3. Verify the registration JWT signature.
//   4. Resolve and validate the trust chain up to a configured trust anchor.
//   5. Apply metadata policies from the chain.
//   6. Upsert the OIDC client record.
//
// The request body must be a compact JWS with Content-Type
// "application/entity-statement+jwt", or a form field named "entity_statement"
// (application/x-www-form-urlencoded).
func (h *Handler) Register(c echo.Context) error {
	if !h.cfg.Federation.Enabled {
		return echo.NewHTTPError(http.StatusNotFound, "openid federation is not enabled")
	}
	if len(h.cfg.Federation.TrustAnchors) == 0 {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error":             "trust_anchors_not_configured",
			"error_description": "No trust anchors configured; explicit federation registration is unavailable.",
		})
	}

	// ── Read the registration JWT from the request ────────────────────────────
	var regJWT []byte

	ct := c.Request().Header.Get("Content-Type")
	if ct == ContentType || ct == "application/jose" {
		raw, err := io.ReadAll(io.LimitReader(c.Request().Body, 512*1024))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "failed to read request body")
		}
		regJWT = raw
	} else {
		// Accept form-encoded submissions too (interop with some OP stacks).
		es := c.FormValue("entity_statement")
		if es == "" {
			return echo.NewHTTPError(http.StatusBadRequest,
				"request must be application/entity-statement+jwt or contain entity_statement form field")
		}
		regJWT = []byte(es)
	}
	if len(regJWT) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "empty registration JWT")
	}

	// ── Validate trust chain ──────────────────────────────────────────────────
	resolver := NewResolver(h.cfg.Federation.TrustAnchors)
	ctx := c.Request().Context()

	rpData, err := resolver.Validate(ctx, regJWT)
	if err != nil {
		c.Logger().Warnf("federation: registration validation failed: %v", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_client_metadata",
			"error_description": err.Error(),
		})
	}

	// ── Resolve the tenant org ────────────────────────────────────────────────
	orgSlug := c.Param("org_slug")
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		c.Logger().Errorf("federation: org %s not found: %v", orgSlug, err)
		return echo.NewHTTPError(http.StatusNotFound, "organisation not found")
	}

	// ── Build the federation registration params ──────────────────────────────
	var jwksURI *string
	if rpData.JWKSUri != "" {
		u := rpData.JWKSUri
		jwksURI = &u
	}
	var logoURL *string
	if rpData.LogoURI != "" {
		l := rpData.LogoURI
		logoURL = &l
	}
	var jwksBytes []byte
	if len(rpData.JWKS) > 0 {
		jwksBytes = []byte(rpData.JWKS)
	}

	params := repository.FederationRegisterParams{
		OrgID:                   org.ID,
		EntityID:                rpData.EntityID,
		Name:                    rpData.Name,
		RedirectURIs:            rpData.RedirectURIs,
		PostLogoutRedirectURIs:  rpData.PostLogoutRedirectURIs,
		GrantTypes:              rpData.GrantTypes,
		ResponseTypes:           rpData.ResponseTypes,
		Scopes:                  rpData.Scopes,
		LogoURL:                 logoURL,
		JWKSUri:                 jwksURI,
		JWKS:                    jwksBytes,
		TokenEndpointAuthMethod: rpData.TokenEndpointAuthMethod,
	}

	client, err := h.clients.RegisterFederated(ctx, params)
	if err != nil {
		c.Logger().Errorf("federation: upsert federated client: %v", err)
		h.fedAudit(c, org.ID, "federation.subordinate.self_register", rpData.EntityID, "failure", nil)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to register client")
	}
	h.fedAudit(c, org.ID, "federation.subordinate.self_register", rpData.EntityID, "success", map[string]any{
		"client_id":   client.ClientID,
		"client_name": client.Name,
		"scopes":      rpData.Scopes,
		"entity_id":   rpData.EntityID,
	})

	// ── Return RFC 7591-style registration response ───────────────────────────
	// OIDF §9.6 prescribes returning the client_id and registered metadata.
	resp := map[string]interface{}{
		"client_id":                  client.ClientID,
		"client_name":                client.Name,
		"redirect_uris":              client.RedirectURIs,
		"post_logout_redirect_uris":  client.PostLogoutRedirectURIs,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"federation_type":            "explicit",
		"entity_id":                  rpData.EntityID,
		"client_id_issued_at":        client.CreatedAt.Unix(),
	}
	if client.JWKSUri != nil {
		resp["jwks_uri"] = *client.JWKSUri
	}
	if client.JWKS != nil {
		resp["jwks"] = *client.JWKS
	}
	if len(rpData.Scopes) > 0 {
		resp["scope"] = joinScopes(rpData.Scopes)
	}

	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusCreated, resp)
}

// joinScopes joins a scope list into a space-separated string.
func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}

// ── Trust Anchor endpoints (federation.trust_anchor_mode = true) ──────────────

// taGuard returns a 404 when called without trust_anchor_mode enabled.
// Returns (issuerURL, org, nil) on success.
func (h *Handler) taGuard(c echo.Context) (string, *orgRow, error) {
	if !h.cfg.Federation.Enabled || !h.cfg.Federation.TrustAnchorMode {
		return "", nil, echo.NewHTTPError(http.StatusNotFound, "trust anchor mode not enabled")
	}
	orgSlug := c.Param("org_slug")
	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug)
	ctx := c.Request().Context()
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound, "organisation not found")
	}
	return issuer, &orgRow{id: org.ID, name: org.Name}, nil
}

type orgRow struct{ id uuid.UUID; name string }

// FetchSubordinateStatement handles GET /:org_slug/federation/fetch
//
// OIDF §7.3.2 — returns a signed Entity Statement (entity-statement+jwt)
// about the subordinate identified by the "sub" query parameter.
// "iss" must match the TA's entity ID.
//
// Example: GET /acme/federation/fetch?iss=https://ta.example.com&sub=https://rp.bank.com
func (h *Handler) FetchSubordinateStatement(c echo.Context) error {
	issuer, org, err := h.taGuard(c)
	if err != nil {
		return err
	}

	subEntityID := c.QueryParam("sub")
	if subEntityID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "missing 'sub' query parameter",
		})
	}

	ctx := c.Request().Context()
	sub, dbErr := h.fed.GetSubordinateByEntityID(ctx, org.id, subEntityID)
	if dbErr != nil {
		if errors.Is(dbErr, pgx.ErrNoRows) {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error":             "not_found",
				"error_description": "subordinate entity not registered with this trust anchor",
			})
		}
		c.Logger().Errorf("federation/fetch: get subordinate %s: %v", subEntityID, dbErr)
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: internal error")
	}
	if sub.Status != "active" {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error":             "entity_suspended",
			"error_description": "subordinate entity is " + sub.Status,
		})
	}

	taEntityID := h.cfg.Federation.TrustAnchorEntityID
	if taEntityID == "" {
		taEntityID = issuer
	}

	lifetime := DefaultLifetime
	if sub.StatementLifetime > 0 {
		lifetime = time.Duration(sub.StatementLifetime) * time.Second
	}

	// Collect issued trust marks for this subordinate as raw JSON payloads.
	var trustMarks []json.RawMessage
	for _, tmID := range sub.TrustMarkIDs {
		tm, tmErr := h.fed.GetTrustMark(ctx, org.id, tmID, subEntityID)
		if tmErr != nil || tm.Revoked || tm.ExpiresAt.Before(time.Now()) {
			continue
		}
		trustMarks = append(trustMarks, json.RawMessage(`"`+tm.IssuedJWT+`"`))
	}

	token, signErr := BuildSubordinateStatement(
		taEntityID, subEntityID,
		sub.JWKS, sub.MetadataOverride, sub.MetadataPolicy,
		sub.TrustMarkIDs, trustMarks,
		lifetime,
		issuer+"/federation/fetch",
		h.keys.CryptoSigner(), jwa.PS256, h.keys.KID(),
	)
	if signErr != nil {
		c.Logger().Errorf("federation/fetch: sign subordinate statement: %v", signErr)
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: signing error")
	}

	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Blob(http.StatusOK, ContentType, token)
}

// ListSubordinates handles GET /:org_slug/federation/list
//
// OIDF §7.3.1 — returns a JSON array of immediate subordinate entity IDs.
func (h *Handler) ListSubordinates(c echo.Context) error {
	_, org, err := h.taGuard(c)
	if err != nil {
		return err
	}

	ids, dbErr := h.fed.ListSubordinates(c.Request().Context(), org.id)
	if dbErr != nil {
		c.Logger().Errorf("federation/list: %v", dbErr)
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: internal error")
	}
	if ids == nil {
		ids = []string{}
	}
	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, ids)
}

// SubordinatesDiscovery handles GET /:org_slug/federation/subordinates
//
// Clavex extension — returns a rich JSON list of all active subordinates in
// the Trust Anchor's federation. Unlike the OIDF §7.3.1 list endpoint (which
// returns only entity IDs), this endpoint returns structured metadata and a
// freshly-signed Entity Statement JWT for each subordinate.
//
// Intended for PA (Public Administration) dashboards and governance tooling
// that need a real-time view of which services are federated.
//
// Query params:
//
//	status — filter by status: "active" (default), "suspended", "revoked", or "all"
func (h *Handler) SubordinatesDiscovery(c echo.Context) error {
	issuer, org, err := h.taGuard(c)
	if err != nil {
		return err
	}

	statusFilter := c.QueryParam("status")
	if statusFilter == "" || statusFilter == "all" {
		statusFilter = "active"
	}
	if statusFilter == "all" {
		statusFilter = ""
	}

	ctx := c.Request().Context()
	subs, dbErr := h.fed.ListSubordinatesFull(ctx, org.id, statusFilter)
	if dbErr != nil {
		c.Logger().Errorf("federation/subordinates: %v", dbErr)
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: internal error")
	}

	taEntityID := h.cfg.Federation.TrustAnchorEntityID
	if taEntityID == "" {
		taEntityID = issuer
	}
	fetchEndpoint := issuer + "/federation/fetch"

	type subordinateEntry struct {
		EntityID           string          `json:"entity_id"`
		Name               string          `json:"name,omitempty"`
		EntityTypes        []string        `json:"entity_types,omitempty"`
		Status             string          `json:"status"`
		TrustMarkIDs       []string        `json:"trust_mark_ids,omitempty"`
		StatementExpiresAt string          `json:"statement_expires_at"`
		RegisteredAt       string          `json:"registered_at"`
		UpdatedAt          string          `json:"updated_at"`
		EntityStatement    string          `json:"entity_statement"`
		Metadata           json.RawMessage `json:"metadata,omitempty"`
	}

	entries := make([]subordinateEntry, 0, len(subs))
	now := time.Now()

	for _, sub := range subs {
		lifetime := DefaultLifetime
		if sub.StatementLifetime > 0 {
			lifetime = time.Duration(sub.StatementLifetime) * time.Second
		}

		// Collect valid, non-revoked, non-expired trust marks.
		var trustMarks []json.RawMessage
		for _, tmID := range sub.TrustMarkIDs {
			tm, tmErr := h.fed.GetTrustMark(ctx, org.id, tmID, sub.EntityID)
			if tmErr != nil || tm.Revoked || tm.ExpiresAt.Before(now) {
				continue
			}
			trustMarks = append(trustMarks, json.RawMessage(`"`+tm.IssuedJWT+`"`))
		}

		token, signErr := BuildSubordinateStatement(
			taEntityID, sub.EntityID,
			sub.JWKS, sub.MetadataOverride, sub.MetadataPolicy,
			sub.TrustMarkIDs, trustMarks,
			lifetime,
			fetchEndpoint,
			h.keys.CryptoSigner(), jwa.PS256, h.keys.KID(),
		)
		if signErr != nil {
			c.Logger().Errorf("federation/subordinates: sign %s: %v", sub.EntityID, signErr)
			continue // skip this subordinate rather than aborting the whole list
		}

		expiresAt := now.Add(lifetime)
		entry := subordinateEntry{
			EntityID:           sub.EntityID,
			Name:               sub.Name,
			EntityTypes:        sub.EntityTypes,
			Status:             sub.Status,
			TrustMarkIDs:       sub.TrustMarkIDs,
			StatementExpiresAt: expiresAt.UTC().Format(time.RFC3339),
			RegisteredAt:       sub.CreatedAt.UTC().Format(time.RFC3339),
			UpdatedAt:          sub.UpdatedAt.UTC().Format(time.RFC3339),
			EntityStatement:    string(token),
			Metadata:           sub.MetadataOverride,
		}
		if entry.TrustMarkIDs == nil {
			entry.TrustMarkIDs = []string{}
		}
		entries = append(entries, entry)
	}

	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, map[string]any{
		"issuer":       taEntityID,
		"retrieved_at": now.UTC().Format(time.RFC3339),
		"count":        len(entries),
		"subordinates": entries,
	})
}

// IssueTrustMarkRequest is the body for POST /federation/trust-mark.
type IssueTrustMarkRequest struct {
	TrustMarkID string `json:"trust_mark_id"`
	Subject     string `json:"sub"`
}

// TrustMarkEndpoint handles POST /:org_slug/federation/trust-mark
//
// OIDF §7.4 — issues a signed trust-mark+jwt to a subject entity.
// The trust mark type must be registered via the admin API first.
func (h *Handler) TrustMarkEndpoint(c echo.Context) error {
	issuer, org, err := h.taGuard(c)
	if err != nil {
		return err
	}

	var req IssueTrustMarkRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "error_description": "invalid request body",
		})
	}
	if req.TrustMarkID == "" || req.Subject == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "error_description": "trust_mark_id and sub are required",
		})
	}

	ctx := c.Request().Context()

	// Verify the trust mark type exists.
	tmType, dbErr := h.fed.GetTrustMarkType(ctx, org.id, req.TrustMarkID)
	if dbErr != nil {
		if errors.Is(dbErr, pgx.ErrNoRows) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "unknown_trust_mark_id",
				"error_description": "trust mark type not registered with this trust anchor",
			})
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: internal error")
	}

	// Verify the subject is a registered subordinate.
	sub, subErr := h.fed.GetSubordinateByEntityID(ctx, org.id, req.Subject)
	if subErr != nil || sub.Status != "active" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "unknown_subject",
			"error_description": "subject is not an active subordinate of this trust anchor",
		})
	}

	taEntityID := h.cfg.Federation.TrustAnchorEntityID
	if taEntityID == "" {
		taEntityID = issuer
	}

	lifetime := time.Duration(tmType.LifetimeSecs) * time.Second
	if lifetime == 0 {
		lifetime = 365 * 24 * time.Hour
	}

	jwt, expiresAt, signErr := IssueTrustMark(
		taEntityID, req.Subject, req.TrustMarkID,
		tmType.LogoURI, tmType.RefURI,
		lifetime,
		h.keys.CryptoSigner(), jwa.PS256, h.keys.KID(),
	)
	if signErr != nil {
		c.Logger().Errorf("federation/trust-mark: sign: %v", signErr)
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: signing error")
	}

	if _, storeErr := h.fed.IssueTrustMark(ctx, repository.IssueTrustMarkParams{
		OrgID:       org.id,
		TrustMarkID: req.TrustMarkID,
		Subject:     req.Subject,
		IssuedJWT:   jwt,
		ExpiresAt:   expiresAt,
	}); storeErr != nil {
		c.Logger().Errorf("federation/trust-mark: persist: %v", storeErr)
		h.fedAudit(c, org.id, "federation.trust_mark.issue", req.Subject, "failure", map[string]any{
			"trust_mark_id": req.TrustMarkID,
		})
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: store error")
	}
	h.fedAudit(c, org.id, "federation.trust_mark.issue", req.Subject, "success", map[string]any{
		"trust_mark_id": req.TrustMarkID,
		"expires_at":    expiresAt.Format(time.RFC3339),
	})

	// OIDF §7.4 — response is the raw compact JWS.
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Blob(http.StatusOK, "application/trust-mark+jwt", []byte(jwt))
}

// TrustMarkListEndpoint handles GET /:org_slug/federation/trust-mark/list
//
// OIDF §7.5 — returns a JSON array of subject entity IDs holding the
// given trust mark (active, non-expired, non-revoked).
func (h *Handler) TrustMarkListEndpoint(c echo.Context) error {
	_, org, err := h.taGuard(c)
	if err != nil {
		return err
	}

	trustMarkID := c.QueryParam("trust_mark_id")
	if trustMarkID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "error_description": "missing trust_mark_id",
		})
	}

	subjects, dbErr := h.fed.ListTrustMarkSubjects(c.Request().Context(), org.id, trustMarkID)
	if dbErr != nil {
		c.Logger().Errorf("federation/trust-mark/list: %v", dbErr)
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: internal error")
	}
	if subjects == nil {
		subjects = []string{}
	}
	return c.JSON(http.StatusOK, subjects)
}

// TrustMarkStatusEndpoint handles GET /:org_slug/federation/trust-mark/status
//
// OIDF §7.6 — returns {"active": true|false} for the given
// (trust_mark_id, sub) pair.
func (h *Handler) TrustMarkStatusEndpoint(c echo.Context) error {
	_, org, err := h.taGuard(c)
	if err != nil {
		return err
	}

	trustMarkID := c.QueryParam("trust_mark_id")
	sub := c.QueryParam("sub")
	if trustMarkID == "" || sub == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "error_description": "trust_mark_id and sub are required",
		})
	}

	tm, dbErr := h.fed.GetTrustMark(c.Request().Context(), org.id, trustMarkID, sub)
	if dbErr != nil {
		if errors.Is(dbErr, pgx.ErrNoRows) {
			return c.JSON(http.StatusOK, map[string]bool{"active": false})
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "federation: internal error")
	}

	active := !tm.Revoked && tm.ExpiresAt.After(time.Now())
	return c.JSON(http.StatusOK, map[string]bool{"active": active})
}


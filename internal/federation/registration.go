package federation

// Trust chain validation for OpenID Federation 1.0 explicit registration.
//
// Specifications:
//   - OIDF 1.0 §9    Trust Chains
//   - OIDF 1.0 §9.6  Explicit Client Registration
//   - OIDF 1.0 §5    Metadata Policies
//
// # Registration flow
//
//  1. The RP sends a signed Entity Statement (self-issued) to POST /federation/register.
//  2. We parse the JWT payload to obtain the RP's entity_id (iss/sub) and
//     its openid_relying_party metadata.
//  3. We fetch the RP's Entity Configuration from {iss}/.well-known/openid-federation
//     and verify the registration JWT signature against the RP's JWKS.
//  4. We resolve the trust chain: if the JWT carries a `trust_chain` claim we
//     use that; otherwise we walk the RP's authority_hints upward.
//  5. For every entity statement in the chain we fetch the issuer's EC to
//     obtain its JWKS and verify the signature.
//  6. We confirm the chain terminates at one of the configured trust anchors.
//  7. We apply any metadata policies collected along the chain (scope
//     intersection, redirect_uri filtering).
//  8. The caller receives a validated *RPRegistrationData ready for DB upsert.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// ── RP registration metadata ──────────────────────────────────────────────────

// RPRegistrationData is the result of a successful trust chain validation.
// All fields are policy-filtered (intersected with the chain's metadata policy).
type RPRegistrationData struct {
	// EntityID is the RP's OIDF entity identifier (same as iss/sub in the JWT).
	EntityID string
	// Name is the RP's human-readable client name (client_name claim).
	Name string
	// RedirectURIs are the RP's allowed redirect endpoints.
	RedirectURIs []string
	// PostLogoutRedirectURIs are the RP's post-logout redirect endpoints.
	PostLogoutRedirectURIs []string
	// GrantTypes lists the OAuth 2.0 grant types the RP requests.
	GrantTypes []string
	// ResponseTypes lists the OIDC response types.
	ResponseTypes []string
	// Scopes is the policy-filtered list of scopes the RP may request.
	Scopes []string
	// Contacts is the RP operator's contact list.
	Contacts []string
	// LogoURI is the RP's application logo.
	LogoURI string
	// JWKSUri is the RP's JWKS endpoint.
	JWKSUri string
	// JWKS is the RP's inline public key set (used when JWKSUri is absent).
	JWKS json.RawMessage
	// TokenEndpointAuthMethod is always "private_key_jwt" for federation clients.
	TokenEndpointAuthMethod string
}

// rpOIDCMetadata mirrors the openid_relying_party metadata sub-object.
type rpOIDCMetadata struct {
	RedirectURIs            []string        `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string        `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes              []string        `json:"grant_types,omitempty"`
	ResponseTypes           []string        `json:"response_types,omitempty"`
	Scope                   string          `json:"scope,omitempty"`
	ClientName              string          `json:"client_name,omitempty"`
	LogoURI                 string          `json:"logo_uri,omitempty"`
	Contacts                []string        `json:"contacts,omitempty"`
	JWKSUri                 string          `json:"jwks_uri,omitempty"`
	JWKS                    json.RawMessage `json:"jwks,omitempty"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method,omitempty"`
}

// entityStatementClaims holds the claims we care about inside any entity statement.
type entityStatementClaims struct {
	Issuer         string          `json:"iss"`
	Subject        string          `json:"sub"`
	IssuedAt       int64           `json:"iat"`
	ExpiresAt      int64           `json:"exp"`
	JWKS           json.RawMessage `json:"jwks,omitempty"`
	AuthorityHints []string        `json:"authority_hints,omitempty"`
	// Metadata contains entity-type-specific sub-objects.
	Metadata struct {
		OpenIDRelyingParty *rpOIDCMetadata `json:"openid_relying_party,omitempty"`
	} `json:"metadata,omitempty"`
	// TrustChain carries an inline chain from the RP (OIDF §9.5).
	TrustChain []string `json:"trust_chain,omitempty"`
	// MetadataPolicy carries OIDF metadata policies applied by intermediates/TA.
	MetadataPolicy struct {
		OpenIDRelyingParty *rpMetadataPolicy `json:"openid_relying_party,omitempty"`
	} `json:"metadata_policy,omitempty"`
}

// rpMetadataPolicy holds the parts of a metadata policy relevant to us.
type rpMetadataPolicy struct {
	Scope struct {
		Subset  []string `json:"subset,omitempty"`
		Superset []string `json:"superset,omitempty"`
		OneOf   []string `json:"one_of,omitempty"`
		Value   string   `json:"value,omitempty"`
	} `json:"scope,omitempty"`
	GrantTypes struct {
		Subset []string `json:"subset,omitempty"`
	} `json:"grant_types,omitempty"`
	ResponseTypes struct {
		Subset []string `json:"subset,omitempty"`
	} `json:"response_types,omitempty"`
}

// ── Resolver ──────────────────────────────────────────────────────────────────

// Resolver validates OpenID Federation 1.0 trust chains for explicit registration.
type Resolver struct {
	hc           *http.Client
	trustAnchors map[string]struct{} // entity IDs we accept as trust anchors
}

// NewResolver constructs a Resolver. trustAnchors must be non-empty for
// explicit registration to work. An http.Client with a 10-second timeout is
// used by default.
func NewResolver(trustAnchors []string) *Resolver {
	tas := make(map[string]struct{}, len(trustAnchors))
	for _, ta := range trustAnchors {
		tas[strings.TrimRight(ta, "/")] = struct{}{}
	}
	return &Resolver{
		hc:           defaultHTTPClient,
		trustAnchors: tas,
	}
}

// defaultHTTPClient is SSRF-guarded: federation entity endpoints are resolved
// from RP-supplied entity IDs, so private/loopback targets are blocked unless
// the operator opts in via SetDefaultHTTPClient.
var defaultHTTPClient = safehttp.Client(10*time.Second, false)

// SetDefaultHTTPClient overrides the client used by resolvers created afterward
// (SSRF-relaxed opt-in wired from the server when
// http.allow_private_outbound_targets is set).
func SetDefaultHTTPClient(hc *http.Client) {
	if hc != nil {
		defaultHTTPClient = hc
	}
}

// WithHTTPClient overrides the outbound HTTP client for this resolver.
func (r *Resolver) WithHTTPClient(hc *http.Client) *Resolver {
	if hc != nil {
		r.hc = hc
	}
	return r
}

// Validate validates the RP's registration request JWT, resolves the trust
// chain, and returns the policy-filtered RP metadata if everything checks out.
//
//   - registrationJWT is the raw compact JWS from the POST body.
//   - The resolver fetches entity configurations as needed via HTTPS.
func (r *Resolver) Validate(ctx context.Context, registrationJWT []byte) (*RPRegistrationData, error) {
	// ── Step 1: parse the registration request (do NOT verify yet) ───────────
	regClaims, err := parseEntityStatement(registrationJWT)
	if err != nil {
		return nil, fmt.Errorf("federation: parse registration JWT: %w", err)
	}
	if regClaims.Issuer == "" || regClaims.Subject == "" {
		return nil, fmt.Errorf("federation: registration JWT missing iss/sub")
	}
	if regClaims.Issuer != regClaims.Subject {
		return nil, fmt.Errorf("federation: registration JWT iss (%s) != sub (%s): must be self-issued", regClaims.Issuer, regClaims.Subject)
	}
	rpEntityID := regClaims.Issuer

	// Check expiry.
	if regClaims.ExpiresAt > 0 && time.Now().Unix() > regClaims.ExpiresAt {
		return nil, fmt.Errorf("federation: registration JWT has expired")
	}

	// ── Step 2: fetch the RP's Entity Configuration to get its JWKS ──────────
	rpEC, err := r.fetchEntityConfig(ctx, rpEntityID)
	if err != nil {
		return nil, fmt.Errorf("federation: fetch RP entity config at %s: %w", rpEntityID, err)
	}
	rpJWKS, err := parseJWKS(rpEC.JWKS)
	if err != nil {
		return nil, fmt.Errorf("federation: parse RP JWKS: %w", err)
	}

	// ── Step 3: verify the registration JWT signature ─────────────────────────
	if err := verifyWithJWKS(registrationJWT, rpJWKS); err != nil {
		return nil, fmt.Errorf("federation: registration JWT signature invalid: %w", err)
	}

	// ── Step 4: resolve the trust chain ──────────────────────────────────────
	// Use the inline trust_chain from the registration JWT if provided (OIDF §9.5).
	// Otherwise fall back to walking authority_hints.
	var chain []string
	if len(regClaims.TrustChain) > 0 {
		chain = regClaims.TrustChain
	} else {
		// Walk authority hints from the RP's Entity Configuration.
		chain, err = r.resolveChain(ctx, rpEntityID, rpEC.AuthorityHints)
		if err != nil {
			return nil, fmt.Errorf("federation: resolve trust chain: %w", err)
		}
	}

	// ── Step 5: validate the chain ────────────────────────────────────────────
	policies, err := r.validateChain(ctx, rpEntityID, chain)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid trust chain: %w", err)
	}

	// ── Step 6: extract RP openid_relying_party metadata ─────────────────────
	rpMeta := regClaims.Metadata.OpenIDRelyingParty
	if rpMeta == nil {
		// Fall back to RP's own EC metadata.
		rpMeta = rpEC.Metadata.OpenIDRelyingParty
	}
	if rpMeta == nil {
		return nil, fmt.Errorf("federation: RP has no openid_relying_party metadata")
	}
	if len(rpMeta.RedirectURIs) == 0 {
		return nil, fmt.Errorf("federation: RP metadata has no redirect_uris")
	}

	// ── Step 7: apply metadata policies ──────────────────────────────────────
	result := buildRegistrationData(rpEntityID, rpMeta, rpEC.JWKS, policies)
	return result, nil
}

// ValidateByEntityID performs automatic federation registration (OIDF 1.0 §10.2)
// for an RP identified by its entity ID URL. Unlike Validate(), no registration
// JWT is needed — the RP's Entity Configuration is fetched directly and the
// trust chain is resolved from its authority_hints.
//
// This is the server-side counterpart of automatic client registration: the OP
// fetches and validates the RP's metadata on demand, the first time an unknown
// entity ID is used as client_id in an authorization request.
func (r *Resolver) ValidateByEntityID(ctx context.Context, entityID string) (*RPRegistrationData, error) {
	if len(r.trustAnchors) == 0 {
		return nil, fmt.Errorf("federation: no trust anchors configured")
	}

	// ── Step 1: fetch the RP's Entity Configuration ───────────────────────────
	rpEC, err := r.fetchEntityConfig(ctx, entityID)
	if err != nil {
		return nil, fmt.Errorf("federation: fetch RP entity config at %s: %w", entityID, err)
	}

	// Self-issued: iss and sub must both equal the entityID.
	if rpEC.Issuer != entityID || rpEC.Subject != entityID {
		return nil, fmt.Errorf("federation: entity config iss/sub mismatch for %s (iss=%s sub=%s)",
			entityID, rpEC.Issuer, rpEC.Subject)
	}

	// Check expiry.
	if rpEC.ExpiresAt > 0 && time.Now().Unix() > rpEC.ExpiresAt {
		return nil, fmt.Errorf("federation: entity config expired for %s", entityID)
	}

	// ── Step 2: extract openid_relying_party metadata ─────────────────────────
	rpMeta := rpEC.Metadata.OpenIDRelyingParty
	if rpMeta == nil {
		return nil, fmt.Errorf("federation: RP %s has no openid_relying_party metadata", entityID)
	}
	if len(rpMeta.RedirectURIs) == 0 {
		return nil, fmt.Errorf("federation: RP %s metadata has no redirect_uris", entityID)
	}

	// ── Step 3: resolve trust chain via authority_hints ───────────────────────
	chain, err := r.resolveChain(ctx, entityID, rpEC.AuthorityHints)
	if err != nil {
		return nil, fmt.Errorf("federation: resolve trust chain for %s: %w", entityID, err)
	}

	// ── Step 4: validate chain and collect metadata policies ──────────────────
	policies, err := r.validateChain(ctx, entityID, chain)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid trust chain for %s: %w", entityID, err)
	}

	return buildRegistrationData(entityID, rpMeta, rpEC.JWKS, policies), nil
}

// ── Chain resolution ──────────────────────────────────────────────────────────

// resolveChain walks authority_hints to build the trust chain as a slice of
// compact JWS entity statements, starting from the RP leaf and ending at the
// trust anchor.
func (r *Resolver) resolveChain(ctx context.Context, rpEntityID string, authorityHints []string) ([]string, error) {
	var chain []string
	visited := map[string]bool{rpEntityID: true}

	for _, hint := range authorityHints {
		hint = strings.TrimRight(hint, "/")
		if visited[hint] {
			continue
		}
		visited[hint] = true

		// Fetch the intermediate/TA entity statement about the previous entity.
		raw, err := r.fetchEntityStatement(ctx, hint, rpEntityID)
		if err != nil {
			// This hint cannot provide a statement — try the next one.
			continue
		}
		chain = append(chain, string(raw))

		if _, isTrustAnchor := r.trustAnchors[hint]; isTrustAnchor {
			// Found a path to a trust anchor — chain is complete.
			return chain, nil
		}

		// Not a TA yet — fetch the intermediate's own EC and recurse up.
		interEC, err := r.fetchEntityConfig(ctx, hint)
		if err != nil {
			continue
		}
		subChain, err := r.resolveChain(ctx, hint, interEC.AuthorityHints)
		if err != nil {
			continue
		}
		chain = append(chain, subChain...)
		return chain, nil
	}
	return nil, fmt.Errorf("no path to a configured trust anchor found via authority_hints %v", authorityHints)
}

// validateChain verifies every entity statement in the chain, checking that:
//   - signatures are valid (using the issuer's EC JWKS)
//   - the chain terminates at a configured trust anchor
//   - the subject of the lowest statement is the expected RP
//
// Returns the collected metadata policies from intermediate entities and TA.
func (r *Resolver) validateChain(ctx context.Context, rpEntityID string, chain []string) ([]*rpMetadataPolicy, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty trust chain")
	}

	// Build a map of entity statements keyed by (iss, sub).
	type esKey struct{ iss, sub string }
	stmts := make(map[esKey]*entityStatementClaims, len(chain))
	rawStmts := make(map[esKey][]byte, len(chain))
	for _, compact := range chain {
		claims, err := parseEntityStatement([]byte(compact))
		if err != nil {
			return nil, fmt.Errorf("parse entity statement in chain: %w", err)
		}
		k := esKey{claims.Issuer, claims.Subject}
		stmts[k] = claims
		rawStmts[k] = []byte(compact)
	}

	// Locate the trust anchor — there must be at least one statement where iss ∈ TAs.
	var taEntityID string
	for k := range stmts {
		if _, ok := r.trustAnchors[k.iss]; ok {
			taEntityID = k.iss
			break
		}
	}
	if taEntityID == "" {
		return nil, fmt.Errorf("trust chain does not contain a statement from a configured trust anchor (accepted: %v)", r.trustAnchorList())
	}

	// Walk the chain from the TA downward to the RP, verifying each statement.
	var policies []*rpMetadataPolicy
	current := taEntityID
	for current != rpEntityID {
		// Find what this entity attests about (the next step downward).
		var nextEntityID string
		var stmt *entityStatementClaims
		var raw []byte
		for k, s := range stmts {
			if k.iss == current && k.sub != current {
				nextEntityID = k.sub
				stmt = s
				raw = rawStmts[k]
				break
			}
		}
		if stmt == nil {
			return nil, fmt.Errorf("trust chain: no entity statement found from %s toward RP %s", current, rpEntityID)
		}

		// Verify signature: fetch the current entity's EC to obtain its JWKS.
		issuerEC, err := r.fetchEntityConfig(ctx, current)
		if err != nil {
			return nil, fmt.Errorf("trust chain: cannot fetch entity config of %s: %w", current, err)
		}
		issuerJWKS, err := parseJWKS(issuerEC.JWKS)
		if err != nil {
			return nil, fmt.Errorf("trust chain: bad JWKS from %s: %w", current, err)
		}
		if err := verifyWithJWKS(raw, issuerJWKS); err != nil {
			return nil, fmt.Errorf("trust chain: entity statement from %s about %s has invalid signature: %w", current, nextEntityID, err)
		}

		// Collect metadata policy.
		if stmt.MetadataPolicy.OpenIDRelyingParty != nil {
			policies = append(policies, stmt.MetadataPolicy.OpenIDRelyingParty)
		}

		// Check expiry.
		if stmt.ExpiresAt > 0 && time.Now().Unix() > stmt.ExpiresAt {
			return nil, fmt.Errorf("trust chain: entity statement from %s about %s has expired", current, nextEntityID)
		}

		current = nextEntityID
	}
	return policies, nil
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

// fetchEntityConfig fetches and parses the entity configuration at
// {entityID}/.well-known/openid-federation.
// The JWT is NOT signature-verified here — the caller must verify it separately
// using the entity's own JWKS (bootstrapped or trusted).
func (r *Resolver) fetchEntityConfig(ctx context.Context, entityID string) (*entityStatementClaims, error) {
	base := strings.TrimRight(entityID, "/")
	u := base + "/.well-known/openid-federation"
	raw, err := r.getJWT(ctx, u)
	if err != nil {
		return nil, err
	}
	return parseEntityStatement(raw)
}

// fetchEntityStatement fetches the entity statement that issuerID makes about subjectID.
// OIDF §6.3: GET {issuer}/fetch?iss={iss}&sub={sub}  OR  GET {issuer}/.well-known/openid-federation-fetch?...
func (r *Resolver) fetchEntityStatement(ctx context.Context, issuerID, subjectID string) ([]byte, error) {
	base := strings.TrimRight(issuerID, "/")
	// Try the standard fetch endpoint first.
	fetchURL := fmt.Sprintf("%s/fetch?iss=%s&sub=%s", base, issuerID, subjectID)
	raw, err := r.getJWT(ctx, fetchURL)
	if err != nil {
		// Fallback: some federations expose a different path.
		fetchURL = fmt.Sprintf("%s/.well-known/openid-federation?sub=%s", base, subjectID)
		raw, err = r.getJWT(ctx, fetchURL)
	}
	return raw, err
}

// getJWT performs a GET request and returns the response body as raw bytes.
// It accepts `application/entity-statement+jwt`, `application/jose`, and `text/plain`.
func (r *Resolver) getJWT(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", ContentType+", application/jose, text/plain")

	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}
	return bytes.TrimSpace(body), nil
}

// ── JWS helpers ───────────────────────────────────────────────────────────────

// parseEntityStatement parses a compact JWS (without signature verification)
// and decodes the payload as entityStatementClaims.
func parseEntityStatement(compact []byte) (*entityStatementClaims, error) {
	msg, err := jws.Parse(compact)
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %w", err)
	}
	if len(msg.Signatures()) == 0 {
		return nil, fmt.Errorf("JWS has no signatures")
	}
	var claims entityStatementClaims
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		return nil, fmt.Errorf("unmarshal entity statement claims: %w", err)
	}
	return &claims, nil
}

// parseJWKS parses a raw JSON JWKS into a jwk.Set.
func parseJWKS(raw json.RawMessage) (jwk.Set, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty JWKS")
	}
	ks, err := jwk.ParseString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	return ks, nil
}

// verifyWithJWKS verifies the JWS signature against any key in the key set.
func verifyWithJWKS(compact []byte, ks jwk.Set) error {
	_, err := jws.Verify(compact, jws.WithKeySet(ks, jws.WithInferAlgorithmFromKey(true)))
	return err
}

// ── Metadata policy ───────────────────────────────────────────────────────────

// buildRegistrationData combines the RP's requested metadata with the
// policy-filtered values from the trust chain.
func buildRegistrationData(entityID string, rp *rpOIDCMetadata, rpECJWKS json.RawMessage, policies []*rpMetadataPolicy) *RPRegistrationData {
	scopes := parseScopes(rp.Scope)
	for _, p := range policies {
		scopes = applySubsetPolicy(scopes, p.Scope.Subset)
	}
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	grantTypes := rp.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	for _, p := range policies {
		grantTypes = applySubsetPolicy(grantTypes, p.GrantTypes.Subset)
	}

	responseTypes := rp.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	for _, p := range policies {
		responseTypes = applySubsetPolicy(responseTypes, p.ResponseTypes.Subset)
	}

	// Protocol keys (used to verify the RP's request objects) come from the
	// openid_relying_party metadata. Prefer an inline JWKS; otherwise the RP
	// advertises a jwks_uri that is resolved live at JAR-verification time, so
	// the inline JWKS is left empty. Only when the RP exposes neither do we fall
	// back to the entity's federation JWKS — that key signs entity statements,
	// not protocol messages, and using it here would break request-object
	// signature verification.
	jwks := rp.JWKS
	if len(jwks) == 0 && rp.JWKSUri == "" {
		jwks = rpECJWKS
	}

	authMethod := rp.TokenEndpointAuthMethod
	if authMethod == "" || authMethod == "private_key_jwt" || authMethod == "none" {
		// Federation clients always use private_key_jwt (OIDF §10.2).
		authMethod = "private_key_jwt"
	}

	name := rp.ClientName
	if name == "" {
		name = entityID
	}

	return &RPRegistrationData{
		EntityID:                entityID,
		Name:                    name,
		RedirectURIs:            rp.RedirectURIs,
		PostLogoutRedirectURIs:  rp.PostLogoutRedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scopes:                  scopes,
		Contacts:                rp.Contacts,
		LogoURI:                 rp.LogoURI,
		JWKSUri:                 rp.JWKSUri,
		JWKS:                    jwks,
		TokenEndpointAuthMethod: authMethod,
	}
}

// parseScopes splits a space-separated scope string into a slice.
func parseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

// applySubsetPolicy intersects values with the policy subset (if non-empty).
func applySubsetPolicy(values, subset []string) []string {
	if len(subset) == 0 {
		return values
	}
	allowed := make(map[string]bool, len(subset))
	for _, s := range subset {
		allowed[s] = true
	}
	var out []string
	for _, v := range values {
		if allowed[v] {
			out = append(out, v)
		}
	}
	return out
}

func (r *Resolver) trustAnchorList() []string {
	out := make([]string, 0, len(r.trustAnchors))
	for ta := range r.trustAnchors {
		out = append(out, ta)
	}
	return out
}

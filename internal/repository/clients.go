package repository

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ClientRepository manages OIDC client registrations.
type ClientRepository struct {
	pool *pgxpool.Pool
}

func NewClientRepository(pool *pgxpool.Pool) *ClientRepository {
	return &ClientRepository{pool: pool}
}

// Create registers a new OIDC client. Returns the client and the plain-text
// secret (shown only once). For public clients the secret is empty.
// An entity event (client.created) is written atomically in the same transaction.
// emptyToNil returns nil for an empty slice so a SQL COALESCE / CASE falls back
// to the column default (or leaves the column unchanged on update) instead of
// persisting an empty array.
func emptyToNil(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// Create inserts a new OIDC client. grantTypes, responseTypes, postLogout and
// isActive are honoured when provided (non-empty / non-nil); pass empty/nil to
// fall back to the column defaults ('{authorization_code}', '{code}', '{}',
// TRUE). Persisting them matters for declarative clients (the Kubernetes
// operator): otherwise a CR that sets grant_types would never converge, since
// the live client keeps the default and every reconcile re-detects "drift".
func (r *ClientRepository) Create(ctx context.Context, orgID uuid.UUID, customClientID, name string, redirectURIs, postLogout, grantTypes, responseTypes []string, isActive *bool, isPublic bool) (*models.OIDCClient, string, error) {
	clientID := customClientID
	if clientID == "" {
		clientID = generateID(24)
	}
	var secretHash *string
	var plainSecret string

	if !isPublic {
		plain, hash, err := generateSecret()
		if err != nil {
			return nil, "", err
		}
		plainSecret = plain
		secretHash = &hash
	}

	authMethod := "client_secret_basic"
	if isPublic {
		authMethod = "none"
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)

	client := &models.OIDCClient{}
	if err = tx.QueryRow(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name, redirect_uris, client_secret_hash, token_endpoint_auth_method,
			post_logout_redirect_uris, grant_types, response_types, is_active)
		VALUES ($1, $2, $3, $4, $5, $6,
			COALESCE($7::text[], '{}'),
			COALESCE($8::text[], '{authorization_code}'),
			COALESCE($9::text[], '{code}'),
			COALESCE($10::bool, TRUE))
		RETURNING client_id, org_id, name, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, logo_url, is_active, mfa_required, keycloak_compat, metadata, jwks_uri, request_object_signing_alg, jwks, created_at, updated_at
	`, clientID, orgID, name, redirectURIs, secretHash, authMethod,
		emptyToNil(postLogout), emptyToNil(grantTypes), emptyToNil(responseTypes), isActive).Scan(
		&client.ClientID, &client.OrgID, &client.Name,
		&client.RedirectURIs, &client.PostLogoutRedirectURIs,
		&client.GrantTypes, &client.ResponseTypes, &client.Scopes,
		&client.TokenEndpointAuthMethod, &client.LogoURL,
		&client.IsActive, &client.MFARequired, &client.KeycloakCompat,
		&client.Metadata, &client.JWKSUri, &client.RequestObjectSigningAlg, &client.JWKS,
		&client.CreatedAt, &client.UpdatedAt,
	); err != nil {
		return nil, "", err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "client",
		EntityID:   client.ClientID,
		EventType:  "client.created",
		Payload:    map[string]any{"name": client.Name, "is_public": isPublic},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, "", err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return client, plainSecret, nil
}

func (r *ClientRepository) GetByClientID(ctx context.Context, clientID string) (*models.OIDCClient, error) {
	c := &models.OIDCClient{}
	err := r.pool.QueryRow(ctx, `
		SELECT client_id, org_id, client_secret_hash, name, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, allowed_audiences, token_endpoint_auth_method, logo_url, is_active, mfa_required, keycloak_compat, metadata, jwks_uri, request_object_signing_alg, id_token_signed_response_alg, userinfo_signed_response_alg, jwks, tls_client_auth_subject_dn, tls_client_auth_san_dns, dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens, require_pkce, require_par, access_token_ttl, refresh_token_ttl, created_at, updated_at
		FROM oidc_clients WHERE client_id = $1
	`, clientID).Scan(
		&c.ClientID, &c.OrgID, &c.ClientSecretHash, &c.Name,
		&c.RedirectURIs, &c.PostLogoutRedirectURIs,
		&c.GrantTypes, &c.ResponseTypes, &c.Scopes, &c.AllowedAudiences,
		&c.TokenEndpointAuthMethod, &c.LogoURL,
		&c.IsActive, &c.MFARequired, &c.KeycloakCompat,
		&c.Metadata, &c.JWKSUri, &c.RequestObjectSigningAlg, &c.IDTokenSignedResponseAlg, &c.UserInfoSignedResponseAlg, &c.JWKS,
		&c.TLSClientAuthSubjectDN, &c.TLSClientAuthSANDNS, &c.DpopBoundAccessTokens, &c.TLSClientCertBoundAccessTokens, &c.RequirePKCE, &c.RequirePAR,
		&c.AccessTokenTTL, &c.RefreshTokenTTL,
		&c.CreatedAt, &c.UpdatedAt,
	)
	return c, err
}

// GetForOrg loads a client only when it belongs to orgID. Use this on admin
// (tenant-scoped) paths instead of GetByClientID, which is intentionally global
// for the OIDC runtime. Returns ErrNoRows on a cross-tenant or missing client.
func (r *ClientRepository) GetForOrg(ctx context.Context, clientID string, orgID uuid.UUID) (*models.OIDCClient, error) {
	c, err := r.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if c.OrgID != orgID {
		return nil, pgx.ErrNoRows
	}
	return c, nil
}

func (r *ClientRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.OIDCClient, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT client_id, org_id, name, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, logo_url, is_active, mfa_required, keycloak_compat, metadata, jwks_uri, request_object_signing_alg, jwks, access_token_ttl, refresh_token_ttl, created_at, updated_at
		FROM oidc_clients WHERE org_id = $1 ORDER BY name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	clients := make([]*models.OIDCClient, 0)
	for rows.Next() {
		c := &models.OIDCClient{}
		if err := rows.Scan(
			&c.ClientID, &c.OrgID, &c.Name,
			&c.RedirectURIs, &c.PostLogoutRedirectURIs,
			&c.GrantTypes, &c.ResponseTypes, &c.Scopes,
			&c.TokenEndpointAuthMethod, &c.LogoURL,
			&c.IsActive, &c.MFARequired, &c.KeycloakCompat,
			&c.Metadata, &c.JWKSUri, &c.RequestObjectSigningAlg, &c.JWKS,
			&c.AccessTokenTTL, &c.RefreshTokenTTL,
			&c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

// Update mutates a client. orgID scopes the write to the owning organization so
// an admin of another tenant cannot modify a client by its (globally unique)
// client_id; a mismatch returns pgx.ErrNoRows.
func (r *ClientRepository) Update(ctx context.Context, clientID string, orgID uuid.UUID, name *string, redirectURIs []string, isActive *bool, mfaRequired *bool, keycloakCompat *bool, accessTokenTTL *int, refreshTokenTTL *int, grantTypes, responseTypes, postLogout []string) (*models.OIDCClient, error) {
	c := &models.OIDCClient{}
	err := r.pool.QueryRow(ctx, `
		UPDATE oidc_clients SET
			name             = COALESCE($2, name),
			redirect_uris    = CASE WHEN $3::text[] IS NOT NULL THEN $3 ELSE redirect_uris END,
			is_active        = COALESCE($4, is_active),
			mfa_required     = COALESCE($5, mfa_required),
			keycloak_compat  = COALESCE($6, keycloak_compat),
			access_token_ttl  = CASE WHEN $7::int IS NULL THEN access_token_ttl WHEN $7::int = 0 THEN NULL ELSE $7::int END,
			refresh_token_ttl = CASE WHEN $8::int IS NULL THEN refresh_token_ttl WHEN $8::int = 0 THEN NULL ELSE $8::int END,
			grant_types      = CASE WHEN $10::text[] IS NOT NULL THEN $10 ELSE grant_types END,
			response_types   = CASE WHEN $11::text[] IS NOT NULL THEN $11 ELSE response_types END,
			post_logout_redirect_uris = CASE WHEN $12::text[] IS NOT NULL THEN $12 ELSE post_logout_redirect_uris END,
			updated_at       = NOW()
		WHERE client_id = $1 AND org_id = $9
		RETURNING client_id, org_id, name, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, logo_url, is_active, mfa_required, keycloak_compat, metadata, jwks_uri, request_object_signing_alg, jwks, access_token_ttl, refresh_token_ttl, created_at, updated_at
	`, clientID, name, redirectURIs, isActive, mfaRequired, keycloakCompat, accessTokenTTL, refreshTokenTTL, orgID,
		emptyToNil(grantTypes), emptyToNil(responseTypes), emptyToNil(postLogout)).Scan(
		&c.ClientID, &c.OrgID, &c.Name,
		&c.RedirectURIs, &c.PostLogoutRedirectURIs,
		&c.GrantTypes, &c.ResponseTypes, &c.Scopes,
		&c.TokenEndpointAuthMethod, &c.LogoURL,
		&c.IsActive, &c.MFARequired, &c.KeycloakCompat,
		&c.Metadata, &c.JWKSUri, &c.RequestObjectSigningAlg, &c.JWKS,
		&c.AccessTokenTTL, &c.RefreshTokenTTL,
		&c.CreatedAt, &c.UpdatedAt,
	)
	return c, err
}

// Delete removes a client, scoped to its owning organization (org_id) so a
// cross-tenant client_id cannot be deleted. Returns ErrNoRows when nothing matched.
func (r *ClientRepository) Delete(ctx context.Context, clientID string, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM oidc_clients WHERE client_id = $1 AND org_id = $2`, clientID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// SetEnabledLoginProviders replaces the enabled_login_providers array for a client.
// Pass an empty slice to revert to the default (show all active providers).
func (r *ClientRepository) SetEnabledLoginProviders(ctx context.Context, clientID string, orgID uuid.UUID, providers []string) error {
	if providers == nil {
		providers = []string{}
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE oidc_clients SET enabled_login_providers = $1, updated_at = NOW()
		WHERE client_id = $2 AND org_id = $3
	`, providers, clientID, orgID)
	return err
}

// RotateSecret generates a new client secret, stores its hash, and returns
// the plain-text value (shown only once).
// An entity event (client.secret_rotated) is written atomically in the same transaction.
func (r *ClientRepository) RotateSecret(ctx context.Context, clientID string, wantOrgID uuid.UUID) (string, error) {
	plain, hash, err := generateSecret()
	if err != nil {
		return "", err
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	// Scope the rotation to the owning org so a cross-tenant client_id cannot have
	// its secret rotated (and exfiltrated). No row → pgx.ErrNoRows.
	var orgID uuid.UUID
	if err = tx.QueryRow(ctx,
		`UPDATE oidc_clients SET client_secret_hash = $2, updated_at = NOW() WHERE client_id = $1 AND org_id = $3 RETURNING org_id`,
		clientID, hash, wantOrgID,
	).Scan(&orgID); err != nil {
		return "", err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "client",
		EntityID:   clientID,
		EventType:  "client.secret_rotated",
		Payload:    map[string]any{"rotated_at": time.Now().UTC().Format(time.RFC3339)},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return "", err
	}

	return plain, tx.Commit(ctx)
}

// RegisterClientParams holds RFC 7591 metadata for dynamic client registration.
type RegisterClientParams struct {
	OrgID                     uuid.UUID
	Name                      string
	RedirectURIs              []string
	PostLogoutRedirectURIs    []string
	GrantTypes                []string
	ResponseTypes             []string
	TokenEndpointAuthMethod   string
	JWKSUri                   *string
	JWKS                      *json.RawMessage
	IDTokenSignedResponseAlg  string
	UserInfoSignedResponseAlg string
	// DpopBoundAccessTokens mirrors the RFC 9449 §5 client metadata field.
	// When true the token endpoint will require a DPoP proof on every request.
	DpopBoundAccessTokens bool
	// TLSClientCertBoundAccessTokens mirrors the RFC 8705 §3 client metadata field.
	// When true the token endpoint will require a TLS client certificate on every request.
	TLSClientCertBoundAccessTokens bool
}

// RegisterClient creates a new OIDC client via dynamic registration (RFC 7591).
// Always issues a client_secret (confidential client). Returns the client and
// the plain-text secret which must be shown to the caller exactly once.
func (r *ClientRepository) RegisterClient(ctx context.Context, p RegisterClientParams) (*models.OIDCClient, string, error) {
	if p.Name == "" {
		p.Name = "Dynamically Registered Client"
	}
	if len(p.GrantTypes) == 0 {
		p.GrantTypes = []string{"authorization_code"}
	}
	if len(p.ResponseTypes) == 0 {
		p.ResponseTypes = []string{"code"}
	}
	if p.TokenEndpointAuthMethod == "" {
		p.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if p.PostLogoutRedirectURIs == nil {
		p.PostLogoutRedirectURIs = []string{}
	}

	clientID := generateID(24)
	plain, hash, err := generateSecret()
	if err != nil {
		return nil, "", err
	}
	// For non-secret auth methods (private_key_jwt, tls_client_auth, none) we
	// still generate a hash internally but never return the plain-text secret
	// to the caller — the handler decides whether to include it in the response.

	client := &models.OIDCClient{}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			grant_types, response_types,
			client_secret_hash, token_endpoint_auth_method,
			jwks_uri, jwks, id_token_signed_response_alg, userinfo_signed_response_alg,
			dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens, request_object_signing_alg
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'')
		RETURNING client_id, org_id, name, redirect_uris, post_logout_redirect_uris,
		          grant_types, response_types, scopes,
		          token_endpoint_auth_method, logo_url,
		          is_active, mfa_required, keycloak_compat,
		          metadata, jwks_uri, request_object_signing_alg, id_token_signed_response_alg, userinfo_signed_response_alg,
		          dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens, created_at, updated_at
	`, clientID, p.OrgID, p.Name,
		p.RedirectURIs, p.PostLogoutRedirectURIs,
		p.GrantTypes, p.ResponseTypes,
		hash, p.TokenEndpointAuthMethod,
		p.JWKSUri, p.JWKS, p.IDTokenSignedResponseAlg, p.UserInfoSignedResponseAlg,
		p.DpopBoundAccessTokens, p.TLSClientCertBoundAccessTokens,
	).Scan(
		&client.ClientID, &client.OrgID, &client.Name,
		&client.RedirectURIs, &client.PostLogoutRedirectURIs,
		&client.GrantTypes, &client.ResponseTypes, &client.Scopes,
		&client.TokenEndpointAuthMethod, &client.LogoURL,
		&client.IsActive, &client.MFARequired, &client.KeycloakCompat,
		&client.Metadata, &client.JWKSUri, &client.RequestObjectSigningAlg, &client.IDTokenSignedResponseAlg, &client.UserInfoSignedResponseAlg,
		&client.DpopBoundAccessTokens, &client.TLSClientCertBoundAccessTokens, &client.CreatedAt, &client.UpdatedAt,
	)
	return client, plain, err
}

// CheckSecret verifies a plain-text secret against the stored bcrypt hash.
func (r *ClientRepository) CheckSecret(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

func generateSecret() (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	h, err := bcrypt.GenerateFromPassword([]byte(plain), 12)
	if err != nil {
		return
	}
	hash = string(h)
	return
}

// IsAllowedPostLogoutURI returns true if the given URI matches a redirect_uri
// of any active client belonging to orgID. Used to validate post_logout_redirect_uri.
func (r *ClientRepository) IsAllowedPostLogoutURI(ctx context.Context, orgID uuid.UUID, uri string) (bool, error) {
	var count int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM oidc_clients
		WHERE org_id = $1 AND is_active = TRUE AND $2 = ANY(redirect_uris)
	`, orgID, uri).Scan(&count)
	return count > 0, err
}

// ListByOrgPage returns a paginated slice of OIDC clients for an org.
// Results are sorted by name. limit=0 defaults to models.DefaultPageSize.
func (r *ClientRepository) ListByOrgPage(ctx context.Context, orgID uuid.UUID, limit, offset int) (*models.Page[*models.OIDCClient], error) {
	if limit <= 0 {
		limit = models.DefaultPageSize
	}
	if limit > models.MaxPageSize {
		limit = models.MaxPageSize
	}

	const cols = `client_id, org_id, name, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, logo_url, is_active, mfa_required, keycloak_compat, metadata, jwks_uri, request_object_signing_alg, jwks, access_token_ttl, refresh_token_ttl, enabled_login_providers, created_at, updated_at`

	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM oidc_clients WHERE org_id = $1`, orgID).Scan(&total); err != nil {
		return nil, err
	}

	rows, err := r.pool.Query(ctx, `SELECT `+cols+` FROM oidc_clients WHERE org_id = $1 ORDER BY name LIMIT $2 OFFSET $3`, orgID, limit+1, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*models.OIDCClient, 0, limit)
	for rows.Next() {
		c := &models.OIDCClient{}
		if err := rows.Scan(
			&c.ClientID, &c.OrgID, &c.Name,
			&c.RedirectURIs, &c.PostLogoutRedirectURIs,
			&c.GrantTypes, &c.ResponseTypes, &c.Scopes,
			&c.TokenEndpointAuthMethod, &c.LogoURL,
			&c.IsActive, &c.MFARequired, &c.KeycloakCompat,
			&c.Metadata, &c.JWKSUri, &c.RequestObjectSigningAlg, &c.JWKS,
			&c.AccessTokenTTL, &c.RefreshTokenTTL,
			&c.EnabledLoginProviders,
			&c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	page := &models.Page[*models.OIDCClient]{
		Items:   items,
		Total:   total,
		HasMore: hasMore,
	}
	if hasMore {
		next := fmt.Sprintf("%d", offset+limit)
		page.NextCursor = &next
	}
	return page, nil
}

// FederationRegisterParams holds the parameters for federation-based client
// registration (OpenID Federation 1.0 §9.6 explicit registration).
// Federation clients always use private_key_jwt authentication — no shared
// secret is generated or stored.
type FederationRegisterParams struct {
	OrgID                   uuid.UUID
	EntityID                string // OIDF RP entity identifier (stored in metadata)
	// ClientID, when non-empty, is used as-is. For automatic registration
	// (OIDF §10.2) the RP's entity ID is its client_id; leave empty for
	// explicit registration to auto-generate a random opaque client_id.
	ClientID                string
	Name                    string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	GrantTypes              []string
	ResponseTypes           []string
	Scopes                  []string
	LogoURL                 *string
	JWKSUri                 *string
	JWKS                    []byte // inline JWKS (JSON)
	TokenEndpointAuthMethod string // always "private_key_jwt"
	// RegistrationType is "explicit" (default) or "automatic" (OIDF §10.2).
	RegistrationType        string
}

// RegisterFederated creates or updates an OIDC client that was registered via
// OpenID Federation 1.0 explicit registration. Returns the client model.
// Idempotent: if a client with this entity_id already exists for the org it is
// updated; otherwise a new client is inserted.
func (r *ClientRepository) RegisterFederated(ctx context.Context, p FederationRegisterParams) (*models.OIDCClient, error) {
	if p.TokenEndpointAuthMethod == "" {
		p.TokenEndpointAuthMethod = "private_key_jwt"
	}
	if len(p.GrantTypes) == 0 {
		p.GrantTypes = []string{"authorization_code"}
	}
	if len(p.ResponseTypes) == 0 {
		p.ResponseTypes = []string{"code"}
	}
	if p.PostLogoutRedirectURIs == nil {
		p.PostLogoutRedirectURIs = []string{}
	}

	// Encode the entity_id into the metadata JSON column.
	regType := p.RegistrationType
	if regType == "" {
		regType = "explicit"
	}
	meta := map[string]interface{}{
		"federation_entity_id":         p.EntityID,
		"federation_registration_type": regType,
	}
	metaJSON, _ := json.Marshal(meta)

	clientID := p.ClientID
	if clientID == "" {
		clientID = generateID(24)
	}

	// Attempt INSERT … ON CONFLICT (org_id, metadata->>'federation_entity_id')
	// to make the operation idempotent.
	client := &models.OIDCClient{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			grant_types, response_types,
			token_endpoint_auth_method, logo_url,
			metadata, jwks_uri, jwks
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (org_id, (metadata->>'federation_entity_id'))
		DO UPDATE SET
			name                      = EXCLUDED.name,
			redirect_uris             = EXCLUDED.redirect_uris,
			post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
			grant_types               = EXCLUDED.grant_types,
			response_types            = EXCLUDED.response_types,
			token_endpoint_auth_method= EXCLUDED.token_endpoint_auth_method,
			logo_url                  = EXCLUDED.logo_url,
			jwks_uri                  = EXCLUDED.jwks_uri,
			jwks                      = EXCLUDED.jwks,
			updated_at                = NOW()
		RETURNING client_id, org_id, name,
		          redirect_uris, post_logout_redirect_uris,
		          grant_types, response_types, scopes,
		          token_endpoint_auth_method, logo_url,
		          is_active, mfa_required, keycloak_compat,
		          metadata, jwks_uri, request_object_signing_alg, jwks,
		          created_at, updated_at
	`, clientID, p.OrgID, p.Name,
		p.RedirectURIs, p.PostLogoutRedirectURIs,
		p.GrantTypes, p.ResponseTypes,
		p.TokenEndpointAuthMethod, p.LogoURL,
		metaJSON, p.JWKSUri, p.JWKS,
	).Scan(
		&client.ClientID, &client.OrgID, &client.Name,
		&client.RedirectURIs, &client.PostLogoutRedirectURIs,
		&client.GrantTypes, &client.ResponseTypes, &client.Scopes,
		&client.TokenEndpointAuthMethod, &client.LogoURL,
		&client.IsActive, &client.MFARequired, &client.KeycloakCompat,
		&client.Metadata, &client.JWKSUri, &client.RequestObjectSigningAlg, &client.JWKS,
		&client.CreatedAt, &client.UpdatedAt,
	)
	return client, err
}

func generateID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

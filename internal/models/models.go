package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Organization represents a tenant in the system.
type Organization struct {
	ID          uuid.UUID              `db:"id"           json:"id"`
	Name        string                 `db:"name"         json:"name"`
	Slug        string                 `db:"slug"         json:"slug"`
	LogoURL     *string                `db:"logo_url"     json:"logo_url,omitempty"`
	Settings    map[string]interface{} `db:"settings"     json:"settings"`
	IsActive    bool                   `db:"is_active"    json:"is_active"`
	MFARequired bool                   `db:"mfa_required" json:"mfa_required"`
	// ClaimsEnrichmentURL is the optional per-org HTTPS endpoint Clavex POSTs to
	// during token issuance for synchronous claims enrichment (Auth0 Actions-style).
	// Nil = feature disabled for this org.
	ClaimsEnrichmentURL *string `db:"claims_enrichment_url"    json:"claims_enrichment_url,omitempty"`
	// ClaimsEnrichmentSecret is sent as Bearer token in the Authorization header.
	// Never exposed in API responses (json:"-").
	ClaimsEnrichmentSecret *string `db:"claims_enrichment_secret" json:"-"`
	// CustomLoginHTML is an optional Go html/template string that, when set,
	// fully replaces the built-in login page for this org.
	CustomLoginHTML *string `db:"custom_login_html"         json:"-"`
	// AutoEnrollDomains is a list of email domains that trigger automatic org
	// membership on registration / JIT provisioning. E.g. ["acme.com", "acme.eu"].
	AutoEnrollDomains []string `db:"auto_enroll_domains" json:"auto_enroll_domains"`
	// AutoEnrollRoleID is the role automatically assigned to auto-enrolled users.
	// Nil = no role assigned (membership only).
	AutoEnrollRoleID *uuid.UUID `db:"auto_enroll_role_id" json:"auto_enroll_role_id,omitempty"`
	// EmailBlocklist contains email domains that are refused at registration.
	// Wildcard prefix "*.example.com" or bare "example.com" are both supported.
	// Ignored when EmailAllowlist is non-empty (allowlist takes priority).
	EmailBlocklist []string `db:"email_blocklist" json:"email_blocklist"`
	// EmailAllowlist, when non-empty, restricts registration to listed domains only.
	// Overrides EmailBlocklist.
	EmailAllowlist []string `db:"email_allowlist" json:"email_allowlist"`
	// FleetIngestSecret is the shared secret fleet agents supply in X-Fleet-Token.
	// Nil means fleet ingestion is disabled for this organization.
	FleetIngestSecret *string `db:"fleet_ingest_secret" json:"-"`
	// AgentTokenAllowedAudiences lists "aud" values agent-token issuance may
	// request beyond the issuer itself (e.g. cloud STS/WIF audiences such as
	// "sts.amazonaws.com" for AWS, "api://AzureADTokenExchange" for Azure, or
	// a GCP Workload Identity Federation pool provider audience). Empty =
	// agent tokens are only ever audienced to the issuer (legacy behaviour).
	AgentTokenAllowedAudiences []string `db:"agent_token_allowed_audiences" json:"agent_token_allowed_audiences"`
	// AccessTokenTTL overrides the server-default access token lifetime (seconds)
	// for all clients in this org.  nil = use server default.
	AccessTokenTTL *int `db:"access_token_ttl"  json:"access_token_ttl,omitempty"`
	// RefreshTokenTTL overrides the server-default refresh token lifetime (seconds)
	// for all clients in this org.  nil = use server default.
	RefreshTokenTTL *int `db:"refresh_token_ttl" json:"refresh_token_ttl,omitempty"`
	// ConformanceMode enables full conformance metadata (credential_response_encryption,
	// credential_request_encryption) for this org's OID4VCI issuer metadata endpoint.
	// Set true for orgs used in OIDF conformance testing.
	ConformanceMode bool      `db:"conformance_mode" json:"conformance_mode"`
	CreatedAt       time.Time `db:"created_at"   json:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"   json:"updated_at"`
}

// User represents a user within an organization.
type User struct {
	ID              uuid.UUID              `db:"id"                  json:"id"`
	OrgID           uuid.UUID              `db:"org_id"              json:"org_id"`
	Email           string                 `db:"email"               json:"email"`
	PasswordHash    *string                `db:"password_hash"       json:"-"`
	FirstName       *string                `db:"first_name"          json:"first_name,omitempty"`
	LastName        *string                `db:"last_name"           json:"last_name,omitempty"`
	AvatarURL       *string                `db:"avatar_url"          json:"avatar_url,omitempty"`
	IsActive        bool                   `db:"is_active"           json:"is_active"`
	IsEmailVerified bool                   `db:"is_email_verified"   json:"is_email_verified"`
	MFARequired     bool                   `db:"mfa_required"        json:"mfa_required"`
	RequiredActions []string               `db:"required_actions"    json:"required_actions"`
	Metadata        map[string]interface{} `db:"metadata"            json:"metadata"`
	CreatedAt       time.Time              `db:"created_at"          json:"created_at"`
	UpdatedAt       time.Time              `db:"updated_at"          json:"updated_at"`
	LastLoginAt     *time.Time             `db:"last_login_at"       json:"last_login_at,omitempty"`
	// IdentitySourceIssuer is the base URL of the Clavex installation whose
	// SD-JWT-VC was used to import the user's verified identity claims.
	// Non-nil when identity was imported via POST /identity/import.
	IdentitySourceIssuer *string `db:"identity_source_issuer" json:"identity_source_issuer,omitempty"`
	// IdentityImportedAt is the timestamp of the last successful identity import.
	IdentityImportedAt *time.Time `db:"identity_imported_at"   json:"identity_imported_at,omitempty"`
}

// GetID returns the user's UUID as string (satisfies oidc.userClaimsFromModel interface).
func (u *User) GetID() string          { return u.ID.String() }
func (u *User) GetOrgID() string       { return u.OrgID.String() }
func (u *User) GetEmail() string       { return u.Email }
func (u *User) GetEmailVerified() bool { return u.IsEmailVerified }
func (u *User) GetFirstName() string {
	if u.FirstName != nil {
		return *u.FirstName
	}
	return ""
}
func (u *User) GetLastName() string {
	if u.LastName != nil {
		return *u.LastName
	}
	return ""
}

// ManagedMarker records whether a resource is owned by an external declarative
// system (today: the Kubernetes operator, managed_by="k8s-operator"). Embedded
// into the resource models the operator reconciles so the console and API can
// warn that out-of-band edits will be reverted. Both fields are nil for
// hand-managed resources. ManagedRef points at the owning object
// (e.g. "ClavexClient/clavex-operator-system/testclient"). See migration 000179.
type ManagedMarker struct {
	ManagedBy  *string `db:"managed_by"  json:"managed_by,omitempty"`
	ManagedRef *string `db:"managed_ref" json:"managed_ref,omitempty"`
}

// Role represents a role within an organization.
type Role struct {
	ID          uuid.UUID `db:"id"          json:"id"`
	OrgID       uuid.UUID `db:"org_id"      json:"org_id"`
	Name        string    `db:"name"        json:"name"`
	Description *string   `db:"description" json:"description,omitempty"`
	IsSystem    bool      `db:"is_system"   json:"is_system"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
	ManagedMarker
}

// Group represents a named collection of users within an organization.
type Group struct {
	ID          uuid.UUID `db:"id"          json:"id"`
	OrgID       uuid.UUID `db:"org_id"      json:"org_id"`
	Name        string    `db:"name"        json:"name"`
	Description *string   `db:"description" json:"description,omitempty"`
	IsSystem    bool      `db:"is_system"   json:"is_system"`
	MemberCount int       `db:"-"           json:"member_count"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"  json:"updated_at"`
	ManagedMarker
}

// OrgBranding holds per-tenant login page customization.
type OrgBranding struct {
	OrgID           uuid.UUID `db:"org_id"           json:"org_id"`
	CompanyName     *string   `db:"company_name"     json:"company_name,omitempty"`
	LogoURL         *string   `db:"logo_url"         json:"logo_url,omitempty"`
	FaviconURL      *string   `db:"favicon_url"      json:"favicon_url,omitempty"`
	PrimaryColor    string    `db:"primary_color"    json:"primary_color"`
	BgColor         string    `db:"bg_color"         json:"bg_color"`
	TextColor       string    `db:"text_color"       json:"text_color"`
	WelcomeTitle    string    `db:"welcome_title"    json:"welcome_title"`
	WelcomeSubtitle *string   `db:"welcome_subtitle" json:"welcome_subtitle,omitempty"`
	CustomCSS       *string   `db:"custom_css"       json:"custom_css,omitempty"`
	UpdatedAt       time.Time `db:"updated_at"       json:"updated_at"`
}

// OIDCClient represents a registered OAuth2/OIDC application.
type OIDCClient struct {
	ClientID               string    `db:"client_id"                    json:"client_id"`
	OrgID                  uuid.UUID `db:"org_id"                       json:"org_id"`
	ClientSecretHash       *string   `db:"client_secret_hash"           json:"-"`
	Name                   string    `db:"name"                         json:"name"`
	RedirectURIs           []string  `db:"redirect_uris"                json:"redirect_uris"`
	PostLogoutRedirectURIs []string  `db:"post_logout_redirect_uris"    json:"post_logout_redirect_uris"`
	GrantTypes             []string  `db:"grant_types"                  json:"grant_types"`
	ResponseTypes          []string  `db:"response_types"               json:"response_types"`
	Scopes                 []string  `db:"scopes"                       json:"scopes"`
	// AllowedAudiences restricts the target audiences this client may request via
	// the RFC 8693 token-exchange grant (resource/audience parameter). Empty means
	// the client may only obtain tokens audienced to itself.
	AllowedAudiences        []string               `db:"allowed_audiences"            json:"allowed_audiences"`
	TokenEndpointAuthMethod string                 `db:"token_endpoint_auth_method"   json:"token_endpoint_auth_method"`
	LogoURL                 *string                `db:"logo_url"                     json:"logo_url,omitempty"`
	IsActive                bool                   `db:"is_active"                    json:"is_active"`
	MFARequired             bool                   `db:"mfa_required"                 json:"mfa_required"`
	KeycloakCompat          bool                   `db:"keycloak_compat"              json:"keycloak_compat"`
	Metadata                map[string]interface{} `db:"metadata"                     json:"metadata"`
	// JAR (RFC 9101): optional JWKS URI and declared signing algorithm for request objects.
	JWKSUri                 *string `db:"jwks_uri"                     json:"jwks_uri,omitempty"`
	RequestObjectSigningAlg string  `db:"request_object_signing_alg"   json:"request_object_signing_alg"`
	// IDTokenSignedResponseAlg is the algorithm the server MUST use to sign ID tokens
	// for this client (RFC 7591 / OIDC Core §2). Empty string means server default (PS256).
	// Registered during dynamic client registration via id_token_signed_response_alg.
	IDTokenSignedResponseAlg string `db:"id_token_signed_response_alg" json:"id_token_signed_response_alg,omitempty"`
	// UserInfoSignedResponseAlg is the algorithm the server MUST use to sign UserInfo
	// responses for this client (OIDC Core §5.3.2). When non-empty (and not "none"),
	// the userinfo endpoint returns a signed JWT with Content-Type: application/jwt.
	UserInfoSignedResponseAlg string `db:"userinfo_signed_response_alg" json:"userinfo_signed_response_alg,omitempty"`
	// JWKS holds an inline JSON Web Key Set for clients that use private_key_jwt
	// client authentication (RFC 7523). When non-nil it takes precedence over
	// JWKSUri for verifying client assertions.
	JWKS *json.RawMessage `db:"jwks"                         json:"jwks,omitempty"`
	// Mutual-TLS client authentication fields (RFC 8705 §2.3).
	// Set token_endpoint_auth_method to "tls_client_auth" to activate.
	TLSClientAuthSubjectDN *string `db:"tls_client_auth_subject_dn" json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientAuthSANDNS    *string `db:"tls_client_auth_san_dns"    json:"tls_client_auth_san_dns,omitempty"`
	// DpopBoundAccessTokens indicates this client always uses DPoP (RFC 9449 §5).
	// When true, the token endpoint MUST reject requests without a DPoP proof,
	// regardless of whether dpop_jkt was bound in the authorization code.
	DpopBoundAccessTokens bool `db:"dpop_bound_access_tokens" json:"dpop_bound_access_tokens,omitempty"`
	// TLSClientCertBoundAccessTokens implements RFC 8705 §3 (Certificate-Bound
	// Access Tokens).  When true, every token request for this client MUST
	// present a valid TLS client certificate.  The issued access token carries
	// a cnf.x5t#S256 claim binding it to the certificate thumbprint.
	TLSClientCertBoundAccessTokens bool `db:"tls_client_certificate_bound_access_tokens" json:"tls_client_certificate_bound_access_tokens,omitempty"`
	// RequirePKCE indicates this client MUST always include a code_challenge (S256)
	// in PAR/authorization requests. Required for FAPI 2.0 §5.2.2-18 compliance.
	RequirePKCE bool `db:"require_pkce" json:"require_pkce,omitempty"`
	// RequirePAR indicates this client MUST use PAR (RFC 9126) for every
	// authorization request.  Set for FAPI 2.0 clients that use unsigned PAR
	// (fapi_request_method=unsigned) and therefore have no request_object_signing_alg.
	RequirePAR bool `db:"require_par" json:"require_par,omitempty"`
	// SessionIsolation, when true, prevents this client's SSO session from being
	// shared with other clients in the same org.  Login on App A does not grant
	// silent SSO access to App B.  Each client has its own independent session cycle.
	SessionIsolation bool `db:"session_isolation" json:"session_isolation,omitempty"`
	// AccessTokenTTL overrides the access token lifetime (seconds) for tokens issued
	// to this client.  nil = inherit from org-level override, then server default.
	// 0 treated as nil (revert to inherited value).
	AccessTokenTTL *int `db:"access_token_ttl"  json:"access_token_ttl,omitempty"`
	// RefreshTokenTTL overrides the refresh token lifetime (seconds) for this client.
	// nil = inherit from org-level override, then server default.
	RefreshTokenTTL *int `db:"refresh_token_ttl" json:"refresh_token_ttl,omitempty"`
	// EnabledLoginProviders restricts which national eID / federated login buttons
	// are shown on the login page for this client.
	// Empty slice = show all active providers (backward-compatible default).
	// Non-empty = show only the listed provider types, e.g. ["spid","cie"].
	// Supported values: "spid", "cie", "itsme", "bundid", "bundidsaml", "digid",
	//   "clave", "franceconnect", "eidas", plus any provider_type value in
	//   identity_providers (e.g. "google", "github").
	EnabledLoginProviders []string `db:"enabled_login_providers" json:"enabled_login_providers"`
	// LastUsedAt records the most recent successful token issuance for this client.
	// Nil means the client has never obtained a token. Used by the Object Lifecycle
	// Management dashboard to surface stale / unused applications.
	LastUsedAt *time.Time `db:"last_used_at"                json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `db:"created_at"                   json:"created_at"`
	UpdatedAt  time.Time  `db:"updated_at"                   json:"updated_at"`
	ManagedMarker
}

// CaptchaSettings holds per-org CAPTCHA provider configuration.
type CaptchaSettings struct {
	OrgID     uuid.UUID `db:"org_id"     json:"org_id"`
	Provider  string    `db:"provider"   json:"provider"` // "turnstile" | "hcaptcha" | "recaptcha"
	SiteKey   string    `db:"site_key"   json:"site_key"`
	SecretKey string    `db:"secret_key" json:"-"`
	IsActive  bool      `db:"is_active"  json:"is_active"`
}

// MFACredential stores a TOTP secret or WebAuthn credential for a user.
type MFACredential struct {
	ID         uuid.UUID              `db:"id"           json:"id"`
	UserID     uuid.UUID              `db:"user_id"      json:"user_id"`
	Type       string                 `db:"type"         json:"type"` // "totp" | "webauthn"
	Name       string                 `db:"name"         json:"name"`
	Data       map[string]interface{} `db:"data"         json:"-"` // never expose raw credential
	IsPrimary  bool                   `db:"is_primary"   json:"is_primary"`
	CreatedAt  time.Time              `db:"created_at"   json:"created_at"`
	LastUsedAt *time.Time             `db:"last_used_at" json:"last_used_at,omitempty"`
}

// LDAPConnection stores the configuration for an LDAP identity provider.
type LDAPConnection struct {
	ID           uuid.UUID         `db:"id"            json:"id"`
	OrgID        uuid.UUID         `db:"org_id"        json:"org_id"`
	Name         string            `db:"name"          json:"name"`
	Host         string            `db:"host"          json:"host"`
	Port         int               `db:"port"          json:"port"`
	UseTLS       bool              `db:"use_tls"       json:"use_tls"`
	BindDN       *string           `db:"bind_dn"       json:"bind_dn,omitempty"`
	BindPassword *string           `db:"bind_password" json:"-"`
	BaseDN       string            `db:"base_dn"       json:"base_dn"`
	UserFilter   string            `db:"user_filter"   json:"user_filter"`
	UserAttrMap  map[string]string `db:"user_attr_map" json:"user_attr_map"`
	IsActive     bool              `db:"is_active"     json:"is_active"`
	LastSyncAt   *time.Time        `db:"last_sync_at"  json:"last_sync_at,omitempty"`
	CreatedAt    time.Time         `db:"created_at"    json:"created_at"`
	UpdatedAt    time.Time         `db:"updated_at"    json:"updated_at"`
}

// SAMLServiceProvider represents a SAML SP that uses clavex as the IdP.
type SAMLServiceProvider struct {
	ID           uuid.UUID `db:"id"              json:"id"`
	OrgID        uuid.UUID `db:"org_id"          json:"org_id"`
	EntityID     string    `db:"entity_id"       json:"entity_id"`
	Name         string    `db:"name"            json:"name"`
	ACSURL       string    `db:"acs_url"         json:"acs_url"`
	SLOURL       *string   `db:"slo_url"         json:"slo_url,omitempty"`
	MetadataXML  *string   `db:"metadata_xml"    json:"-"`
	NameIDFormat string    `db:"name_id_format"  json:"name_id_format"`
	IsActive     bool      `db:"is_active"       json:"is_active"`
	CreatedAt    time.Time `db:"created_at"      json:"created_at"`
}

func (s *SAMLServiceProvider) GetEntityID() string     { return s.EntityID }
func (s *SAMLServiceProvider) GetACSURL() string       { return s.ACSURL }
func (s *SAMLServiceProvider) GetSLOURL() *string      { return s.SLOURL }
func (s *SAMLServiceProvider) GetNameIDFormat() string { return s.NameIDFormat }

// Webhook represents a per-tenant HTTP callback registered for one or more events.
// The Secret is used to sign the request body with HMAC-SHA256 (X-Clavex-Signature header).
type Webhook struct {
	ID     uuid.UUID `db:"id"           json:"id"`
	OrgID  uuid.UUID `db:"org_id"       json:"org_id"`
	URL    string    `db:"url"          json:"url"`
	Events []string  `db:"events"       json:"events"`
	// EventFilter holds optional fine-grained event subtypes (e.g. "user.login.new_device").
	// When non-empty, the webhook fires ONLY for events that match one of these subtypes.
	// An empty slice means "all events in Events[]" (backwards-compatible behaviour).
	EventFilter []string  `db:"event_filter" json:"event_filter"`
	Secret      string    `db:"secret"       json:"-"` // never expose the signing secret
	IsActive    bool      `db:"is_active"    json:"is_active"`
	CreatedAt   time.Time `db:"created_at"   json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"   json:"updated_at"`
	ManagedMarker
}

// AgentToken is a machine identity for an AI agent acting on behalf of a human
// user. It is a signed JWT (same key as OIDC tokens) with additional claims:
// token_type=agent, agent_id, delegated_by. Revocable independently from the
// user's browser session — supports MCP (Model Context Protocol) OAuth 2.0 flows.
type AgentToken struct {
	ID        uuid.UUID  `db:"id"               json:"id"`
	OrgID     uuid.UUID  `db:"org_id"           json:"org_id"`
	UserID    uuid.UUID  `db:"user_id"          json:"user_id"`
	AgentID   string     `db:"agent_id"         json:"agent_id"`
	AgentName string     `db:"agent_name"       json:"agent_name"`
	Scope     string     `db:"scope"            json:"scope"`
	JTI       string     `db:"jti"              json:"jti"`
	IsRevoked bool       `db:"is_revoked"       json:"is_revoked"`
	ExpiresAt time.Time  `db:"expires_at"       json:"expires_at"`
	RevokedAt *time.Time `db:"revoked_at"       json:"revoked_at,omitempty"`
	RevokedBy *uuid.UUID `db:"revoked_by"       json:"revoked_by,omitempty"`
	CreatedAt time.Time  `db:"created_at"       json:"created_at"`
	CreatedBy *uuid.UUID `db:"created_by"       json:"created_by,omitempty"`
	// LastUsedAt is the most recent time the token was presented to a resource
	// server (updated best-effort on introspection). Nil until first use.
	LastUsedAt *time.Time `db:"last_used_at"     json:"last_used_at,omitempty"`
	// MCP-specific fields (Model Context Protocol OAuth 2.0)
	MCPServerID    *string `db:"mcp_server_id"    json:"mcp_server_id,omitempty"`
	MCPResourceURL *string `db:"mcp_resource_url" json:"mcp_resource_url,omitempty"`
	// Audience is the "aud" claim embedded in the signed JWT at issuance
	// time. Nil means the issuer default (legacy behaviour); a non-nil value
	// must have been present in the issuing org's
	// AgentTokenAllowedAudiences at issuance time (e.g. a cloud STS/WIF
	// audience for Terraform federation — see internal/handler/agent_token.go).
	Audience *string `db:"audience" json:"audience,omitempty"`
}

// WebhookDelivery records one delivery attempt for a webhook.
// Each retry of the same logical payload gets a separate row (attempt 1, 2, 3…).
type WebhookDelivery struct {
	ID          uuid.UUID `db:"id"           json:"id"`
	WebhookID   uuid.UUID `db:"webhook_id"   json:"webhook_id"`
	OrgID       uuid.UUID `db:"org_id"       json:"org_id"`
	DeliveryID  string    `db:"delivery_id"  json:"delivery_id"` // Payload.ID (idempotency key)
	Event       string    `db:"event"        json:"event"`
	Payload     []byte    `db:"payload"      json:"payload"` // raw JSON
	Attempt     int       `db:"attempt"      json:"attempt"`
	Status      string    `db:"status"       json:"status"`      // pending | success | failed
	HTTPStatus  *int      `db:"http_status"  json:"http_status"` // nil on network error
	Error       *string   `db:"error"        json:"error,omitempty"`
	DurationMs  *int      `db:"duration_ms"  json:"duration_ms,omitempty"`
	AttemptedAt time.Time `db:"attempted_at" json:"attempted_at"`
}

// ScimPushConfig configures outbound SCIM provisioning to an external directory.
// When users are created/updated/deactivated in Clavex, the SCIM pusher sends
// corresponding SCIM 2.0 requests to the configured endpoint.
type ScimPushConfig struct {
	ID            uuid.UUID `db:"id"             json:"id"`
	OrgID         uuid.UUID `db:"org_id"         json:"org_id"`
	Name          string    `db:"name"           json:"name"`
	EndpointURL   string    `db:"endpoint_url"   json:"endpoint_url"`
	BearerToken   string    `db:"bearer_token"   json:"-"` // never expose in API responses
	EnabledEvents []string  `db:"enabled_events" json:"enabled_events"`
	IsActive      bool      `db:"is_active"      json:"is_active"`
	CreatedAt     time.Time `db:"created_at"     json:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"     json:"updated_at"`
}

// ScimPushDelivery is a single outbound push attempt recorded for observability.
// Admins can view the delivery log from the console and retry failed deliveries.
type ScimPushDelivery struct {
	ID          int64      `db:"id"           json:"id"`
	ConfigID    uuid.UUID  `db:"config_id"    json:"config_id"`
	Event       string     `db:"event"        json:"event"`
	SubjectID   *uuid.UUID `db:"subject_id"   json:"subject_id,omitempty"`
	SubjectType string     `db:"subject_type" json:"subject_type"` // "user" | "group"
	HTTPStatus  *int       `db:"http_status"  json:"http_status,omitempty"`
	ErrorMsg    *string    `db:"error_msg"    json:"error_msg,omitempty"`
	DurationMS  *int       `db:"duration_ms"  json:"duration_ms,omitempty"`
	Success     bool       `db:"success"      json:"success"`
	CreatedAt   time.Time  `db:"created_at"   json:"created_at"`
}

// AuditLog records security-relevant events.
type AuditLog struct {
	ID           int64                  `db:"id"            json:"id"`
	OrgID        *uuid.UUID             `db:"org_id"        json:"org_id,omitempty"`
	UserID       *uuid.UUID             `db:"user_id"       json:"user_id,omitempty"`
	ActorEmail   *string                `db:"actor_email"   json:"actor_email,omitempty"`
	Action       string                 `db:"action"        json:"action"`
	ResourceType *string                `db:"resource_type" json:"resource_type,omitempty"`
	ResourceID   *string                `db:"resource_id"   json:"resource_id,omitempty"`
	Status       string                 `db:"status"        json:"status"`
	IPAddress    *string                `db:"ip_address"    json:"ip_address,omitempty"`
	UserAgent    *string                `db:"user_agent"    json:"user_agent,omitempty"`
	Metadata     map[string]interface{} `db:"metadata"      json:"metadata"`
	CreatedAt    time.Time              `db:"created_at"    json:"created_at"`
}

// ProtocolMapper controls how user data is mapped into token claims for an OIDC client.
// mapper_type: "user_property" | "user_attribute" | "hardcoded" | "role_list" | "group_membership"
type ProtocolMapper struct {
	ID               uuid.UUID `db:"id"                   json:"id"`
	OrgID            uuid.UUID `db:"org_id"               json:"org_id"`
	ClientID         string    `db:"client_id"            json:"client_id"`
	Name             string    `db:"name"                 json:"name"`
	MapperType       string    `db:"mapper_type"          json:"mapper_type"`
	ClaimName        string    `db:"claim_name"           json:"claim_name"`
	ClaimValue       *string   `db:"claim_value"          json:"claim_value,omitempty"`
	AttributeName    *string   `db:"attribute_name"       json:"attribute_name,omitempty"`
	AddToAccessToken bool      `db:"add_to_access_token"  json:"add_to_access_token"`
	AddToIDToken     bool      `db:"add_to_id_token"      json:"add_to_id_token"`
	AddToUserinfo    bool      `db:"add_to_userinfo"      json:"add_to_userinfo"`
	CreatedAt        time.Time `db:"created_at"           json:"created_at"`
}

// PasswordPolicy defines per-org password complexity rules.
type PasswordPolicy struct {
	OrgID             uuid.UUID `db:"org_id"                json:"org_id"`
	MinLength         int       `db:"min_length"            json:"min_length"`
	RequireUppercase  bool      `db:"require_uppercase"     json:"require_uppercase"`
	RequireNumber     bool      `db:"require_number"        json:"require_number"`
	RequireSymbol     bool      `db:"require_symbol"        json:"require_symbol"`
	MaxAgeDays        *int      `db:"max_age_days"          json:"max_age_days,omitempty"`
	PreventReuseCount int       `db:"prevent_reuse_count"   json:"prevent_reuse_count"`
	// BreachedPasswordAction controls what happens when a breached password is detected.
	// Values: "" or "off" (disabled), "warn" (log only), "block" (reject the password).
	BreachedPasswordAction string    `db:"breached_password_action" json:"breached_password_action"`
	UpdatedAt              time.Time `db:"updated_at"            json:"updated_at"`
	ManagedMarker
}

// AdminRole defines a named set of admin-console permissions that can be
// assigned to users within an org. Superadmins and legacy full org admins
// are not bound by admin role permissions.
type AdminRole struct {
	ID          uuid.UUID `db:"id"          json:"id"`
	OrgID       uuid.UUID `db:"org_id"      json:"org_id"`
	Name        string    `db:"name"        json:"name"`
	Description *string   `db:"description" json:"description,omitempty"`
	// Permissions is the set of permission tokens granted by this role.
	// See internal/middleware/permissions.go for the canonical list.
	Permissions []string `db:"permissions" json:"permissions"`
	// IsSystem marks roles created by Clavex itself; they cannot be deleted.
	IsSystem  bool      `db:"is_system"   json:"is_system"`
	CreatedAt time.Time `db:"created_at"  json:"created_at"`
	UpdatedAt time.Time `db:"updated_at"  json:"updated_at"`
}

// AdminRoleAssignment records that a user has been granted an admin role.
type AdminRoleAssignment struct {
	ID        uuid.UUID  `db:"id"         json:"id"`
	OrgID     uuid.UUID  `db:"org_id"     json:"org_id"`
	UserID    uuid.UUID  `db:"user_id"    json:"user_id"`
	RoleID    uuid.UUID  `db:"role_id"    json:"role_id"`
	RoleName  string     `db:"role_name"  json:"role_name"` // joined from admin_roles
	CreatedBy *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}

// SMTPSettings holds per-org SMTP server configuration.
type SMTPSettings struct {
	OrgID       uuid.UUID `db:"org_id"       json:"org_id"`
	Host        string    `db:"host"         json:"host"`
	Port        int       `db:"port"         json:"port"`
	Username    *string   `db:"username"     json:"username,omitempty"`
	Password    *string   `db:"password"     json:"-"` // never expose
	FromAddress string    `db:"from_address" json:"from_address"`
	FromName    string    `db:"from_name"    json:"from_name"`
	UseTLS      bool      `db:"use_tls"      json:"use_tls"`
	IsActive    bool      `db:"is_active"    json:"is_active"`
	UpdatedAt   time.Time `db:"updated_at"   json:"updated_at"`
}

// IdentityProvider represents an external OAuth2/OIDC federation source.
type IdentityProvider struct {
	ID               uuid.UUID `db:"id"                  json:"id"`
	OrgID            uuid.UUID `db:"org_id"              json:"org_id"`
	Name             string    `db:"name"                json:"name"`
	ProviderType     string    `db:"provider_type"       json:"provider_type"`
	ClientID         string    `db:"client_id"           json:"client_id"`
	AuthorizationURL string    `db:"authorization_url"   json:"authorization_url"`
	TokenURL         string    `db:"token_url"           json:"token_url"`
	UserinfoURL      *string   `db:"userinfo_url"        json:"userinfo_url,omitempty"`
	Scopes           string    `db:"scopes"              json:"scopes"`
	EmailClaim       string    `db:"email_claim"         json:"email_claim"`
	FirstNameClaim   string    `db:"first_name_claim"    json:"first_name_claim"`
	LastNameClaim    string    `db:"last_name_claim"     json:"last_name_claim"`
	IsActive         bool      `db:"is_active"           json:"is_active"`
	// JIT provisioning controls (migration 000029)
	AllowJIT          bool              `db:"allow_jit"           json:"allow_jit"`
	RolesClaim        *string           `db:"roles_claim"         json:"roles_claim,omitempty"`
	RoleClaimMappings map[string]string `db:"role_claim_mappings" json:"role_claim_mappings"`
	// IsPromoted controls login page UX: promoted IDPs appear as a full-width
	// primary button above the email/password form (migration 000096).
	IsPromoted bool `db:"is_promoted" json:"is_promoted"`
	// Apple Sign In With Apple credentials (migration 000078).
	// The client_secret for Apple is a short-lived ES256 JWT signed with
	// the developer's .p8 private key.  These three fields supply the JWT
	// signing material so Clavex can generate a fresh secret on every
	// token exchange instead of storing a (quickly-expiring) static token.
	AppleTeamID     *string   `db:"apple_team_id"     json:"apple_team_id,omitempty"`
	AppleKeyID      *string   `db:"apple_key_id"      json:"apple_key_id,omitempty"`
	ApplePrivateKey *string   `db:"apple_private_key" json:"-"` // never serialised; sensitive
	CreatedAt       time.Time `db:"created_at"          json:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"          json:"updated_at"`
	ManagedMarker
}

// ClientScope is a reusable, org-level scope definition assignable to OIDC clients.
type ClientScope struct {
	ID          uuid.UUID `db:"id"          json:"id"`
	OrgID       uuid.UUID `db:"org_id"      json:"org_id"`
	Name        string    `db:"name"        json:"name"`
	Description *string   `db:"description" json:"description,omitempty"`
	Protocol    string    `db:"protocol"    json:"protocol"`
	IsDefault   bool      `db:"is_default"  json:"is_default"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"  json:"updated_at"`
}

// ── SPID / CIE models (migration 000031) ─────────────────────────────────────

// SPIDInstanceConfig holds the instance-level SPID SP identity (singleton).
// One row per Clavex deployment: EntityID, signing keypair, legal/contact info
// for SP metadata submitted to AgID. Migration 000161.
type SPIDInstanceConfig struct {
	ID             uuid.UUID `db:"id"               json:"id"`
	EntityID       string    `db:"entity_id"        json:"entity_id"`
	OrgName        string    `db:"org_name"         json:"org_name"`
	OrgDisplayName string    `db:"org_display_name" json:"org_display_name"`
	OrgLocality    string    `db:"org_locality"     json:"org_locality"`
	OrgURL         string    `db:"org_url"          json:"org_url"`
	ContactEmail   string    `db:"contact_email"    json:"contact_email"`
	ContactPhone   *string   `db:"contact_phone"    json:"contact_phone,omitempty"`
	VATNumber      *string   `db:"vat_number"       json:"vat_number,omitempty"`
	IPACode        *string   `db:"ipa_code"         json:"ipa_code,omitempty"`
	EntityType     string    `db:"entity_type"      json:"entity_type"` // "private" | "public"
	SpCertPem      *string   `db:"sp_cert_pem"      json:"-"`
	SpKeyPem       *string   `db:"sp_key_pem"       json:"-"`
	CreatedAt      time.Time `db:"created_at"       json:"created_at"`
	UpdatedAt      time.Time `db:"updated_at"       json:"updated_at"`
}

// SPIDConfig holds per-org SPID authentication preferences (migration 000031,
// identity fields removed in 000161).
type SPIDConfig struct {
	OrgID        uuid.UUID `db:"org_id"        json:"org_id"`
	AuthnLevel   int       `db:"authn_level"   json:"authn_level"` // 1 | 2 | 3
	AttributeSet []string  `db:"attribute_set" json:"attribute_set"`
	IsActive     bool      `db:"is_active"     json:"is_active"`
	CreatedAt    time.Time `db:"created_at"    json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"    json:"updated_at"`
}

// SPIDIdP represents an entry in the official SPID IdP registry.
type SPIDIdP struct {
	ID                uuid.UUID  `db:"id"                    json:"id"`
	EntityID          string     `db:"entity_id"             json:"entity_id"`
	DisplayName       string     `db:"display_name"          json:"display_name"`
	LogoURL           *string    `db:"logo_url"              json:"logo_url,omitempty"`
	MetadataURL       string     `db:"metadata_url"          json:"metadata_url"`
	MetadataXML       *string    `db:"metadata_xml"          json:"-"`
	MetadataFetchedAt *time.Time `db:"metadata_fetched_at"   json:"metadata_fetched_at,omitempty"`
	IsActive          bool       `db:"is_active"             json:"is_active"`
	IsTest            bool       `db:"is_test"               json:"is_test"`
	CreatedAt         time.Time  `db:"created_at"            json:"created_at"`
	UpdatedAt         time.Time  `db:"updated_at"            json:"updated_at"`
}

// SPIDIdentity contains the verified identity attributes extracted from a SPID assertion.
type SPIDIdentity struct {
	SpidCode     string `json:"spid_code"`
	FiscalNumber string `json:"fiscal_number"` // codice fiscale
	Name         string `json:"name"`
	FamilyName   string `json:"family_name"`
	DateOfBirth  string `json:"date_of_birth,omitempty"`
	PlaceOfBirth string `json:"place_of_birth,omitempty"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"mobile_phone,omitempty"`
	Level        int    `json:"level"` // authn level (L1/L2/L3)
}

// ── BundID SAML SP models (migration 000051) ──────────────────────────────────

// BundIDSAMLConfig holds the per-org BundID SAML Service Provider settings.
// One row per org, stored in bundid_saml_configs.
type BundIDSAMLConfig struct {
	OrgID          uuid.UUID `db:"org_id"          json:"org_id"`
	EntityID       string    `db:"entity_id"       json:"entity_id"`
	OrgName        string    `db:"org_name"        json:"org_name"`
	OrgDisplayName string    `db:"org_display_name" json:"org_display_name"`
	OrgURL         string    `db:"org_url"         json:"org_url"`
	ContactEmail   string    `db:"contact_email"   json:"contact_email"`
	ContactPhone   *string   `db:"contact_phone"   json:"contact_phone,omitempty"`
	// Environment: "production" or "integration"
	Environment string `db:"environment" json:"environment"`
	// MinLoA: "low" | "substantial" | "high"
	MinLoA       string    `db:"min_loa"       json:"min_loa"`
	AttributeSet []string  `db:"attribute_set" json:"attribute_set"`
	SpCertPem    *string   `db:"sp_cert_pem"   json:"sp_cert_pem,omitempty"`
	SpKeyPem     *string   `db:"sp_key_pem"    json:"-"` // never serialised to clients
	IsActive     bool      `db:"is_active"     json:"is_active"`
	CreatedAt    time.Time `db:"created_at"   json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"   json:"updated_at"`
}

// ── OID4VCI / OID4VP models ───────────────────────────────────────────────────

// CredentialConfig defines a Verifiable Credential type an organisation can issue.
type CredentialConfig struct {
	ID            uuid.UUID              `db:"id"             json:"id"`
	OrgID         uuid.UUID              `db:"org_id"         json:"org_id"`
	VCT           string                 `db:"vct"            json:"vct"`
	DisplayName   string                 `db:"display_name"   json:"display_name"`
	Description   *string                `db:"description"    json:"description,omitempty"`
	ClaimsMapping map[string]interface{} `db:"claims_mapping" json:"claims_mapping"`
	TTLSeconds    int                    `db:"ttl_seconds"    json:"ttl_seconds"`
	// ── Adaptive Credential Freshness ────────────────────────────────────────
	// AdaptiveTTL enables the adaptive lifecycle worker for this credential type.
	// Credentials used frequently are silently renewed; dormant ones are revoked.
	AdaptiveTTL bool `db:"adaptive_ttl"            json:"adaptive_ttl"`
	// MinTTLSeconds is the floor for renewed credential lifetime (default 7 days).
	MinTTLSeconds int `db:"min_ttl_seconds"         json:"min_ttl_seconds"`
	// MaxTTLSeconds is the ceiling beyond which no further renewals are granted (default 1 year).
	MaxTTLSeconds int `db:"max_ttl_seconds"         json:"max_ttl_seconds"`
	// RenewalThreshold is the fraction of TTL elapsed that triggers renewal (0.0–1.0, default 0.8).
	RenewalThreshold float64 `db:"renewal_threshold"       json:"renewal_threshold"`
	// InactivityRevokeDays is the number of days without login after which an
	// unused credential is proactively revoked (default 90).
	InactivityRevokeDays int  `db:"inactivity_revoke_days"  json:"inactivity_revoke_days"`
	IsActive             bool `db:"is_active"      json:"is_active"`
	// Category is the credential class: identity | training | qualification | badge.
	Category string `db:"category"      json:"category"`
	// SchemaFields declares the expected payload fields for the admin issue UI.
	SchemaFields []SchemaFieldDef `db:"schema_fields" json:"schema_fields"`
	// PreIssuanceWebhookURL is the optional HTTPS endpoint called before issuing
	// this credential type. Clavex POSTs a signed request and gates issuance on
	// {"allowed":true/false}. Nil = hook disabled.
	PreIssuanceWebhookURL *string `db:"pre_issuance_webhook_url"    json:"pre_issuance_webhook_url,omitempty"`
	// PreIssuanceWebhookSecret is the HMAC-SHA256 signing secret sent in
	// X-Clavex-Signature. Never exposed in API responses (json:"-").
	PreIssuanceWebhookSecret *string `db:"pre_issuance_webhook_secret" json:"-"`
	// RequireVP controls whether the wallet must present a Verifiable Presentation
	// (OID4VP) before this credential is issued. When true the credential endpoint
	// responds with "presentation_required" if no vp_token is supplied.
	RequireVP bool `db:"require_vp" json:"require_vp"`
	// PresentationDefinitionVPR is the Presentation Exchange v2 definition the
	// wallet must satisfy when RequireVP is true. Nil = use a default identity PD.
	PresentationDefinitionVPR map[string]interface{} `db:"presentation_definition_vpr" json:"presentation_definition_vpr,omitempty"`
	// DeferredIssuance signals that credentials of this type are not issued
	// synchronously. The credential endpoint returns a transaction_id; the wallet
	// polls POST /deferred-credential until the issuer completes issuance
	// (OID4VCI Final §11). Typical use: PA workflows requiring manual review.
	DeferredIssuance bool `db:"deferred_issuance" json:"deferred_issuance"`
	// SourceIdpType links this credential configuration to a specific identity
	// provider type. When set, credentials of this type are automatically offered
	// after a successful login via that IdP and the issuance pipeline injects
	// verified claims sourced from that IdP.
	// Known values: "franceconnect" | "spid" | "cie" | "itsme" | "bundid" | "digid" | "clave"
	SourceIdpType *string `db:"source_idp_type" json:"source_idp_type,omitempty"`
	// CredentialFormat selects the credential encoding.
	// "vc+sd-jwt" (default) — W3C SD-JWT-VC.
	// "mso_mdoc"             — ISO 18013-5 mobile document signed by a DS key.
	CredentialFormat string `db:"credential_format" json:"credential_format"`
	// SelectiveDisclosure controls per-claim selective disclosure for SD-JWT-VC issuance.
	// When true (default) every mapped claim becomes an independent SD-JWT disclosure.
	// The holder wallet can reveal individual claims (e.g. age_over_18 only) without
	// exposing the full credential — privacy by design per SD-JWT-VC Final §4.1.
	// When false all claims are embedded verbatim in the signed issuer JWT (no SD).
	// The Clavex issuance pipeline also auto-derives age_over_18 and age_in_years from
	// birth_date when SelectiveDisclosure is true.
	SelectiveDisclosure bool `db:"selective_disclosure" json:"selective_disclosure"`
	// ── Credential Chaining (OID4VP → OID4VCI auto-issuance) ─────────────────
	// ChainSourceVCT enables Credential Chaining: when non-nil this config is
	// automatically triggered after a successful OID4VP presentation of a
	// credential whose vct (SD-JWT-VC) or doctype (ISO 18013-5 mdoc) matches.
	// Clavex creates a pre-authorized offer and returns the deep-link URI in the
	// VP response so the wallet can immediately collect the derived credential.
	//
	// Use case: present CIE digital → automatically receive a residence
	// certificate — zero extra auth steps, eIDAS LoA High assurance.
	ChainSourceVCT *string `db:"chain_source_vct"     json:"chain_source_vct,omitempty"`
	// ChainClaimsMapping transforms input VP claims into output credential claims.
	// Format: {"<output_claim>": "<input_vp_claim>"}.
	// When nil, all non-system VP claims are forwarded verbatim as the payload.
	ChainClaimsMapping map[string]interface{} `db:"chain_claims_mapping"  json:"chain_claims_mapping,omitempty"`
	// ChainOfferTTLMins is the lifetime (minutes) of the auto-generated
	// pre-authorized code offer. Defaults to 15 minutes.
	ChainOfferTTLMins int `db:"chain_offer_ttl_mins"  json:"chain_offer_ttl_mins"`
	// RequireKeyAttestation controls whether key_attestations_required is
	// advertised in the OID4VCI issuer metadata for this credential type.
	// When false (default) standard wallets (e.g. EUDI reference wallet) can
	// complete the pre-authorized code flow without a wallet key attestation.
	// Set to true only for HAIP conformance testing or high-security issuance
	// scenarios that genuinely require wallet attestation (HAIP §4.4).
	RequireKeyAttestation bool `db:"require_key_attestation" json:"require_key_attestation"`
	// DelegatedBy is the entity ID (URL) of the issuer that granted this org the
	// right to issue credentials under this VCT (ARF EUDIW §6.3.4).
	// When non-nil this config operates in "delegated issuance" mode.
	DelegatedBy *string `db:"delegated_by"    json:"delegated_by,omitempty"`
	// DelegationJWT is the compact JWS delegation grant signed by the delegating
	// issuer.  It is embedded as the "del.proof" claim in every issued SD-JWT-VC
	// so wallets can verify the delegation chain offline.
	DelegationJWT *string   `db:"delegation_jwt"  json:"delegation_jwt,omitempty"`
	CreatedAt     time.Time `db:"created_at"     json:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"     json:"updated_at"`
}

// MarketplaceListing is a public-facing credential template in the Clavex
// Credential Marketplace (clavex.eu/credentials).
// PA and private issuers publish listings so wallet developers can discover
// and import credential configurations with one click.
type MarketplaceListing struct {
	ID                 uuid.UUID              `db:"id"                    json:"id"`
	OrgID              uuid.UUID              `db:"org_id"                json:"org_id"`
	CredentialConfigID *uuid.UUID             `db:"credential_config_id"  json:"credential_config_id,omitempty"`
	DisplayName        string                 `db:"display_name"          json:"display_name"`
	Description        *string                `db:"description"           json:"description,omitempty"`
	IssuerName         string                 `db:"issuer_name"           json:"issuer_name"`
	VCT                string                 `db:"vct"                   json:"vct"`
	CredentialFormat   string                 `db:"credential_format"     json:"credential_format"`
	Lang               string                 `db:"lang"                  json:"lang"`
	IssuerEndpoint     string                 `db:"issuer_endpoint"       json:"issuer_endpoint"`
	SchemaJSON         map[string]interface{} `db:"schema_json"           json:"schema_json"`
	OfferTemplate      *string                `db:"offer_template"        json:"offer_template,omitempty"`
	Tags               []string               `db:"tags"                  json:"tags"`
	Status             string                 `db:"status"                json:"status"`
	IsPublic           bool                   `db:"is_public"             json:"is_public"`
	ModerationNote     *string                `db:"moderation_note"       json:"moderation_note,omitempty"`
	CreatedAt          time.Time              `db:"created_at"            json:"created_at"`
	UpdatedAt          time.Time              `db:"updated_at"            json:"updated_at"`
}

// MarketplaceListingPublic is the redacted view exposed in the public catalog.
// It omits org_id and moderation_note but adds issuer metadata for display.
type MarketplaceListingPublic struct {
	ID               uuid.UUID              `json:"id"`
	DisplayName      string                 `json:"display_name"`
	Description      *string                `json:"description,omitempty"`
	IssuerName       string                 `json:"issuer_name"`
	IssuerOrgSlug    string                 `json:"issuer_org_slug"`
	VCT              string                 `json:"vct"`
	CredentialFormat string                 `json:"credential_format"`
	Lang             string                 `json:"lang"`
	IssuerEndpoint   string                 `json:"issuer_endpoint"`
	SchemaJSON       map[string]interface{} `json:"schema_json"`
	OfferTemplate    *string                `json:"offer_template,omitempty"`
	Tags             []string               `json:"tags"`
	CreatedAt        time.Time              `json:"created_at"`
}

// SchemaFieldDef describes a single claim field expected in a Verified credential payload.
type SchemaFieldDef struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Type      string `json:"type"` // "string" | "date" | "number" | "url"
	Mandatory bool   `json:"mandatory"`
}

// CredentialOffer represents a pending OID4VCI pre-authorized code offer.
type CredentialOffer struct {
	ID              uuid.UUID  `db:"id"                json:"id"`
	OrgID           uuid.UUID  `db:"org_id"            json:"org_id"`
	UserID          *uuid.UUID `db:"user_id"           json:"user_id,omitempty"`
	VCT             string     `db:"vct"               json:"vct"`
	PreAuthCode     string     `db:"pre_auth_code"     json:"-"`
	TxCodeHash      *string    `db:"tx_code_hash"      json:"-"`
	AccessTokenHash *string    `db:"access_token_hash" json:"-"`
	Status          string     `db:"status"            json:"status"`
	ExpiresAt       time.Time  `db:"expires_at"        json:"expires_at"`
	CreatedAt       time.Time  `db:"created_at"        json:"created_at"`
	// Payload carries arbitrary claim data for Verified credentials (training,
	// qualification, badge). When non-nil it is used as the SD-JWT claims source
	// instead of the user's profile attributes.
	Payload map[string]interface{} `db:"payload"           json:"payload,omitempty"`
	// VPSessionID links this offer to a pending OID4VP presentation session when
	// the credential config requires a Verifiable Presentation (RequireVP=true).
	VPSessionID *string `db:"vp_session_id"     json:"vp_session_id,omitempty"`
	// CNonce is the c_nonce issued for this offer at the token endpoint; the
	// holder key proof presented at the credential endpoint MUST carry it
	// (OID4VCI §8.2). CNonceExpiresAt bounds its validity.
	CNonce          *string    `db:"c_nonce"           json:"-"`
	CNonceExpiresAt *time.Time `db:"c_nonce_expires_at" json:"-"`
}

// IssuedCredential is an audit record of a credential that was issued to a wallet.
type IssuedCredential struct {
	ID               uuid.UUID  `db:"id"                 json:"id"`
	OrgID            uuid.UUID  `db:"org_id"             json:"org_id"`
	UserID           *uuid.UUID `db:"user_id"            json:"user_id,omitempty"`
	VCT              string     `db:"vct"                json:"vct"`
	SDJWTHash        string     `db:"sd_jwt_hash"        json:"sd_jwt_hash"`
	IssuedAt         time.Time  `db:"issued_at"          json:"issued_at"`
	ExpiresAt        *time.Time `db:"expires_at"         json:"expires_at,omitempty"`
	IsRevoked        bool       `db:"is_revoked"         json:"is_revoked"`
	RevokedAt        *time.Time `db:"revoked_at"         json:"revoked_at,omitempty"`
	RevocationReason *string    `db:"revocation_reason"  json:"revocation_reason,omitempty"`
	StatusListID     *uuid.UUID `db:"status_list_id"     json:"status_list_id,omitempty"`
	StatusIndex      *int       `db:"status_index"       json:"status_index,omitempty"`
	// ── Adaptive TTL tracking ─────────────────────────────────────────────────
	// LastPresentedAt is updated each time the credential's status-list slot is
	// queried by a verifier — a reliable proxy for "credential was presented".
	LastPresentedAt *time.Time `db:"last_presented_at"  json:"last_presented_at,omitempty"`
	// PresentationCount is a monotonically-increasing counter (never-used vs used).
	PresentationCount int `db:"presentation_count" json:"presentation_count"`
	// AdaptiveRenewedAt records the last time the adaptive worker extended this
	// credential's ExpiresAt (audit trail).
	AdaptiveRenewedAt *time.Time `db:"adaptive_renewed_at" json:"adaptive_renewed_at,omitempty"`
}

// FederatedInstallation is a partner Clavex instance registered for cross-
// installation revocation propagation (migration 000156).
type FederatedInstallation struct {
	ID    uuid.UUID `db:"id"                  json:"id"`
	OrgID uuid.UUID `db:"org_id"              json:"org_id"`
	// EntityID is the partner's canonical base URL / OIDF entity identifier.
	EntityID    string `db:"entity_id"           json:"entity_id"`
	DisplayName string `db:"display_name"        json:"display_name"`
	// JWKSUri is fetched on demand to verify inbound SET signatures.
	JWKSUri          string `db:"jwks_uri"            json:"jwks_uri"`
	InboundTokenHash string `db:"inbound_token_hash"  json:"-"`
	OutboundToken    string `db:"outbound_token"      json:"-"`
	// SSFEndpoint is the partner's inbound endpoint where we POST revocation SETs.
	SSFEndpoint string `db:"ssf_endpoint"        json:"ssf_endpoint"`
	// PropagateOn lists the revocation reasons that trigger cross-installation propagation.
	PropagateOn []string  `db:"propagate_on"        json:"propagate_on"`
	IsActive    bool      `db:"is_active"           json:"is_active"`
	CreatedAt   time.Time `db:"created_at"          json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"          json:"updated_at"`
}

// PresentationSession tracks an in-flight OID4VP presentation request.
// DeferredCredential represents a pending credential issuance request (OID4VCI Final §11).
// Created when the credential config has DeferredIssuance=true; the wallet receives a
// transaction_id and polls POST /deferred-credential until status transitions to
// "completed" (issuer approved) or "failed" (issuer rejected).
type DeferredCredential struct {
	ID                        uuid.UUID              `db:"id"                          json:"id"`
	OrgID                     uuid.UUID              `db:"org_id"                      json:"org_id"`
	TransactionID             string                 `db:"transaction_id"              json:"transaction_id"`
	OfferID                   uuid.UUID              `db:"offer_id"                    json:"offer_id"`
	CredentialConfigurationID string                 `db:"credential_configuration_id" json:"credential_configuration_id"`
	ProofKeyID                string                 `db:"proof_key_id"                json:"proof_key_id"`
	ClaimsPayload             map[string]interface{} `db:"claims_payload"              json:"claims_payload,omitempty"`
	Status                    string                 `db:"status"                      json:"status"` // pending | completed | failed | expired
	CredentialJWT             *string                `db:"credential_jwt"              json:"credential_jwt,omitempty"`
	ErrorCode                 *string                `db:"error_code"                  json:"error_code,omitempty"`
	ErrorDescription          *string                `db:"error_description"           json:"error_description,omitempty"`
	CreatedAt                 time.Time              `db:"created_at"                  json:"created_at"`
	ExpiresAt                 time.Time              `db:"expires_at"                  json:"expires_at"`
	CompletedAt               *time.Time             `db:"completed_at"                json:"completed_at,omitempty"`
}

type PresentationSession struct {
	ID                     uuid.UUID              `db:"id"                      json:"id"`
	OrgID                  uuid.UUID              `db:"org_id"                  json:"org_id"`
	RequestID              string                 `db:"request_id"              json:"request_id"`
	PresentationDefinition map[string]interface{} `db:"presentation_definition" json:"presentation_definition,omitempty"`
	// DCQLQuery is the OID4VP 1.0 Final DCQL query (OID4VP §6).
	// When non-nil it takes precedence over PresentationDefinition.
	DCQLQuery   map[string]interface{} `db:"dcql_query"              json:"dcql_query,omitempty"`
	ResponseURI string                 `db:"response_uri"            json:"response_uri"`
	RedirectURI *string                `db:"redirect_uri"            json:"redirect_uri,omitempty"`
	State       *string                `db:"state"                   json:"state,omitempty"`
	Nonce       string                 `db:"nonce"                   json:"nonce"`
	Status      string                 `db:"status"                  json:"status"`
	VPClaims    map[string]interface{} `db:"vp_claims"               json:"vp_claims,omitempty"`
	// CIBAAuthReqID links this VP session to a CIBA backchannel auth request.
	// Non-nil when this session was created as part of a CIBA+OID4VP SCA flow:
	// after successful VP verification the CIBA request is auto-approved.
	CIBAAuthReqID *string `db:"ciba_auth_req_id"        json:"ciba_auth_req_id,omitempty"`
	// ClientID is the OID4VP client_id used in the authorization request.
	// For redirect_uri scheme: "redirect_uri:<response_uri>".
	// For x509_san_dns scheme: "x509_san_dns:<hostname>".
	// Used by the response handler to verify KB-JWT aud (OID4VP 1.0 Final §11.4).
	ClientID  string    `db:"client_id"               json:"client_id,omitempty"`
	CreatedAt time.Time `db:"created_at"              json:"created_at"`
	ExpiresAt time.Time `db:"expires_at"              json:"expires_at"`
}

// GDPRProcessingRecord is an Article 30 Record of Processing Activity.
type GDPRProcessingRecord struct {
	ID              uuid.UUID   `db:"id"               json:"id"`
	OrgID           uuid.UUID   `db:"org_id"           json:"org_id"`
	ActivityName    string      `db:"activity_name"    json:"activity_name"`
	Purpose         string      `db:"purpose"          json:"purpose"`
	LegalBasis      string      `db:"legal_basis"      json:"legal_basis"`
	DataCategories  []string    `db:"data_categories"  json:"data_categories"`
	DataSubjects    string      `db:"data_subjects"    json:"data_subjects"`
	RetentionPeriod string      `db:"retention_period" json:"retention_period"`
	Recipients      interface{} `db:"recipients"       json:"recipients"`
	Processors      interface{} `db:"processors"       json:"processors"`
	IsActive        bool        `db:"is_active"        json:"is_active"`
	CreatedAt       time.Time   `db:"created_at"       json:"created_at"`
	UpdatedAt       time.Time   `db:"updated_at"       json:"updated_at"`
}

// ── Login history / event sourcing ───────────────────────────────────────────

// LoginEvent is an immutable record of a single authentication attempt.
// The table is append-only — never updated or deleted (except cascade on org delete).
type LoginEvent struct {
	ID            int64      `db:"id"             json:"id"`
	OrgID         uuid.UUID  `db:"org_id"         json:"org_id"`
	UserID        *uuid.UUID `db:"user_id"        json:"user_id,omitempty"`
	Email         *string    `db:"email"          json:"email,omitempty"`
	AuthMethod    string     `db:"auth_method"    json:"auth_method"`
	Status        string     `db:"status"         json:"status"`
	FailureReason *string    `db:"failure_reason" json:"failure_reason,omitempty"`
	IPAddress     *string    `db:"ip_address"     json:"ip_address,omitempty"`
	UserAgent     *string    `db:"user_agent"     json:"user_agent,omitempty"`
	CountryCode   *string    `db:"country_code"   json:"country_code,omitempty"`
	City          *string    `db:"city"           json:"city,omitempty"`
	ASNOrg        *string    `db:"asn_org"        json:"asn_org,omitempty"`
	ClientID      *uuid.UUID `db:"client_id"      json:"client_id,omitempty"`
	SessionID     *string    `db:"session_id"     json:"session_id,omitempty"`
	CreatedAt     time.Time  `db:"created_at"     json:"created_at"`
}

// OrgRateLimits holds the per-tenant rate limit configuration.
type OrgRateLimits struct {
	OrgID                uuid.UUID `db:"org_id"                   json:"org_id"`
	LoginPerIPPerMin     int       `db:"login_per_ip_per_min"     json:"login_per_ip_per_min"`
	TokenPerClientPerMin int       `db:"token_per_client_per_min" json:"token_per_client_per_min"`
	GlobalPerIPPerMin    int       `db:"global_per_ip_per_min"    json:"global_per_ip_per_min"`
	// EndpointLimits is a map of path key → requests-per-minute limit.
	// Example: {"/elevate": 3, "/oid4vci/offers": 10}
	// A missing key means no per-endpoint limit is enforced (global limit applies).
	EndpointLimits map[string]int `db:"endpoint_limits"          json:"endpoint_limits"`
	UpdatedAt      time.Time      `db:"updated_at"               json:"updated_at"`
	ManagedMarker
}

// ── Pagination ────────────────────────────────────────────────────────────────

// PageParams are the parsed query parameters for cursor-based pagination.
type PageParams struct {
	// Limit is the maximum number of items to return (capped at MaxPageSize).
	Limit int
	// After is the opaque cursor (UUID of the last item seen).
	After *uuid.UUID
	// Query is an optional email/name search filter.
	Query string
	// SortBy is the column to sort by ("email" | "created_at").
	SortBy string
}

// Page wraps a list result with cursor metadata for the client.
type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor,omitempty"`
	Total      int64   `json:"total,omitempty"`
	HasMore    bool    `json:"has_more"`
}

const MaxPageSize = 200
const DefaultPageSize = 50

// ── eIDAS ─────────────────────────────────────────────────────────────────────

// EidasConfig stores the SAML SP configuration for the eIDAS node integration.
type EidasConfig struct {
	ID             uuid.UUID `db:"id"               json:"id"`
	OrgID          uuid.UUID `db:"org_id"           json:"org_id"`
	EntityID       string    `db:"entity_id"        json:"entity_id"`
	EidasNodeURL   string    `db:"eidas_node_url"   json:"eidas_node_url"`
	ACSURL         string    `db:"acs_url"          json:"acs_url"`
	IdpCertPem     string    `db:"idp_cert_pem"     json:"-"` // never serialised
	SpCertPem      string    `db:"sp_cert_pem"      json:"sp_cert_pem"`
	SpKeyPem       string    `db:"sp_key_pem"       json:"-"` // never serialised
	RequestedLoA   string    `db:"requested_loa"    json:"requested_loa"`
	OrgName        string    `db:"org_name"         json:"org_name"`
	OrgDisplayName string    `db:"org_display_name" json:"org_display_name"`
	OrgURL         string    `db:"org_url"          json:"org_url"`
	ContactEmail   string    `db:"contact_email"    json:"contact_email"`
	IsActive       bool      `db:"is_active"        json:"is_active"`
	CreatedAt      time.Time `db:"created_at"       json:"created_at"`
	UpdatedAt      time.Time `db:"updated_at"       json:"updated_at"`
}

// TrustedDevice is a device that has passed MFA verification and been
// registered as trusted by the user.  Subsequent logins from the same device
// skip the MFA step-up requirement.
type TrustedDevice struct {
	ID              uuid.UUID `db:"id"               json:"id"`
	OrgID           uuid.UUID `db:"org_id"           json:"org_id"`
	UserID          uuid.UUID `db:"user_id"          json:"user_id"`
	FingerprintHash string    `db:"fingerprint_hash" json:"-"` // never exposed
	DisplayName     *string   `db:"display_name"     json:"display_name,omitempty"`
	UserAgent       *string   `db:"user_agent"       json:"user_agent,omitempty"`
	LastIP          *string   `db:"last_ip"          json:"last_ip,omitempty"`
	LastSeenAt      time.Time `db:"last_seen_at"     json:"last_seen_at"`
	CreatedAt       time.Time `db:"created_at"       json:"created_at"`
}

// ClientBranding holds per-OIDC-client login page customisation.
// Takes precedence over OrgBranding; missing fields fall back to org then default.
type ClientBranding struct {
	ClientID     string    `db:"client_id"    json:"client_id"`
	CompanyName  *string   `db:"company_name" json:"company_name,omitempty"`
	LogoURL      *string   `db:"logo_url"     json:"logo_url,omitempty"`
	PrimaryColor *string   `db:"primary_color" json:"primary_color,omitempty"`
	CreatedAt    time.Time `db:"created_at"   json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"   json:"updated_at"`
}

// AdminAPIKey is a long-lived machine-to-machine credential for the superadmin API.
type AdminAPIKey struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	KeyPrefix   string     `json:"key_prefix"`
	Scope       string     `json:"scope"`
	OrgID       *uuid.UUID `json:"org_id,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
}

// RARGrant is a persistent record of an RFC 9396 authorization_details consent.
// One active record per (org, user, client); revoked records are kept for audit.
type RARGrant struct {
	ID                   uuid.UUID        `json:"id"`
	OrgID                uuid.UUID        `json:"org_id"`
	UserID               uuid.UUID        `json:"user_id"`
	ClientID             string           `json:"client_id"`
	Scope                string           `json:"scope"`
	AuthorizationDetails []map[string]any `json:"authorization_details"`
	GrantedAt            time.Time        `json:"granted_at"`
	LastUsedAt           *time.Time       `json:"last_used_at,omitempty"`
	RevokedAt            *time.Time       `json:"revoked_at,omitempty"`
	IsActive             bool             `json:"is_active"`
}

// CrossOrgTrust is a directional trust relationship between two organizations
// that allows RFC 8693 token exchange across org boundaries.
//
// A trust A→B means: users from org A may exchange their tokens for tokens that
// are valid in org B (subject to scope and client_id restrictions).
type CrossOrgTrust struct {
	ID          uuid.UUID `json:"id"`
	SourceOrgID uuid.UUID `json:"source_org_id"`
	TargetOrgID uuid.UUID `json:"target_org_id"`
	// AllowedScopes, if non-nil, further narrows the scopes the exchanged token may carry.
	AllowedScopes []string `json:"allowed_scopes"`
	// AllowedClientIDs, if non-nil, restricts which clients may trigger the exchange.
	AllowedClientIDs []string `json:"allowed_client_ids"`
	// MaxTokenTTL caps the access-token lifetime (seconds). nil = server default.
	MaxTokenTTL *int `json:"max_token_ttl,omitempty"`
	// RequireMFA, when true, rejects exchanges where the subject_token has no MFA amr.
	RequireMFA bool      `json:"require_mfa"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by"`
}

// MdocProximitySession tracks an in-flight ISO 18013-5 / eIDAS 2.0 proximity
// verification session. One session = one QR code shown at a physical counter.
//
// Status flow: pending → scanned → completed | failed | expired
type MdocProximitySession struct {
	ID                     uuid.UUID              `db:"id"                      json:"id"`
	OrgID                  uuid.UUID              `db:"org_id"                  json:"org_id"`
	RequestID              string                 `db:"request_id"              json:"request_id"`
	Nonce                  string                 `db:"nonce"                   json:"nonce"`
	ClientID               string                 `db:"client_id"               json:"client_id"`
	ResponseURI            string                 `db:"response_uri"            json:"response_uri"`
	RequestedDocTypes      []string               `db:"requested_doc_types"     json:"requested_doc_types"`
	PresentationDefinition map[string]interface{} `db:"presentation_definition" json:"presentation_definition"`
	Status                 string                 `db:"status"                  json:"status"`
	VPClaims               map[string]interface{} `db:"vp_claims"               json:"vp_claims,omitempty"`
	IssuerCountry          *string                `db:"issuer_country"          json:"issuer_country,omitempty"`
	ErrorMessage           *string                `db:"error_message"           json:"error_message,omitempty"`
	RedirectURI            *string                `db:"redirect_uri"            json:"redirect_uri,omitempty"`
	CreatedAt              time.Time              `db:"created_at"              json:"created_at"`
	ExpiresAt              time.Time              `db:"expires_at"              json:"expires_at"`
	CompletedAt            *time.Time             `db:"completed_at"            json:"completed_at,omitempty"`
}

// OrgIACARoot is a trusted X.509 CA certificate uploaded by an operator for
// mdoc proximity IssuerAuth chain validation (ISO 18013-5 §9.3.3).
type OrgIACARoot struct {
	ID                uuid.UUID  `db:"id"                 json:"id"`
	OrgID             uuid.UUID  `db:"org_id"             json:"org_id"`
	Label             string     `db:"label"              json:"label"`
	SubjectDN         string     `db:"subject_dn"         json:"subject_dn"`
	SHA256Fingerprint string     `db:"sha256_fingerprint" json:"sha256_fingerprint"`
	PEM               string     `db:"pem"                json:"pem"`
	DocTypes          []string   `db:"doc_types"          json:"doc_types"`
	CreatedAt         time.Time  `db:"created_at"         json:"created_at"`
	CreatedBy         *uuid.UUID `db:"created_by"         json:"created_by,omitempty"`
	IsActive          bool       `db:"is_active"          json:"is_active"`
}

// OrgMdocIssuer holds the Document Signer (DS) key + certificate for issuing
// ISO 18013-5 mdoc credentials via OID4VCI (format: "mso_mdoc").
// The DS certificate must be signed by the org's IACA CA.
type OrgMdocIssuer struct {
	ID          uuid.UUID `db:"id"                   json:"id"`
	OrgID       uuid.UUID `db:"org_id"               json:"org_id"`
	DisplayName string    `db:"display_name"         json:"display_name"`
	DocType     string    `db:"doc_type"             json:"doc_type"`
	// DSPrivateKeyPEM is the PKCS#8 PEM-encoded ECDSA private key.
	// Nil when the key is managed by an external KMS.
	DSPrivateKeyPEM    *string   `db:"ds_private_key_pem"   json:"-"`
	DSCertificatePEM   string    `db:"ds_certificate_pem"   json:"ds_certificate_pem"`
	IACACertificatePEM *string   `db:"iaca_certificate_pem" json:"iaca_certificate_pem,omitempty"`
	ValidityHours      int       `db:"validity_hours"       json:"validity_hours"`
	IsActive           bool      `db:"is_active"            json:"is_active"`
	CreatedAt          time.Time `db:"created_at"           json:"created_at"`
	UpdatedAt          time.Time `db:"updated_at"           json:"updated_at"`
}

// ── Shared Signals Framework (SSF) ───────────────────────────────────────────

// SSFStream is a receiver registration per the OpenID SSF Framework.
// Each stream represents a subscription from an RP (receiver) to this OP
// (transmitter) for a set of CAEP/RISC security event types.
type SSFStream struct {
	ID              uuid.UUID `db:"id"               json:"stream_id"`
	OrgID           uuid.UUID `db:"org_id"           json:"-"`
	ClientID        string    `db:"client_id"        json:"aud"`
	DeliveryMethod  string    `db:"delivery_method"  json:"-"` // "push" | "poll"
	PushEndpoint    *string   `db:"push_endpoint"    json:"push_endpoint,omitempty"`
	PushSecretHash  *string   `db:"push_secret_hash" json:"-"` // SHA-256 of the signing secret; never exposed
	EventsRequested []string  `db:"events_requested" json:"events_requested"`
	Status          string    `db:"status"           json:"status"` // "enabled" | "paused" | "disabled"
	Description     *string   `db:"description"      json:"description,omitempty"`
	CreatedAt       time.Time `db:"created_at"       json:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"       json:"updated_at"`
}

// SSFPendingSet is a SET queued for poll-based delivery (RFC 8936).
type SSFPendingSet struct {
	JTI       string    `db:"jti"`
	StreamID  uuid.UUID `db:"stream_id"`
	Payload   string    `db:"payload"` // compact JWT
	EventType string    `db:"event_type"`
	CreatedAt time.Time `db:"created_at"`
	ExpiresAt time.Time `db:"expires_at"`
}

// ── Lifecycle (Joiner/Mover/Leaver) ──────────────────────────────────────────

// LifecycleTrigger is the event that fires a lifecycle rule.
type LifecycleTrigger string

const (
	TriggerJoiner LifecycleTrigger = "joiner" // user created
	TriggerMover  LifecycleTrigger = "mover"  // user attributes changed
	TriggerLeaver LifecycleTrigger = "leaver" // user deactivated or deleted
)

// LifecycleCondition is a single attribute predicate.
// All conditions in a rule must match (AND logic).
//
// field: email | first_name | last_name | is_active | <metadata key>
// op:    eq | neq | contains | starts_with | ends_with | exists | not_exists
// value: string (unused for exists / not_exists)
type LifecycleCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
}

// LifecycleAction is one action to execute when a rule fires.
// type: assign_role | remove_role | add_to_group | remove_from_group |
//
//	revoke_sessions | send_notification
//
// For assign_role / remove_role:  role_name is required.
// For add_to_group / remove_from_group: group_name is required.
// For send_notification: notification_type ("account_disabled" etc.) is used.
// revoke_sessions has no extra parameters.
type LifecycleAction struct {
	Type             string `json:"type"`
	RoleName         string `json:"role_name,omitempty"`
	GroupName        string `json:"group_name,omitempty"`
	NotificationType string `json:"notification_type,omitempty"`
}

// LifecycleRule is a single JML workflow rule stored in identity.lifecycle_rules.
type LifecycleRule struct {
	ID          uuid.UUID            `db:"id"          json:"id"`
	OrgID       uuid.UUID            `db:"org_id"      json:"org_id"`
	Name        string               `db:"name"        json:"name"`
	Description *string              `db:"description" json:"description,omitempty"`
	Trigger     LifecycleTrigger     `db:"trigger"     json:"trigger"`
	Priority    int                  `db:"priority"    json:"priority"`
	Conditions  []LifecycleCondition `db:"conditions"  json:"conditions"`
	Actions     []LifecycleAction    `db:"actions"     json:"actions"`
	IsActive    bool                 `db:"is_active"   json:"is_active"`
	CreatedAt   time.Time            `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time            `db:"updated_at"  json:"updated_at"`
}

// ── Access Review / Certification (Identity Governance) ──────────────────────

// AccessReviewCampaign represents a periodic certification campaign where
// reviewers certify that users should retain their current role assignments.
type AccessReviewCampaign struct {
	ID          uuid.UUID `db:"id"            json:"id"`
	OrgID       uuid.UUID `db:"org_id"        json:"org_id"`
	Name        string    `db:"name"          json:"name"`
	Description *string   `db:"description"   json:"description,omitempty"`
	// frequency: "monthly" | "quarterly" | "annual" | "one_time"
	Frequency string `db:"frequency"     json:"frequency"`
	// status: "pending" | "active" | "completed" | "cancelled"
	Status   string    `db:"status"        json:"status"`
	StartsAt time.Time `db:"starts_at"     json:"starts_at"`
	EndsAt   time.Time `db:"ends_at"       json:"ends_at"`
	// ReminderDays: days before EndsAt to send reminder emails (e.g. [3,1])
	ReminderDays []int      `db:"reminder_days" json:"reminder_days"`
	AutoRevoke   bool       `db:"auto_revoke"   json:"auto_revoke"`
	CreatedBy    *uuid.UUID `db:"created_by"    json:"created_by,omitempty"`
	CreatedAt    time.Time  `db:"created_at"    json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at"    json:"updated_at"`

	// Computed stats (not stored in DB, populated on read)
	TotalItems    int `db:"-" json:"total_items,omitempty"`
	PendingItems  int `db:"-" json:"pending_items,omitempty"`
	ApprovedItems int `db:"-" json:"approved_items,omitempty"`
	RevokedItems  int `db:"-" json:"revoked_items,omitempty"`
}

// AccessReviewItem is a single user × role certification task within a campaign.
type AccessReviewItem struct {
	ID         uuid.UUID `db:"id"              json:"id"`
	CampaignID uuid.UUID `db:"campaign_id"     json:"campaign_id"`
	OrgID      uuid.UUID `db:"org_id"          json:"org_id"`
	UserID     uuid.UUID `db:"user_id"         json:"user_id"`
	RoleID     uuid.UUID `db:"role_id"         json:"role_id"`
	ReviewerID uuid.UUID `db:"reviewer_id"     json:"reviewer_id"`
	// decision: "pending" | "approved" | "revoked" | "auto_revoked"
	Decision       string     `db:"decision"        json:"decision"`
	Token          string     `db:"token"           json:"-"` // never expose in API responses
	DecidedAt      *time.Time `db:"decided_at"      json:"decided_at,omitempty"`
	Comment        *string    `db:"comment"         json:"comment,omitempty"`
	LastRemindedAt *time.Time `db:"last_reminded_at" json:"last_reminded_at,omitempty"`
	CreatedAt      time.Time  `db:"created_at"      json:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"      json:"updated_at"`

	// Denormalised fields populated by JOIN queries (not stored)
	UserEmail     string `db:"user_email"    json:"user_email,omitempty"`
	UserName      string `db:"user_name"     json:"user_name,omitempty"`
	RoleName      string `db:"role_name"     json:"role_name,omitempty"`
	ReviewerEmail string `db:"reviewer_email" json:"reviewer_email,omitempty"`
	ReviewerName  string `db:"reviewer_name"  json:"reviewer_name,omitempty"`
}

// ── Login Flow Step Builder ───────────────────────────────────────────────────

// LoginFlow is a named sequence of steps applied during the authentication
// interaction for an organisation (or a specific OIDC client).
type LoginFlow struct {
	ID          uuid.UUID `db:"id"          json:"id"`
	OrgID       uuid.UUID `db:"org_id"      json:"org_id"`
	Name        string    `db:"name"        json:"name"`
	Description *string   `db:"description" json:"description,omitempty"`
	IsDefault   bool      `db:"is_default"  json:"is_default"`
	IsActive    bool      `db:"is_active"   json:"is_active"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"  json:"updated_at"`

	// Steps populated by JOIN — not stored in this row.
	Steps []LoginFlowStep `db:"-" json:"steps,omitempty"`
}

// LoginFlowStep is one configurable block within a LoginFlow.
// The step_type selects which pre-built action executes; Config is its
// JSON parameters (different shape per type).
//
// Supported step types:
//   - check_attribute        block/allow based on user profile field
//   - require_mfa            force MFA (blocks if not enrolled)
//   - block_if_no_mfa        deny if no MFA is enrolled
//   - enrich_claims          call external HTTP API, map response to claims
//   - set_claim              set a static or attribute-derived claim
//   - webhook                POST to external URL (post-login, non-blocking)
//   - check_ip_risk          deny or require MFA based on risk score
//   - require_email_verified deny if email not verified
//   - check_breach           deny or require MFA if credentials were found in a data breach
//   - check_verified         deny if IDA assurance_level is below the configured minimum (low/substantial/high)
type LoginFlowStep struct {
	ID        uuid.UUID       `db:"id"        json:"id"`
	FlowID    uuid.UUID       `db:"flow_id"   json:"flow_id"`
	OrgID     uuid.UUID       `db:"org_id"    json:"org_id"`
	StepType  string          `db:"step_type" json:"step_type"`
	Position  int             `db:"position"  json:"position"`
	Config    json.RawMessage `db:"config"    json:"config"`
	IsActive  bool            `db:"is_active" json:"is_active"`
	CreatedAt time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt time.Time       `db:"updated_at" json:"updated_at"`
}

// ── Entity Review Campaigns ───────────────────────────────────────────────────

// EntityReviewCampaign is a periodic certification campaign for OIDC clients,
// groups, or roles. Admins confirm each entity is still needed; unconfirmed
// entities are auto-disabled when the campaign deadline passes.
type EntityReviewCampaign struct {
	ID          uuid.UUID `db:"id"             json:"id"`
	OrgID       uuid.UUID `db:"org_id"         json:"org_id"`
	Name        string    `db:"name"           json:"name"`
	Description *string   `db:"description"    json:"description,omitempty"`
	// EntityType: "client" | "group" | "role"
	EntityType string `db:"entity_type"    json:"entity_type"`
	// FrequencyDays: recurrence interval (0 = one-shot).
	FrequencyDays int `db:"frequency_days" json:"frequency_days"`
	// Status: "pending" | "active" | "completed" | "cancelled"
	Status       string     `db:"status"         json:"status"`
	StartsAt     time.Time  `db:"starts_at"      json:"starts_at"`
	EndsAt       time.Time  `db:"ends_at"        json:"ends_at"`
	ReminderDays []int      `db:"reminder_days"  json:"reminder_days"`
	AutoDisable  bool       `db:"auto_disable"   json:"auto_disable"`
	CreatedBy    *uuid.UUID `db:"created_by"     json:"created_by,omitempty"`
	CreatedAt    time.Time  `db:"created_at"     json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at"     json:"updated_at"`

	// Computed counts (populated on read, not stored).
	TotalItems      int `db:"-" json:"total_items,omitempty"`
	PendingItems    int `db:"-" json:"pending_items,omitempty"`
	ConfirmedItems  int `db:"-" json:"confirmed_items,omitempty"`
	DeprecatedItems int `db:"-" json:"deprecated_items,omitempty"`
}

// EntityReviewItem is a single entity certification task within a campaign.
type EntityReviewItem struct {
	ID         uuid.UUID `db:"id"               json:"id"`
	CampaignID uuid.UUID `db:"campaign_id"      json:"campaign_id"`
	OrgID      uuid.UUID `db:"org_id"           json:"org_id"`
	EntityType string    `db:"entity_type"      json:"entity_type"`
	EntityID   string    `db:"entity_id"        json:"entity_id"`
	EntityName string    `db:"entity_name"      json:"entity_name"`
	ReviewerID uuid.UUID `db:"reviewer_id"      json:"reviewer_id"`
	// Decision: "pending" | "confirmed" | "deprecated" | "auto_deprecated"
	Decision       string     `db:"decision"         json:"decision"`
	Token          string     `db:"token"            json:"-"`
	DecidedAt      *time.Time `db:"decided_at"       json:"decided_at,omitempty"`
	Comment        *string    `db:"comment"          json:"comment,omitempty"`
	LastRemindedAt *time.Time `db:"last_reminded_at" json:"last_reminded_at,omitempty"`
	CreatedAt      time.Time  `db:"created_at"       json:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"       json:"updated_at"`

	// Denormalised reviewer info (populated by JOIN queries).
	ReviewerEmail string `db:"reviewer_email" json:"reviewer_email,omitempty"`
	ReviewerName  string `db:"reviewer_name"  json:"reviewer_name,omitempty"`
}

// ── Actions V2 ────────────────────────────────────────────────────────────────

// ActionTarget is a named external HTTP endpoint that receives event hooks,
// or an inline JS sandbox that runs directly in-process.
type ActionTarget struct {
	ID    uuid.UUID `db:"id"             json:"id"`
	OrgID uuid.UUID `db:"org_id"         json:"org_id"`
	Name  string    `db:"name"           json:"name"`
	// TargetType is "http" (default) or "sandbox" (inline JS).
	TargetType string `db:"target_type"    json:"target_type"`
	URL        string `db:"url"            json:"url"`
	// SandboxCode holds the JS source when TargetType == "sandbox".
	// The code must export an onEvent(event) function.
	SandboxCode   *string   `db:"sandbox_code"   json:"sandbox_code,omitempty"`
	TimeoutMs     int       `db:"timeout_ms"     json:"timeout_ms"`
	SigningSecret *string   `db:"signing_secret" json:"-"` // never exposed
	IsActive      bool      `db:"is_active"      json:"is_active"`
	CreatedAt     time.Time `db:"created_at"     json:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"     json:"updated_at"`
}

// ActionExecution binds a target to an event type.
// When the event fires Clavex calls the target and (for sync events) uses
// the response to modify behaviour.
type ActionExecution struct {
	ID       uuid.UUID `db:"id"         json:"id"`
	OrgID    uuid.UUID `db:"org_id"     json:"org_id"`
	TargetID uuid.UUID `db:"target_id"  json:"target_id"`
	Name     string    `db:"name"       json:"name"`
	// EventType: "user.pre_login" | "user.pre_token" | "user.created" |
	//            "user.updated" | "user.deleted" | "user.pre_create" |
	//            "user.pre_update" | "user.pre_password_change"
	EventType string          `db:"event_type" json:"event_type"`
	Condition json.RawMessage `db:"condition"  json:"condition"`
	// Mode determines the dispatch strategy:
	//   fire_and_forget — POST asynchronously, ignore response (default)
	//   mutation        — POST synchronously, use modified response body as
	//                     the actual request data (request/response mutation)
	Mode      string    `db:"mode"       json:"mode"`
	IsActive  bool      `db:"is_active"  json:"is_active"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`

	// Denormalised (populated by JOIN).
	TargetName string `db:"target_name" json:"target_name,omitempty"`
	TargetURL  string `db:"target_url"  json:"target_url,omitempty"`
}

// WSFedRelyingParty is a registered WS-Federation passive requestor SP.
type WSFedRelyingParty struct {
	ID                   uuid.UUID         `db:"id"                     json:"id"`
	OrgID                uuid.UUID         `db:"org_id"                 json:"org_id"`
	Name                 string            `db:"name"                   json:"name"`
	Realm                string            `db:"realm"                  json:"realm"`
	WreplyURIs           []string          `db:"wreply_uris"            json:"wreply_uris"`
	TokenLifetimeSeconds int               `db:"token_lifetime_seconds" json:"token_lifetime_seconds"`
	ClaimsMapping        map[string]string `db:"claims_mapping"         json:"claims_mapping"`
	IsActive             bool              `db:"is_active"              json:"is_active"`
	CreatedAt            time.Time         `db:"created_at"             json:"created_at"`
	UpdatedAt            time.Time         `db:"updated_at"             json:"updated_at"`
}

// OrgAsset is an uploaded binary asset (logo, favicon, background) stored on S3.
type OrgAsset struct {
	ID          uuid.UUID `db:"id"           json:"id"`
	OrgID       uuid.UUID `db:"org_id"       json:"org_id"`
	AssetType   string    `db:"asset_type"   json:"asset_type"` // logo|favicon|background|icon
	S3Key       string    `db:"s3_key"       json:"s3_key"`
	ContentType string    `db:"content_type" json:"content_type"`
	SizeBytes   int64     `db:"size_bytes"   json:"size_bytes"`
	URL         string    `db:"url"          json:"url"`
	CreatedAt   time.Time `db:"created_at"   json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"   json:"updated_at"`
}

// ServiceAccount is an org-scoped M2M identity with its own client_id/secret.
type ServiceAccount struct {
	ID               uuid.UUID  `db:"id"                 json:"id"`
	OrgID            uuid.UUID  `db:"org_id"             json:"org_id"`
	Name             string     `db:"name"               json:"name"`
	Description      *string    `db:"description"        json:"description,omitempty"`
	ClientID         string     `db:"client_id"          json:"client_id"`
	ClientSecretHash string     `db:"client_secret_hash" json:"-"`
	Scopes           []string   `db:"scopes"             json:"scopes"`
	IsActive         bool       `db:"is_active"          json:"is_active"`
	LastUsedAt       *time.Time `db:"last_used_at"       json:"last_used_at,omitempty"`
	CreatedAt        time.Time  `db:"created_at"         json:"created_at"`
	UpdatedAt        time.Time  `db:"updated_at"         json:"updated_at"`
}

// AppFamily groups OIDC clients for cross-app SSO and coordinated logout.
type AppFamily struct {
	ID          uuid.UUID `db:"id"          json:"id"`
	OrgID       uuid.UUID `db:"org_id"      json:"org_id"`
	Name        string    `db:"name"        json:"name"`
	Description *string   `db:"description" json:"description,omitempty"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"  json:"updated_at"`
	// Populated on Get/List
	Members []AppFamilyMember `db:"-" json:"members,omitempty"`
}

// AppFamilyMember is a client that belongs to an application family.
type AppFamilyMember struct {
	FamilyID             uuid.UUID `db:"family_id"              json:"family_id"`
	ClientID             string    `db:"client_id"              json:"client_id"`
	BackchannelLogoutURI *string   `db:"backchannel_logout_uri" json:"backchannel_logout_uri,omitempty"`
	CreatedAt            time.Time `db:"created_at"             json:"created_at"`
}

// ─── Feature Flags ─────────────────────────────────────────────────────────────

// FeatureFlag is a per-org boolean flag that is resolved and injected as the
// "flags" claim in every JWT issued to users of that organisation.
type FeatureFlag struct {
	ID          uuid.UUID `db:"id"          json:"id"`
	OrgID       uuid.UUID `db:"org_id"      json:"org_id"`
	Key         string    `db:"key"         json:"key"`
	Description string    `db:"description" json:"description"`
	Value       bool      `db:"value"       json:"value"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"  json:"updated_at"`
}

// FeatureFlagOverride overrides a flag's default value for a specific user or role.
// Resolution order: user override > role override > flag default.
type FeatureFlagOverride struct {
	ID         uuid.UUID `db:"id"          json:"id"`
	FlagID     uuid.UUID `db:"flag_id"     json:"flag_id"`
	TargetType string    `db:"target_type" json:"target_type"` // "user" | "role"
	TargetID   uuid.UUID `db:"target_id"   json:"target_id"`
	Value      bool      `db:"value"       json:"value"`
}

// ── Account Center ────────────────────────────────────────────────────────────

// AccountCenterConfig stores the per-org configuration for the user-facing
// Account Center widget (<ClavexAccountCenter /> in @clavex/react).
// Each boolean field controls whether the corresponding self-service section
// is rendered in the widget.  When no row exists for an org, DefaultAccountCenterConfig
// supplies all-enabled defaults so the widget always works out of the box.
type AccountCenterConfig struct {
	OrgID          uuid.UUID `db:"org_id"           json:"org_id"`
	ShowProfile    bool      `db:"show_profile"     json:"show_profile"`
	ShowPassword   bool      `db:"show_password"    json:"show_password"`
	ShowMFA        bool      `db:"show_mfa"         json:"show_mfa"`
	ShowPasskeys   bool      `db:"show_passkeys"    json:"show_passkeys"`
	ShowSessions   bool      `db:"show_sessions"    json:"show_sessions"`
	ShowActivity   bool      `db:"show_activity"    json:"show_activity"`
	ShowDataExport bool      `db:"show_data_export" json:"show_data_export"`
	// PageTitle is an optional custom heading shown inside the widget.
	// Defaults to "My Account" when nil.
	PageTitle *string   `db:"page_title"       json:"page_title,omitempty"`
	UpdatedAt time.Time `db:"updated_at"       json:"updated_at"`
}

// DefaultAccountCenterConfig returns an AccountCenterConfig with all sections
// enabled, used as a fallback when the org has not saved a custom config.
func DefaultAccountCenterConfig(orgID uuid.UUID) *AccountCenterConfig {
	return &AccountCenterConfig{
		OrgID:          orgID,
		ShowProfile:    true,
		ShowPassword:   true,
		ShowMFA:        true,
		ShowPasskeys:   true,
		ShowSessions:   true,
		ShowActivity:   true,
		ShowDataExport: true,
	}
}

package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// PAMAlertConfig holds server-level configuration for PAM security alert
// delivery to Slack and Microsoft Teams.
type PAMAlertConfig struct {
	// SlackWebhookURL is an Incoming Webhook URL for a Slack channel.
	SlackWebhookURL string `mapstructure:"slack_webhook_url"`
	// TeamsWebhookURL is an Incoming Webhook URL for a Microsoft Teams channel.
	TeamsWebhookURL string `mapstructure:"teams_webhook_url"`
	// AdminBaseURL is the base URL of the Clavex admin console, used to build
	// deep-link buttons in alert messages (e.g. "https://admin.example.com").
	AdminBaseURL string `mapstructure:"admin_base_url"`
	// StaleCredentialDays is the number of days after which a vault credential
	// that has not been rotated triggers a stale-credential alert. Default: 30.
	StaleCredentialDays int `mapstructure:"stale_credential_days"`
	// SessionMaxHours is the maximum privileged session duration before a
	// long-session alert fires. Default: 8.
	SessionMaxHours int `mapstructure:"session_max_hours"`
}

// ShieldConfig holds configuration for Clavex Shield features.
type ShieldConfig struct {
	ThreatFeed ThreatFeedConfig `mapstructure:"threat_feed"`
}

// ThreatFeedConfig configures the distributed community threat feed.
// Enable with shield.threat_feed.enabled=true and set a URL pointing to the
// Clavex Shield aggregator (e.g. https://feed.clavex.eu).
type ThreatFeedConfig struct {
	// Enabled activates the distributed threat feed. Default false.
	Enabled bool `mapstructure:"enabled"`
	// URL is the base URL of the Clavex Shield aggregator.
	URL string `mapstructure:"url"`
	// SharedKey is the HMAC-SHA256 key used to obfuscate IPs before reporting.
	// Hex or base64-encoded. Distributed to authenticated installations only.
	SharedKey string `mapstructure:"shared_key"`
	// Report enables opt-in contribution: detected brute-force IPs are reported
	// to the aggregator in the background. Requires a valid license JWT.
	Report bool `mapstructure:"report"`
	// SigningPubKey is the PEM-encoded EC P-256 public key of the aggregator,
	// used to verify the cryptographic signature on downloaded feed payloads.
	SigningPubKey string `mapstructure:"signing_pub_key"`
	// Threshold is the minimum number of distinct reporting installations
	// required for an IP hash to be included in the published feed. Default 5.
	Threshold int `mapstructure:"threshold"`
}

type Config struct {
	Dev            bool                 `mapstructure:"dev"`
	HTTP           HTTPConfig           `mapstructure:"http"`
	Database       DatabaseConfig       `mapstructure:"database"`
	Redis          RedisConfig          `mapstructure:"redis"`
	Auth           AuthConfig           `mapstructure:"auth"`
	Shield         ShieldConfig         `mapstructure:"shield"`
	Federation     FederationConfig     `mapstructure:"federation"`
	Connectors     ConnectorsConfig     `mapstructure:"connectors"`
	Telemetry      TelemetryConfig      `mapstructure:"telemetry"`
	UsageReporting UsageReportingConfig `mapstructure:"usage_reporting"`
	License        LicenseConfig        `mapstructure:"license"`
	FGA            FGAConfig            `mapstructure:"fga"`
	Storage        StorageConfig        `mapstructure:"storage"`
	PAMAlerts      PAMAlertConfig       `mapstructure:"pam_alerts"`
	OID4VP         OID4VPConfig         `mapstructure:"oid4vp"`
	SSF            SSFConfig            `mapstructure:"ssf"`
}

// SSFConfig configures the Shared Signals Framework receiver (inbound CAEP SETs).
type SSFConfig struct {
	// TrustedTransmitters is the allow-list of upstream transmitters whose
	// Security Event Tokens (SETs) the receiver accepts. A SET is verified against
	// the JWKS of the matching issuer; SETs from issuers not listed here (or any
	// SET when the list is empty) are rejected. This is the ONLY authentication of
	// the inbound /:org_slug/ssf/events endpoint.
	TrustedTransmitters []SSFTrustedTransmitter `mapstructure:"trusted_transmitters"`
}

// SSFTrustedTransmitter pairs a SET issuer with the JWKS used to verify its
// signature.
type SSFTrustedTransmitter struct {
	// Issuer is the exact value of the SET "iss" claim.
	Issuer string `mapstructure:"issuer"`
	// JWKSURI is the HTTPS URL of the transmitter's JWKS used to verify SET signatures.
	JWKSURI string `mapstructure:"jwks_uri"`
}

// StorageConfig configures S3-compatible object storage for org binary assets
// (logos, favicons, backgrounds). When Endpoint is empty, asset upload is disabled
// and the API returns 501.
type StorageConfig struct {
	// Endpoint is the S3-compatible API base URL.
	// e.g. "https://s3.eu-west-1.amazonaws.com" or "http://minio:9000"
	Endpoint string `mapstructure:"endpoint"`
	// Bucket is the S3 bucket name where assets are stored.
	Bucket string `mapstructure:"bucket"`
	// Region is the AWS region (or "us-east-1" for MinIO).
	Region string `mapstructure:"region"`
	// AccessKey is the AWS access key ID or MinIO access key.
	AccessKey string `mapstructure:"access_key"`
	// SecretKey is the AWS secret access key or MinIO secret key.
	SecretKey string `mapstructure:"secret_key"`
	// PublicBaseURL overrides the public URL prefix for served assets.
	// e.g. "https://cdn.example.com/assets"
	// If empty, assets are served from Endpoint/Bucket/<key>.
	PublicBaseURL string `mapstructure:"public_base_url"`
	// LocalDir, when set, enables the local filesystem backend as a fallback
	// when Endpoint is empty. Files are written to LocalDir and served at
	// LocalBaseURL (which must be an absolute URL reachable by clients).
	// e.g. LocalDir="/var/lib/clavex/assets", LocalBaseURL="https://auth.example.com/_assets"
	LocalDir     string `mapstructure:"local_dir"`
	LocalBaseURL string `mapstructure:"local_base_url"`
}

// TelemetryConfig controls OpenTelemetry distributed tracing.
type TelemetryConfig struct {
	// Enabled toggles OTLP trace export. When false a no-op provider is used.
	Enabled bool `mapstructure:"enabled"`
	// OTLPEndpoint is the OTLP/HTTP collector base URL,
	// e.g. "http://otel-collector:4318". Traces are posted to /v1/traces.
	OTLPEndpoint string `mapstructure:"otlp_endpoint"`
	// ServiceName is embedded into every span's resource (default: "clavex").
	ServiceName string `mapstructure:"service_name"`
	// SampleRate is a probability in [0.0, 1.0]; 1.0 = 100 % (default).
	SampleRate float64 `mapstructure:"sample_rate"`
}

// FederationConfig controls OpenID Federation 1.0 behaviour.
// When Enabled is false the /.well-known/openid-federation endpoint returns 404
// and no federation fields are added to the OIDC Discovery document.
type FederationConfig struct {
	// Enabled activates OIDF 1.0 support. Default false.
	Enabled bool `mapstructure:"enabled"`

	// OrganizationName is the human-readable operator name published in
	// federation_entity metadata (visible to federation-aware RPs).
	OrganizationName string `mapstructure:"organization_name"`

	// AuthorityHints is the ordered list of trust anchor / intermediate entity
	// IDs the federation uses to build the trust chain upward from this OP.
	// Examples:
	//   IDEM-GARR:  ["https://registry.idem.garr.it"]
	//   GÉANT:      ["https://federation.geant.org"]
	AuthorityHints []string `mapstructure:"authority_hints"`

	// JWTLifetime is the Entity Configuration JWT validity in seconds.
	// 0 (default) → 86400 s (24 h).
	JWTLifetime time.Duration `mapstructure:"jwt_lifetime"`

	// Contacts is an optional list of email addresses / URIs for the operator.
	Contacts []string `mapstructure:"contacts"`

	// HomepageURI links to the operator's web site.
	HomepageURI string `mapstructure:"homepage_uri"`

	// LogoURI is the URL of a logo shown in federation discovery UIs.
	LogoURI string `mapstructure:"logo_uri"`

	// TrustAnchors is the list of trust anchor entity IDs this OP will accept
	// when validating explicit federation registration requests.
	// If empty, explicit registration will reject all requests.
	// Examples:
	//   IDEM-GARR:  ["https://registry.idem.garr.it"]
	//   GÉANT:      ["https://federation.geant.org"]
	TrustAnchors []string `mapstructure:"trust_anchors"`

	// TrustAnchorMode activates Clavex as a Trust Anchor for private eIDAS 2.0
	// ecosystems (banking consortia, university federations, wallet ecosystems).
	// When true the TA federation endpoints are served:
	//   GET  /federation/fetch          — entity statements about subordinates (OIDF §7.3.2)
	//   GET  /federation/list           — list of subordinate entity IDs (OIDF §7.3.1)
	//   POST /federation/trust-mark     — issue a trust mark (OIDF §7.4)
	//   GET  /federation/trust-mark/list   — list trust mark subjects (OIDF §7.5)
	//   GET  /federation/trust-mark/status — active/revoked status (OIDF §7.6)
	// The TA Entity Configuration omits authority_hints (self-signed root).
	TrustAnchorMode bool `mapstructure:"trust_anchor_mode"`

	// TrustAnchorEntityID overrides the entity ID used in the TA Entity Configuration.
	// Defaults to the OIDC issuer URL when empty.
	// Use a stable, well-known URI for production deployments,
	// e.g. "https://trust.consortium.eu".
	TrustAnchorEntityID string `mapstructure:"trust_anchor_entity_id"`
}

// ConnectorsConfig holds zero or more event-connector definitions.
type ConnectorsConfig struct {
	HTTP []HTTPConnectorConfig `mapstructure:"http"`
	MQTT []MQTTConnectorConfig `mapstructure:"mqtt"`
}

// HTTPConnectorConfig configures a single HTTP event connector.
type HTTPConnectorConfig struct {
	URL    string   `mapstructure:"url"`
	Secret string   `mapstructure:"secret"`
	Events []string `mapstructure:"events"` // empty = all events
}

// MQTTConnectorConfig configures a single MQTT event connector.
type MQTTConnectorConfig struct {
	BrokerURL    string   `mapstructure:"broker_url"`
	ClientID     string   `mapstructure:"client_id"`
	Username     string   `mapstructure:"username"`
	Password     string   `mapstructure:"password"`
	TopicPattern string   `mapstructure:"topic_pattern"` // default: "clavex/%s"
	QoS          byte     `mapstructure:"qos"`
	Events       []string `mapstructure:"events"`
}

type HTTPConfig struct {
	Addr        string `mapstructure:"addr"`
	BaseDomain  string `mapstructure:"base_domain"` // e.g. clavex.eu
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`
	// MTLSClientCACertFile is the path to a PEM CA bundle used to verify client
	// TLS certificates (RFC 8705 Mutual-TLS Client Authentication).
	// When non-empty, the server requires clients to present a valid certificate
	// signed by one of these CAs. Certificate-bound access tokens (cnf.x5t#S256)
	// are issued whenever a client cert is present, regardless of this setting.
	MTLSClientCACertFile string `mapstructure:"mtls_client_ca_cert_file"`
	// CORSAllowedOrigins lists the browser origins allowed to call the API
	// cross-origin (config/ENV only — CLAVEX_HTTP_CORS_ALLOWED_ORIGINS; there is no
	// UI to change it). SECURITY: a literal "*" allows ANY origin. This is only
	// safe because credentialed CORS is disabled and the API authenticates with
	// Bearer tokens (a malicious site cannot read responses without the token).
	// Prefer listing exact origins; do not use "*" in production unless you
	// understand the implication.
	CORSAllowedOrigins []string `mapstructure:"cors_allowed_origins"`
	// TrustedProxies is a list of CIDR ranges for upstream proxies (e.g. Kubernetes
	// pod network) that are trusted to set X-Forwarded-For. When non-empty, Echo
	// uses X-Forwarded-For to resolve the real client IP instead of RemoteAddr.
	// Example: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
	TrustedProxies []string `mapstructure:"trusted_proxies"`
	// AllowPrivateOutboundTargets, when true, disables the SSRF guard on
	// operator/tenant-configured outbound requests (webhooks, SCIM push, SSF push,
	// federation/JAR fetchers, Vault, upstream IdP token/userinfo, SMS gateways),
	// permitting connections to private/loopback/link-local addresses. Default
	// false (block). Enable only when these intentionally target internal hosts.
	AllowPrivateOutboundTargets bool `mapstructure:"allow_private_outbound_targets"`
}

// IssuerURL builds the per-tenant OIDC issuer URL.
// It is now a method on Config so it can prefer Auth.IssuerBase (which carries
// the correct public scheme even when TLS is terminated upstream by a proxy).
func (h *HTTPConfig) IssuerURL(orgSlug string) string {
	scheme := "https"
	if h.TLSCertFile == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/%s", scheme, h.BaseDomain, orgSlug)
}

// IssuerURLFromBase builds the per-tenant OIDC issuer URL using issuerBase
// (e.g. "https://id.clavex.eu") as the base, falling back to IssuerURL when
// issuerBase is empty. This is the preferred method when TLS is terminated by
// an upstream proxy and TLSCertFile is not set.
func (h *HTTPConfig) IssuerURLFromBase(issuerBase, orgSlug string) string {
	if issuerBase != "" {
		return strings.TrimRight(issuerBase, "/") + "/" + orgSlug
	}
	return h.IssuerURL(orgSlug)
}

// CORSAllowOrigin returns a function compatible with echo's AllowOriginFunc.
func (h *HTTPConfig) CORSAllowOrigin(origin string) (bool, error) {
	if len(h.CORSAllowedOrigins) == 0 {
		return false, nil
	}
	for _, o := range h.CORSAllowedOrigins {
		if o == "*" || o == origin {
			return true, nil
		}
	}
	return false, nil
}

// DatabaseMode controls whether the application uses an external PostgreSQL
// instance or starts its own embedded one (for self-hosted deployments).
type DatabaseMode string

const (
	// DatabaseModeExternal uses a user-supplied DSN to connect to an existing
	// PostgreSQL server.
	DatabaseModeExternal DatabaseMode = "external"
	// DatabaseModeEmbedded downloads and starts a bundled PostgreSQL process
	// managed entirely by clavex. Suitable for single-node self-hosted setups.
	DatabaseModeEmbedded DatabaseMode = "embedded"
)

type DatabaseConfig struct {
	// Mode selects the database backend. Defaults to "external".
	Mode DatabaseMode `mapstructure:"mode"`

	// External mode: full libpq-compatible DSN.
	// e.g. postgres://user:pass@host:5432/clavex?sslmode=require
	DSN string `mapstructure:"dsn"`

	// Embedded mode options.
	Embedded EmbeddedDatabaseConfig `mapstructure:"embedded"`

	MaxConns int32 `mapstructure:"max_conns"`
	MinConns int32 `mapstructure:"min_conns"`
}

type EmbeddedDatabaseConfig struct {
	// DataDir is where the embedded PostgreSQL stores its data files.
	// Defaults to <user cache dir>/clavex/pgdata.
	DataDir  string `mapstructure:"data_dir"`
	Port     uint32 `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Database string `mapstructure:"database"`
}

// RedisMode selects the Redis topology.
type RedisMode string

const (
	// RedisModeStandalone connects to a single Redis node (default).
	RedisModeStandalone RedisMode = "standalone"
	// RedisModeCluster connects to a Redis Cluster (multiple shards).
	RedisModeCluster RedisMode = "cluster"
	// RedisModeSentinel uses Redis Sentinel for HA failover.
	RedisModeSentinel RedisMode = "sentinel"
)

type RedisConfig struct {
	// Mode selects the Redis topology. Defaults to "standalone".
	Mode RedisMode `mapstructure:"mode"`

	// Standalone / Sentinel primary node address (host:port).
	Addr string `mapstructure:"addr"`

	// Cluster mode: comma-separated list of seed addresses.
	// e.g. "redis-1:6379,redis-2:6379,redis-3:6379"
	Addrs []string `mapstructure:"addrs"`

	// Sentinel mode: master group name and sentinel addresses.
	MasterName    string   `mapstructure:"master_name"`
	SentinelAddrs []string `mapstructure:"sentinel_addrs"`

	Password         string `mapstructure:"password"`
	SentinelPassword string `mapstructure:"sentinel_password"` // if sentinels require auth
	DB               int    `mapstructure:"db"`                // ignored in cluster mode

	// TLS
	TLSEnabled  bool   `mapstructure:"tls_enabled"`
	TLSCertFile string `mapstructure:"tls_cert_file"` // client cert (mTLS)
	TLSKeyFile  string `mapstructure:"tls_key_file"`
	TLSCAFile   string `mapstructure:"tls_ca_file"` // custom CA

	// Pool sizing
	PoolSize    int `mapstructure:"pool_size"`     // default: 10
	MinIdleConn int `mapstructure:"min_idle_conn"` // default: 2
}

type AuthConfig struct {
	// RSA private key PEM path for signing JWTs / OIDC tokens
	SigningKeyFile string `mapstructure:"signing_key_file"`
	// Issuer base URL (e.g. https://clavex.eu)
	IssuerBase string `mapstructure:"issuer_base"`
	// Access token lifetime in seconds
	AccessTokenTTL int `mapstructure:"access_token_ttl"`
	// Refresh token lifetime in seconds
	RefreshTokenTTL int `mapstructure:"refresh_token_ttl"`
	// AdminSecret is the HMAC secret used to sign admin-console JWTs.
	// Must be set via env CLAVEX_AUTH_ADMIN_SECRET or config file.
	AdminSecret string `mapstructure:"admin_secret"`
	// AdminCookieDomain scopes the HttpOnly admin-session cookie. Leave empty
	// for a host-only cookie (single-host deploys); set to a parent domain such
	// as ".clavex.eu" when the SPA and API live on different subdomains.
	// Set via CLAVEX_AUTH_ADMIN_COOKIE_DOMAIN.
	AdminCookieDomain string `mapstructure:"admin_cookie_domain"`
	// AdminCookieSecure marks the admin-session cookie Secure (HTTPS-only).
	// Defaults to true; set false only for local http:// development.
	// Set via CLAVEX_AUTH_ADMIN_COOKIE_SECURE.
	AdminCookieSecure bool `mapstructure:"admin_cookie_secure"`
	// EncryptionKey is the master secret for AES-256-GCM encryption of secrets at rest
	// (LDAP bind passwords, SCIM push bearer tokens, webhook signing secrets).
	// If empty, AdminSecret is used as the key source.
	// Set via CLAVEX_AUTH_ENCRYPTION_KEY or config file.
	EncryptionKey string `mapstructure:"encryption_key"`
	// KeyBackend selects where RSA signing keys are stored and rotated.
	// "file" (default): load from signing_key_file; in-memory rotation only.
	// "db": keys are stored in the signing_keys table, encrypted with KeyEncryptionKey.
	// Set via CLAVEX_AUTH_KEY_BACKEND.
	KeyBackend string `mapstructure:"key_backend"`
	// KeyEncryptionKey is the base64url-encoded 32-byte key used to encrypt
	// signing keys stored in the database (key_backend=db).
	// Generate with: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
	// Set via CLAVEX_AUTH_KEY_ENCRYPTION_KEY.
	KeyEncryptionKey string `mapstructure:"key_encryption_key"`

	// ── HashiCorp Vault Transit backend (key_backend=vault) ──────────────────
	// VaultAddress is the Vault server URL, e.g. "https://vault.corp:8200".
	// Set via CLAVEX_AUTH_VAULT_ADDRESS.
	VaultAddress string `mapstructure:"vault_address"`
	// VaultToken is the Vault token used for authentication.
	// Set via CLAVEX_AUTH_VAULT_TOKEN (or the standard VAULT_TOKEN env var).
	VaultToken string `mapstructure:"vault_token"`
	// VaultTransitKey is the Transit key name used for signing (default: "clavex-signing").
	// Set via CLAVEX_AUTH_VAULT_TRANSIT_KEY.
	VaultTransitKey string `mapstructure:"vault_transit_key"`
	// VaultTransitMount is the Transit mount path (default: "transit").
	// Set via CLAVEX_AUTH_VAULT_TRANSIT_MOUNT.
	VaultTransitMount string `mapstructure:"vault_transit_mount"`
	// VaultNamespace is the Vault Enterprise namespace (optional).
	// Set via CLAVEX_AUTH_VAULT_NAMESPACE.
	VaultNamespace string `mapstructure:"vault_namespace"`

	// ── AWS KMS backend (key_backend=awskms) ─────────────────────────────────
	// AWSKMSKeyID is the KMS key ID or ARN for signing.
	// Set via CLAVEX_AUTH_AWS_KMS_KEY_ID.
	AWSKMSKeyID string `mapstructure:"aws_kms_key_id"`
	// AWSKMSRegion is the AWS region (defaults to AWS_REGION env var).
	// Set via CLAVEX_AUTH_AWS_KMS_REGION.
	AWSKMSRegion string `mapstructure:"aws_kms_region"`

	// SAMLCertFile is the X.509 certificate PEM used in SAML IdP metadata.
	// If empty, the OIDC signing key's self-signed certificate is generated on startup.
	SAMLCertFile string `mapstructure:"saml_cert_file"`

	// WebAuthn (Passkey) configuration for MFA enrollment.
	// If WebAuthnRPID is empty, WebAuthn endpoints return 501.
	WebAuthnRPID   string `mapstructure:"webauthn_rp_id"`   // e.g. "localhost"
	WebAuthnRPName string `mapstructure:"webauthn_rp_name"` // e.g. "Clavex"
	// TOTPIssuer is the issuer label shown in authenticator apps during TOTP enrollment.
	// Defaults to "Clavex". Set via CLAVEX_AUTH_TOTP_ISSUER or config file.
	TOTPIssuer string `mapstructure:"totp_issuer"`

	// GeoIPCityDBPath is the path to a MaxMind GeoLite2-City.mmdb file.
	// When set, login events are enriched with country_code and city.
	// Leave empty to disable geo-IP enrichment (default).
	GeoIPCityDBPath string `mapstructure:"geoip_city_db_path"`

	// GeoIPASNDBPath is the optional path to a GeoLite2-ASN.mmdb file.
	// When set alongside GeoIPCityDBPath, asn_org is also populated.
	GeoIPASNDBPath    string   `mapstructure:"geoip_asn_db_path"`
	WebAuthnRPOrigins []string `mapstructure:"webauthn_rp_origins"` // e.g. ["http://localhost:5173"]

	// LoginAlertThreshold is the risk score (0-100) above which a security
	// email alert is sent to the user after a successful login.
	// Defaults to 60. Set to 0 to disable alerts.
	LoginAlertThreshold int `mapstructure:"login_alert_threshold"`

	// DeviceTrustSecret is the HMAC key used to sign device trust cookies.
	// Must be at least 32 bytes. If empty, device trust is disabled.
	DeviceTrustSecret string `mapstructure:"device_trust_secret"`

	// AbuseIPDBKey is the AbuseIPDB v2 API key for Clavex Shield threat-intel
	// enrichment.  When set, login IPs are checked against AbuseIPDB and the
	// Tor exit-node list; flagged IPs add +20 to the risk score automatically.
	// Leave empty to disable (default — no external calls are made).
	AbuseIPDBKey string `mapstructure:"abuseipdb_key"`

	// AbuseIPDBThreshold is the minimum AbuseIPDB confidence score (0-100) to
	// treat an IP as malicious.  Defaults to 25 when AbuseIPDBKey is set.
	AbuseIPDBThreshold int `mapstructure:"abuseipdb_threshold"`

	// ── Post-Quantum Cryptography (NIST FIPS 204 / ML-DSA) ───────────────────
	// PQCEnabled activates experimental PQC key generation and JWKS exposure.
	// When true, an ML-DSA-65 key pair is generated/loaded from the database
	// and published in the JWKS endpoint alongside the classical RSA key
	// (hybrid mode). The private key is encrypted at rest with key_encryption_key
	// (required), independent of key_backend — PQC keys always live in the DB.
	// JWT signing remains classical; PQC is passive (discovery only) for now.
	// Set via CLAVEX_AUTH_PQC_ENABLED.
	PQCEnabled bool `mapstructure:"pqc_enabled"`

	// PQCAlgorithm selects the PQC algorithm. Currently only "ml-dsa-65" is
	// supported (NIST FIPS 204, Dilithium3, security level 3).
	// Set via CLAVEX_AUTH_PQC_ALGORITHM.
	PQCAlgorithm string `mapstructure:"pqc_algorithm"`
}

// LoadFrom loads configuration from a specific file path (optional).
// If path is empty it falls back to searching config.yaml in "." and "/etc/clavex".
// Environment variables with prefix CLAVEX_ always override file values.
func LoadFrom(path string) (*Config, error) {
	v := viper.New()

	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/clavex")
	}

	v.SetEnvPrefix("CLAVEX")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Defaults
	v.SetDefault("dev", false)
	v.SetDefault("http.addr", ":8080")
	v.SetDefault("http.base_domain", "localhost")
	v.SetDefault("database.mode", "external")
	v.SetDefault("database.max_conns", 20)
	v.SetDefault("database.min_conns", 2)
	v.SetDefault("database.embedded.port", 5433)
	v.SetDefault("database.embedded.username", "clavex")
	v.SetDefault("database.embedded.password", "clavex")
	v.SetDefault("database.embedded.database", "clavex")
	v.SetDefault("oid4vp.require_trusted_issuer", true)
	v.SetDefault("license.enforce_installation_binding", true)
	v.SetDefault("redis.mode", "standalone")
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conn", 2)
	v.SetDefault("shield.threat_feed.threshold", 5)
	v.SetDefault("shield.threat_feed.url", "https://feed.clavex.eu")
	v.SetDefault("auth.access_token_ttl", 3600)
	v.SetDefault("auth.refresh_token_ttl", 86400*30)
	v.SetDefault("auth.totp_issuer", "Clavex")
	v.SetDefault("usage_reporting.enabled", true)
	v.SetDefault("usage_reporting.endpoint", "https://telemetry.clavex.eu/v1/report")
	v.SetDefault("pam_alerts.stale_credential_days", 30)
	v.SetDefault("pam_alerts.session_max_hours", 8)
	v.SetDefault("auth.pqc_enabled", false)
	v.SetDefault("auth.pqc_algorithm", "ml-dsa-65")
	v.SetDefault("auth.admin_cookie_secure", true)

	// Explicit bindings are required for nested keys: Viper's AutomaticEnv
	// does not reliably populate nested struct fields during Unmarshal.
	for _, pair := range []struct{ key, env string }{
		{"dev", "CLAVEX_DEV"},
		{"http.addr", "CLAVEX_HTTP_ADDR"},
		{"http.base_domain", "CLAVEX_HTTP_BASE_DOMAIN"},
		{"http.tls_cert_file", "CLAVEX_HTTP_TLS_CERT_FILE"},
		{"http.tls_key_file", "CLAVEX_HTTP_TLS_KEY_FILE"},
		{"http.mtls_client_ca_cert_file", "CLAVEX_HTTP_MTLS_CLIENT_CA_CERT_FILE"},
		{"http.cors_allowed_origins", "CLAVEX_HTTP_CORS_ALLOWED_ORIGINS"},
		{"http.trusted_proxies", "CLAVEX_HTTP_TRUSTED_PROXIES"},
		{"database.mode", "CLAVEX_DATABASE_MODE"},
		{"database.dsn", "CLAVEX_DATABASE_DSN"},
		{"database.max_conns", "CLAVEX_DATABASE_MAX_CONNS"},
		{"database.min_conns", "CLAVEX_DATABASE_MIN_CONNS"},
		{"database.embedded.data_dir", "CLAVEX_DATABASE_EMBEDDED_DATA_DIR"},
		{"database.embedded.port", "CLAVEX_DATABASE_EMBEDDED_PORT"},
		{"redis.mode", "CLAVEX_REDIS_MODE"},
		{"redis.addr", "CLAVEX_REDIS_ADDR"},
		{"redis.addrs", "CLAVEX_REDIS_ADDRS"},
		{"redis.password", "CLAVEX_REDIS_PASSWORD"},
		{"redis.db", "CLAVEX_REDIS_DB"},
		{"redis.tls_enabled", "CLAVEX_REDIS_TLS_ENABLED"},
		{"auth.signing_key_file", "CLAVEX_AUTH_SIGNING_KEY_FILE"},
		{"auth.issuer_base", "CLAVEX_AUTH_ISSUER_BASE"},
		{"auth.access_token_ttl", "CLAVEX_AUTH_ACCESS_TOKEN_TTL"},
		{"auth.refresh_token_ttl", "CLAVEX_AUTH_REFRESH_TOKEN_TTL"},
		{"auth.admin_secret", "CLAVEX_AUTH_ADMIN_SECRET"},
		{"auth.admin_cookie_domain", "CLAVEX_AUTH_ADMIN_COOKIE_DOMAIN"},
		{"auth.admin_cookie_secure", "CLAVEX_AUTH_ADMIN_COOKIE_SECURE"},
		{"auth.key_backend", "CLAVEX_AUTH_KEY_BACKEND"},
		{"auth.key_encryption_key", "CLAVEX_AUTH_KEY_ENCRYPTION_KEY"},
		{"auth.vault_address", "CLAVEX_AUTH_VAULT_ADDRESS"},
		{"auth.vault_token", "CLAVEX_AUTH_VAULT_TOKEN"},
		{"auth.vault_transit_key", "CLAVEX_AUTH_VAULT_TRANSIT_KEY"},
		{"auth.vault_transit_mount", "CLAVEX_AUTH_VAULT_TRANSIT_MOUNT"},
		{"auth.vault_namespace", "CLAVEX_AUTH_VAULT_NAMESPACE"},
		{"auth.aws_kms_key_id", "CLAVEX_AUTH_AWS_KMS_KEY_ID"},
		{"auth.aws_kms_region", "CLAVEX_AUTH_AWS_KMS_REGION"},
		{"auth.saml_cert_file", "CLAVEX_AUTH_SAML_CERT_FILE"},
		{"auth.webauthn_rp_id", "CLAVEX_AUTH_WEBAUTHN_RP_ID"},
		{"auth.webauthn_rp_name", "CLAVEX_AUTH_WEBAUTHN_RP_NAME"},
		{"auth.totp_issuer", "CLAVEX_AUTH_TOTP_ISSUER"},
		{"auth.geoip_city_db_path", "CLAVEX_AUTH_GEOIP_CITY_DB_PATH"},
		{"auth.geoip_asn_db_path", "CLAVEX_AUTH_GEOIP_ASN_DB_PATH"},
		{"auth.abuseipdb_key", "CLAVEX_AUTH_ABUSEIPDB_KEY"},
		{"auth.abuseipdb_threshold", "CLAVEX_AUTH_ABUSEIPDB_THRESHOLD"},
		{"shield.threat_feed.enabled", "CLAVEX_SHIELD_THREAT_FEED_ENABLED"},
		{"shield.threat_feed.url", "CLAVEX_SHIELD_THREAT_FEED_URL"},
		{"shield.threat_feed.shared_key", "CLAVEX_SHIELD_THREAT_FEED_SHARED_KEY"},
		{"shield.threat_feed.report", "CLAVEX_SHIELD_THREAT_FEED_REPORT"},
		{"shield.threat_feed.signing_pub_key", "CLAVEX_SHIELD_THREAT_FEED_SIGNING_PUB_KEY"},
		{"shield.threat_feed.threshold", "CLAVEX_SHIELD_THREAT_FEED_THRESHOLD"},
		{"auth.pqc_enabled", "CLAVEX_AUTH_PQC_ENABLED"},
		{"auth.pqc_algorithm", "CLAVEX_AUTH_PQC_ALGORITHM"},
		// Federation scalar keys: nested-struct Unmarshal does not pick these
		// up from env automatically, so each must be explicitly bound here.
		{"federation.enabled", "CLAVEX_FEDERATION_ENABLED"},
		{"federation.organization_name", "CLAVEX_FEDERATION_ORGANIZATION_NAME"},
		{"federation.jwt_lifetime", "CLAVEX_FEDERATION_JWT_LIFETIME"},
		{"federation.homepage_uri", "CLAVEX_FEDERATION_HOMEPAGE_URI"},
		{"federation.logo_uri", "CLAVEX_FEDERATION_LOGO_URI"},
		{"federation.trust_anchor_mode", "CLAVEX_FEDERATION_TRUST_ANCHOR_MODE"},
		{"federation.trust_anchor_entity_id", "CLAVEX_FEDERATION_TRUST_ANCHOR_ENTITY_ID"},
	} {
		if err := v.BindEnv(pair.key, pair.env); err != nil {
			return nil, fmt.Errorf("config bind env %s: %w", pair.env, err)
		}
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	// Viper does not reliably unmarshal a string env var into []string via mapstructure.
	// Fall back to reading the env var directly and splitting on comma.
	splitCSV := func(raw string) []string {
		var out []string
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	if len(cfg.HTTP.TrustedProxies) == 0 {
		if raw := os.Getenv("CLAVEX_HTTP_TRUSTED_PROXIES"); raw != "" {
			cfg.HTTP.TrustedProxies = splitCSV(raw)
		}
	} else if len(cfg.HTTP.TrustedProxies) == 1 && strings.Contains(cfg.HTTP.TrustedProxies[0], ",") {
		cfg.HTTP.TrustedProxies = splitCSV(cfg.HTTP.TrustedProxies[0])
	}
	if len(cfg.HTTP.CORSAllowedOrigins) == 0 {
		if raw := os.Getenv("CLAVEX_HTTP_CORS_ALLOWED_ORIGINS"); raw != "" {
			cfg.HTTP.CORSAllowedOrigins = splitCSV(raw)
		}
	} else if len(cfg.HTTP.CORSAllowedOrigins) == 1 && strings.Contains(cfg.HTTP.CORSAllowedOrigins[0], ",") {
		cfg.HTTP.CORSAllowedOrigins = splitCSV(cfg.HTTP.CORSAllowedOrigins[0])
	}
	// Federation []string fields share the same viper/env limitation: a CSV env
	// var is not unmarshalled into a slice, so split it manually.
	if len(cfg.Federation.TrustAnchors) == 0 {
		if raw := os.Getenv("CLAVEX_FEDERATION_TRUST_ANCHORS"); raw != "" {
			cfg.Federation.TrustAnchors = splitCSV(raw)
		}
	} else if len(cfg.Federation.TrustAnchors) == 1 && strings.Contains(cfg.Federation.TrustAnchors[0], ",") {
		cfg.Federation.TrustAnchors = splitCSV(cfg.Federation.TrustAnchors[0])
	}
	if len(cfg.Federation.AuthorityHints) == 0 {
		if raw := os.Getenv("CLAVEX_FEDERATION_AUTHORITY_HINTS"); raw != "" {
			cfg.Federation.AuthorityHints = splitCSV(raw)
		}
	} else if len(cfg.Federation.AuthorityHints) == 1 && strings.Contains(cfg.Federation.AuthorityHints[0], ",") {
		cfg.Federation.AuthorityHints = splitCSV(cfg.Federation.AuthorityHints[0])
	}
	if len(cfg.Federation.Contacts) == 0 {
		if raw := os.Getenv("CLAVEX_FEDERATION_CONTACTS"); raw != "" {
			cfg.Federation.Contacts = splitCSV(raw)
		}
	} else if len(cfg.Federation.Contacts) == 1 && strings.Contains(cfg.Federation.Contacts[0], ",") {
		cfg.Federation.Contacts = splitCSV(cfg.Federation.Contacts[0])
	}
	if !cfg.Dev && len(cfg.Auth.AdminSecret) < 32 {
		return nil, fmt.Errorf("auth.admin_secret must be at least 32 characters in production")
	}
	return &cfg, nil
}

// UsageReportingConfig controls anonymous installation telemetry.
// No personal data is ever sent. Enabled by default — opt out with enabled: false.
type UsageReportingConfig struct {
	// Enabled activates 24h telemetry pings to Clavex. Default: true.
	// Set to false to opt out.
	Enabled bool `mapstructure:"enabled"`
	// Endpoint overrides the default telemetry collector (e.g. for air-gapped relays).
	// Default: https://telemetry.clavex.eu/v1/report
	Endpoint string `mapstructure:"endpoint"`
}

// LicenseConfig holds the path to the Clavex license JWT.
// Community edition (one organization, unlimited users) runs without a license.
// Enterprise licenses are distributed by email on purchase.
type LicenseConfig struct {
	// KeyFile is the filesystem path to a Clavex license JWT file.
	// Example: /etc/clavex/license.jwt
	KeyFile string `mapstructure:"key_file"`
	// EnforceInstallationBinding rejects (reverts to community) a license whose
	// sub is bound to a different installation_uuid than this deployment's
	// (anti-sharing). Default true. A multi-node cluster shares one DB → one uuid,
	// so the license is valid on every node; only a separate deployment is
	// rejected. Set false only during a DB migration/restore that rotates the
	// uuid, or to grace licenses issued before installation binding.
	EnforceInstallationBinding bool `mapstructure:"enforce_installation_binding"`
}

// FGAConfig wires Clavex to an OpenFGA instance for fine-grained / relationship-
// based access control (ReBAC). When Enabled is false every FGA API endpoint
// returns 501. When Enabled is true and Endpoint is reachable, organizations
// can define authorization models (Zanzibar-style type graphs) and use
// POST /fga/check to evaluate relationship queries.
type FGAConfig struct {
	// Enabled activates the FGA proxy API. Default: false.
	Enabled bool `mapstructure:"enabled"`
	// Endpoint is the base URL of the OpenFGA HTTP server.
	// Example: http://openfga:8080
	Endpoint string `mapstructure:"endpoint"`
	// APIKey is the shared secret for OpenFGA API-key authentication.
	// Leave empty for unauthenticated / mTLS-protected deployments.
	APIKey string `mapstructure:"api_key"`
}

// OID4VPConfig holds OpenID for Verifiable Presentations settings.
type OID4VPConfig struct {
	// TrustedCredentialIssuers is a list of {issuer, kty, crv, alg, x, y, n, e}
	// entries. When a DCQL credential's iss claim matches an issuer URL, the
	// issuer signature is verified using that key without outbound JWKS discovery.
	// Using a slice (not a map) avoids Viper's dot-in-key parsing issue with URLs.
	TrustedCredentialIssuers []TrustedCredentialIssuer `mapstructure:"trusted_credential_issuers"`

	// RequireTrustedIssuer, when true (the default), rejects a DCQL presentation
	// whose credential issuer is not present in TrustedCredentialIssuers instead of
	// accepting its claims with the issuer signature unverified. Set false only for
	// the OIDF conformance suite, where the test harness is the (untrusted) issuer.
	RequireTrustedIssuer bool `mapstructure:"require_trusted_issuer"`

	// JARCertFile and JARKeyFile point to the PEM-encoded certificate chain and
	// private key used to sign JAR JWTs (x509_san_dns client_id_scheme).
	// The certificate MUST have a dNSName SAN matching the server hostname and
	// MUST be signed by a CA trusted by the target wallet (e.g. Let's Encrypt).
	//
	// When omitted, a self-signed ephemeral cert is generated at startup — fine
	// for development but rejected by production wallets (EUDI, etc.).
	JARCertFile string `mapstructure:"jar_cert_file"`
	JARKeyFile  string `mapstructure:"jar_key_file"`
}

// TrustedCredentialIssuer pairs an issuer URL with its public JWK fields.
type TrustedCredentialIssuer struct {
	Issuer string `mapstructure:"issuer"`
	Kty    string `mapstructure:"kty"`
	Crv    string `mapstructure:"crv"`
	Alg    string `mapstructure:"alg"`
	// EC fields
	X string `mapstructure:"x"`
	Y string `mapstructure:"y"`
	// RSA fields
	N string `mapstructure:"n"`
	E string `mapstructure:"e"`
}

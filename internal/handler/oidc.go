package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"strconv"
	"time"

	"github.com/clavex-eu/clavex/internal/breach"
	captchapkg "github.com/clavex-eu/clavex/internal/captcha"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/connector"
	"github.com/clavex-eu/clavex/internal/enrichment"
	"github.com/clavex-eu/clavex/internal/federation"
	"github.com/clavex-eu/clavex/internal/flowengine"
	"github.com/clavex-eu/clavex/internal/geoip"
	"github.com/clavex-eu/clavex/internal/lockout"
	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/metrics"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/policy"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/risk"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/shield"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/clavex-eu/clavex/internal/tracing"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	jwkPkg "github.com/lestrrat-go/jwx/v2/jwk"
	jwtPkg "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
)

const ssoCookie = "clavex_sso"

// bsCookie is the non-HttpOnly browser-state cookie used by the check_session_iframe
// (OIDC Session Management 1.0 §3). Its value is the SSO session ID and must be
// readable by the JS running in the OP check-session iframe (no HttpOnly).
// SameSite=None is required so the cookie is sent when the iframe is loaded
// cross-origin from an RP page.
const bsCookie = "clavex_bs"

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// buildCredentialScopeSet returns the set of OID4VCI scope values registered
// for the given org. Used by the authorize handler to allow wallet-initiated
// authorization code flows where scope = credential scope (no "openid").
func buildCredentialScopeSet(ctx context.Context, repo *repository.OID4WRepository, orgID uuid.UUID) map[string]bool {
	configs, err := repo.ListCredentialConfigs(ctx, orgID)
	if err != nil || len(configs) == 0 {
		return nil
	}
	scopes := make(map[string]bool, len(configs))
	for _, cfg := range configs {
		if !cfg.IsActive {
			continue
		}
		// Derive the scope exactly the way BuildIssuerMetadata publishes it, via
		// oid4w.CredentialConfigID — the full sanitised VCT path, NOT path.Base.
		// e.g. https://id.clavex.eu/vct/conformance-identity -> vct_conformance-identity.
		// Using path.Base here (conformance-identity) diverged from the published
		// metadata scope and broke wallet-initiated auth code flows: the wallet
		// sends the metadata scope, which then failed the "must include openid" check.
		scopes[oid4w.CredentialConfigID(cfg.VCT)] = true
	}
	return scopes
}

func setSSOCookie(c echo.Context, sessID string) {
	setSSOCookieNamed(c, ssoCookie, sessID)
}

// setSSOCookieNamed sets the SSO cookie under an arbitrary name.
// Used for isolated sessions (session_isolation=true clients).
func setSSOCookieNamed(c echo.Context, name, sessID string) {
	c.SetCookie(&http.Cookie{
		Name:     name,
		Value:    sessID,
		Path:     "/",
		MaxAge:   int(session.SSOSessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	// Also set the non-HttpOnly browser-state cookie read by the check_session_iframe.
	c.SetCookie(&http.Cookie{
		Name:     bsCookie,
		Value:    sessID,
		Path:     "/",
		MaxAge:   int(session.SSOSessionTTL.Seconds()),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
}

// isolatedCookieName returns the per-client SSO cookie name for session-isolated clients.
// It is deterministic (SHA-256 of clientID) so the same name is always used for a
// given client without any server-side state.
func isolatedCookieName(clientID string) string {
	sum := sha256.Sum256([]byte(clientID))
	return "clavex_iso_" + base64.RawURLEncoding.EncodeToString(sum[:6]) // 8 base64url chars
}

//go:embed templates/*.html
var templateFS embed.FS

var loginTmpl = template.Must(
	template.ParseFS(templateFS, "templates/login.html"),
)

var mfaChallengeTmpl = template.Must(
	template.ParseFS(templateFS, "templates/mfa_challenge.html"),
)

var emailSentTmpl = template.Must(
	template.ParseFS(templateFS, "templates/email_sent.html"),
)

var resetPasswordTmpl = template.Must(
	template.ParseFS(templateFS, "templates/reset_password.html"),
)

var updatePasswordTmpl = template.Must(
	template.ParseFS(templateFS, "templates/update_password.html"),
)

var breachWarningTmpl = template.Must(
	template.ParseFS(templateFS, "templates/breach_warning.html"),
)

var mdocProximityTmpl = template.Must(
	template.ParseFS(templateFS, "templates/mdoc_proximity.html"),
)

var checkSessionTmpl = template.Must(
	template.ParseFS(templateFS, "templates/check_session.html"),
)

// formPostTmpl is the self-submitting HTML form used for response_mode=form_post
// (OAuth 2.0 Form Post Response Mode). The browser auto-POSTs the authorization
// response parameters to the redirect_uri on page load.
var formPostTmpl = template.Must(template.New("form_post").Parse(`<!DOCTYPE html>
<html>
<head><title>Submitting…</title></head>
<body>
<form method="post" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}"/>
{{end}}<noscript><button type="submit">Continue</button></noscript>
</form>
<script nonce="{{.Nonce}}">document.forms[0].submit();</script>
</body>
</html>`))

// OIDCHandler handles OIDC / OAuth2 protocol endpoints.
type OIDCHandler struct {
	cfg             *config.Config
	pool            *pgxpool.Pool
	tc              *oidc.TokenConfig
	store           *session.Store
	rdb             redis.UniversalClient
	orgs            *repository.OrgRepository
	clients         *repository.ClientRepository
	users           *repository.UserRepository
	codes           *repository.AuthCodeRepository
	tokens          *repository.RefreshTokenRepository
	groups          *repository.GroupRepository
	mfa             *repository.MFARepository
	mappers         *repository.MapperRepository
	audit           *repository.AuditRepository
	smtp            *repository.SMTPRepository
	pwPolicy        *repository.PasswordPolicyRepository
	breach          *breach.Checker
	deviceCodes     *repository.DeviceCodeRepository
	cibaRequests    *repository.CIBARepository
	cibaNotifyCfg   *repository.CIBANotificationRepository
	cibaPushTokens  *repository.CIBAPushTokenRepository
	vpSessions      *repository.OID4WRepository
	smsSettings     *repository.SMSSettingsRepository
	captchaRepo     *repository.CaptchaRepository
	loginHistory    *repository.LoginHistoryRepository
	geo             *geoip.DB
	policies        *policy.Repository
	riskScorer      *risk.Scorer
	shieldClient    *shield.Client     // nil when AbuseIPDB/Tor intel disabled
	feedClient      *shield.FeedClient // nil when distributed threat feed disabled
	trustedDev      *repository.TrustedDeviceRepository
	grantRepo       *repository.RARGrantRepository
	crossOrgTrusts  *repository.CrossOrgTrustRepository
	ssfDisp         *ssf.Dispatcher                  // nil when SSF is not configured
	walletStepUp    *WalletStepUpHandler             // nil when wallet step-up is not configured
	oid4vpH         *OID4VPHandler                   // nil when OID4VP challenge is not configured
	flowEngine      *flowengine.Engine               // nil when no flow is configured
	guard           *lockout.Guard                   // nil when adaptive lockout is disabled
	ipRules         *repository.IPRulesRepository    // nil when IP rules are not configured
	idpRepo         *repository.IDPRepository        // for rendering IDP buttons on login page
	spidRepo        *repository.SPIDRepository       // for rendering SPID buttons on login page
	eidasRepo       *repository.EidasRepository      // for rendering eIDAS button on login page
	bundidSAMLRepo  *repository.BundIDSAMLRepository // for rendering BundID SAML button on login page
	serviceAccounts *repository.ServiceAccountRepository
	flags           *repository.FeatureFlagRepository // nil when feature flags disabled
	orgSigners      *oidc.OrgSignerCache              // nil when BYOK not enabled
	vciH            *OID4VCIHandler                   // nil when OID4VCI is not configured; delegates pre-authorized_code grant
	pqcSigner       *oidc.PQCSigner                   // nil when pqc_enabled=false; passive JWKS exposure only
	encKeys         *oidc.EncKeySet                   // nil when request-object encryption is not enabled
}

// WithOID4VCIHandler wires the OID4VCI handler so the OIDC token endpoint can
// delegate the pre-authorized_code grant (OID4VCI §6.1) to it. Wallets discover
// the token endpoint from the AS metadata (RFC 8414) and send pre-authorized code
// requests there; without this delegation they receive unsupported_grant_type.
func (h *OIDCHandler) WithSPIDRepository(r *repository.SPIDRepository) *OIDCHandler {
	h.spidRepo = r
	return h
}

func (h *OIDCHandler) WithEidasRepository(r *repository.EidasRepository) *OIDCHandler {
	h.eidasRepo = r
	return h
}

func (h *OIDCHandler) WithBundIDSAMLRepository(r *repository.BundIDSAMLRepository) *OIDCHandler {
	h.bundidSAMLRepo = r
	return h
}

func (h *OIDCHandler) WithOID4VCIHandler(vci *OID4VCIHandler) *OIDCHandler {
	h.vciH = vci
	return h
}

// WithSSFDispatcher attaches an SSF dispatcher so the OIDC handler fires
// CAEP token-claims-change events to registered push receivers on token revocation.
// This enables zero-trust Continuous Access Evaluation (CAE / RFC 9700):
// resource servers are notified in real time instead of waiting for cache expiry.
func (h *OIDCHandler) WithSSFDispatcher(d *ssf.Dispatcher) *OIDCHandler {
	h.ssfDisp = d
	return h
}

// WithWalletStepUp attaches a WalletStepUpHandler so Introspect can trigger
// Continuous Adaptive Authentication (CAA) wallet step-up challenges when the
// risk scorer flags a high-risk introspection event.
func (h *OIDCHandler) WithWalletStepUp(w *WalletStepUpHandler) *OIDCHandler {
	h.walletStepUp = w
	return h
}

// WithOID4VPHandler attaches the OID4VP handler so the login flow engine's
// oid4vp_challenge step can create presentation sessions and the challenge/resume
// endpoints are wired to the same credential verification infrastructure.
func (h *OIDCHandler) WithOID4VPHandler(vp *OID4VPHandler) *OIDCHandler {
	h.oid4vpH = vp
	return h
}

// WithServiceAccountRepository enables service account client_credentials grants.
func (h *OIDCHandler) WithServiceAccountRepository(r *repository.ServiceAccountRepository) *OIDCHandler {
	h.serviceAccounts = r
	return h
}

// WithOrgSigners attaches an OrgSignerCache so that organisations with a BYOK
// signing key use their own RSA key for token issuance and JWKS.
func (h *OIDCHandler) WithOrgSigners(c *oidc.OrgSignerCache) *OIDCHandler {
	h.orgSigners = c
	return h
}

// WithFeatureFlagRepository enables feature-flag injection into issued JWTs.
// When set, resolved flag values are added to every access token as the "flags" claim.
func (h *OIDCHandler) WithFeatureFlagRepository(r *repository.FeatureFlagRepository) *OIDCHandler {
	h.flags = r
	return h
}

// WithFlowEngine attaches the login flow engine to the OIDC handler.
// When set, each successful authentication runs the configured flow steps.
func (h *OIDCHandler) WithFlowEngine(e *flowengine.Engine) *OIDCHandler {
	h.flowEngine = e
	return h
}

// WithGuard attaches the adaptive lockout guard to the OIDC handler.
// When set, failed password attempts are tracked per (orgID, email) and accounts
// are temporarily locked for a duration that scales with the current risk score.
func (h *OIDCHandler) WithGuard(g *lockout.Guard) *OIDCHandler {
	h.guard = g
	return h
}

// WithIPRules attaches the IP rules repository that enforces per-org allow/deny
// CIDR rules before credential verification (deny) and the policy engine (allow).
func (h *OIDCHandler) WithIPRules(r *repository.IPRulesRepository) *OIDCHandler {
	h.ipRules = r
	return h
}

// WithShieldClient attaches a Clavex Shield threat-intel client that enriches
// the risk score with external feed data (AbuseIPDB, Tor exit nodes).
// Must be called before the handler serves requests (i.e. from server.go).
func (h *OIDCHandler) WithShieldClient(c *shield.Client) *OIDCHandler {
	h.shieldClient = c
	h.riskScorer = risk.NewScorer(h.loginHistory, c, h.feedClient)
	return h
}

// WithFeedClient attaches the Clavex Shield distributed threat feed client.
func (h *OIDCHandler) WithFeedClient(f *shield.FeedClient) *OIDCHandler {
	h.feedClient = f
	h.riskScorer = risk.NewScorer(h.loginHistory, h.shieldClient, f)
	return h
}

// WithPQCSigner attaches a PQCSigner so its ML-DSA-65 public key is included
// in the JWKS endpoint alongside the classical RSA key (hybrid mode).
// JWT signing remains classical; PQC is passive (discovery only).
func (h *OIDCHandler) WithPQCSigner(s *oidc.PQCSigner) *OIDCHandler {
	h.pqcSigner = s
	return h
}

// RotatePQCSigningKey generates a fresh ML-DSA-65 key, retires the previous one,
// and returns the new kid. Returns 404 when pqc_enabled=false. Mirrors the
// classical rotate-signing-key endpoint (superadmin only).
func (h *OIDCHandler) RotatePQCSigningKey(c echo.Context) error {
	if h.pqcSigner == nil {
		return echo.NewHTTPError(http.StatusNotFound, "pqc signing is not enabled")
	}
	if err := h.pqcSigner.Rotate(c.Request().Context()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"kid": h.pqcSigner.KID()})
}

// WithEncKeys attaches the request-object encryption key set so its public key
// is published in the JWKS endpoint (use=enc) and incoming encrypted (JWE)
// request objects are decrypted at the authorization endpoint.
func (h *OIDCHandler) WithEncKeys(s *oidc.EncKeySet) *OIDCHandler {
	h.encKeys = s
	return h
}

// RotateEncKey generates a fresh request-object encryption key, retires the
// previous one (kept for the decryption grace window), and returns the new kid.
// Returns 404 when request-object encryption is not enabled (superadmin only).
func (h *OIDCHandler) RotateEncKey(c echo.Context) error {
	if h.encKeys == nil {
		return echo.NewHTTPError(http.StatusNotFound, "request-object encryption is not enabled")
	}
	if err := h.encKeys.Rotate(c.Request().Context()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"kid": h.encKeys.KID()})
}

// jarDecryptOpts returns the ParseJAR/FetchRequestURI option that enables
// decryption of encrypted (JWE) request objects, or no options when
// request-object encryption is not configured.
func (h *OIDCHandler) jarDecryptOpts() []oidc.JAROption {
	if h.encKeys == nil {
		return nil
	}
	return []oidc.JAROption{oidc.WithJWEDecrypter(h.encKeys)}
}

func NewOIDCHandler(cfg *config.Config, pool *pgxpool.Pool, rdb redis.UniversalClient, keys oidc.Signer) *OIDCHandler {
	tc := &oidc.TokenConfig{
		Keys:            keys,
		AccessTokenTTL:  time.Duration(cfg.Auth.AccessTokenTTL) * time.Second,
		RefreshTokenTTL: time.Duration(cfg.Auth.RefreshTokenTTL) * time.Second,
		IDTokenTTL:      time.Duration(cfg.Auth.AccessTokenTTL) * time.Second,
	}
	h := &OIDCHandler{
		cfg:            cfg,
		pool:           pool,
		tc:             tc,
		store:          session.NewStore(rdb),
		rdb:            rdb,
		orgs:           repository.NewOrgRepository(pool),
		clients:        repository.NewClientRepository(pool),
		users:          repository.NewUserRepository(pool),
		codes:          repository.NewAuthCodeRepository(pool),
		tokens:         repository.NewRefreshTokenRepository(pool),
		groups:         repository.NewGroupRepository(pool),
		mfa:            repository.NewMFARepository(pool),
		mappers:        repository.NewMapperRepository(pool),
		audit:          repository.NewAuditRepository(pool),
		smtp:           repository.NewSMTPRepository(pool),
		pwPolicy:       repository.NewPasswordPolicyRepository(pool),
		breach:         breach.New(),
		deviceCodes:    repository.NewDeviceCodeRepository(pool),
		cibaRequests:   repository.NewCIBARepository(pool),
		cibaNotifyCfg:  repository.NewCIBANotificationRepository(pool),
		cibaPushTokens: repository.NewCIBAPushTokenRepository(pool),
		vpSessions:     repository.NewOID4WRepository(pool),
		smsSettings:    repository.NewSMSSettingsRepository(pool),
		captchaRepo:    repository.NewCaptchaRepository(pool),
		loginHistory:   repository.NewLoginHistoryRepository(pool),
		policies:       policy.NewRepository(pool),
		grantRepo:      repository.NewRARGrantRepository(pool),
		crossOrgTrusts: repository.NewCrossOrgTrustRepository(pool),
	}
	h.riskScorer = risk.NewScorer(h.loginHistory, h.shieldClient, h.feedClient)
	h.trustedDev = repository.NewTrustedDeviceRepository(pool)
	h.idpRepo = repository.NewIDPRepository(pool)

	// Open geo-IP database (optional — silently disabled if path not set).
	if cfg.Auth.GeoIPCityDBPath != "" {
		if db, err := geoip.Open(cfg.Auth.GeoIPCityDBPath, cfg.Auth.GeoIPASNDBPath); err == nil {
			h.geo = db
		}
	}
	if h.geo == nil {
		h.geo, _ = geoip.Open("", "") // no-op DB
	}
	return h
}

// issuerFromRequest derives the per-tenant OIDC issuer URL from the incoming
// request Host header. This keeps discovery metadata, ID-token iss claims, and
// endpoint URLs consistent regardless of whether the server is reached via
// localhost, a Docker gateway hostname, or a public domain.
func (h *OIDCHandler) issuerFromRequest(c echo.Context, orgSlug string) string {
	return h.IssuerFromRequest(c, orgSlug)
}

// IssuerFromRequest is the exported version of issuerFromRequest, used by other
// handlers (e.g. SSFHandler) that need to derive the per-tenant issuer URL.
func (h *OIDCHandler) IssuerFromRequest(c echo.Context, orgSlug string) string {
	// If Auth.IssuerBase is configured (e.g. https://id.clavex.eu), use it
	// directly — this is the authoritative public base and avoids schema
	// detection issues when TLS is terminated upstream by a proxy.
	if base := h.cfg.Auth.IssuerBase; base != "" {
		return strings.TrimRight(base, "/") + "/" + orgSlug
	}
	scheme := "http"
	if h.cfg.HTTP.TLSCertFile != "" {
		scheme = "https"
	}
	if fwdProto := c.Request().Header.Get("X-Forwarded-Proto"); fwdProto != "" {
		scheme = fwdProto
	}
	host := c.Request().Header.Get("X-Forwarded-Host")
	if host == "" {
		host = c.Request().Host
	}
	if host == "" {
		host = h.cfg.HTTP.BaseDomain
	}
	return fmt.Sprintf("%s://%s/%s", scheme, host, orgSlug)
}

// htuFromEcho builds the DPoP htu (scheme://host/path) for the current request,
// using the same host-resolution priority as issuerFromRequest so that the value
// matches what clients compute from the discovery document:
//  1. cfg.Auth.IssuerBase (if configured, e.g. "https://id.clavex.eu")
//  2. X-Forwarded-Host header (reverse-proxy scenario)
//  3. r.Host (direct / test)
func (h *OIDCHandler) htuFromEcho(c echo.Context) string {
	path := c.Request().URL.Path
	if base := h.cfg.Auth.IssuerBase; base != "" {
		// Strip trailing slash and any path component (IssuerBase is always scheme://host)
		u, err := url.Parse(strings.TrimRight(base, "/"))
		if err == nil {
			return u.Scheme + "://" + u.Host + path
		}
	}
	r := c.Request()
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
		scheme = fwdProto
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host + path
}

// newTC returns a per-request TokenConfig copy with the given issuer URL.
// This avoids a data race where multiple goroutines mutate h.tc.Issuer.
func (h *OIDCHandler) newTC(issuer string) *oidc.TokenConfig {
	return &oidc.TokenConfig{
		Keys:            h.tc.Keys,
		Issuer:          issuer,
		AccessTokenTTL:  h.tc.AccessTokenTTL,
		RefreshTokenTTL: h.tc.RefreshTokenTTL,
		IDTokenTTL:      h.tc.IDTokenTTL,
	}
}

// applyTTLOverrides adjusts tc's TTLs using per-org then per-client settings.
// Hierarchy: global default → org override → client override (client wins).
// nil means "not set / inherit"; 0 is treated as nil (revert to server default).
func applyTTLOverrides(tc *oidc.TokenConfig, org *models.Organization, cl *models.OIDCClient) {
	if org != nil {
		if org.AccessTokenTTL != nil && *org.AccessTokenTTL > 0 {
			tc.AccessTokenTTL = time.Duration(*org.AccessTokenTTL) * time.Second
			tc.IDTokenTTL = tc.AccessTokenTTL
		}
		if org.RefreshTokenTTL != nil && *org.RefreshTokenTTL > 0 {
			tc.RefreshTokenTTL = time.Duration(*org.RefreshTokenTTL) * time.Second
		}
	}
	if cl != nil {
		if cl.AccessTokenTTL != nil && *cl.AccessTokenTTL > 0 {
			tc.AccessTokenTTL = time.Duration(*cl.AccessTokenTTL) * time.Second
			tc.IDTokenTTL = tc.AccessTokenTTL
		}
		if cl.RefreshTokenTTL != nil && *cl.RefreshTokenTTL > 0 {
			tc.RefreshTokenTTL = time.Duration(*cl.RefreshTokenTTL) * time.Second
		}
	}
}

// applyOrgOverrides applies per-org/per-client TTL overrides AND, if the org
// has a BYOK signing key, switches tc.Keys to the org-specific signer.
// It supersedes direct calls to applyTTLOverrides at token-issuance sites.
func (h *OIDCHandler) applyOrgOverrides(ctx context.Context, tc *oidc.TokenConfig, org *models.Organization, cl *models.OIDCClient) {
	applyTTLOverrides(tc, org, cl)
	if org != nil && h.orgSigners != nil {
		tc.Keys = h.orgSigners.For(ctx, org.ID)
	}
}

// ── Discovery ─────────────────────────────────────────────────────────────────

func (h *OIDCHandler) Discovery(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	if _, err := h.orgs.GetBySlug(ctx, orgSlug); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	base := h.issuerFromRequest(c, orgSlug)
	// RFC 8414 §3: discovery document must not be cached
	c.Response().Header().Set("Cache-Control", "no-store")
	resp := map[string]interface{}{
		// RFC 8414 + OIDC Discovery 1.0 required fields
		"issuer":                 base,
		"authorization_endpoint": base + "/authorize",
		"token_endpoint":         base + "/token",
		"userinfo_endpoint":      base + "/userinfo",
		"jwks_uri":               base + "/.well-known/jwks.json",
		"registration_endpoint":  base + "/register",

		// Token management endpoints
		"end_session_endpoint":   base + "/logout",
		"check_session_iframe":   base + "/check-session",
		"introspection_endpoint": base + "/introspect",
		"revocation_endpoint":    base + "/revoke",

		// Supported values
		"response_types_supported":              []string{"code", "id_token", "token", "code id_token", "code token", "token id_token", "code token id_token"},
		"response_modes_supported":              []string{"query", "fragment", "form_post", "jwt", "query.jwt", "fragment.jwt"},
		"grant_types_supported":                 []string{"authorization_code", "implicit", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:device_code", "urn:openid:params:grant-type:ciba", "urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"PS256", "RS256"},
		"userinfo_signing_alg_values_supported": []string{"none", "PS256", "RS256"},
		// JARM (draft-ietf-oauth-jarm / FAPI 2.0 Message Signing)
		"authorization_signing_alg_values_supported": []string{"PS256", "RS256"},
		// attest_jwt_client_auth: OAuth 2.0 Attestation-Based Client Authentication
		// (draft-ietf-oauth-attestation-based-client-auth / OAuth2-ATCA07) — required
		// by HAIP 1.0.  §10.1 mandates two companion alg fields:
		//   client_attestation_signing_alg_values_supported     — client attestation JWT
		//   client_attestation_pop_signing_alg_values_supported — attestation PoP JWT
		"token_endpoint_auth_methods_supported":               []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth", "attest_jwt_client_auth", "none"},
		"token_endpoint_auth_signing_alg_values_supported":    []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"},
		"client_attestation_signing_alg_values_supported":     []string{"ES256", "PS256"},
		"client_attestation_pop_signing_alg_values_supported": []string{"ES256", "PS256"},
		"introspection_endpoint_auth_methods_supported":       []string{"client_secret_basic", "client_secret_post"},
		"revocation_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":                    []string{"S256"},
		// PAR (RFC 9126)
		"pushed_authorization_request_endpoint": base + "/par",
		"require_pushed_authorization_requests": false,
		// Device Authorization (RFC 8628)
		"device_authorization_endpoint": base + "/device_authorization",
		// CIBA (OpenID Connect CIBA Core 1.0 — poll delivery mode)
		"backchannel_authentication_endpoint":                             base + "/bc-authorize",
		"backchannel_token_delivery_modes_supported":                      []string{"poll"},
		"backchannel_authentication_request_signing_alg_values_supported": []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"},
		"backchannel_user_code_parameter_supported":                       false,
		// JAR (RFC 9101) — request objects; "none" = unsecured (permitted for public clients)
		"request_object_signing_alg_values_supported": []string{"none", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"},
		// DPoP (RFC 9449)
		"dpop_signing_alg_values_supported": []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"},

		// RAR (RFC 9396) / OID4VCI §12.2.4: advertise openid_credential type
		"authorization_details_types_supported": []string{"openid_credential"},

		// Scopes and claims
		"scopes_supported": []string{"openid", "profile", "email", "offline_access"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "jti", "nbf",
			"email", "email_verified",
			"name", "given_name", "family_name",
			"auth_time", "nonce", "at_hash",
			"org_id", "roles", "groups",
			"verified_claims",
		},

		// OpenID Connect for Identity Assurance 1.0 §8 — OP metadata for verified_claims.
		// trust_framework values follow the OIDF eKYC-IDA WG registry.
		// Note: verified_claims_supported and electronic_records_supported are NOT
		// included here because they are not in the RFC 8414 schema that the OID4VCI
		// conformance suite validates against (they caused CheckForUnexpectedParameters
		// warnings).  Support is still fully functional; the absence of these advisory
		// flags only affects clients that key on them for capability detection.
		"trust_frameworks_supported": []string{
			"eidas",
			"it_spid",
			"it_cie",
			"de_bund",
			"fr_idv",
			"nl_id",
			"es_clave",
		},
		"evidence_supported": []string{"electronic_record"},
		"claims_in_verified_claims_supported": []string{
			"given_name", "family_name", "name",
			"birthdate", "place_of_birth",
			"nationalities",
			"address",
		},

		// Feature flags (RFC 8414 §2 + OIDC Discovery §3)
		"claims_parameter_supported":                 true,
		"request_parameter_supported":                true, // JAR (RFC 9101) — `request` JWT param supported
		"request_uri_parameter_supported":            true, // PAR (RFC 9126)
		"require_request_uri_registration":           false,
		"frontchannel_logout_supported":              false,
		"backchannel_logout_supported":               false,
		"tls_client_certificate_bound_access_tokens": true,

		// require_pkce and shared_signals_supported are also omitted: they are
		// not in the RFC 8414 / OID4VCI schema and trigger conformance warnings.
		// PKCE is still enforced by the authorization endpoint; SSF is advertised
		// at /.well-known/ssf-configuration.
		"authorization_response_iss_parameter_supported": true, // RFC 9207
	}

	// OpenID Federation 1.0 — advertise federation support when enabled.
	// OIDF §10.1: client_registration_types_supported and
	// federation_registration_endpoint are required in the Discovery document
	// when the OP participates in a federation.
	if h.cfg.Federation.Enabled {
		resp["client_registration_types_supported"] = []string{"automatic", "explicit"}
		resp["federation_registration_endpoint"] = base + "/federation/register"
		resp["request_object_signing_alg_values_supported"] = []string{"RS256", "PS256", "ES256"}
	}

	return c.JSON(http.StatusOK, resp)
}

// JWKS returns the public JSON Web Key Set.
// If the org has a BYOK signing key, only that org's public keys are returned.
// Otherwise the global JWKS is returned.
// When pqc_enabled=true the ML-DSA-65 PQC key is appended to all JWKS responses
// (hybrid mode per NIST SP 800-208 / BSI TR-02102-1).
func (h *OIDCHandler) JWKS(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")

	var jwks []byte
	if h.orgSigners != nil {
		ctx := c.Request().Context()
		if org, err := h.orgs.GetBySlug(ctx, c.Param("org_slug")); err == nil {
			jwks = h.orgSigners.For(ctx, org.ID).JWKS()
		}
	}
	if jwks == nil {
		jwks = h.tc.Keys.JWKS()
	}

	if h.pqcSigner != nil {
		jwks = oidc.MergeJWKS(jwks, h.pqcSigner.JWKObject())
	}

	// Publish the request-object encryption public key (use=enc) so RPs can
	// encrypt their JAR request objects to it (RFC 9101 §6.2).
	if h.encKeys != nil {
		jwks = oidc.MergeJWKS(jwks, h.encKeys.JWKObject())
	}

	return c.Blob(http.StatusOK, "application/json", jwks)
}

// ── Dynamic Client Registration (RFC 7591) ────────────────────────────────────

type dcrRequest struct {
	RedirectURIs            []string        `json:"redirect_uris"`
	ClientName              string          `json:"client_name"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	PostLogoutRedirectURIs  []string        `json:"post_logout_redirect_uris"`
	JWKSUri                 string          `json:"jwks_uri"`
	JWKS                    json.RawMessage `json:"jwks"`
	Scope                   string          `json:"scope"`
	// OIDC Core §2: algorithm used to sign ID tokens issued to this client.
	// Permitted: "RS256", "PS256", "ES256". Default (empty) → server default PS256.
	IDTokenSignedResponseAlg string `json:"id_token_signed_response_alg"`
	// OIDC Core §5.3.2: algorithm used to sign UserInfo responses.
	// When set (and not "none"), the userinfo endpoint returns application/jwt.
	UserInfoSignedResponseAlg string `json:"userinfo_signed_response_alg"`
	// RFC 9449 §5: when true the token endpoint requires DPoP on every request.
	DpopBoundAccessTokens bool `json:"dpop_bound_access_tokens"`
	// RFC 8705 §3: when true the token endpoint requires a TLS client certificate on every request.
	TLSClientCertBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens"`
}

// Register handles RFC 7591 dynamic client registration.
// POST /:org_slug/register
func (h *OIDCHandler) Register(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	var req dcrRequest
	if err := c.Bind(&req); err != nil || len(req.RedirectURIs) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_client_metadata",
			"error_description": "redirect_uris is required",
		})
	}

	// RFC 6749 §3.1.2: redirect URIs MUST NOT contain a fragment component.
	for _, ru := range req.RedirectURIs {
		parsed, parseErr := url.Parse(ru)
		if parseErr != nil || parsed.Fragment != "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_redirect_uri",
				"error_description": "redirect_uri must not contain a fragment",
			})
		}
	}

	var jwksUriPtr *string
	if req.JWKSUri != "" {
		jwksUriPtr = &req.JWKSUri
	}
	var jwksPtr *json.RawMessage
	if len(req.JWKS) > 0 {
		jwksPtr = &req.JWKS
	}
	// Validate id_token_signed_response_alg: only well-known safe algs accepted.
	if req.IDTokenSignedResponseAlg != "" {
		switch req.IDTokenSignedResponseAlg {
		case "RS256", "PS256", "ES256":
			// OK
		default:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_client_metadata",
				"error_description": "id_token_signed_response_alg must be RS256, PS256, or ES256",
			})
		}
	}
	// Validate userinfo_signed_response_alg.
	if req.UserInfoSignedResponseAlg != "" {
		switch req.UserInfoSignedResponseAlg {
		case "none", "RS256", "PS256", "ES256":
			// OK
		default:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_client_metadata",
				"error_description": "userinfo_signed_response_alg must be none, RS256, PS256, or ES256",
			})
		}
	}

	client, secret, err := h.clients.RegisterClient(ctx, repository.RegisterClientParams{
		OrgID:                          org.ID,
		Name:                           req.ClientName,
		RedirectURIs:                   req.RedirectURIs,
		PostLogoutRedirectURIs:         req.PostLogoutRedirectURIs,
		GrantTypes:                     req.GrantTypes,
		ResponseTypes:                  req.ResponseTypes,
		TokenEndpointAuthMethod:        req.TokenEndpointAuthMethod,
		JWKSUri:                        jwksUriPtr,
		JWKS:                           jwksPtr,
		IDTokenSignedResponseAlg:       req.IDTokenSignedResponseAlg,
		UserInfoSignedResponseAlg:      req.UserInfoSignedResponseAlg,
		DpopBoundAccessTokens:          req.DpopBoundAccessTokens,
		TLSClientCertBoundAccessTokens: req.TLSClientCertBoundAccessTokens,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}

	now := time.Now().Unix()
	resp := map[string]interface{}{
		"client_id":                                  client.ClientID,
		"client_id_issued_at":                        now,
		"redirect_uris":                              client.RedirectURIs,
		"post_logout_redirect_uris":                  client.PostLogoutRedirectURIs,
		"grant_types":                                client.GrantTypes,
		"response_types":                             client.ResponseTypes,
		"token_endpoint_auth_method":                 client.TokenEndpointAuthMethod,
		"client_name":                                client.Name,
		"id_token_signed_response_alg":               client.IDTokenSignedResponseAlg,
		"userinfo_signed_response_alg":               client.UserInfoSignedResponseAlg,
		"dpop_bound_access_tokens":                   client.DpopBoundAccessTokens,
		"tls_client_certificate_bound_access_tokens": client.TLSClientCertBoundAccessTokens,
	}
	// RFC 7591 §3.2.1: MUST NOT return client_secret for non-secret auth methods.
	if client.TokenEndpointAuthMethod != "private_key_jwt" &&
		client.TokenEndpointAuthMethod != "tls_client_auth" &&
		client.TokenEndpointAuthMethod != "none" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	if client.JWKSUri != nil && *client.JWKSUri != "" {
		resp["jwks_uri"] = *client.JWKSUri
	}
	return c.JSON(http.StatusCreated, resp)
}

// ── Authorize ─────────────────────────────────────────────────────────────────

func (h *OIDCHandler) Authorize(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	// Build per-request token config (own copy to avoid data races)
	tc := h.newTC(h.issuerFromRequest(c, orgSlug))

	params := queryToMap(c)
	_ = tc

	// PAR (RFC 9126): if request_uri is present, load the stored authorization
	// parameters from Redis and merge them on top of the query-string values.
	// PAR params take precedence; query string may only carry client_id (RFC 9126 §4).
	const parURNPrefix = "urn:ietf:params:oauth:request-uri:"
	// requestObjectProcessed is set to true once a request object (PAR or JAR) has
	// been parsed. Used below for FAPI2 PAR enforcement and state-stripping.
	requestObjectProcessed := false
	// parUsed is set to true exclusively when a PAR request_uri is consumed.
	// FAPI 2.0 §5.2.2-1 requires PAR for all clients with request_object_signing_alg.
	parUsed := false

	// When federation auto-registration is configured, wrap the client lookup so
	// unknown entity IDs are transparently registered on first use (OIDF §10.2).
	// This must be built before request-object (PAR/JAR) processing: a first-time
	// federation RP is not yet in the database, so its request object can only be
	// resolved and verified once auto-registration has fetched the RP's entity
	// configuration (and thus its protocol jwks_uri).
	clientLookup := oidc.ClientLookup(h.clients)
	if h.cfg.Federation.Enabled && len(h.cfg.Federation.TrustAnchors) > 0 {
		resolver := federation.NewResolver(h.cfg.Federation.TrustAnchors)
		clientLookup = federation.NewAutoRegisterLookup(h.clients, resolver, h.clients, org.ID)
	}

	if requestURI := params["request_uri"]; requestURI != "" {
		if strings.HasPrefix(requestURI, parURNPrefix) {
			token := strings.TrimPrefix(requestURI, parURNPrefix)
			redisKey := parKeyPrefix + orgSlug + ":" + token
			stored, redisErr := h.rdb.HGetAll(ctx, redisKey).Result()
			if redisErr != nil || len(stored) == 0 {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid_request_uri: PAR request not found or expired")
			}
			// RFC 9126 §4: the authorization request MUST only contain client_id
			// and request_uri. All other authorization parameters come exclusively
			// from the PAR body. Rebuild params from the stored PAR map so that
			// query-string parameters (e.g. redirect_uri) cannot leak in and
			// bypass FAPI 2.0 §5.3 requirements.
			queryClientID := params["client_id"]
			params = make(map[string]string, len(stored)+1)
			for k, v := range stored {
				params[k] = v
			}
			if params["client_id"] == "" && queryClientID != "" {
				params["client_id"] = queryClientID
			}
			// RFC 9126 §4: the client_id in the authorization request MUST match
			// the client_id used to create the PAR request.
			if queryClientID != "" && queryClientID != params["client_id"] {
				return h.redirectWithError(c, &oidc.AuthorizeError{
					Code:         "invalid_request",
					Description:  "request_uri was not issued to this client",
					RedirectURI:  params["redirect_uri"],
					State:        params["state"],
					ResponseMode: params["response_mode"],
					ClientID:     queryClientID,
					OrgSlug:      orgSlug,
				})
			}
			// One-time use: delete immediately (RFC 9126 §4).
			_ = h.rdb.Del(ctx, redisKey)
			parUsed = true
			requestObjectProcessed = true
		} else if strings.HasPrefix(requestURI, "https://") || strings.HasPrefix(requestURI, "http://") {
			// RFC 9101 §5: request_uri is an HTTP URL pointing to a remote Request Object JWT.
			// Fetch and parse the JWT, then merge its claims on top of query-string params.
			clientID := params["client_id"]
			if clientID == "" {
				return echo.NewHTTPError(http.StatusBadRequest, "client_id is required when using request_uri")
			}
			jarClient, err := clientLookup.GetByClientID(ctx, clientID)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "unknown client_id")
			}
			jarParams, jarErr := oidc.FetchRequestURI(ctx, requestURI, jarClient, tc.Issuer, h.jarDecryptOpts()...)
			if jarErr != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid request_uri: "+jarErr.Error())
			}
			// RFC 9101: JAR claims take precedence; rebuild params from JWT claims
			// only so that query-string-only params (e.g. redirect_uri not in JAR)
			// cannot leak in and satisfy validation that should fail (FAPI 2.0 §5.3).
			queryClientID := params["client_id"]
			params = make(map[string]string, len(jarParams)+1)
			for k, v := range jarParams {
				params[k] = v
			}
			if params["client_id"] == "" && queryClientID != "" {
				params["client_id"] = queryClientID
			}
			delete(params, "request_uri")
			requestObjectProcessed = true
		} else {
			return echo.NewHTTPError(http.StatusBadRequest, "unsupported request_uri format")
		}
	}

	// JAR (RFC 9101): if a signed request object is present, parse it and
	// merge its claims on top of the query-string parameters.  We must resolve
	// the client first to get its jwks_uri; a missing/invalid client_id is
	// caught again (cleanly) by ValidateAuthorizeRequest below.
	if requestJWT := params["request"]; requestJWT != "" {
		clientID := params["client_id"]
		if clientID != "" {
			if jarClient, err := clientLookup.GetByClientID(ctx, clientID); err == nil {
				jarParams, jarErr := oidc.ParseJAR(ctx, requestJWT, jarClient, tc.Issuer, h.jarDecryptOpts()...)
				if jarErr != nil {
					return echo.NewHTTPError(http.StatusBadRequest, "invalid request object: "+jarErr.Error())
				}
				// RFC 9101 §4 / FAPI 2.0 §5.3: rebuild params exclusively from
				// the JAR claims so that query-string-only params (e.g. redirect_uri
				// not present in the JWT payload) cannot bypass FAPI validation.
				// Only client_id is permitted to come from the query string.
				params = make(map[string]string, len(jarParams)+1)
				for k, v := range jarParams {
					params[k] = v
				}
				if params["client_id"] == "" {
					params["client_id"] = clientID
				}
				// OpenID Federation §12.1.1.1: a request object jti must be
				// single-use. Replay violations are surfaced via the reserved
				// policy keys so ValidateAuthorizeRequest returns a redirectable error.
				h.enforceRequestObjectJTIReplay(c, params)
				requestObjectProcessed = true
			}
		}
		delete(params, "request") // consumed; do not pass downstream
	}

	// FAPI 2.0 §5.2.2 enforcement for clients that declare request_object_signing_alg
	// or set require_par=true (unsigned-PAR DPoP clients).
	if cid := params["client_id"]; cid != "" {
		if fapiClient, cerr := h.clients.GetByClientID(ctx, cid); cerr == nil &&
			(fapiClient.RequirePAR ||
				(fapiClient.RequestObjectSigningAlg != "" && fapiClient.RequestObjectSigningAlg != "none")) {
			// §5.2.2-1: PAR is mandatory. Reject any plain authorization request
			// that did not go through PAR (e.g. fapi_request_method=unsigned).
			if !parUsed {
				return h.redirectWithError(c, &oidc.AuthorizeError{
					Code:         "invalid_request",
					Description:  "pushed authorization request (PAR) is required",
					RedirectURI:  params["redirect_uri"],
					State:        params["state"],
					ResponseMode: params["response_mode"],
					ClientID:     cid,
					OrgSlug:      orgSlug,
				})
			}
			// §5.2.2: state MUST only be echoed when present in the request object.
			if !requestObjectProcessed && params["state"] != "" {
				delete(params, "state")
			}
		}
	}

	// RFC 9396 RAR: parse authorization_details from the request parameters.
	// The value is a JSON array; invalid JSON is rejected per RFC 9396 §2.
	// Build the set of registered OID4VCI credential scopes for this org so
	// that wallet-initiated authorization code flows (scope = credential scope,
	// no "openid") are not rejected by the OIDC scope check.
	credScopes := buildCredentialScopeSet(ctx, repository.NewOID4WRepository(h.pool), org.ID)
	req, authErr := oidc.ValidateAuthorizeRequest(ctx, params, orgSlug, org.ID.String(), clientLookup, requestObjectProcessed, credScopes)
	if authErr != nil {
		if authErr.RedirectURI == "" {
			// Cannot safely redirect the error back to the client (e.g. unknown
			// client_id / untrusted redirect_uri), so render it directly as the
			// error page. Use the OAuth error code and description so it is a
			// well-defined, recognisable error rather than a generic "Bad Request".
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             authErr.Code,
				"error_description": authErr.Description,
			})
		}
		return h.redirectWithError(c, authErr)
	}

	var authorizationDetails []map[string]any
	if rawAD := params["authorization_details"]; rawAD != "" {
		if err := json.Unmarshal([]byte(rawAD), &authorizationDetails); err != nil {
			return h.redirectWithError(c, &oidc.AuthorizeError{
				Code:         "invalid_authorization_details",
				Description:  "authorization_details must be a valid JSON array",
				RedirectURI:  req.RedirectURI,
				State:        req.State,
				ResponseMode: req.ResponseMode,
				ClientID:     req.ClientID,
				OrgSlug:      orgSlug,
			})
		}
		// Basic type validation: each element must have a "type" string field.
		for _, detail := range authorizationDetails {
			if t, ok := detail["type"].(string); !ok || t == "" {
				return h.redirectWithError(c, &oidc.AuthorizeError{
					Code:         "invalid_authorization_details",
					Description:  "each authorization_details object must have a non-empty string \"type\" field",
					RedirectURI:  req.RedirectURI,
					State:        req.State,
					ResponseMode: req.ResponseMode,
					ClientID:     req.ClientID,
					OrgSlug:      orgSlug,
				})
			}
		}
		req.AuthorizationDetails = authorizationDetails
	}

	// prompt=none: check for an existing SSO session (OIDC Core §3.1.2.1).
	// If a valid SSO cookie exists for this org, issue the code silently.
	// Otherwise return login_required without any UI interaction.
	if req.Prompt == "none" {
		ssoCookieLookup := ssoCookie
		if req.SessionIsolation {
			ssoCookieLookup = isolatedCookieName(req.ClientID)
		}
		cookie, cerr := c.Cookie(ssoCookieLookup)
		if cerr == nil && cookie.Value != "" {
			ssoSess, serr := h.store.GetSSOSession(ctx, cookie.Value)
			if serr == nil && ssoSess != nil && ssoSess.OrgSlug == orgSlug &&
				(!req.SessionIsolation || ssoSess.ClientID == req.ClientID) {
				// max_age enforcement: if the session is too old, re-auth is required.
				if req.MaxAge > 0 && ssoSess.AuthTime > 0 {
					if age := time.Now().Unix() - ssoSess.AuthTime; age > int64(req.MaxAge) {
						return h.redirectWithError(c, &oidc.AuthorizeError{
							Code:         "login_required",
							Description:  "max_age exceeded — re-authentication required",
							RedirectURI:  req.RedirectURI,
							State:        req.State,
							ResponseMode: req.ResponseMode,
							ClientID:     req.ClientID,
							OrgSlug:      orgSlug,
						})
					}
				}
				code, err := oidc.IssueAuthorizationCode(ctx, &oidc.AuthorizeRequest{
					OrgSlug:              orgSlug,
					OrgID:                ssoSess.OrgID,
					ClientID:             req.ClientID,
					RedirectURI:          req.RedirectURI,
					Scope:                req.Scope,
					State:                req.State,
					Nonce:                req.Nonce,
					PKCEChallenge:        req.PKCEChallenge,
					PKCEMethod:           req.PKCEMethod,
					ResponseMode:         req.ResponseMode,
					AuthTime:             ssoSess.AuthTime,
					AuthorizationDetails: authorizationDetails,
					AcrValues:            params["acr_values"],
					ClaimsParam:          params["claims"],
					DpopJKT:              req.DpopJKT,
				}, ssoSess.UserID, h.store, h.codes)
				if err != nil {
					return h.redirectWithError(c, &oidc.AuthorizeError{
						Code:         "server_error",
						Description:  "failed to issue authorization code",
						RedirectURI:  req.RedirectURI,
						State:        req.State,
						ResponseMode: req.ResponseMode,
						ClientID:     req.ClientID,
						OrgSlug:      orgSlug,
					})
				}
				// prompt=none SSO path: build hybrid id_token if needed.
				var hybridTok string
				if strings.Contains(req.ResponseType, "id_token") {
					hybridTok = h.hybridIDToken(c, code, req.Nonce, orgSlug, req.ClientID, ssoSess.UserID, ssoSess.AuthTime)
				}
				sessState := oidc.ComputeSessionState(req.ClientID, oidc.RPOriginFromRedirectURI(req.RedirectURI), ssoSess.ID)
				return h.redirectWithCode(c, req.RedirectURI, code, req.State, orgSlug, req.ClientID, req.ResponseMode, hybridTok, sessState)
			}
		}
		return h.redirectWithError(c, &oidc.AuthorizeError{
			Code:         "login_required",
			Description:  "user authentication required",
			RedirectURI:  req.RedirectURI,
			State:        req.State,
			ResponseMode: req.ResponseMode,
			ClientID:     req.ClientID,
			OrgSlug:      orgSlug,
		})
	}

	// prompt=login: force re-authentication regardless of any existing session.
	// We always show the login form; this flag is forwarded to the session so
	// AuthorizeSubmit can record that the user explicitly re-authenticated.
	forceLogin := req.Prompt == "login"

	// Silent SSO: if the user already has a valid SSO session and prompt is not
	// "login", issue the code without showing the login form (OIDC Core §3.1.2.1).
	// This is required for tests like oidcc-max-age-10000 that expect a consistent
	// auth_time across multiple authorizations without prompt=none.
	if !forceLogin {
		ssoCookieLookup := ssoCookie
		if req.SessionIsolation {
			ssoCookieLookup = isolatedCookieName(req.ClientID)
		}
		if cookie, cerr := c.Cookie(ssoCookieLookup); cerr == nil && cookie.Value != "" {
			if ssoSess, serr := h.store.GetSSOSession(ctx, cookie.Value); serr == nil && ssoSess != nil &&
				ssoSess.OrgSlug == orgSlug &&
				(!req.SessionIsolation || ssoSess.ClientID == req.ClientID) {
				// max_age check: if the session is too old, fall through to the login form.
				maxAgeExceeded := req.MaxAge > 0 && ssoSess.AuthTime > 0 &&
					time.Now().Unix()-ssoSess.AuthTime > int64(req.MaxAge)
				if !maxAgeExceeded {
					code, err := oidc.IssueAuthorizationCode(ctx, &oidc.AuthorizeRequest{
						OrgSlug:              orgSlug,
						OrgID:                ssoSess.OrgID,
						ClientID:             req.ClientID,
						RedirectURI:          req.RedirectURI,
						Scope:                req.Scope,
						State:                req.State,
						Nonce:                req.Nonce,
						PKCEChallenge:        req.PKCEChallenge,
						PKCEMethod:           req.PKCEMethod,
						ResponseMode:         req.ResponseMode,
						AuthTime:             ssoSess.AuthTime,
						AuthorizationDetails: authorizationDetails,
						AcrValues:            params["acr_values"],
						ClaimsParam:          params["claims"],
						DpopJKT:              req.DpopJKT,
					}, ssoSess.UserID, h.store, h.codes)
					if err == nil {
						// Silent SSO path: build hybrid id_token if needed.
						var hybridTok string
						if strings.Contains(req.ResponseType, "id_token") {
							hybridTok = h.hybridIDToken(c, code, req.Nonce, orgSlug, req.ClientID, ssoSess.UserID, ssoSess.AuthTime)
						}
						sessState := oidc.ComputeSessionState(req.ClientID, oidc.RPOriginFromRedirectURI(req.RedirectURI), ssoSess.ID)
						return h.redirectWithCode(c, req.RedirectURI, code, req.State, orgSlug, req.ClientID, req.ResponseMode, hybridTok, sessState)
					}
				}
			}
		}
	}

	_ = forceLogin // carried in LoginSession below

	// Persist the login session in Redis so the POST handler can access it
	sessID := uuid.NewString()
	loginSess := &session.LoginSession{
		ID:                   sessID,
		OrgSlug:              orgSlug,
		OrgID:                org.ID.String(),
		ClientID:             req.ClientID,
		RedirectURI:          req.RedirectURI,
		Scope:                req.Scope,
		State:                req.State,
		Nonce:                req.Nonce,
		PKCEChallenge:        req.PKCEChallenge,
		PKCEMethod:           req.PKCEMethod,
		ResponseMode:         req.ResponseMode,
		ResponseType:         req.ResponseType,
		Prompt:               req.Prompt,
		LoginHint:            req.LoginHint,
		MaxAge:               req.MaxAge,
		CreatedAt:            time.Now(),
		AuthorizationDetails: authorizationDetails,
		AcrValues:            params["acr_values"],
		ClaimsParam:          params["claims"],
		DpopJKT:              req.DpopJKT,
		SessionIsolation:     req.SessionIsolation,
	}
	if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	// Load per-org CAPTCHA settings (non-fatal if unavailable)
	var captchaEnabled bool
	var captchaSiteKey, captchaScriptURL string
	if cs, err := h.captchaRepo.Get(ctx, org.ID); err == nil && cs != nil && cs.IsActive {
		if v, verr := captchapkg.New(cs.Provider, cs.SiteKey, cs.SecretKey); verr == nil {
			captchaEnabled = true
			captchaSiteKey = v.SiteKey()
			captchaScriptURL = v.ScriptURL()
		}
	}

	passkeyEnabled := h.cfg.Auth.WebAuthnRPID != ""
	// Optionally resolve the client display name for custom templates.
	clientName := ""
	if cl, clErr := h.clients.GetByClientID(ctx, req.ClientID); clErr == nil {
		clientName = cl.Name
	}
	cancelURL := "/" + orgSlug + "/authorize/cancel?login_session_id=" + sessID

	// Load active IDPs for promoted-source buttons on the login page.
	idpProviders := h.loadIDPButtons(ctx, org.ID, orgSlug, req.ClientID)

	return renderLoginWithCaptcha(c, org.Name, org.LogoURL, org.CustomLoginHTML, sessID, orgSlug, req.LoginHint, "", captchaEnabled, captchaSiteKey, captchaScriptURL, passkeyEnabled, clientName, cancelURL, idpProviders)
}

// AuthorizeDispatch is the POST handler for the authorization endpoint.
// It dispatches to AuthorizeSubmit (login form submission) when the body
// contains login_session_id, or to Authorize (RP authorization request)
// when the body contains response_type / client_id (OIDC Core §3.1.2.1).
func (h *OIDCHandler) AuthorizeDispatch(c echo.Context) error {
	if c.FormValue("login_session_id") != "" {
		return h.AuthorizeSubmit(c)
	}
	return h.Authorize(c)
}

// CancelLogin handles GET /:org_slug/authorize/cancel?login_session_id=…
// The user clicked "Cancel" on the login form.  Redirect back to the
// client redirect_uri with error=access_denied (RFC 6749 §4.1.2.1).
func (h *OIDCHandler) CancelLogin(c echo.Context) error {
	ctx := c.Request().Context()
	sessID := c.QueryParam("login_session_id")
	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess == nil {
		// Session expired or unknown — nothing to redirect to, just show a message.
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired")
	}
	_ = h.store.DeleteLoginSession(ctx, sessID)
	return h.redirectWithError(c, &oidc.AuthorizeError{
		Code:         "access_denied",
		Description:  "The user cancelled authentication",
		RedirectURI:  loginSess.RedirectURI,
		State:        loginSess.State,
		ResponseMode: loginSess.ResponseMode,
		ClientID:     loginSess.ClientID,
		OrgSlug:      loginSess.OrgSlug,
	})
}

// AuthorizeSubmit handles credential submission from the login form.
func (h *OIDCHandler) AuthorizeSubmit(c echo.Context) error {
	ctx := c.Request().Context()

	sessID := c.FormValue("login_session_id")
	email := c.FormValue("email")
	password := c.FormValue("password")

	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please try again")
	}

	// Look up the org to get logo for error re-renders
	org, _ := h.orgs.GetBySlug(ctx, loginSess.OrgSlug)
	orgName := loginSess.OrgSlug
	var logoURL *string
	var customLoginHTML *string
	if org != nil {
		orgName = org.Name
		logoURL = org.LogoURL
		customLoginHTML = org.CustomLoginHTML
	}

	passkeyEnabled := h.cfg.Auth.WebAuthnRPID != ""
	renderErr := func(msg string) error {
		return renderLogin(c, orgName, logoURL, customLoginHTML, sessID, loginSess.OrgSlug, email, msg, passkeyEnabled)
	}

	// CAPTCHA verification (if the org has it enabled)
	orgID, _ := uuid.Parse(loginSess.OrgID)

	// ── IP deny/allow rules ───────────────────────────────────────────────────
	// Deny check runs before any authentication work (credential lookup, CAPTCHA,
	// MFA) so that blocked addresses are rejected cheaply.
	// Allow check is used later to bypass the policy engine for trusted IPs.
	ipRuleMatch := ""
	if h.ipRules != nil {
		if match, err := h.ipRules.CheckIP(ctx, orgID, c.RealIP()); err == nil {
			ipRuleMatch = match
		}
	}
	if ipRuleMatch == "deny" {
		h.recordAuthEvent(c, loginSess.OrgID, nil, email, "login.blocked", "ip_deny_rule")
		return renderErr("Access denied.")
	}

	if cs, cerr := h.captchaRepo.Get(ctx, orgID); cerr == nil && cs != nil && cs.IsActive {
		if v, verr := captchapkg.New(cs.Provider, cs.SiteKey, cs.SecretKey); verr == nil {
			// Turnstile: cf-turnstile-response; hCaptcha: h-captcha-response; reCAPTCHA: g-recaptcha-response
			token := c.FormValue("cf-turnstile-response")
			if token == "" {
				token = c.FormValue("h-captcha-response")
			}
			if token == "" {
				token = c.FormValue("g-recaptcha-response")
			}
			if err := v.Verify(ctx, token, c.RealIP()); err != nil {
				return renderErr("Please complete the CAPTCHA challenge.")
			}
		}
	}

	user, err := h.users.GetByEmail(ctx, orgID, email)
	if err != nil || !user.IsActive {
		// ── Adaptive lockout: record failure even for unknown/inactive accounts ──
		// We still call RecordFailure so that someone probing accounts can be
		// slowed down. We cannot compute a risk score without a user ID so we
		// pass score=0 (lowest band, 5 attempts → 30 s).
		if h.guard != nil {
			h.guard.RecordFailure(ctx, loginSess.OrgID, email, 0)
		}
		// Record failed login
		h.recordAuthEvent(c, loginSess.OrgID, nil, email, "login.failed", "user not found or inactive")
		return renderErr("Invalid email or password.")
	}

	// ── Adaptive lockout: check before attempting password verification ────────
	// Check AFTER finding the user so we can associate the lock to the real
	// account; the error message is deliberately identical to the "bad password"
	// message to avoid user enumeration.
	if h.guard != nil {
		if remaining, locked := h.guard.IsLocked(ctx, loginSess.OrgID, email); locked {
			h.recordAuthEvent(c, loginSess.OrgID, &user.ID, email,
				"login.blocked", "adaptive_lockout")
			return renderErr(fmt.Sprintf(
				"Too many failed attempts. Please try again in %s.",
				lockout.FormatDuration(remaining),
			))
		}
	}

	if user.PasswordHash == nil || !h.users.CheckPassword(*user.PasswordHash, password) {
		h.recordAuthEvent(c, loginSess.OrgID, &user.ID, email, "login.failed", "invalid password")
		connector.Dispatch(loginSess.OrgID, connector.EventUserLoginFailed, map[string]any{
			"email": email, "reason": "invalid_password",
		})
		// ── Adaptive lockout: compute risk score and apply lockout if threshold met ──
		if h.guard != nil {
			score := 0
			if h.riskScorer != nil {
				if s, serr := h.riskScorer.Compute(ctx, orgID, user.ID); serr == nil {
					score = s.Score
				}
			}
			dur := h.guard.RecordFailure(ctx, loginSess.OrgID, email, score)
			if dur > 0 {
				h.recordAuthEvent(c, loginSess.OrgID, &user.ID, email,
					"login.lockout", fmt.Sprintf("score=%d dur=%s", score, dur))
				connector.Dispatch(loginSess.OrgID, connector.EventUserIdentifierLockout, map[string]any{
					"email":            email,
					"user_id":          user.ID.String(),
					"lockout_duration": dur.String(),
					"lockout_seconds":  int(dur.Seconds()),
					"risk_score":       score,
				})
			}
		}
		return renderErr("Invalid email or password.")
	}

	// Record auth_time at password verification — carried through MFA/resume.
	loginSess.AuthTime = time.Now().Unix()

	// ── Adaptive lockout: clear failure counter on successful password entry ──
	if h.guard != nil {
		h.guard.ClearFailures(ctx, loginSess.OrgID, email)
	}

	// ── Breached password check (HIBP k-anonymity) ────────────────────────────
	// Runs after credential verification so we only query HIBP for valid creds.
	// Fail-open: network/API errors are silently swallowed (never block the user).
	if !loginSess.BreachWarningAcknowledged {
		if policy, err := h.pwPolicy.Get(ctx, user.OrgID); err == nil &&
			policy.BreachedPasswordAction != "" &&
			policy.BreachedPasswordAction != "off" {
			if result, bErr := h.breach.Check(password); bErr == nil && result.Pwned {
				switch policy.BreachedPasswordAction {
				case "block":
					h.recordAuthEvent(c, loginSess.OrgID, &user.ID, email, "login.blocked", "breached_password")
					return renderErr(fmt.Sprintf(
						"This password has appeared in %d known data breach(es). "+
							"Please choose a different password to sign in.",
						result.Count,
					))
				case "force_reset":
					// Force the user to change their password before the code is issued.
					// Reuses the same UPDATE_PASSWORD interstitial as the required-action flow.
					h.recordAuthEvent(c, loginSess.OrgID, &user.ID, email, "login.breach_force_reset", "")
					loginSess.UserID = user.ID.String()
					if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
						return renderErr("An error occurred. Please try again.")
					}
					return c.Redirect(http.StatusFound,
						"/"+loginSess.OrgSlug+"/update-password?login_session_id="+sessID)
				case "warn":
					// Show a one-time warning interstitial; the user acknowledges and continues.
					h.recordAuthEvent(c, loginSess.OrgID, &user.ID, email, "login.breach_warn", "")
					loginSess.UserID = user.ID.String()
					if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
						return renderErr("An error occurred. Please try again.")
					}
					return c.Redirect(http.StatusFound,
						"/"+loginSess.OrgSlug+"/breach-warning?login_session_id="+sessID+
							"&count="+fmt.Sprintf("%d", result.Count))
				}
			}
		}
	}

	// ── Policy engine ─────────────────────────────────────────────────────────
	// Evaluate per-org auth-flow policy rules.  Runs after credential check so
	// user signals (MFA enrolled, new country, last login) are available.
	// Policy can block the login or force MFA step-up regardless of org setting.
	// Skipped when the source IP matched an explicit allow rule.
	if h.policies != nil && ipRuleMatch != "allow" {
		orgIDForPolicy, _ := uuid.Parse(loginSess.OrgID)
		mfaCount, _ := h.mfa.CountConfirmedByUser(ctx, user.ID)

		// geo-IP lookup — traced separately so operators can see latency
		_, geoSpan := tracing.Tracer("clavex/handler").Start(ctx, "geoip.lookup")
		geoInfo := h.geo.Lookup(c.RealIP())
		geoSpan.SetAttributes(
			attribute.String("geoip.ip", c.RealIP()),
			attribute.String("geoip.country", geoInfo.CountryCode),
			attribute.String("geoip.city", geoInfo.City),
		)
		geoSpan.End()

		anomaly, _ := h.loginHistory.GetAnomalySignals(ctx, user.ID, c.RealIP(), geoInfo.CountryCode)
		policyInput := policy.EvalInput{
			IPAddress:   c.RealIP(),
			Country:     geoInfo.CountryCode,
			UserAgent:   c.Request().UserAgent(),
			ClientID:    loginSess.ClientID,
			RequestTime: time.Now().UTC(),
			UserID:      user.ID.String(),
			MFAEnrolled: mfaCount > 0,
			NewCountry:  anomaly != nil && anomaly.NewCountry,
			LastLoginAt: user.LastLoginAt,
		}
		if p, perr := h.policies.LoadPolicy(ctx, orgIDForPolicy, nil); perr == nil {
			// policy evaluation — traced to expose rule engine latency
			_, policySpan := tracing.Tracer("clavex/handler").Start(ctx, "policy.evaluate")
			outcome := policy.Evaluate(p, policyInput)
			policySpan.SetAttributes(
				attribute.String("policy.action", string(outcome.Action)),
				attribute.String("policy.reason", outcome.Reason),
			)
			policySpan.End()
			if outcome.IsDeny() {
				h.recordAuthEvent(c, loginSess.OrgID, &user.ID, user.Email, "login.blocked", outcome.Reason)
				return renderErr("Access denied by security policy.")
			}
			if outcome.IsMFARequired() {
				// Inject forced MFA into the session so step-up is checked below.
				_ = outcome // mfaRequired will be overridden to true
				loginSess.ForceMFA = true
			}
		}
	}

	// ── MFA enforcement ───────────────────────────────────────────────────────
	mfaRequired := (org != nil && org.MFARequired) || user.MFARequired || loginSess.ForceMFA
	if mfaRequired {
		confirmed, err := h.mfa.CountConfirmedByUser(ctx, user.ID)
		if err != nil {
			c.Logger().Errorf("CountConfirmedByUser failed: user=%s err=%v", user.Email, err)
			return renderErr("An error occurred. Please try again.")
		}
		if confirmed == 0 {
			return renderErr("Two-factor authentication is required for this account but has not been enrolled. Please contact your administrator.")
		}

		// ── Device trust: skip MFA for known trusted devices ──────────────────
		if secret := h.cfg.Auth.DeviceTrustSecret; secret != "" {
			if cookie, err := c.Cookie(repository.DeviceTrustCookieName); err == nil && cookie.Value != "" {
				orgIDParsed, _ := uuid.Parse(loginSess.OrgID)
				fp := repository.FingerprintHash(secret, cookie.Value, user.ID)
				if h.trustedDev.IsTrusted(ctx, orgIDParsed, user.ID, fp) {
					// Trusted device — skip MFA, fall through to code issuance below.
					goto skipMFA
				}
			}
		}

		// Password OK but MFA still pending — update session and show TOTP form.
		loginSess.UserID = user.ID.String()
		loginSess.MFAPending = true
		if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
			c.Logger().Errorf("SaveLoginSession (MFA pending) failed: user=%s err=%v", user.Email, err)
			return renderErr("An error occurred. Please try again.")
		}
		return renderMFAChallenge(c, orgName, logoURL, sessID, "", h.deviceTrustDaysForOrg(org))
	}
skipMFA:

	// ── Required actions check ────────────────────────────────────────────────
	for _, action := range user.RequiredActions {
		if action == "VERIFY_EMAIL" && !user.IsEmailVerified {
			return h.startEmailVerification(c, user, org, orgName, loginSess)
		}
		if action == "UPDATE_PASSWORD" {
			// Force password change — mark session, redirect to change-password page
			loginSess.UserID = user.ID.String()
			if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
				c.Logger().Errorf("SaveLoginSession (UPDATE_PASSWORD) failed: user=%s err=%v", user.Email, err)
				return renderErr("An error occurred. Please try again.")
			}
			return c.Redirect(http.StatusFound, "/"+loginSess.OrgSlug+"/update-password?login_session_id="+sessID)
		}
		if action == "ENROLL_PASSKEY" {
			// Admin has requested that this user enrol a passkey before receiving
			// an auth code. Redirect to the login-time passkey enrollment page.
			loginSess.UserID = user.ID.String()
			if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
				c.Logger().Errorf("SaveLoginSession (ENROLL_PASSKEY) failed: user=%s err=%v", user.Email, err)
				return renderErr("An error occurred. Please try again.")
			}
			return c.Redirect(http.StatusFound, "/"+loginSess.OrgSlug+"/enroll-passkey?login_session_id="+sessID)
		}
	}

	// ── Login flow engine ─────────────────────────────────────────────────────
	// Run the visual step-builder flow (if configured for this org/client).
	// The flow can deny the login, force MFA step-up, or inject extra claims.
	if h.flowEngine != nil {
		fr := h.flowEngine.Run(ctx, orgID, flowengine.UserContext{
			User:      user,
			OrgSlug:   loginSess.OrgSlug,
			ClientID:  loginSess.ClientID,
			IPAddress: c.RealIP(),
			AuthTime:  loginSess.AuthTime,
		})
		if fr.UpgradeSPIDLevel > 0 {
			// check_verified with upgrade:"spid": initiate an in-session SPID level
			// upgrade. The UpgradeSSO handler re-authenticates the user at the
			// required level while preserving the original OIDC session context.
			loginSess.UserID = user.ID.String()
			loginSess.RequiredSPIDLevel = fr.UpgradeSPIDLevel
			if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
				return renderErr("An error occurred. Please try again.")
			}
			return c.Redirect(http.StatusFound, "/"+loginSess.OrgSlug+"/spid/upgrade?login_session_id="+sessID)
		}
		if fr.UpgradeCIE {
			// check_verified with upgrade:"cie": initiate an in-session CIE
			// re-authentication to raise assurance_level to eIDAS High.
			loginSess.UserID = user.ID.String()
			loginSess.RequiredCIEUpgrade = true
			if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
				return renderErr("An error occurred. Please try again.")
			}
			return c.Redirect(http.StatusFound, "/"+loginSess.OrgSlug+"/cie/upgrade?login_session_id="+sessID)
		}
		if fr.ForceReauth {
			// check_session_age with action:"require_reauth": redirect to client with
			// error=login_required so it re-initiates the authorization request.
			_ = h.store.DeleteLoginSession(ctx, sessID)
			return h.redirectWithError(c, &oidc.AuthorizeError{
				Code:         "login_required",
				Description:  "session too old — re-authentication required",
				RedirectURI:  loginSess.RedirectURI,
				State:        loginSess.State,
				ResponseMode: loginSess.ResponseMode,
				ClientID:     loginSess.ClientID,
				OrgSlug:      loginSess.OrgSlug,
			})
		}
		if fr.Deny {
			h.recordAuthEvent(c, loginSess.OrgID, &user.ID, email, "login.blocked", "flow:"+fr.DenyReason)
			// check_verified with step_up_url: redirect to a stronger IdP rather than
			// showing a denial page. The IdP callback will update assurance_level and
			// call /authorize/resume so the flow is re-evaluated at the higher level.
			if fr.StepUpURL != "" {
				loginSess.UserID = user.ID.String()
				if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
					return renderErr("An error occurred. Please try again.")
				}
				// Append the login_session_id so the IdP callback can resume.
				stepUpDest := fr.StepUpURL
				if strings.Contains(stepUpDest, "?") {
					stepUpDest += "&login_session_id=" + sessID
				} else {
					stepUpDest += "?login_session_id=" + sessID
				}
				return c.Redirect(http.StatusFound, stepUpDest)
			}
			return renderErr(fr.DenyReason)
		}
		if fr.ForceMFA && !loginSess.ForceMFA {
			loginSess.ForceMFA = true
			loginSess.UserID = user.ID.String()
			loginSess.MFAPending = true
			if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
				return renderErr("An error occurred. Please try again.")
			}
			return renderMFAChallenge(c, orgName, logoURL, sessID, "", h.deviceTrustDaysForOrg(org))
		}
		// oid4vp_challenge: pause login and require a wallet credential presentation.
		// Extra claims accumulated by preceding steps are saved in the login session
		// so they survive the challenge redirect and are merged on resume.
		if fr.OID4VPChallenge != nil && h.oid4vpH != nil {
			if len(fr.ExtraClaims) > 0 {
				loginSess.ExtraClaims = fr.ExtraClaims
			}
			orgIDParsed, _ := uuid.Parse(loginSess.OrgID)
			vpSess, err := h.oid4vpH.CreateLoginChallengeSession(
				ctx, orgIDParsed, loginSess.OrgSlug,
				fr.OID4VPChallenge.DCQLQuery,
				fr.OID4VPChallenge.PresentationDefinition,
			)
			if err != nil {
				return renderErr("An error occurred. Please try again.")
			}
			loginSess.UserID = user.ID.String()
			loginSess.OID4VPPending = true
			loginSess.OID4VPRequestID = vpSess.RequestID
			loginSess.OID4VPMessage = fr.OID4VPChallenge.Message
			if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
				return renderErr("An error occurred. Please try again.")
			}
			return c.Redirect(http.StatusFound,
				"/"+loginSess.OrgSlug+"/authorize/oid4vp-challenge?login_session_id="+sessID+"&request_id="+vpSess.RequestID)
		}
		if len(fr.ExtraClaims) > 0 {
			loginSess.ExtraClaims = fr.ExtraClaims
		}
	}

	code, err := oidc.IssueAuthorizationCode(ctx, &oidc.AuthorizeRequest{
		OrgSlug:              loginSess.OrgSlug,
		OrgID:                loginSess.OrgID,
		ClientID:             loginSess.ClientID,
		RedirectURI:          loginSess.RedirectURI,
		Scope:                loginSess.Scope,
		State:                loginSess.State,
		Nonce:                loginSess.Nonce,
		PKCEChallenge:        loginSess.PKCEChallenge,
		PKCEMethod:           loginSess.PKCEMethod,
		AuthTime:             loginSess.AuthTime,
		AuthorizationDetails: loginSess.AuthorizationDetails,
		AcrValues:            loginSess.AcrValues,
		ClaimsParam:          loginSess.ClaimsParam,
		ExtraClaims:          loginSess.ExtraClaims,
		DpopJKT:              loginSess.DpopJKT,
	}, user.ID.String(), h.store, h.codes)
	if err != nil {
		c.Logger().Errorf("IssueAuthorizationCode failed: org=%s client=%s user=%s redirect=%s err=%v",
			loginSess.OrgSlug, loginSess.ClientID, user.Email, loginSess.RedirectURI, err)
		return renderErr("An error occurred. Please try again.")
	}

	h.recordAuthEvent(c, loginSess.OrgID, &user.ID, user.Email, "login.success", "")
	_ = h.store.DeleteLoginSession(ctx, sessID)
	connector.Dispatch(loginSess.OrgID, connector.EventUserLogin, map[string]any{
		"user_id": user.ID.String(), "email": user.Email, "client_id": loginSess.ClientID,
	})
	connector.Dispatch(loginSess.OrgID, connector.EventTokenIssued, map[string]any{
		"user_id": user.ID.String(), "client_id": loginSess.ClientID, "scope": loginSess.Scope,
	})

	// Create an SSO session so that future prompt=none requests can succeed
	// without re-prompting (OIDC Core §3.1.2.1).
	ssoSess := &session.SSOSession{
		ID:        uuid.NewString(),
		UserID:    user.ID.String(),
		OrgID:     loginSess.OrgID,
		OrgSlug:   loginSess.OrgSlug,
		AuthTime:  loginSess.AuthTime,
		CreatedAt: time.Now(),
	}
	if loginSess.SessionIsolation {
		ssoSess.ClientID = loginSess.ClientID
	}
	if err := h.store.SaveSSOSession(ctx, ssoSess); err == nil {
		cookieName := ssoCookie
		if loginSess.SessionIsolation {
			cookieName = isolatedCookieName(loginSess.ClientID)
		}
		setSSOCookieNamed(c, cookieName, ssoSess.ID)
	}

	// Build hybrid id_token for response_type=code id_token.
	var hybridTok string
	if strings.Contains(loginSess.ResponseType, "id_token") {
		hybridTok = h.hybridIDToken(c, code, loginSess.Nonce, loginSess.OrgSlug, loginSess.ClientID, user.ID.String(), loginSess.AuthTime)
	}
	sessState := oidc.ComputeSessionState(loginSess.ClientID, oidc.RPOriginFromRedirectURI(loginSess.RedirectURI), ssoSess.ID)
	return h.redirectWithCode(c, loginSess.RedirectURI, code, loginSess.State, loginSess.OrgSlug, loginSess.ClientID, loginSess.ResponseMode, hybridTok, sessState)
}

// ── Token endpoint ────────────────────────────────────────────────────────────

func (h *OIDCHandler) Token(c echo.Context) error {
	// RFC 6749 §5.1: token responses MUST NOT be cached.
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Pragma", "no-cache")

	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	tc := h.newTC(h.issuerFromRequest(c, orgSlug))
	grantType := c.FormValue("grant_type")

	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.token")
	defer span.End()
	span.SetAttributes(
		attribute.String("org_slug", orgSlug),
		attribute.String("grant_type", grantType),
	)

	// DPoP (RFC 9449): parse proof if present.
	// htu = URL without query string; htm = HTTP method.
	// RFC 9449 §7.1: reject when more than one DPoP proof header is present.
	if dpopVals := c.Request().Header.Values("DPoP"); len(dpopVals) > 1 {
		return tokenError(c, "invalid_dpop_proof", "exactly one DPoP header is allowed (RFC 9449 §7.1)")
	}
	htu := h.htuFromEcho(c)
	dpop, dpopErr := oidc.ParseDPoPProof(c.Request().Header.Get("DPoP"), c.Request().Method, htu)
	if dpopErr != nil {
		return tokenError(c, "invalid_dpop_proof", dpopErr.Error())
	}
	// Anti-replay: every DPoP jti must be unique within a 5-minute window.
	if dpop != nil {
		if replayErr := oidc.CheckJTI(ctx, dpop.JTI, h.rdb); replayErr != nil {
			return tokenError(c, "invalid_dpop_proof", "dpop proof jti already used")
		}
	}

	// RFC 8705: extract client certificate from the TLS connection (if present).
	// This enables certificate-bound access tokens (cnf.x5t#S256) regardless
	// of whether strict mTLS is enforced at the transport layer.
	mtls := oidc.CertFromRequest(c.Request())

	switch grantType {
	case "authorization_code":
		clientID, _, attestJKT, err := h.authenticateClient(c)
		if err != nil {
			return tokenError(c, "invalid_client", echoMsg(err))
		}
		// Resolve per-client settings (id_token alg, sender-constrained checks, TTL override).
		idTokenAlg := ""
		var cl *models.OIDCClient
		if fetched, clErr := h.clients.GetByClientID(ctx, clientID); clErr == nil {
			cl = fetched
			idTokenAlg = cl.IDTokenSignedResponseAlg
			// FAPI 2.0 §5.3.1.1-6: sender-constrained token required (DPoP or mTLS).
			// Accept an mTLS client certificate as an alternative so that the same
			// client can serve both DPoP and MTLS conformance plans.
			// Use invalid_request (not invalid_dpop_proof) when no proof is present
			// at all — invalid_dpop_proof is reserved for a proof that IS present
			// but fails validation (RFC 9449 §5, FAPI2 conformance expectation).
			if cl.DpopBoundAccessTokens && dpop == nil && mtls == nil {
				return tokenError(c, "invalid_request",
					"sender-constrained access token required: provide a DPoP proof or mTLS client certificate")
			}
			// RFC 8705 §3: tls_client_certificate_bound_access_tokens requires a
			// valid TLS client certificate on every token request.  Reject here
			// (before code consumption) so the auth code remains valid on retry.
			if cl.TLSClientCertBoundAccessTokens && mtls == nil {
				return tokenError(c, "invalid_client",
					"mTLS client certificate is required for this client")
			}
		}
		// Build a synchronous claims-enrichment hook if the org has one configured.
		var enricher oidc.ClaimsEnricher
		var orgForToken *models.Organization
		if o, orgErr := h.orgs.GetBySlug(ctx, orgSlug); orgErr == nil {
			orgForToken = o
			if orgForToken.ClaimsEnrichmentURL != nil && *orgForToken.ClaimsEnrichmentURL != "" {
				hookURL := *orgForToken.ClaimsEnrichmentURL
				hookSecret := ""
				if orgForToken.ClaimsEnrichmentSecret != nil {
					hookSecret = *orgForToken.ClaimsEnrichmentSecret
				}
				enricher = func(eCtx context.Context, cid, scope string, uc *oidc.UserClaims) (map[string]any, error) {
					extra, enrichErr := enrichment.Enrich(eCtx, hookURL, hookSecret, enrichment.Payload{
						Sub:      uc.UserID,
						OrgID:    uc.OrgID,
						Email:    uc.Email,
						ClientID: cid,
						Scope:    scope,
						Extra:    uc.ExtraClaims,
					})
					if enrichErr != nil {
						c.Logger().Warnf("claims enrichment hook error: org=%s err=%v", orgSlug, enrichErr)
					}
					return extra, enrichErr
				}
			}
		}
		// Apply per-org then per-client TTL overrides (client wins over org, both win over global).
		h.applyOrgOverrides(ctx, tc, orgForToken, cl)
		rawCode := c.FormValue("code")
		ts, err := oidc.ExchangeCode(ctx,
			clientID,
			rawCode,
			c.FormValue("redirect_uri"),
			c.FormValue("code_verifier"),
			idTokenAlg,
			tc, h.codes, h.tokens, h.users, h.groups, h.mappers,
			dpop,
			h.grantRepo,
			mtls,
			enricher,
			h.flags,
			attestJKT,
		)
		if err != nil {
			var te *oidc.TokenError
			if ok := isTokenError(err, &te); ok {
				// RFC 6749 §4.1.2: if code was already used, revoke the access token
				// previously issued for this code (best-effort, async).
				//
				// We intentionally do NOT revoke the entire refresh token family here.
				// RFC 6749 §4.1.2 and RFC 9700 §2.2.1 only RECOMMEND revoking access
				// tokens; they say nothing about refresh token families.  Cascading
				// family revocation on code replay caused false positives in slow
				// flows (e.g., JAR+JARM): the async SetRevocationData goroutine always
				// completes before the code replay goroutine in those flows, making
				// code retries appear as attacks and invalidating the refresh token
				// before the client can use it (breaking fapi2-security-profile-id2-
				// refresh-token in the JARM conformance plan).
				if te.Code == "invalid_grant" {
					c.Logger().Warnf("token invalid_grant: org=%s client=%s redirect_uri=%q desc=%s",
						orgSlug, clientID, c.FormValue("redirect_uri"), te.Description)
					capturedTC := tc
					codeHash := oidc.HashToken(rawCode)
					go func() {
						bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						// Only revoke when a previous successful exchange is confirmed
						// (AccessTokenJTI is set asynchronously alongside RefreshFamilyID).
						if ac, err := h.codes.GetUsedByHash(bgCtx, codeHash); err == nil && ac != nil && ac.AccessTokenJTI != "" {
							ttl := capturedTC.AccessTokenTTL
							_ = h.store.RevokeToken(bgCtx, ac.AccessTokenJTI, ttl)
						}
					}()
				}
				return tokenError(c, te.Code, te.Description)
			}
			c.Logger().Errorf("ExchangeCode internal error: org=%s client=%s err=%v", orgSlug, clientID, err)
			return echo.ErrInternalServerError
		}
		// Store device metadata for session management.
		if ts.RefreshToken != "" {
			go h.tokens.SetDeviceInfoByHash(context.Background(),
				oidc.HashToken(ts.RefreshToken),
				c.Request().UserAgent(), c.RealIP())
		}
		// Track last use for Object Lifecycle Management (best-effort, async).
		go repository.TouchClientLastUsed(context.Background(), h.pool, clientID)
		metrics.TokensIssuedTotal.WithLabelValues(orgSlug, "authorization_code").Inc()
		return c.JSON(http.StatusOK, ts)

	case "refresh_token":
		clientID, _, attestJKT, err := h.authenticateClient(c)
		if err != nil {
			return tokenError(c, "invalid_client", echoMsg(err))
		}
		// FAPI 2.0 §5.3.1.1-6 / RFC 8705 §7.1: sender-constrained token required.
		// For mTLS-bound clients the certificate must be re-presented on every
		// refresh request — storing the thumbprint is not a substitute for PoP.
		var clForRefresh *models.OIDCClient
		if fetched, clErr := h.clients.GetByClientID(ctx, clientID); clErr == nil {
			clForRefresh = fetched
			if clForRefresh.DpopBoundAccessTokens && dpop == nil && mtls == nil {
				return tokenError(c, "invalid_request",
					"sender-constrained access token required: provide a DPoP proof or mTLS client certificate")
			}
			if clForRefresh.TLSClientCertBoundAccessTokens && mtls == nil {
				return tokenError(c, "invalid_client",
					"mTLS client certificate is required for this client")
			}
		}
		// Build enricher for refresh flow (same hook, re-injects fresh claims on rotation).
		var refreshEnricher oidc.ClaimsEnricher
		var orgForRefresh *models.Organization
		if o, orgErr := h.orgs.GetBySlug(ctx, orgSlug); orgErr == nil {
			orgForRefresh = o
			if orgForRefresh.ClaimsEnrichmentURL != nil && *orgForRefresh.ClaimsEnrichmentURL != "" {
				hookURL := *orgForRefresh.ClaimsEnrichmentURL
				hookSecret := ""
				if orgForRefresh.ClaimsEnrichmentSecret != nil {
					hookSecret = *orgForRefresh.ClaimsEnrichmentSecret
				}
				refreshEnricher = func(eCtx context.Context, cid, scope string, uc *oidc.UserClaims) (map[string]any, error) {
					extra, enrichErr := enrichment.Enrich(eCtx, hookURL, hookSecret, enrichment.Payload{
						Sub:      uc.UserID,
						OrgID:    uc.OrgID,
						Email:    uc.Email,
						ClientID: cid,
						Scope:    scope,
						Extra:    uc.ExtraClaims,
					})
					if enrichErr != nil {
						c.Logger().Warnf("claims enrichment hook error (refresh): org=%s err=%v", orgSlug, enrichErr)
					}
					return extra, enrichErr
				}
			}
		}
		// Apply per-org then per-client TTL overrides.
		h.applyOrgOverrides(ctx, tc, orgForRefresh, clForRefresh)
		ts, err := oidc.ExchangeRefreshToken(ctx,
			clientID,
			c.FormValue("refresh_token"),
			tc, h.tokens, h.users, h.store, h.mappers,
			dpop,
			mtls,
			refreshEnricher,
			h.flags,
			attestJKT,
		)
		if err != nil {
			var te *oidc.TokenError
			if ok := isTokenError(err, &te); ok {
				return tokenError(c, te.Code, te.Description)
			}
			return echo.ErrInternalServerError
		}
		// Propagate device metadata to the newly-rotated refresh token.
		if ts.RefreshToken != "" {
			go h.tokens.SetDeviceInfoByHash(context.Background(),
				oidc.HashToken(ts.RefreshToken),
				c.Request().UserAgent(), c.RealIP())
		}
		go repository.TouchClientLastUsed(context.Background(), h.pool, clientID)
		metrics.TokensIssuedTotal.WithLabelValues(orgSlug, "refresh_token").Inc()
		return c.JSON(http.StatusOK, ts)

	case "client_credentials":
		// Check if this is a service account (client_id prefix "sa_").
		ccClientID := c.FormValue("client_id")
		if h.serviceAccounts != nil && strings.HasPrefix(ccClientID, "sa_") {
			ccSecret := c.FormValue("client_secret")
			if ccSecret == "" {
				_, ccSecret, _ = c.Request().BasicAuth()
			}
			sa, err := h.serviceAccounts.VerifySecret(ctx, ccClientID, ccSecret)
			if err != nil {
				return tokenError(c, "invalid_client", "invalid service account credentials")
			}
			scope := c.FormValue("scope")
			if scope == "" {
				scope = strings.Join(sa.Scopes, " ")
			} else {
				// RFC 6749 §3.3: constrain the requested scope to the service
				// account's granted scopes (empty sa.Scopes ⇒ allow-all).
				scope = oidc.FilterScope(scope, sa.Scopes)
			}
			te, err := oidc.ExchangeClientCredentials(ctx, "sa:"+sa.ID.String(), scope, tc, dpop, mtls)
			if err != nil {
				return echo.ErrInternalServerError
			}
			go h.serviceAccounts.TouchLastUsed(context.Background(), sa.ID)
			metrics.TokensIssuedTotal.WithLabelValues(orgSlug, "client_credentials").Inc()
			return c.JSON(http.StatusOK, te)
		}
		clientID, _, _, err := h.authenticateClient(c)
		if err != nil {
			return tokenError(c, "invalid_client", echoMsg(err))
		}
		// Apply per-org/per-client TTL overrides for client_credentials, and
		// constrain the requested scope to the client's registered scopes
		// (RFC 6749 §3.3; empty client.Scopes ⇒ allow-all).
		ccScope := c.FormValue("scope")
		if ccCl, ccClErr := h.clients.GetByClientID(ctx, clientID); ccClErr == nil {
			var ccOrg *models.Organization
			if o, oErr := h.orgs.GetBySlug(ctx, orgSlug); oErr == nil {
				ccOrg = o
			}
			h.applyOrgOverrides(ctx, tc, ccOrg, ccCl)
			ccScope = oidc.FilterScope(ccScope, ccCl.Scopes)
		}
		te, err := oidc.ExchangeClientCredentials(ctx, clientID, ccScope, tc, dpop, mtls)
		if err != nil {
			return echo.ErrInternalServerError
		}
		go repository.TouchClientLastUsed(context.Background(), h.pool, clientID)
		metrics.TokensIssuedTotal.WithLabelValues(orgSlug, "client_credentials").Inc()
		return c.JSON(http.StatusOK, te)

	case "urn:ietf:params:oauth:grant-type:token-exchange": // RFC 8693
		clientID, _, _, err := h.authenticateClient(c)
		if err != nil {
			return tokenError(c, "invalid_client", echoMsg(err))
		}

		// Cross-org exchange: resource=urn:clavex:org:{source_org_slug} signals
		// that the subject_token was issued for a different org (the source) and
		// the caller wants a token valid in the current org (the target, identified
		// by the :org_slug URL parameter).
		resource := c.FormValue("resource")
		const crossOrgURN = "urn:clavex:org:"
		if strings.HasPrefix(resource, crossOrgURN) {
			sourceSlug := strings.TrimPrefix(resource, crossOrgURN)
			sourceOrg, err := h.orgs.GetBySlug(ctx, sourceSlug)
			if err != nil {
				return tokenError(c, "invalid_request", "source organization not found")
			}
			targetSlug := c.Param("org_slug")
			targetOrg, err := h.orgs.GetBySlug(ctx, targetSlug)
			if err != nil {
				return tokenError(c, "invalid_request", "target organization not found")
			}
			if sourceOrg.ID == targetOrg.ID {
				return tokenError(c, "invalid_request", "source and target org must differ for cross-org exchange")
			}

			trust, err := h.crossOrgTrusts.GetTrust(ctx, sourceOrg.ID, targetOrg.ID)
			if err != nil {
				return tokenError(c, "access_denied", "no active cross-org trust from source to target organization")
			}

			allowed, effectiveScope := repository.IsTrustAllowed(trust, clientID, c.FormValue("scope"))
			if !allowed {
				return tokenError(c, "access_denied", "cross-org trust does not permit this client or scope")
			}

			// Policy: require_mfa — verify the subject_token carried an MFA amr.
			targetIssuer := h.issuerFromRequest(c, targetSlug)
			if trust.RequireMFA {
				subjectTok, parseErr := jwtPkg.Parse(
					[]byte(c.FormValue("subject_token")),
					jwtPkg.WithVerify(false),
					jwtPkg.WithValidate(false),
				)
				if parseErr != nil {
					return tokenError(c, "invalid_request", "cannot parse subject_token")
				}
				amrVal, _ := subjectTok.Get("amr")
				amrSlice, _ := amrVal.([]interface{})
				mfaMethods := map[string]bool{"mfa": true, "otp": true, "totp": true, "hwk": true, "swk": true, "phr": true}
				hasMFA := false
				for _, v := range amrSlice {
					if mfaMethods[fmt.Sprint(v)] {
						hasMFA = true
						break
					}
				}
				if !hasMFA {
					return tokenError(c, "access_denied", "cross-org trust requires MFA; subject_token amr does not satisfy requirement")
				}
			}

			// Policy: max_token_ttl — cap the target token config TTL.
			targetTC := h.newTC(targetIssuer)
			// Apply per-org/per-client TTL overrides for the target org and client.
			var teCl *models.OIDCClient
			if fetched, clErr := h.clients.GetByClientID(ctx, clientID); clErr == nil {
				teCl = fetched
			}
			h.applyOrgOverrides(ctx, targetTC, targetOrg, teCl)
			// Trust MaxTokenTTL is a hard cap: it overrides even per-client settings.
			if trust.MaxTokenTTL != nil {
				maxTTL := time.Duration(*trust.MaxTokenTTL) * time.Second
				if targetTC.AccessTokenTTL > maxTTL {
					targetTC.AccessTokenTTL = maxTTL
				}
			}
			var teAllowedAud []string
			if teCl != nil {
				teAllowedAud = teCl.AllowedAudiences
			}
			// The subject_token was issued by the SOURCE org, so it must be
			// verified against the source issuer (not the target).
			sourceTC := h.newTC(h.issuerFromRequest(c, sourceSlug))
			resp, err := oidc.ExchangeToken(ctx,
				clientID,
				c.FormValue("subject_token"),
				c.FormValue("subject_token_type"),
				c.FormValue("audience"),
				effectiveScope,
				teAllowedAud,
				sourceTC,
				targetTC, h.tokens, h.users, h.store, h.mappers,
			)
			if err != nil {
				var te *oidc.TokenError
				if ok := isTokenError(err, &te); ok {
					return tokenError(c, te.Code, te.Description)
				}
				return echo.ErrInternalServerError
			}
			return c.JSON(http.StatusOK, resp)
		}

		// Same-org exchange (original path).
		var soAllowedAud []string
		if soCl, soErr := h.clients.GetByClientID(ctx, clientID); soErr == nil {
			soAllowedAud = soCl.AllowedAudiences
		}
		resp, err := oidc.ExchangeToken(ctx,
			clientID,
			c.FormValue("subject_token"),
			c.FormValue("subject_token_type"),
			c.FormValue("audience"),
			c.FormValue("scope"),
			soAllowedAud,
			tc, // same org: verify and issue with the same issuer
			tc, h.tokens, h.users, h.store, h.mappers,
		)
		if err != nil {
			var te *oidc.TokenError
			if ok := isTokenError(err, &te); ok {
				return tokenError(c, te.Code, te.Description)
			}
			return echo.ErrInternalServerError
		}
		return c.JSON(http.StatusOK, resp)

	case "urn:ietf:params:oauth:grant-type:device_code": // RFC 8628
		return h.deviceCodeGrant(c)

	case "urn:openid:params:grant-type:ciba": // CIBA Core 1.0 — poll mode
		return h.cibaGrant(c)

	case "urn:ietf:params:oauth:grant-type:pre-authorized_code": // OID4VCI §6.1
		// Wallets resolve the token endpoint from the OAuth AS metadata (RFC 8414)
		// and send pre-authorized_code requests here.  Delegate to the OID4VCI
		// handler which owns the offer repository and nonce logic.
		if h.vciH == nil {
			return tokenError(c, "unsupported_grant_type", "grant_type not supported")
		}
		return h.vciH.Token(c)

	default:
		return tokenError(c, "unsupported_grant_type", "grant_type not supported")
	}
}

// ── Introspect (RFC 7662) ─────────────────────────────────────────────────────

// introspectCacheKey returns a Redis key for a token without storing the raw token value.
func introspectCacheKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return "introspect:" + hex.EncodeToString(h[:])
}

func (h *OIDCHandler) Introspect(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	tc := h.newTC(h.issuerFromRequest(c, orgSlug))
	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.introspect")
	defer span.End()
	span.SetAttributes(attribute.String("org_slug", orgSlug))

	if _, _, _, err := h.authenticateClient(c); err != nil {
		span.SetStatus(otelcodes.Error, "invalid_client")
		return tokenError(c, "invalid_client", err.Error())
	}

	token := c.FormValue("token")
	cacheKey := introspectCacheKey(token)

	// Cache hit — return immediately
	if cached, err := h.rdb.Get(ctx, cacheKey).Bytes(); err == nil {
		var resp oidc.IntrospectionResponse
		if json.Unmarshal(cached, &resp) == nil {
			return c.JSON(http.StatusOK, resp)
		}
	}

	resp := oidc.Introspect(ctx, token, tc, h.store)

	// ── Wallet step-up (Continuous Adaptive Authentication) ──────────────────
	// For active tokens, evaluate risk and — when risk is high and the org has
	// SPID/CIE credential configurations — return a step-up enriched response
	// without caching it (challenge state changes independently of the token).
	if resp.Active && resp.Sub != "" && resp.OrgID != "" &&
		h.walletStepUp != nil && h.riskScorer != nil {
		if enriched, ok := h.checkWalletStepUp(ctx, orgSlug, resp); ok {
			return c.JSON(http.StatusOK, enriched)
		}
	}

	// Cache: active tokens until expiry (max 30 s); inactive/invalid for 10 s
	ttl := 10 * time.Second
	if resp.Active && resp.Exp > 0 {
		remaining := time.Until(time.Unix(resp.Exp, 0))
		if remaining > 0 {
			if remaining > 30*time.Second {
				remaining = 30 * time.Second
			}
			ttl = remaining
		}
	}
	if b, err := json.Marshal(resp); err == nil {
		h.rdb.SetEx(ctx, cacheKey, b, ttl)
	}

	return c.JSON(http.StatusOK, resp)
}

// checkWalletStepUp evaluates whether the given active-token introspection
// response requires a wallet step-up challenge. It returns (enrichedMap, true)
// when a challenge is needed, or (nil, false) when step-up is not triggered.
//
// Fast path: if there is already a pending challenge for (orgID, userID) in
// Redis we return it immediately without computing a new risk score.
// Slow path: compute the risk score; if ≥ walletStepUpRiskThreshold we create
// a new challenge, fire an SSF assurance-level-change event and return the
// enriched introspect response.
func (h *OIDCHandler) checkWalletStepUp(
	ctx context.Context,
	orgSlug string,
	resp oidc.IntrospectionResponse,
) (map[string]any, bool) {
	orgID, err := uuid.Parse(resp.OrgID)
	if err != nil {
		return nil, false
	}
	userID, err := uuid.Parse(resp.Sub)
	if err != nil {
		return nil, false
	}

	// Fast path: reuse existing pending challenge (avoids a risk score DB query).
	if pending, _ := h.store.GetPendingWalletStepUpChallenge(ctx, resp.OrgID, resp.Sub); pending != nil {
		fields := h.walletStepUp.stepUpFields(orgSlug, pending.ID)
		return h.mergeIntrospectStepUp(resp, fields)
	}

	// Slow path: compute risk score.
	score, err := h.riskScorer.Compute(ctx, orgID, userID)
	if err != nil || score.Score < walletStepUpRiskThreshold {
		return nil, false
	}

	fields := h.walletStepUp.CheckAndCreateStepUp(ctx, orgID, orgSlug, resp.Sub, score.Score, score.Reason)
	if fields == nil {
		// Org has no SPID/CIE configs — step-up not applicable.
		return nil, false
	}

	return h.mergeIntrospectStepUp(resp, fields)
}

// mergeIntrospectStepUp marshals the base introspection response to a map and
// overlays the step-up fields, returning the merged map.
func (h *OIDCHandler) mergeIntrospectStepUp(resp oidc.IntrospectionResponse, fields map[string]any) (map[string]any, bool) {
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, false
	}
	var merged map[string]any
	if err := json.Unmarshal(b, &merged); err != nil {
		return nil, false
	}
	for k, v := range fields {
		merged[k] = v
	}
	return merged, true
}

// ── Revoke (RFC 7009) ─────────────────────────────────────────────────────────

func (h *OIDCHandler) Revoke(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	tc := h.newTC(h.issuerFromRequest(c, orgSlug))

	token := c.FormValue("token")
	hint := c.FormValue("token_type_hint")

	// Capture subject and JTI before revocation for CAE event dispatch.
	// For JWT access tokens we parse them; for opaque refresh tokens we do a
	// DB lookup via hash so we can fire the SSF SET with the correct sub.
	var caeSub, caeJTI string

	if hint == "refresh_token" {
		// Look up the refresh token first so we have the user sub for SSF.
		if rt, err := h.tokens.GetByHash(ctx, oidc.HashToken(token)); err == nil && rt.UserID != nil {
			caeSub = rt.UserID.String()
		}
		_ = oidc.RevokeRefreshTokenByValue(ctx, token, h.tokens)
	} else {
		// For JWTs, parse before revoking to capture sub + jti.
		if tok, jti, _, err := tc.VerifyAccessToken(token); err == nil {
			caeSub = tok.Subject()
			caeJTI = jti
		}
		// Try access token first, then refresh token
		if err := oidc.RevokeAccessToken(ctx, token, tc, h.store); err != nil {
			_ = oidc.RevokeRefreshTokenByValue(ctx, token, h.tokens)
		} else {
			// Invalidate introspection cache entry for the revoked token
			h.rdb.Del(ctx, introspectCacheKey(token))
		}
	}
	org, _ := h.orgs.GetBySlug(ctx, orgSlug)
	if org != nil {
		connector.Dispatch(org.ID.String(), connector.EventTokenRevoked, map[string]any{
			"token_type_hint": hint,
		})
		// CAE (Continuous Access Evaluation): push a CAEP SET to all registered
		// push receivers so resource servers invalidate the token immediately,
		// without waiting for cache TTL or introspection polling intervals.
		if h.ssfDisp != nil && caeSub != "" {
			h.ssfDisp.Dispatch(org.ID, orgSlug, caeSub,
				ssf.EventTokenClaimsChange,
				ssf.TokenRevokedBody(caeJTI))
		}
	}
	return c.NoContent(http.StatusOK)
}

// ── UserInfo (OIDC Core §5.3) ─────────────────────────────────────────────────

func (h *OIDCHandler) UserInfo(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	tc := h.newTC(h.issuerFromRequest(c, orgSlug))
	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.userinfo")
	defer span.End()
	span.SetAttributes(attribute.String("org_slug", orgSlug))

	// FAPI-R-6.2.1-11: the resource endpoint MUST return x-fapi-interaction-id
	// on every response, echoing the client-supplied value when present and
	// generating a fresh UUID otherwise. Set it up-front so all return paths
	// (success and error) carry the header.
	fapiInteractionID := c.Request().Header.Get("X-Fapi-Interaction-Id")
	if fapiInteractionID == "" {
		fapiInteractionID = uuid.NewString()
	}
	c.Response().Header().Set("X-Fapi-Interaction-Id", fapiInteractionID)

	rawToken := extractBearer(c.Request())
	if rawToken == "" && c.Request().Method == http.MethodPost {
		// RFC 6750 §2.2: access_token as form body parameter is only valid for
		// POST requests (methods with defined request-body semantics).
		// MUST NOT be used with GET (which would expose the token in URLs/logs).
		rawToken = c.FormValue("access_token")
	}
	if rawToken == "" {
		span.SetStatus(otelcodes.Error, "missing bearer token")
		return echo.NewHTTPError(http.StatusUnauthorized, "missing bearer token")
	}

	tok, jti, _, err := tc.VerifyAccessToken(rawToken)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "invalid token")
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
	}
	if revoked, _ := h.store.IsRevoked(ctx, jti); revoked {
		return echo.NewHTTPError(http.StatusUnauthorized, "token revoked")
	}

	// DPoP (RFC 9449 §7.3): if the access token is sender-constrained (cnf.jkt),
	// the caller must present a valid DPoP proof that matches the bound key.
	if boundJKT, bound := oidc.JKTFromCNF(tok); bound {
		// RFC 9449 §7.1: multiple DPoP header values MUST be rejected.
		if len(c.Request().Header["Dpop"]) > 1 {
			return echo.NewHTTPError(http.StatusBadRequest, "multiple DPoP headers are not allowed")
		}
		proofJWT := c.Request().Header.Get("DPoP")
		if proofJWT == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "DPoP proof required for sender-constrained token")
		}
		htu := h.htuFromEcho(c)
		dpopKey, dpopProofErr := oidc.ParseDPoPProof(proofJWT, c.Request().Method, htu)
		if dpopProofErr != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid DPoP proof: "+dpopProofErr.Error())
		}
		if dpopKey.JKT != boundJKT {
			return echo.NewHTTPError(http.StatusUnauthorized, "DPoP key mismatch")
		}
		// RFC 9449 §4.2 + §7.2: ath (access token hash) is REQUIRED at resource server.
		if dpopKey.ATH == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "DPoP proof missing required ath claim")
		}
		ath256 := sha256.Sum256([]byte(rawToken))
		if dpopKey.ATH != base64.RawURLEncoding.EncodeToString(ath256[:]) {
			return echo.NewHTTPError(http.StatusUnauthorized, "DPoP proof ath mismatch")
		}
		// FAPI2 Security Profile ID2 §5.4: DPoP proofs MUST use PS256 or ES256.
		if dpopKey.Alg != "PS256" && dpopKey.Alg != "ES256" {
			return echo.NewHTTPError(http.StatusUnauthorized, "DPoP proof must use PS256 or ES256")
		}
		if replayErr := oidc.CheckJTI(ctx, dpopKey.JTI, h.rdb); replayErr != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "DPoP proof jti already used")
		}
	}

	// RFC 8705 §3.1: if the access token carries a certificate thumbprint
	// (cnf.x5t#S256), the caller must present the matching client certificate.
	// Mismatched cert (e.g. Client1 cert + Client2 token) must be rejected.
	if boundThumb, bound := oidc.ThumbprintFromCNF(tok); bound {
		mtls := oidc.CertFromRequest(c.Request())
		if mtls == nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "mTLS certificate required for sender-constrained token")
		}
		if mtls.X5TS256 != boundThumb {
			return echo.NewHTTPError(http.StatusUnauthorized, "mTLS certificate thumbprint mismatch")
		}
	}

	claims, err := oidc.BuildUserInfo(ctx, tok, h.users, h.groups)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "user not found")
	}

	// OIDC Core §5.3.2: if the client registered userinfo_signed_response_alg,
	// return a signed JWT instead of plain JSON.
	clientID := ""
	if auds := tok.Audience(); len(auds) > 0 {
		clientID = auds[0]
	}
	if clientID != "" {
		if cl, clErr := h.clients.GetByClientID(ctx, clientID); clErr == nil &&
			cl.UserInfoSignedResponseAlg != "" && cl.UserInfoSignedResponseAlg != "none" {
			alg := oidc.ResolveIDTokenAlg(cl.UserInfoSignedResponseAlg)
			signed, signErr := tc.SignUserInfoClaims(clientID, claims, alg)
			if signErr != nil {
				return echo.ErrInternalServerError
			}
			return c.Blob(http.StatusOK, "application/jwt", []byte(signed))
		}
	}
	return c.JSON(http.StatusOK, claims)
}

// ── Logout (RP-Initiated) ─────────────────────────────────────────────────────

func (h *OIDCHandler) Logout(c echo.Context) error {
	// Supports both GET (OIDC RP-Initiated Logout 1.0 §2) and POST.
	// Parameters may arrive as query-string (GET) or form body (POST).
	param := func(key string) string {
		if v := c.QueryParam(key); v != "" {
			return v
		}
		return c.FormValue(key)
	}

	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	tc := h.newTC(h.issuerFromRequest(c, orgSlug))

	if hint := param("id_token_hint"); hint != "" {
		_ = oidc.RevokeAccessToken(ctx, hint, tc, h.store)
	}

	// Clear the SSO session and both cookies so subsequent prompt=none
	// requests get login_required and the check_session_iframe detects the change.
	if cookie, err := c.Cookie(ssoCookie); err == nil && cookie.Value != "" {
		_ = h.store.DeleteSSOSession(ctx, cookie.Value)
		c.SetCookie(&http.Cookie{
			Name: ssoCookie, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	c.SetCookie(&http.Cookie{
		Name: bsCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: false, Secure: true, SameSite: http.SameSiteNoneMode,
	})

	postLogout := param("post_logout_redirect_uri")
	if postLogout != "" {
		// Validate against registered client redirect URIs to prevent open redirect.
		// RFC 8414 §3 allows post_logout_redirect_uri only if the client registered it.
		// As a safe fallback we verify the URI belongs to a known client in this org.
		orgID, err := h.orgs.GetIDBySlug(ctx, orgSlug)
		if err == nil {
			if allowed, _ := h.clients.IsAllowedPostLogoutURI(ctx, orgID, postLogout); allowed {
				state := param("state")
				if state != "" {
					postLogout += "?state=" + url.QueryEscape(state)
				}
				return c.Redirect(http.StatusFound, postLogout)
			}
		}
		// URI not registered — silently ignore and return JSON response.
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "logged out"})
}

// ── Check Session iframe (OIDC Session Management 1.0 §3.3) ──────────────────

// CheckSession serves the check_session_iframe HTML page.
// The RP loads this page in a hidden iframe and periodically posts messages to
// detect whether the OP session has changed (e.g., the user logged out in another tab).
func (h *OIDCHandler) CheckSession(c echo.Context) error {
	// Must not be cached — session state can change at any time.
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return checkSessionTmpl.Execute(c.Response().Writer, nil)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// authenticateClient verifies client credentials from HTTP Basic Auth, POST params,
// a private_key_jwt client assertion (RFC 7523), a mutual-TLS client
// certificate (RFC 8705 §2 — tls_client_auth), or an attestation-based
// client assertion (draft-ietf-oauth-attestation-based-client-auth).
// Returns (clientID, clientSecret, error).
func (h *OIDCHandler) authenticateClient(c echo.Context) (string, string, string, error) {
	switch c.FormValue("client_assertion_type") {
	// private_key_jwt: client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
	case "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
		clientID, err := h.authenticateClientByAssertion(c)
		return clientID, "", "", err
	// attest_jwt_client_auth: client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation
	case "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation":
		clientID, jkt, err := h.authenticateClientByAttestationAssertion(c)
		return clientID, "", jkt, err
	}

	// Header-based attestation transport (draft-ietf-oauth-attestation-based-client-auth §8):
	//   OAuth-Client-Attestation: <attest_jwt>
	//   OAuth-Client-Attestation-PoP: <pop_jwt>
	// The OIDF conformance suite uses headers rather than form parameters.
	if c.Request().Header.Get("OAuth-Client-Attestation") != "" {
		clientID, jkt, err := h.authenticateClientByAttestationAssertion(c)
		return clientID, "", jkt, err
	}

	// tls_client_auth (RFC 8705 §2): client sends client_id in the request body
	// and authenticates by presenting a TLS client certificate. The server verifies
	// that the certificate's Subject DN or SAN matches what the client registered.
	if r := c.Request(); r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientID := c.FormValue("client_id")
		if clientID != "" {
			client, err := h.clients.GetByClientID(r.Context(), clientID)
			if err == nil && client.IsActive && client.TokenEndpointAuthMethod == "tls_client_auth" {
				cert := r.TLS.PeerCertificates[0]
				if authenticateByClientCert(cert, client) {
					return clientID, "", "", nil
				}
				return "", "", "", echo.NewHTTPError(http.StatusUnauthorized, "tls_client_auth: certificate subject mismatch")
			}
		}
	}

	// Try HTTP Basic first (client_secret_basic)
	clientID, clientSecret, ok := c.Request().BasicAuth()
	if !ok {
		clientID = c.FormValue("client_id")
		clientSecret = c.FormValue("client_secret")
	}
	if clientID == "" {
		return "", "", "", echo.NewHTTPError(http.StatusUnauthorized, "client_id required")
	}

	client, err := h.clients.GetByClientID(c.Request().Context(), clientID)
	if err != nil || !client.IsActive {
		return "", "", "", echo.NewHTTPError(http.StatusUnauthorized, "unknown client")
	}

	// Clients that require stronger authentication must not authenticate via
	// this fallthrough path (no assertion / no cert in the request).
	switch client.TokenEndpointAuthMethod {
	case "private_key_jwt":
		return "", "", "", echo.NewHTTPError(http.StatusUnauthorized, "client_assertion required")
	case "attest_jwt_client_auth":
		return "", "", "", echo.NewHTTPError(http.StatusUnauthorized, "attestation client_assertion required")
	case "tls_client_auth":
		return "", "", "", echo.NewHTTPError(http.StatusUnauthorized, "mTLS certificate required")
	}

	// Public clients have no secret
	if client.ClientSecretHash == nil {
		return clientID, "", "", nil
	}
	if !h.clients.CheckSecret(*client.ClientSecretHash, clientSecret) {
		return "", "", "", echo.NewHTTPError(http.StatusUnauthorized, "invalid client secret")
	}
	return clientID, clientSecret, "", nil
}

// authenticateByClientCert validates a TLS client certificate against a client's
// registered mTLS identity (RFC 8705 §2.3).
// Returns true when the certificate's Subject DN matches TLSClientAuthSubjectDN,
// or the certificate's DNS SAN matches TLSClientAuthSANDNS.
func authenticateByClientCert(cert *x509.Certificate, client *models.OIDCClient) bool {
	if client.TLSClientAuthSubjectDN != nil && *client.TLSClientAuthSubjectDN != "" {
		return cert.Subject.String() == *client.TLSClientAuthSubjectDN
	}
	if client.TLSClientAuthSANDNS != nil && *client.TLSClientAuthSANDNS != "" {
		for _, dns := range cert.DNSNames {
			if dns == *client.TLSClientAuthSANDNS {
				return true
			}
		}
	}
	return false
}

// authenticateClientByAssertion validates a private_key_jwt client assertion
// per RFC 7523 §2.2 and returns the authenticated client_id.
func (h *OIDCHandler) authenticateClientByAssertion(c echo.Context) (string, error) {
	ctx := c.Request().Context()

	assertion := c.FormValue("client_assertion")
	if assertion == "" {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "client_assertion required")
	}

	// Parse unverified to extract client_id so we can do the DB lookup.
	// Full crypto validation happens in oidc.ValidateClientAssertionJWT below.
	tok, err := jwtPkg.Parse([]byte(assertion), jwtPkg.WithVerify(false), jwtPkg.WithValidate(false))
	if err != nil {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "invalid client_assertion")
	}
	clientID := tok.Issuer()
	if clientID == "" {
		clientID = tok.Subject()
	}
	if clientID == "" {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "client_assertion missing iss/sub")
	}

	client, err := h.clients.GetByClientID(ctx, clientID)
	if err != nil || !client.IsActive {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "unknown client")
	}
	if client.TokenEndpointAuthMethod != "private_key_jwt" {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "client not configured for private_key_jwt")
	}

	// Resolve the client's public key set: inline JWKS takes precedence over jwks_uri.
	keySet, err := h.resolveClientJWKS(ctx, client)
	if err != nil {
		return "", err
	}

	// Delegate full JWT validation (signature, exp, aud, JTI replay) to the
	// oidc package function so the logic is independently unit-testable.
	orgSlug := c.Param("org_slug")
	issuer := h.issuerFromRequest(c, orgSlug)
	jtiCache := &redisJTICache{rdb: h.rdb}
	// extraAudiences accepts /par (PAR endpoint) and /bc-authorize (CIBA
	// backchannel authentication endpoint) in addition to the token endpoint
	// and issuer, since this function authenticates clients at all three.
	if _, err = oidc.ValidateClientAssertionJWT(ctx, assertion, keySet, issuer+"/token", issuer, jtiCache, issuer+"/par", issuer+"/bc-authorize"); err != nil {
		var te *oidc.TokenError
		if errors.As(err, &te) {
			return "", echo.NewHTTPError(http.StatusUnauthorized, te.Description)
		}
		return "", echo.NewHTTPError(http.StatusUnauthorized, "client_assertion invalid")
	}

	return clientID, nil
}

// resolveClientJWKS returns the key set for clientID from the DB (inline JWKS
// or fetched from jwks_uri).  Used by both private_key_jwt and attest_jwt_client_auth
// authentication paths.
func (h *OIDCHandler) resolveClientJWKS(ctx context.Context, client *models.OIDCClient) (jwkPkg.Set, error) {
	var (
		keySet jwkPkg.Set
		err    error
	)
	switch {
	case client.JWKS != nil && len(*client.JWKS) > 2: // "{}" is len 2
		keySet, err = jwkPkg.Parse(*client.JWKS)
		if err != nil {
			return nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid client JWKS")
		}
	case client.JWKSUri != nil && *client.JWKSUri != "":
		fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(fetchCtx, http.MethodGet, *client.JWKSUri, nil)
		resp, httpErr := http.DefaultClient.Do(req)
		if httpErr != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			return nil, echo.NewHTTPError(http.StatusUnauthorized, "cannot fetch client jwks_uri")
		}
		defer resp.Body.Close()
		keySet, err = jwkPkg.ParseReader(resp.Body)
		if err != nil {
			return nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid JWKS at jwks_uri")
		}
	default:
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "client has no JWKS configured")
	}
	return keySet, nil
}

// authenticateClientByAttestationAssertion validates an OAuth 2.0 Attestation-Based
// Client Authentication assertion per
// draft-ietf-oauth-attestation-based-client-auth.
//
// client_assertion_type must be
//   urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation
//
// client_assertion must be "<attest_jwt>~<pop_jwt>" (tilde-separated).
// The attestation JWT is verified against the client's registered JWKS
// (self-attestation model); the PoP JWT is verified against cnf.jwk from
// the attestation JWT.
func (h *OIDCHandler) authenticateClientByAttestationAssertion(c echo.Context) (string, string, error) {
	ctx := c.Request().Context()

	// Accept both form-based (client_assertion=<attest_jwt>~<pop_jwt>) and
	// header-based (OAuth-Client-Attestation / OAuth-Client-Attestation-PoP)
	// transports. The conformance suite uses headers; form params are the
	// fallback for interop with non-header-aware clients.
	clientAssertion := c.FormValue("client_assertion")
	if clientAssertion == "" {
		attestHdr := c.Request().Header.Get("OAuth-Client-Attestation")
		popHdr := c.Request().Header.Get("OAuth-Client-Attestation-PoP")
		if attestHdr != "" && popHdr != "" {
			clientAssertion = attestHdr + "~" + popHdr
		}
	}
	if clientAssertion == "" {
		return "", "", echo.NewHTTPError(http.StatusUnauthorized, "client_assertion required")
	}

	// Parse the attestation JWT unverified to extract sub (= client_id) so
	// we can do the DB lookup before full crypto validation.
	parts := strings.SplitN(clientAssertion, "~", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", echo.NewHTTPError(http.StatusUnauthorized, "client_assertion must be <attest_jwt>~<pop_jwt>")
	}
	unverifiedAttest, err := jwtPkg.Parse([]byte(parts[0]),
		jwtPkg.WithVerify(false),
		jwtPkg.WithValidate(false),
	)
	if err != nil {
		return "", "", echo.NewHTTPError(http.StatusUnauthorized, "invalid attestation JWT")
	}
	clientID := unverifiedAttest.Subject()
	if clientID == "" {
		return "", "", echo.NewHTTPError(http.StatusUnauthorized, "attestation JWT missing sub (client_id)")
	}

	client, err := h.clients.GetByClientID(ctx, clientID)
	if err != nil || !client.IsActive {
		return "", "", echo.NewHTTPError(http.StatusUnauthorized, "unknown client")
	}
	if client.TokenEndpointAuthMethod != "attest_jwt_client_auth" {
		return "", "", echo.NewHTTPError(http.StatusUnauthorized, "client not configured for attest_jwt_client_auth")
	}

	// Resolve the client's public key set (used to verify the attestation JWT).
	keySet, err := h.resolveClientJWKS(ctx, client)
	if err != nil {
		return "", "", err
	}

	orgSlug := c.Param("org_slug")
	issuer := h.issuerFromRequest(c, orgSlug)
	jtiCache := &redisJTICache{rdb: h.rdb}
	instanceJKT, valErr := oidc.ValidateAttestationAssertionJWT(
		ctx,
		clientAssertion,
		keySet,
		issuer+"/token",
		issuer,
		clientID,
		jtiCache,
		issuer+"/par",
		issuer+"/bc-authorize",
	)
	if valErr != nil {
		var te *oidc.TokenError
		if errors.As(valErr, &te) {
			return "", "", echo.NewHTTPError(http.StatusUnauthorized, te.Description)
		}
		return "", "", echo.NewHTTPError(http.StatusUnauthorized, "client_assertion invalid")
	}

	return clientID, instanceJKT, nil
}

// redisJTICache adapts redis.UniversalClient to the oidc.JTICache interface.
type redisJTICache struct {
	rdb redis.UniversalClient
}

func (r *redisJTICache) CheckAndSet(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	set, err := r.rdb.SetNX(ctx, key, 1, ttl).Result()
	if err != nil {
		return false, err
	}
	return !set, nil // SetNX returns true if NEW; we return true if ALREADY USED
}

// hybridIDToken builds the authorization-response ID token for hybrid flows
// (response_type=code id_token). The token contains only the claims required by
// OIDC Core §3.3.2.11: sub, iss, aud, iat, exp, nonce, auth_time, c_hash.
// Returns an empty string on any error (the code redirect still succeeds, but
// without the id_token — not ideal; callers should log the error).
func (h *OIDCHandler) hybridIDToken(c echo.Context, code, nonce, orgSlug, clientID, userID string, authTime int64) string {
	cHash := oidc.ComputeAtHash(code)
	tc := h.newTC(h.issuerFromRequest(c, orgSlug))
	// Honour per-client id_token_signed_response_alg if registered (fail-open: default PS256).
	idTokenAlg := ""
	if cl, err := h.clients.GetByClientID(c.Request().Context(), clientID); err == nil {
		idTokenAlg = cl.IDTokenSignedResponseAlg
	}
	idTok, err := tc.IssueIDToken(clientID, nonce, oidc.UserClaims{
		UserID:   userID,
		AuthTime: authTime,
		CHash:    cHash,
	}, oidc.ResolveIDTokenAlg(idTokenAlg))
	if err != nil {
		c.Logger().Errorf("hybridIDToken: %v", err)
		return ""
	}
	return idTok
}

type loginData struct {
	OrgName string
	OrgSlug string
	// LogoURL is the URL of the org's logo; empty string if none.
	LogoURL string
	// ClientName is the display name of the OIDC client requesting authentication.
	ClientName string
	// ActionURL is the form POST target, e.g. "/acme/authorize".
	ActionURL        string
	LoginSessionID   string
	Email            string
	Error            string
	CaptchaEnabled   bool
	CaptchaSiteKey   string
	CaptchaScriptURL string
	Nonce            string // CSP nonce for inline/external scripts
	PasskeyEnabled   bool
	// EmailOTPEnabled shows the "Sign in with email code" link.
	EmailOTPEnabled bool
	// CancelURL is the URL the "Cancel" button links to.
	// It redirects back to the client redirect_uri with error=access_denied.
	// Empty when there is no cancellable OIDC session (e.g. account portal login).
	CancelURL string
	// IDPProviders is the list of active external identity providers for this org.
	// Promoted ones (IsPromoted=true) are rendered as full-width primary buttons
	// above the email/password form; others appear as secondary links below.
	IDPProviders []*idpButton
	// RememberDeviceDays is the number of days to trust this device after a
	// successful MFA step-up. >0 shows the "Remember this device" checkbox on
	// the MFA challenge form; 0 hides it (device trust not configured / disabled).
	RememberDeviceDays int
}

// idpButton carries the minimum IDP info needed to render a login button.
type idpButton struct {
	ID         string
	Name       string
	IsPromoted bool
	StartURL   string // e.g. "/acme/idp/uuid"
}

func renderLogin(c echo.Context, orgName string, logoURL *string, customHTML *string, sessID, orgSlug, email, errMsg string, passkeyEnabled bool) error {
	return renderLoginWithCaptcha(c, orgName, logoURL, customHTML, sessID, orgSlug, email, errMsg, false, "", "", passkeyEnabled, "", "", nil)
}

func renderLoginWithCaptcha(c echo.Context, orgName string, logoURL *string, customHTML *string, sessID, orgSlug, email, errMsg string, captchaEnabled bool, captchaSiteKey, captchaScriptURL string, passkeyEnabled bool, clientName, cancelURL string, idps []*idpButton) error {
	var logoStr string
	if logoURL != nil {
		logoStr = *logoURL
	}
	data := loginData{
		OrgName:          orgName,
		OrgSlug:          orgSlug,
		LogoURL:          logoStr,
		ClientName:       clientName,
		ActionURL:        "/" + orgSlug + "/authorize",
		LoginSessionID:   sessID,
		Email:            email,
		Error:            errMsg,
		CaptchaEnabled:   captchaEnabled,
		CaptchaSiteKey:   captchaSiteKey,
		CaptchaScriptURL: captchaScriptURL,
		Nonce:            middleware.GetCSPNonce(c),
		PasskeyEnabled:   passkeyEnabled,
		EmailOTPEnabled:  true,
		CancelURL:        cancelURL,
		IDPProviders:     idps,
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(http.StatusOK)

	// If the org has a custom login template, parse and execute it.
	// Falls back to the built-in template on any parse/execute error (fail-open,
	// so a typo in the custom template never hard-locks an org out).
	if customHTML != nil && *customHTML != "" {
		tmpl, err := template.New("custom_login").Parse(*customHTML)
		if err != nil {
			c.Logger().Errorf("custom login template parse error: org=%s err=%v — falling back to built-in", orgSlug, err)
		} else {
			if execErr := tmpl.Execute(c.Response().Writer, data); execErr != nil {
				c.Logger().Errorf("custom login template execute error: org=%s err=%v", orgSlug, execErr)
			}
			return nil
		}
	}

	return loginTmpl.Execute(c.Response().Writer, data)
}

// orgDeviceTrustDays returns the number of days to trust a device after a
// successful MFA challenge. It reads org.Settings["device_trust_days"] (int,
// default 30). Returns 0 when org is nil (caller should hide the checkbox).
func orgDeviceTrustDays(org *models.Organization) int {
	const defaultDays = 30
	if org == nil || org.Settings == nil {
		return defaultDays
	}
	switch v := org.Settings["device_trust_days"].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
		}
	}
	return defaultDays
}

// deviceTrustDaysForOrg returns the configured device-trust window for the org,
// or 0 when device trust is globally disabled (no DeviceTrustSecret in config).
// A zero return hides the "Remember this device" checkbox on the MFA form.
func (h *OIDCHandler) deviceTrustDaysForOrg(org *models.Organization) int {
	if h.cfg.Auth.DeviceTrustSecret == "" {
		return 0
	}
	return orgDeviceTrustDays(org)
}

func renderMFAChallenge(c echo.Context, orgName string, logoURL *string, sessID, errMsg string, days int) error {
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(http.StatusOK)
	// Extract org_slug from the route param (set on the /:org_slug group)
	orgSlug := c.Param("org_slug")
	var logoStr string
	if logoURL != nil {
		logoStr = *logoURL
	}
	return mfaChallengeTmpl.Execute(c.Response().Writer, loginData{
		OrgName:            orgName,
		LogoURL:            logoStr,
		LoginSessionID:     sessID,
		Error:              errMsg,
		OrgSlug:            orgSlug,
		ActionURL:          "/" + orgSlug + "/authorize",
		Nonce:              middleware.GetCSPNonce(c),
		RememberDeviceDays: days,
	})
}

// MFAChallengeSubmit handles TOTP code submission after password has been verified.
// POST /:org_slug/mfa-challenge
func (h *OIDCHandler) MFAChallengeSubmit(c echo.Context) error {
	ctx := c.Request().Context()

	sessID := c.FormValue("login_session_id")
	totpCode := c.FormValue("totp_code")
	rememberDevice := c.FormValue("remember_device") == "1"
	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess == nil || !loginSess.MFAPending {
		return echo.NewHTTPError(http.StatusBadRequest, "MFA session expired — please sign in again")
	}

	org, _ := h.orgs.GetBySlug(ctx, loginSess.OrgSlug)
	orgName := loginSess.OrgSlug
	var logoURL *string
	if org != nil {
		orgName = org.Name
		logoURL = org.LogoURL
	}

	renderErr := func(msg string) error {
		return renderMFAChallenge(c, orgName, logoURL, sessID, msg, h.deviceTrustDaysForOrg(org))
	}

	userID, err := uuid.Parse(loginSess.UserID)
	if err != nil {
		return renderErr("Invalid session. Please sign in again.")
	}

	// Brute-force throttle: a 6-digit TOTP/backup code is guessable, so cap the
	// number of attempts at the second factor with the same adaptive lockout
	// guard used for passwords (keyed on org+user). Without this an attacker who
	// has the password could brute-force the MFA challenge — a full MFA bypass.
	if h.guard != nil {
		if d, locked := h.guard.IsLocked(ctx, loginSess.OrgID, loginSess.UserID); locked {
			return renderErr("Too many incorrect codes. Try again in " + lockout.FormatDuration(d) + ".")
		}
	}

	// Load all confirmed TOTP credentials for the user.
	creds, err := h.mfa.ListByUser(ctx, userID)
	if err != nil {
		return renderErr("An error occurred. Please try again.")
	}

	verified := false
	for _, cr := range creds {
		if cr.Type != "totp" {
			continue
		}
		// Fetch full data (includes secret).
		full, err := h.mfa.GetWithData(ctx, cr.ID)
		if err != nil {
			continue
		}
		if confirmed, _ := full.Data["confirmed"].(bool); !confirmed {
			continue
		}
		secret, _ := full.Data["secret"].(string)
		if totp.Validate(totpCode, secret) {
			verified = true
			break
		}
	}

	// Fall back to backup code if TOTP check failed.
	if !verified && totpCode != "" {
		if ok, _ := h.mfa.ConsumeBackupCode(ctx, userID, totpCode); ok {
			verified = true
		}
	}

	if !verified {
		if h.guard != nil {
			h.guard.RecordFailure(ctx, loginSess.OrgID, loginSess.UserID, 0)
		}
		return renderErr("Invalid authenticator code. Please try again.")
	}
	if h.guard != nil {
		h.guard.ClearFailures(ctx, loginSess.OrgID, loginSess.UserID)
	}

	// MFA passed — issue authorization code.
	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		return renderErr("An error occurred. Please try again.")
	}

	// max_age enforcement: MFA adds some time since password entry — re-check.
	if loginSess.MaxAge > 0 && loginSess.AuthTime > 0 {
		if age := time.Now().Unix() - loginSess.AuthTime; age > int64(loginSess.MaxAge) {
			_ = h.store.DeleteLoginSession(ctx, sessID)
			return h.redirectWithError(c, &oidc.AuthorizeError{
				Code:         "login_required",
				Description:  "max_age exceeded — re-authentication required",
				RedirectURI:  loginSess.RedirectURI,
				State:        loginSess.State,
				ResponseMode: loginSess.ResponseMode,
				ClientID:     loginSess.ClientID,
				OrgSlug:      loginSess.OrgSlug,
			})
		}
	}

	code, err := oidc.IssueAuthorizationCode(ctx, &oidc.AuthorizeRequest{
		OrgSlug:              loginSess.OrgSlug,
		OrgID:                loginSess.OrgID,
		ClientID:             loginSess.ClientID,
		RedirectURI:          loginSess.RedirectURI,
		Scope:                loginSess.Scope,
		State:                loginSess.State,
		Nonce:                loginSess.Nonce,
		PKCEChallenge:        loginSess.PKCEChallenge,
		PKCEMethod:           loginSess.PKCEMethod,
		AuthTime:             loginSess.AuthTime,
		AuthorizationDetails: loginSess.AuthorizationDetails,
		AcrValues:            loginSess.AcrValues,
		ClaimsParam:          loginSess.ClaimsParam,
		DpopJKT:              loginSess.DpopJKT,
	}, user.ID.String(), h.store, h.codes)
	if err != nil {
		return renderErr("An error occurred. Please try again.")
	}

	h.recordAuthEvent(c, loginSess.OrgID, &user.ID, user.Email, "mfa.success", "")
	_ = h.store.DeleteLoginSession(ctx, sessID)

	// ── Device trust: register this device as trusted after successful MFA ────
	// Only when the user ticked "Remember this device" and device trust is enabled.
	if rememberDevice {
		if secret := h.cfg.Auth.DeviceTrustSecret; secret != "" {
			if orgIDParsed, err := uuid.Parse(loginSess.OrgID); err == nil {
				trustDays := orgDeviceTrustDays(org)
				trustTTL := time.Duration(trustDays) * 24 * time.Hour
				deviceToken, cookieErr := c.Cookie(repository.DeviceTrustCookieName)
				var token string
				if cookieErr != nil || deviceToken.Value == "" {
					// No cookie yet — generate one and set it.
					raw := make([]byte, 24)
					if _, rerr := rand.Read(raw); rerr == nil {
						token = base64URLEncode(raw)
					}
				} else {
					token = deviceToken.Value
				}
				if token != "" {
					fp := repository.FingerprintHash(secret, token, user.ID)
					ua := c.Request().UserAgent()
					if len(ua) > 256 {
						ua = ua[:256]
					}
					_ = h.trustedDev.Trust(ctx, orgIDParsed, user.ID, fp, ua, ua, c.RealIP())
					// (Re-)set the device cookie with the org-configured TTL.
					dtCookie := new(http.Cookie)
					dtCookie.Name = repository.DeviceTrustCookieName
					dtCookie.Value = token
					dtCookie.Path = "/"
					dtCookie.HttpOnly = true
					dtCookie.SameSite = http.SameSiteLaxMode
					dtCookie.MaxAge = int(trustTTL.Seconds())
					c.SetCookie(dtCookie)
				}
			}
		}
	}

	connector.Dispatch(loginSess.OrgID, connector.EventMFASuccess, map[string]any{
		"user_id": user.ID.String(), "email": user.Email,
	})
	connector.Dispatch(loginSess.OrgID, connector.EventUserLogin, map[string]any{
		"user_id": user.ID.String(), "email": user.Email, "client_id": loginSess.ClientID, "mfa": true,
	})

	var hybridTok string
	if strings.Contains(loginSess.ResponseType, "id_token") {
		hybridTok = h.hybridIDToken(c, code, loginSess.Nonce, loginSess.OrgSlug, loginSess.ClientID, user.ID.String(), loginSess.AuthTime)
	}
	// Session state: use SSO cookie if available (set just above by setSSOCookie).
	var mfaSessState string
	if ck, err := c.Cookie(bsCookie); err == nil && ck.Value != "" {
		mfaSessState = oidc.ComputeSessionState(loginSess.ClientID, oidc.RPOriginFromRedirectURI(loginSess.RedirectURI), ck.Value)
	}
	return h.redirectWithCode(c, loginSess.RedirectURI, code, loginSess.State, loginSess.OrgSlug, loginSess.ClientID, loginSess.ResponseMode, hybridTok, mfaSessState)
}

// ── Authorize resume (after external step: IdP SSO, email verify, etc.) ───────

// AuthorizeResume resumes the code-issuance flow after an external step
// (IdP SSO callback, email OTP, password update) has completed authentication.
// GET /:org_slug/authorize/resume?login_session_id=...
func (h *OIDCHandler) AuthorizeResume(c echo.Context) error {
	ctx := c.Request().Context()
	sessID := c.QueryParam("login_session_id")
	if sessID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}

	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please start over")
	}
	if loginSess.UserID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "authentication not completed")
	}
	if loginSess.MFAPending {
		org, _ := h.orgs.GetBySlug(ctx, loginSess.OrgSlug)
		orgName, logoURL := loginSess.OrgSlug, (*string)(nil)
		if org != nil {
			orgName = org.Name
			logoURL = org.LogoURL
		}
		return renderMFAChallenge(c, orgName, logoURL, sessID, "", h.deviceTrustDaysForOrg(org))
	}

	// max_age enforcement (OIDC Core §3.1.2.1): if the stored auth_time is older
	// than max_age seconds the session is too old — force re-authentication.
	if loginSess.MaxAge > 0 && loginSess.AuthTime > 0 {
		age := time.Now().Unix() - loginSess.AuthTime
		if age > int64(loginSess.MaxAge) {
			_ = h.store.DeleteLoginSession(ctx, sessID)
			return h.redirectWithError(c, &oidc.AuthorizeError{
				Code:         "login_required",
				Description:  "max_age exceeded — re-authentication required",
				RedirectURI:  loginSess.RedirectURI,
				State:        loginSess.State,
				ResponseMode: loginSess.ResponseMode,
				ClientID:     loginSess.ClientID,
				OrgSlug:      loginSess.OrgSlug,
			})
		}
	}

	code, err := oidc.IssueAuthorizationCode(ctx, &oidc.AuthorizeRequest{
		OrgSlug:              loginSess.OrgSlug,
		OrgID:                loginSess.OrgID,
		ClientID:             loginSess.ClientID,
		RedirectURI:          loginSess.RedirectURI,
		Scope:                loginSess.Scope,
		State:                loginSess.State,
		Nonce:                loginSess.Nonce,
		PKCEChallenge:        loginSess.PKCEChallenge,
		PKCEMethod:           loginSess.PKCEMethod,
		AuthTime:             loginSess.AuthTime,
		AuthorizationDetails: loginSess.AuthorizationDetails,
		AcrValues:            loginSess.AcrValues,
		ClaimsParam:          loginSess.ClaimsParam,
		ExtraClaims:          loginSess.ExtraClaims,
		DpopJKT:              loginSess.DpopJKT,
	}, loginSess.UserID, h.store, h.codes)
	if err != nil {
		return echo.ErrInternalServerError
	}

	h.recordAuthEvent(c, loginSess.OrgID, nil, "", "login.success.idp", "")
	_ = h.store.DeleteLoginSession(ctx, sessID)

	var hybridTok string
	if strings.Contains(loginSess.ResponseType, "id_token") {
		hybridTok = h.hybridIDToken(c, code, loginSess.Nonce, loginSess.OrgSlug, loginSess.ClientID, loginSess.UserID, loginSess.AuthTime)
	}
	// Session state: use browser-state cookie set during the original login.
	var idpSessState string
	if ck, err := c.Cookie(bsCookie); err == nil && ck.Value != "" {
		idpSessState = oidc.ComputeSessionState(loginSess.ClientID, oidc.RPOriginFromRedirectURI(loginSess.RedirectURI), ck.Value)
	}
	return h.redirectWithCode(c, loginSess.RedirectURI, code, loginSess.State, loginSess.OrgSlug, loginSess.ClientID, loginSess.ResponseMode, hybridTok, idpSessState)
}

// ── OID4VP in-login challenge flow ────────────────────────────────────────────
//
// When the login flow engine's oid4vp_challenge step fires, the login handler
// redirects the user here.  The page shows a QR code for the wallet app and
// polls for completion.  Once the wallet has presented the credential, the
// browser is redirected to OID4VPResume which issues the authorization code.

// OID4VPChallengePage handles GET /:org_slug/authorize/oid4vp-challenge
//
// Renders an HTML page that:
//   - Shows the wallet deep-link as a scannable QR code.
//   - Polls GET /:org_slug/wallet/request/:req_id/status every 2 s.
//   - Auto-redirects to the resume endpoint when status = "verified".
func (h *OIDCHandler) OID4VPChallengePage(c echo.Context) error {
	sessID := c.QueryParam("login_session_id")
	requestID := c.QueryParam("request_id")
	if sessID == "" || requestID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id and request_id required")
	}

	loginSess, err := h.store.GetLoginSession(c.Request().Context(), sessID)
	if err != nil || loginSess == nil || !loginSess.OID4VPPending {
		return echo.NewHTTPError(http.StatusBadRequest, "session expired — please sign in again")
	}
	if loginSess.OID4VPRequestID != requestID {
		return echo.NewHTTPError(http.StatusBadRequest, "request ID mismatch")
	}

	orgSlug := c.Param("org_slug")
	baseURL := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug)

	// The wallet deep-link URI that encodes the OID4VP request_uri.
	requestURI := baseURL + "/wallet/request/" + requestID
	walletDeepLink := "openid4vp://?request_uri=" + url.QueryEscape(requestURI) + "&client_id=" + url.QueryEscape(baseURL)
	qrImgURL := "/" + orgSlug + "/wallet/request/" + requestID + "/qr"
	statusURL := "/" + orgSlug + "/wallet/request/" + requestID + "/status"
	resumeURL := "/" + orgSlug + "/authorize/oid4vp-resume?login_session_id=" + sessID

	msg := loginSess.OID4VPMessage
	if msg == "" {
		msg = "Please present your verifiable credential to continue."
	}

	nonce := middleware.GetCSPNonce(c)
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().WriteHeader(http.StatusOK)
	return oid4vpChallengePageTmpl.Execute(c.Response().Writer, map[string]any{
		"OrgSlug":    orgSlug,
		"Message":    msg,
		"WalletLink": walletDeepLink,
		"QRImgURL":   qrImgURL,
		"StatusURL":  statusURL,
		"ResumeURL":  resumeURL,
		"Nonce":      nonce,
	})
}

// OID4VPResume handles GET /:org_slug/authorize/oid4vp-resume
//
// Called by the challenge page JS once the wallet has submitted the VP token
// and the presentation session status is "verified".  The handler:
//  1. Loads the login session and verifies OID4VPPending.
//  2. Loads the presentation session and confirms status = "verified".
//  3. Merges verified credential claims into the token extra_claims.
//  4. Issues the OIDC authorization code and redirects to the client.
func (h *OIDCHandler) OID4VPResume(c echo.Context) error {
	ctx := c.Request().Context()
	sessID := c.QueryParam("login_session_id")
	if sessID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}

	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "session expired — please sign in again")
	}
	if !loginSess.OID4VPPending || loginSess.OID4VPRequestID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "no OID4VP challenge in progress")
	}

	// Fetch the presentation session to get the verified credential claims.
	if h.oid4vpH == nil {
		return echo.ErrInternalServerError
	}
	vpSess, err := h.oid4vpH.repo.GetPresentationSession(ctx, loginSess.OID4VPRequestID)
	if err != nil || vpSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "presentation session not found — please try again")
	}
	if vpSess.Status != "verified" {
		// Challenge page polled too eagerly or the wallet didn't complete.
		return echo.NewHTTPError(http.StatusBadRequest, "credential not yet verified — please wait for the wallet to complete")
	}

	// Merge verified credential claims into the login session's extra_claims so
	// they appear in the issued tokens. Existing extra_claims (from flow steps
	// that ran before oid4vp_challenge) are preserved.
	if loginSess.ExtraClaims == nil {
		loginSess.ExtraClaims = map[string]any{}
	}
	for k, v := range vpSess.VPClaims {
		loginSess.ExtraClaims[k] = v
	}
	// Flag that the OID4VP challenge has been satisfied.
	loginSess.ExtraClaims["acr_oid4vp"] = "verified"
	loginSess.OID4VPPending = false

	code, err := oidc.IssueAuthorizationCode(ctx, &oidc.AuthorizeRequest{
		OrgSlug:              loginSess.OrgSlug,
		OrgID:                loginSess.OrgID,
		ClientID:             loginSess.ClientID,
		RedirectURI:          loginSess.RedirectURI,
		Scope:                loginSess.Scope,
		State:                loginSess.State,
		Nonce:                loginSess.Nonce,
		PKCEChallenge:        loginSess.PKCEChallenge,
		PKCEMethod:           loginSess.PKCEMethod,
		AuthTime:             loginSess.AuthTime,
		AuthorizationDetails: loginSess.AuthorizationDetails,
		AcrValues:            loginSess.AcrValues,
		ClaimsParam:          loginSess.ClaimsParam,
		ExtraClaims:          loginSess.ExtraClaims,
		DpopJKT:              loginSess.DpopJKT,
	}, loginSess.UserID, h.store, h.codes)
	if err != nil {
		return echo.ErrInternalServerError
	}

	h.recordAuthEvent(c, loginSess.OrgID, nil, "", "login.success.oid4vp_challenge", "")
	_ = h.store.DeleteLoginSession(ctx, sessID)

	var hybridTok string
	if strings.Contains(loginSess.ResponseType, "id_token") {
		hybridTok = h.hybridIDToken(c, code, loginSess.Nonce, loginSess.OrgSlug, loginSess.ClientID, loginSess.UserID, loginSess.AuthTime)
	}
	var sessState string
	if ck, err := c.Cookie(bsCookie); err == nil && ck.Value != "" {
		sessState = oidc.ComputeSessionState(loginSess.ClientID, oidc.RPOriginFromRedirectURI(loginSess.RedirectURI), ck.Value)
	}
	return h.redirectWithCode(c, loginSess.RedirectURI, code, loginSess.State, loginSess.OrgSlug, loginSess.ClientID, loginSess.ResponseMode, hybridTok, sessState)
}

// oid4vpChallengePageTmpl is the browser-side challenge page rendered during an
// oid4vp_challenge login flow step.  JS polls the status endpoint every 2 s and
// auto-redirects once the wallet has submitted a valid vp_token.
var oid4vpChallengePageTmpl = template.Must(template.New("oid4vp_challenge").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Credential verification required</title>
<style nonce="{{.Nonce}}">
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f5f7;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:2.5rem 2rem;max-width:420px;width:100%;text-align:center}
h1{font-size:1.3rem;font-weight:600;color:#1d1d1f;margin-bottom:.5rem}
p{font-size:.95rem;color:#6e6e73;margin-bottom:1.5rem;line-height:1.5}
.qr{display:block;margin:0 auto 1.5rem;border-radius:8px;border:1px solid #e0e0e0}
.btn{display:inline-block;padding:.75rem 1.5rem;background:#0071e3;color:#fff;border-radius:980px;text-decoration:none;font-size:.95rem;font-weight:500;margin-bottom:1rem;transition:background .2s}
.btn:hover{background:#0077ed}
.status{font-size:.85rem;color:#8e8e93;margin-top:1rem}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #c7c7cc;border-top-color:#0071e3;border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:4px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
  <h1>Credential verification required</h1>
  <p>{{.Message}}</p>
  <img class="qr" src="{{.QRImgURL}}" width="280" height="280" alt="Scan with your wallet app">
  <a class="btn" href="{{.WalletLink}}">Open in wallet app</a>
  <div class="status" id="status"><span class="spinner"></span> Waiting for wallet&hellip;</div>
</div>
<script nonce="{{.Nonce}}">
(function(){
  var statusURL = {{.StatusURL | js}};
  var resumeURL = {{.ResumeURL | js}};
  var attempts = 0;
  var maxAttempts = 150; // 5 minutes at 2s intervals
  function poll(){
    if(++attempts > maxAttempts){
      document.getElementById('status').textContent = 'Verification timed out. Please reload and try again.';
      return;
    }
    fetch(statusURL,{credentials:'same-origin'})
      .then(function(r){return r.json()})
      .then(function(d){
        if(d.status==='verified'){
          document.getElementById('status').textContent = 'Verified! Redirecting\u2026';
          window.location.href = resumeURL;
        } else if(d.status==='failed'){
          document.getElementById('status').textContent = 'Verification failed. Please try again.';
        } else {
          setTimeout(poll, 2000);
        }
      })
      .catch(function(){ setTimeout(poll, 3000); });
  }
  setTimeout(poll, 1500);
})();
</script>
</body>
</html>`))

// ── Email verification flow ───────────────────────────────────────────────────

// startEmailVerification generates a verify token, sends the email, shows confirmation page.
func (h *OIDCHandler) startEmailVerification(c echo.Context, user *models.User, org *models.Organization, orgName string, loginSess *session.LoginSession) error {
	ctx := c.Request().Context()

	// Generate a 20-byte random token
	tokenBytes := make([]byte, 20)
	if _, err := rand.Read(tokenBytes); err != nil {
		return echo.ErrInternalServerError
	}
	token := base64URLEncode(tokenBytes)

	if err := h.store.SaveEmailVerifyToken(ctx, token, user.ID.String(), loginSess.ID); err != nil {
		return echo.ErrInternalServerError
	}

	scheme := "http"
	if c.Request().TLS != nil || c.Request().Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	verifyURL := scheme + "://" + c.Request().Host + "/" + loginSess.OrgSlug + "/verify-email?token=" + token

	// Best-effort email send — don't block login on SMTP failure
	m, err := mailer.ForOrg(ctx, h.smtp, user.OrgID)
	if err != nil {
		log.Warn().Err(err).Str("org_id", user.OrgID.String()).Msg("SMTP not configured — cannot send verification email")
	} else {
		if sendErr := m.SendEmailVerification(user.Email, orgName, verifyURL); sendErr != nil {
			log.Error().Err(sendErr).Str("to", user.Email).Msg("failed to send verification email")
		}
	}

	// Show "check your email" page
	type emailSentData struct{ Email string }
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(http.StatusOK)
	return emailSentTmpl.Execute(c.Response().Writer, emailSentData{Email: user.Email})
}

// VerifyEmail handles the email verification link click.
// GET /:org_slug/verify-email?token=...
func (h *OIDCHandler) VerifyEmail(c echo.Context) error {
	ctx := c.Request().Context()
	token := c.QueryParam("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing verification token")
	}

	userIDStr, loginSessionID, err := h.store.ConsumeEmailVerifyToken(ctx, token)
	if err != nil || userIDStr == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "verification link invalid or expired — please sign in again to receive a new link")
	}

	userID, _ := uuid.Parse(userIDStr)
	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	// Mark email as verified and remove VERIFY_EMAIL required action
	newActions := make([]string, 0, len(user.RequiredActions))
	for _, a := range user.RequiredActions {
		if a != "VERIFY_EMAIL" {
			newActions = append(newActions, a)
		}
	}
	if err := h.users.SetRequiredActions(ctx, userID, newActions); err != nil {
		return echo.ErrInternalServerError
	}
	if err := h.users.SetEmailVerified(ctx, userID); err != nil {
		return echo.ErrInternalServerError
	}

	h.recordAuthEvent(c, user.OrgID.String(), &userID, user.Email, "email.verified", "")

	// Resume the authorize flow
	return c.Redirect(http.StatusFound, "/"+c.Param("org_slug")+"/authorize/resume?login_session_id="+loginSessionID)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// recordAuthEvent fires an audit log entry for an authentication event.
// Errors are swallowed — audit logging must never break the auth flow.
func (h *OIDCHandler) recordAuthEvent(c echo.Context, orgIDStr string, userID *uuid.UUID, email, action, detail string) {
	orgID, _ := uuid.Parse(orgIDStr)
	ip := c.RealIP()
	ua := c.Request().UserAgent()
	resType := "session"
	entry := &models.AuditLog{
		OrgID:        &orgID,
		UserID:       userID,
		ActorEmail:   &email,
		Action:       action,
		ResourceType: &resType,
		Status:       "success",
		IPAddress:    &ip,
		UserAgent:    &ua,
	}
	if detail != "" {
		entry.Status = "failure"
		entry.Metadata = map[string]interface{}{"detail": detail}
	}
	if err := h.audit.Record(c.Request().Context(), entry); err != nil {
		log.Warn().Err(err).Str("action", action).Msg("failed to record audit event")
	}

	// Persist to the immutable login_history table for event sourcing /
	// anomaly detection. Map action names to the auth_method + status fields.
	status := "success"
	var failureReason *string
	if detail != "" {
		status = "failure"
		failureReason = &detail
	}
	authMethod := loginActionToMethod(action)

	// Enrich with geo-IP data (best-effort; nil-safe when DB not configured).
	geo := h.geo.Lookup(ip)
	var countryCode, city, asnOrg *string
	if geo.CountryCode != "" {
		countryCode = &geo.CountryCode
	}
	if geo.City != "" {
		city = &geo.City
	}
	if geo.ASNOrg != "" {
		asnOrg = &geo.ASNOrg
	}

	// Enrich with Clavex Shield threat-intel (best-effort; nil-safe when disabled).
	var shieldMalicious *bool
	var shieldConfidence *int
	var shieldTorExit *bool
	if h.shieldClient != nil && ip != "" {
		verdict := h.shieldClient.Check(c.Request().Context(), ip)
		shieldMalicious = &verdict.IsMalicious
		conf := verdict.Confidence
		shieldConfidence = &conf
		shieldTorExit = &verdict.IsTorExit
	}

	h.loginHistory.RecordLogin(c.Request().Context(), repository.RecordLoginParams{
		OrgID:           orgID,
		UserID:          userID,
		Email:           &email,
		AuthMethod:      authMethod,
		Status:          status,
		FailureReason:   failureReason,
		IPAddress:       &ip,
		UserAgent:       &ua,
		CountryCode:     countryCode,
		City:            city,
		ASNOrg:          asnOrg,
		IsMalicious:     shieldMalicious,
		ConfidenceScore: shieldConfidence,
		IsTorExit:       shieldTorExit,
	})

	// ── Prometheus: login counter ───────────────────────────────────────────
	orgSlugForMetric := orgID.String() // fallback when slug not available in this ctx
	metrics.LoginTotal.WithLabelValues(orgSlugForMetric, status, authMethod).Inc()

	// ── Risk-based login alert ────────────────────────────────────────────────
	// Fire-and-forget: compute risk score and send email if above threshold.
	threshold := h.cfg.Auth.LoginAlertThreshold
	if threshold == 0 {
		threshold = 60 // safe default
	}
	if status == "success" && userID != nil {
		capturedUserID := *userID
		capturedOrgID := orgID
		capturedEmail := email
		capturedCountry := countryCode
		capturedCity := city
		capturedIP := ip
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			score, err := h.riskScorer.Compute(ctx, capturedOrgID, capturedUserID)
			if err == nil {
				// Record every computed risk score regardless of alert threshold.
				metrics.RiskScoreHistogram.WithLabelValues(capturedOrgID.String()).Observe(float64(score.Score))
			}
			if err != nil || score.Score < threshold {
				return
			}
			m, err := mailer.ForOrg(ctx, h.smtp, capturedOrgID)
			if err != nil {
				return // SMTP not configured — silent
			}
			country := "an unknown location"
			if capturedCountry != nil && *capturedCountry != "" {
				if capturedCity != nil && *capturedCity != "" {
					country = *capturedCity + ", " + *capturedCountry
				} else {
					country = *capturedCountry
				}
			}
			subject := "Security alert: new login detected"
			htmlBody := loginAlertEmail(country, capturedIP, score.Reason)
			if err := m.Send(capturedEmail, subject, htmlBody); err != nil {
				log.Warn().Err(err).Str("email", capturedEmail).Msg("login alert email failed")
			}
		}()
	}
}

// loginAlertEmail returns an HTML email body for a suspicious login event.
func loginAlertEmail(location, ip string, reasons []string) string {
	reasonList := ""
	for _, r := range reasons {
		reasonList += "<li>" + r + "</li>"
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:560px;margin:auto;padding:24px">
<h2 style="color:#e53e3e">&#9888; Security Alert</h2>
<p>We detected a new login to your account from an unusual location:</p>
<table style="border-collapse:collapse;width:100%%">
  <tr><td style="padding:6px 12px;font-weight:bold">Location</td><td>%s</td></tr>
  <tr><td style="padding:6px 12px;font-weight:bold">IP Address</td><td>%s</td></tr>
  <tr><td style="padding:6px 12px;font-weight:bold">Risk signals</td><td><ul>%s</ul></td></tr>
</table>
<p>If this was you, no action is needed.</p>
<p>If this <strong>was not you</strong>, please change your password immediately and contact your administrator.</p>
<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
<p style="font-size:12px;color:#718096">This alert was sent because your account's risk score exceeded the alert threshold.</p>
</body></html>`, location, ip, reasonList)
}

// loginActionToMethod maps an audit action string to the login_history auth_method.
func loginActionToMethod(action string) string {
	switch action {
	case "login.success", "login.failed":
		return "password"
	case "mfa.success", "mfa.failed":
		return "totp"
	case "login.success.idp":
		return "idp"
	case "login.success.spid":
		return "spid"
	case "login.success.cie":
		return "cie"
	case "login.success.device":
		return "device"
	case "login.success.magic_link":
		return "magic_link"
	default:
		return "password"
	}
}

// enforceRequestObjectJTIReplay enforces single-use of a federation request
// object's jti (OpenID Federation §12.1.1.1). The jti and exp are surfaced by
// ParseJAR via reserved params (only for federation clients). A first sighting
// is recorded in Redis with a TTL covering the request object's lifetime; a
// repeat sighting records a redirectable invalid_request_object policy error.
// Store errors fail open so a transient Redis issue cannot block valid requests.
func (h *OIDCHandler) enforceRequestObjectJTIReplay(c echo.Context, params map[string]string) {
	jti := params[oidc.JARJtiKey]
	// jti/exp are internal markers — drop them so they never flow downstream.
	delete(params, oidc.JARJtiKey)
	expStr := params[oidc.JARExpKey]
	delete(params, oidc.JARExpKey)

	if jti == "" || params[oidc.JARPolicyErrorKey] != "" {
		return
	}

	ttl := 10 * time.Minute
	if expStr != "" {
		if exp, err := strconv.ParseInt(expStr, 10, 64); err == nil {
			if d := time.Until(time.Unix(exp, 0)); d > 0 {
				ttl = d + time.Minute // remember slightly past expiry
			}
		}
	}

	// Scope by client_id so distinct RPs reusing a jti value cannot collide.
	key := "oidc:jarjti:" + params["client_id"] + ":" + jti
	firstUse, err := h.rdb.SetNX(c.Request().Context(), key, "1", ttl).Result()
	if err != nil {
		c.Logger().Warnf("federation: jti replay check failed (failing open): %v", err)
		return
	}
	if !firstUse {
		params[oidc.JARPolicyErrorKey] = "invalid_request_object"
		params[oidc.JARPolicyDescKey] = "request object jti has already been used (OpenID Federation 12.1.1.1)"
	}
}

func (h *OIDCHandler) redirectWithError(c echo.Context, ae *oidc.AuthorizeError) error {
	// RFC 6749 §4.1.2.1 restricts error_description to a narrow charset (no
	// quotes, backslash or non-ASCII). Sanitise before it is placed into the
	// redirect/JARM/form response so a stray character cannot make the whole
	// error response invalid for the client.
	ae.Description = oidc.SanitizeErrorDescription(ae.Description)

	// JARM §4.2: when the client requested a JWT response mode, error responses
	// MUST also be wrapped in a signed JARM JWT (not sent as plain query params).
	if oidc.IsJARMMode(ae.ResponseMode) {
		issuer := h.issuerFromRequest(c, ae.OrgSlug)
		jarmJWT, err := oidc.BuildJARMErrorResponse(h.tc.Keys, issuer, ae.ClientID, ae.Code, ae.Description, ae.State)
		if err != nil {
			return echo.ErrInternalServerError
		}
		dest, err := oidc.BuildJARMRedirectURL(jarmJWT, ae.RedirectURI, ae.ResponseMode)
		if err != nil {
			return echo.ErrInternalServerError
		}
		return c.Redirect(http.StatusFound, dest)
	}
	u, _ := url.Parse(ae.RedirectURI)
	// RFC 6749 §4.1.2.1: preserve any query parameters already present in the
	// registered redirect_uri (e.g. ?dummy1=lorem&dummy2=ipsum) and merge error
	// parameters into them, so the callback receives both sets.
	params := u.Query()
	params.Set("error", ae.Code)
	if ae.Description != "" {
		params.Set("error_description", ae.Description)
	}
	if ae.State != "" {
		params.Set("state", ae.State)
	}
	// OAuth 2.0 Form Post Response Mode: error responses MUST also be POST-ed
	// as a form body (not returned via a GET query string redirect).
	if ae.ResponseMode == "form_post" {
		type field struct{ Name, Value string }
		fields := []field{{"error", ae.Code}}
		if ae.Description != "" {
			fields = append(fields, field{"error_description", ae.Description})
		}
		if ae.State != "" {
			fields = append(fields, field{"state", ae.State})
		}
		c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
		c.Response().Header().Set("Cache-Control", "no-store")
		c.Response().WriteHeader(http.StatusOK)
		_ = formPostTmpl.Execute(c.Response().Writer, struct {
			Action string
			Fields []field
			Nonce  string
		}{Action: ae.RedirectURI, Fields: fields, Nonce: middleware.GetCSPNonce(c)})
		return nil
	}
	// OIDC Core §3.3.2.1: for hybrid flows the default response_mode is fragment.
	// Error responses MUST use the same channel as successful responses.
	if ae.ResponseMode == "fragment" {
		u.Fragment = params.Encode()
	} else {
		u.RawQuery = params.Encode()
	}
	return c.Redirect(http.StatusFound, u.String())
}

// redirectWithCode redirects to redirect_uri with the authorization code.
// When responseMode is "query.jwt" or "fragment.jwt" the response parameters are
// wrapped in a signed JARM JWT (FAPI 2.0 Message Signing, draft-ietf-oauth-jarm).
// Plain "query" mode adds ISS per RFC 9207 for mix-up attack prevention.
// "fragment" mode (hybrid flow default) places params in the URI fragment.
// "form_post" mode returns a self-submitting HTML form (OAuth 2.0 Form Post Response Mode).
// idToken is non-empty for hybrid flows (response_type=code id_token) and is
// included in the fragment/form_post response alongside the code.
// sessionState is the OIDC Session Management session_state parameter; may be "".
func (h *OIDCHandler) redirectWithCode(c echo.Context, redirectURI, code, state, orgSlug, clientID, responseMode, idToken, sessionState string) error {
	if oidc.IsJARMMode(responseMode) {
		issuer := h.issuerFromRequest(c, orgSlug)
		jarmJWT, err := oidc.BuildJARMResponse(h.tc.Keys, issuer, clientID, code, state)
		if err != nil {
			return echo.ErrInternalServerError
		}
		dest, err := oidc.BuildJARMRedirectURL(jarmJWT, redirectURI, responseMode)
		if err != nil {
			return echo.ErrInternalServerError
		}
		return c.Redirect(http.StatusFound, dest)
	}

	issuer := h.issuerFromRequest(c, orgSlug)

	if responseMode == "fragment" {
		// Hybrid flow: place params in the URI fragment (OIDC Core §3.3.2.5).
		// RFC 9207: iss must appear with its literal value (no percent-encoding of
		// the scheme/host) — build the fragment manually so ':' and '/' are preserved.
		frag := url.Values{}
		frag.Set("code", code)
		if state != "" {
			frag.Set("state", state)
		}
		if idToken != "" {
			frag.Set("id_token", idToken)
		}
		if sessionState != "" {
			frag.Set("session_state", sessionState)
		}
		u, _ := url.Parse(redirectURI)
		// Append iss without encoding ':' and '/' (RFC 3986 allows them in query values).
		fragStr := frag.Encode()
		if fragStr != "" {
			fragStr += "&"
		}
		fragStr += "iss=" + issuer
		u.Fragment = fragStr
		return c.Redirect(http.StatusFound, u.String())
	}

	if responseMode == "form_post" {
		// OAuth 2.0 Form Post Response Mode — return a self-submitting HTML form.
		// The browser POSTs code + state + iss to the redirect_uri.
		type field struct{ Name, Value string }
		fields := []field{{"code", code}}
		if state != "" {
			fields = append(fields, field{"state", state})
		}
		fields = append(fields, field{"iss", issuer})
		if idToken != "" {
			fields = append(fields, field{"id_token", idToken})
		}
		if sessionState != "" {
			fields = append(fields, field{"session_state", sessionState})
		}

		c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
		c.Response().Header().Set("Cache-Control", "no-store")
		c.Response().WriteHeader(http.StatusOK)

		_ = formPostTmpl.Execute(c.Response().Writer, struct {
			Action string
			Fields []field
			Nonce  string
		}{Action: redirectURI, Fields: fields, Nonce: middleware.GetCSPNonce(c)})
		return nil
	}

	// Plain query mode (default): add code + state + iss as query params.
	// RFC 9207: iss must appear with its literal issuer value. url.Values.Encode()
	// percent-encodes ':' and '/' which causes the conformance suite's raw-value
	// comparison to fail (it compares before URL-decoding). Append iss directly to
	// RawQuery so ':' and '/' are preserved — RFC 3986 §3.4 permits them unencoded
	// in query string values.
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	if sessionState != "" {
		q.Set("session_state", sessionState)
	}
	rawQuery := q.Encode()
	if rawQuery != "" {
		rawQuery += "&"
	}
	rawQuery += "iss=" + issuer
	u.RawQuery = rawQuery
	return c.Redirect(http.StatusFound, u.String())
}

func tokenError(c echo.Context, code, description string) error {
	return c.JSON(http.StatusBadRequest, map[string]string{
		"error":             code,
		"error_description": sanitizeErrorDescription(description),
	})
}

// sanitizeErrorDescription replaces any byte outside the RFC 6749 §5.2
// error_description set — %x20-21 / %x23-5B / %x5D-7E, plus Tab/LF/CR — with a
// space. Internal messages occasionally contain UTF-8 punctuation (em dash, §)
// which would otherwise produce a non-conformant response body.
func sanitizeErrorDescription(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c == '\t' || c == '\n' || c == '\r',
			c >= 0x20 && c <= 0x21,
			c >= 0x23 && c <= 0x5B,
			c >= 0x5D && c <= 0x7E:
			// allowed
		default:
			b[i] = ' '
		}
	}
	return string(b)
}

// echoMsg extracts the human-readable message from an error, unwrapping
// echo.HTTPError so callers get just the message string rather than the
// "code=N, message=…" representation produced by (*echo.HTTPError).Error().
func echoMsg(err error) string {
	if he, ok := err.(*echo.HTTPError); ok {
		return fmt.Sprint(he.Message)
	}
	return err.Error()
}

func queryToMap(c echo.Context) map[string]string {
	m := make(map[string]string)
	// Always read query-string parameters.
	for k, v := range c.QueryParams() {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	// For POST requests (OIDC Core §3.1.2.1 requires GET and POST support),
	// also read application/x-www-form-urlencoded body parameters.
	// Form values do not override query-string values (query takes precedence).
	if c.Request().Method == http.MethodPost {
		if err := c.Request().ParseForm(); err == nil {
			for k, v := range c.Request().PostForm {
				if _, exists := m[k]; !exists && len(v) > 0 {
					m[k] = v[0]
				}
			}
		}
	}
	return m
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	// RFC 6750 §2.1 / RFC 9449 §7.1: token type comparisons are case-insensitive.
	lower := strings.ToLower(h)
	if strings.HasPrefix(lower, "bearer ") {
		return h[len("bearer "):]
	}
	// RFC 9449 §7.1: DPoP-bound tokens use "DPoP" as the auth scheme.
	if strings.HasPrefix(lower, "dpop ") {
		return h[len("dpop "):]
	}
	return ""
}

func isTokenError(err error, target **oidc.TokenError) bool {
	var te *oidc.TokenError
	if errors.As(err, &te) {
		*target = te
		return true
	}
	return false
}

// ── Password reset (email link) ───────────────────────────────────────────────

// ResetPasswordPage renders the "set new password" form for email-link resets.
// GET /:org_slug/reset-password?token=...
func (h *OIDCHandler) ResetPasswordPage(c echo.Context) error {
	token := c.QueryParam("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing token")
	}
	return resetPasswordTmpl.Execute(c.Response().Writer, map[string]interface{}{
		"OrgSlug": c.Param("org_slug"),
		"Token":   token,
	})
}

// ResetPasswordSubmit processes the password reset form.
// POST /:org_slug/reset-password
func (h *OIDCHandler) ResetPasswordSubmit(c echo.Context) error {
	ctx := c.Request().Context()
	token := c.FormValue("token")
	password := c.FormValue("password")
	confirm := c.FormValue("confirm")
	orgSlug := c.Param("org_slug")

	renderErr := func(msg string) error {
		return resetPasswordTmpl.Execute(c.Response().Writer, map[string]interface{}{
			"OrgSlug": orgSlug,
			"Token":   token,
			"Error":   msg,
		})
	}

	if token == "" {
		return renderErr("Invalid or expired reset link.")
	}
	if password == "" {
		return renderErr("Password cannot be empty.")
	}
	if password != confirm {
		return renderErr("Passwords do not match.")
	}
	if len(password) < 8 {
		return renderErr("Password must be at least 8 characters.")
	}

	userIDStr, err := h.store.ConsumePWResetToken(ctx, token)
	if err != nil || userIDStr == "" {
		return renderErr("Invalid or expired reset link.")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return renderErr("Invalid or expired reset link.")
	}

	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		return renderErr("User not found.")
	}

	if err := h.users.SetPassword(ctx, userID, password); err != nil {
		return renderErr("Failed to update password. Please try again.")
	}

	// Remove UPDATE_PASSWORD required action if present
	newActions := make([]string, 0, len(user.RequiredActions))
	for _, a := range user.RequiredActions {
		if a != "UPDATE_PASSWORD" {
			newActions = append(newActions, a)
		}
	}
	_ = h.users.SetRequiredActions(ctx, userID, newActions)

	h.recordAuthEvent(c, user.OrgID.String(), &userID, user.Email, "password.reset", "")

	// Show a simple success page
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = c.Response().Writer.Write([]byte(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Password Updated</title>` +
		`<style>body{font-family:system-ui,sans-serif;background:#F0F4F8;display:flex;align-items:center;justify-content:center;min-height:100vh;}` +
		`.card{background:white;padding:48px;border-radius:16px;text-align:center;max-width:400px;}h1{color:#0D1F2D;}p{color:#6B7A8D;margin-top:12px;}</style></head>` +
		`<body><div class="card"><h1>&#10003; Password updated</h1><p>Your password has been changed. You can now close this tab and sign in again.</p></div></body></html>`))
	return nil
}

// ── Forced password update (required action in login flow) ───────────────────

// UpdatePasswordPage renders the "update password" form triggered by the UPDATE_PASSWORD required action.
// GET /:org_slug/update-password?login_session_id=...
func (h *OIDCHandler) UpdatePasswordPage(c echo.Context) error {
	sessID := c.QueryParam("login_session_id")
	if sessID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing login_session_id")
	}
	return updatePasswordTmpl.Execute(c.Response().Writer, map[string]interface{}{
		"OrgSlug":        c.Param("org_slug"),
		"LoginSessionID": sessID,
	})
}

// UpdatePasswordSubmit processes the forced password change and resumes the auth flow.
// POST /:org_slug/update-password
func (h *OIDCHandler) UpdatePasswordSubmit(c echo.Context) error {
	ctx := c.Request().Context()
	sessID := c.FormValue("login_session_id")
	password := c.FormValue("password")
	confirm := c.FormValue("confirm")
	orgSlug := c.Param("org_slug")

	renderErr := func(msg string) error {
		return updatePasswordTmpl.Execute(c.Response().Writer, map[string]interface{}{
			"OrgSlug":        orgSlug,
			"LoginSessionID": sessID,
			"Error":          msg,
		})
	}

	if sessID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing login_session_id")
	}
	if password == "" {
		return renderErr("Password cannot be empty.")
	}
	if password != confirm {
		return renderErr("Passwords do not match.")
	}
	if len(password) < 8 {
		return renderErr("Password must be at least 8 characters.")
	}

	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess.UserID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid or expired session")
	}

	userID, err := uuid.Parse(loginSess.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid session")
	}

	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	// Breached password check: the new password must not be known-breached in
	// any mode other than "off".  block/warn/force_reset all reject it here —
	// the user must pick a safe password when actively changing their credentials.
	if policy, err := h.pwPolicy.Get(ctx, user.OrgID); err == nil &&
		policy.BreachedPasswordAction != "" &&
		policy.BreachedPasswordAction != "off" {
		if result, bErr := h.breach.Check(password); bErr == nil && result.Pwned {
			return renderErr(fmt.Sprintf(
				"This password has appeared in %d known data breach(es). "+
					"Please choose a different password.",
				result.Count,
			))
		}
	}

	if err := h.users.SetPassword(ctx, userID, password); err != nil {
		return renderErr("Failed to update password. Please try again.")
	}

	// Remove UPDATE_PASSWORD from required_actions
	newActions := make([]string, 0, len(user.RequiredActions))
	for _, a := range user.RequiredActions {
		if a != "UPDATE_PASSWORD" {
			newActions = append(newActions, a)
		}
	}
	_ = h.users.SetRequiredActions(ctx, userID, newActions)

	h.recordAuthEvent(c, user.OrgID.String(), &userID, user.Email, "password.updated", "")

	// Continue from where we left off
	return c.Redirect(http.StatusFound, "/"+orgSlug+"/authorize/resume?login_session_id="+sessID)
}

// ── Breach warning interstitial ───────────────────────────────────────────────

// BreachWarningPage renders the breach-warning interstitial for action=warn.
// GET /:org_slug/breach-warning?login_session_id=...&count=N
func (h *OIDCHandler) BreachWarningPage(c echo.Context) error {
	sessID := c.QueryParam("login_session_id")
	if sessID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing login_session_id")
	}
	count := 0
	if n, err := fmt.Sscanf(c.QueryParam("count"), "%d", &count); n == 0 || err != nil {
		count = 1
	}
	orgSlug := c.Param("org_slug")
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().WriteHeader(http.StatusOK)
	return breachWarningTmpl.Execute(c.Response().Writer, map[string]interface{}{
		"OrgSlug":        orgSlug,
		"LoginSessionID": sessID,
		"Count":          count,
	})
}

// BreachWarningAcknowledge handles the "Continue signing in" POST from the interstitial.
// POST /:org_slug/breach-warning
// Sets BreachWarningAcknowledged on the session then resumes AuthorizeSubmit.
func (h *OIDCHandler) BreachWarningAcknowledge(c echo.Context) error {
	ctx := c.Request().Context()
	sessID := c.FormValue("login_session_id")
	if sessID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing login_session_id")
	}
	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "session expired — please sign in again")
	}
	loginSess.BreachWarningAcknowledged = true
	if err := h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}
	// Resume the authorize flow (AuthorizeResume checks for MFA, required actions, etc.)
	return c.Redirect(http.StatusFound,
		"/"+c.Param("org_slug")+"/authorize/resume?login_session_id="+sessID)
}

// providerStartPath maps identity_providers.provider_type values to their
// tenant-scoped SSO path prefix. Providers not in this map use the generic
// OIDC path ("/idp/").
var providerStartPath = map[string]string{
	"cie":           "/cie/",
	"itsme":         "/itsme/",
	"bundid":        "/bundid/",
	"digid":         "/digid/",
	"clave":         "/clave/",
	"franceconnect": "/franceconnect/",
}

// loadIDPButtons returns the list of national eID / federated login buttons to
// render on the login page for a given OIDC client.
//
// When client.EnabledLoginProviders is empty the legacy behaviour is preserved:
// all active OIDC providers are shown (using the correct per-type StartURL).
//
// When non-empty, only providers whose type appears in the list are included.
// Special values handled separately:
//   - "spid"      → SPID IdPs from the global SPID registry
//   - "eidas"     → eIDAS node configured for the org
//   - "bundidsaml"→ BundID SAML SP configured for the org
//
// Non-fatal: any DB error is silently skipped so the login page still works.
func (h *OIDCHandler) loadIDPButtons(ctx context.Context, orgID uuid.UUID, orgSlug, clientID string) []*idpButton {
	// Resolve the client's allow-list (empty = show all).
	var allowed map[string]bool
	if clientID != "" {
		if cl, err := h.clients.GetByClientID(ctx, clientID); err == nil && len(cl.EnabledLoginProviders) > 0 {
			allowed = make(map[string]bool, len(cl.EnabledLoginProviders))
			for _, p := range cl.EnabledLoginProviders {
				allowed[p] = true
			}
		}
	}

	want := func(providerType string) bool {
		return len(allowed) == 0 || allowed[providerType]
	}

	var out []*idpButton

	// OIDC / national-eID providers stored in identity_providers table.
	if h.idpRepo != nil {
		if idps, err := h.idpRepo.ListActivePromoted(ctx, orgID); err == nil {
			for _, p := range idps {
				if !want(p.ProviderType) {
					continue
				}
				path := providerStartPath[p.ProviderType]
				if path == "" {
					path = "/idp/"
				}
				out = append(out, &idpButton{
					ID:         p.ID.String(),
					Name:       p.Name,
					IsPromoted: p.IsPromoted,
					StartURL:   "/" + orgSlug + path + p.ID.String() + "?login_session_id=",
				})
			}
		}
	}

	// SPID — global registry of Italian IdPs, separate from identity_providers.
	if want("spid") && h.spidRepo != nil {
		if spidIdPs, err := h.spidRepo.ListIdPs(ctx, false); err == nil {
			for _, idp := range spidIdPs {
				if !idp.IsActive {
					continue
				}
				out = append(out, &idpButton{
					ID:         idp.ID.String(),
					Name:       "SPID — " + idp.DisplayName,
					IsPromoted: false,
					StartURL:   "/" + orgSlug + "/spid/sso/" + idp.ID.String() + "?login_session_id=",
				})
			}
		}
	}

	// eIDAS — single endpoint per org, no idp_id.
	if want("eidas") && h.eidasRepo != nil {
		if cfg, err := h.eidasRepo.GetConfig(ctx, orgID); err == nil && cfg != nil {
			out = append(out, &idpButton{
				ID:         "eidas",
				Name:       "eIDAS",
				IsPromoted: false,
				StartURL:   "/" + orgSlug + "/eidas/sso?login_session_id=",
			})
		}
	}

	// BundID SAML — single endpoint per org, no idp_id.
	if want("bundidsaml") && h.bundidSAMLRepo != nil {
		if cfg, err := h.bundidSAMLRepo.GetConfig(ctx, orgID); err == nil && cfg != nil {
			out = append(out, &idpButton{
				ID:         "bundidsaml",
				Name:       "BundID",
				IsPromoted: false,
				StartURL:   "/" + orgSlug + "/bundidsaml/sso?login_session_id=",
			})
		}
	}

	return out
}

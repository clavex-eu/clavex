package server

import (
	"context"
	gocrypto "crypto"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/actionsrunner"
	"github.com/clavex-eu/clavex/internal/alerting"
	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/connectorregistry"
	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/enrichment"
	"github.com/clavex-eu/clavex/internal/federation"
	"github.com/clavex-eu/clavex/internal/fga"
	"github.com/clavex-eu/clavex/internal/flowengine"
	"github.com/clavex-eu/clavex/internal/forwardauth"
	gdprpkg "github.com/clavex-eu/clavex/internal/gdpr"
	"github.com/clavex-eu/clavex/internal/handler"
	"github.com/clavex-eu/clavex/internal/ingressreconcile"
	"github.com/clavex-eu/clavex/internal/license"
	"github.com/clavex-eu/clavex/internal/lifecycle"
	"github.com/clavex-eu/clavex/internal/lockout"
	"github.com/clavex-eu/clavex/internal/mcpserver"
	"github.com/clavex-eu/clavex/internal/merkle"
	"github.com/clavex-eu/clavex/internal/metrics"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/clavex-eu/clavex/internal/scim"
	"github.com/clavex-eu/clavex/internal/scimpush"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/shield"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/clavex-eu/clavex/internal/webhook"
	"github.com/clavex-eu/clavex/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
)

// Server wraps the Echo instance and holds shared dependencies.
type Server struct {
	echo           *echo.Echo
	cfg            *config.Config
	pool           *pgxpool.Pool
	enc            *crypto.Encryptor
	dispatcher     *audit.Dispatcher
	retention      *audit.RetentionWorker
	gdprWorker     *gdprpkg.RetentionWorker
	webhookDisp    *webhook.Dispatcher
	webhookRepo    *repository.WebhookRepository
	licenseChecker *license.Checker
	ssfDisp        *ssf.Dispatcher
	pamNotifier    *alerting.PAMNotifier
	feedClient     *shield.FeedClient      // nil when distributed threat feed disabled
	merkleSealer   *merkle.Sealer          // nil when signing key is not configured
	oidcH          *handler.OIDCHandler    // kept for post-New wiring (e.g. WithPQCSigner)
	fedH           *federation.Handler     // kept for post-New wiring (WithEncKeys)
	dbSigner       *oidc.DBSigner          // nil unless key_backend=db; target of scheduled global OIDC rotation
	pqcSigner      *oidc.PQCSigner         // nil unless PQC enabled; target of scheduled global PQC rotation
	orgSigners     *oidc.OrgSignerCache    // nil unless key_backend=db; target of scheduled per-org OIDC rotation
	orgPQCSigners  *oidc.OrgPQCSignerCache // nil unless PQC enabled+key_backend=db; target of scheduled per-org PQC rotation
}

// SSFDispatcher returns the SSF event dispatcher. Used by workers that need
// to fire CAEP events (e.g. MDS3 policy enforcer).
func (s *Server) SSFDispatcher() *ssf.Dispatcher { return s.ssfDisp }

// PAMNotifier returns the PAM/compliance alert notifier (Slack + Teams).
// Used by background workers to send security drift alerts.
func (s *Server) PAMNotifier() *alerting.PAMNotifier { return s.pamNotifier }

// WithLicense attaches a license Checker to the server, enabling the
// X-Clavex-License-Warning response header and the /superadmin/license endpoint.
func (s *Server) WithLicense(c *license.Checker) *Server {
	s.licenseChecker = c
	return s
}

// New wires up all routes and middleware and returns a ready-to-start Server.
func New(cfg *config.Config, pool *pgxpool.Pool, rdb redis.UniversalClient, keys oidc.Signer, orgSigners ...*oidc.OrgSignerCache) *Server {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// srvRef is assigned the constructed *Server at the end of New(). Route
	// middleware registered below that needs a dependency attached after New()
	// (e.g. the license Checker, wired via WithLicense) reads it lazily through
	// this pointer, which is non-nil by the time any request is served.
	var srvRef *Server

	// ── Trusted-proxy IP extraction ───────────────────────────────────────────
	// When running behind a reverse proxy or Kubernetes ingress, RemoteAddr is the
	// pod IP. Configure Echo to extract the real client IP from X-Forwarded-For
	// using the CIDRs listed in http.trusted_proxies.
	if len(cfg.HTTP.TrustedProxies) > 0 {
		var opts []echo.TrustOption
		for _, cidr := range cfg.HTTP.TrustedProxies {
			if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
				opts = append(opts, echo.TrustIPRange(ipNet))
			} else {
				log.Warn().Str("cidr", cidr).Msg("http.trusted_proxies: invalid CIDR, skipping")
			}
		}
		e.IPExtractor = echo.ExtractIPFromXFFHeader(opts...)
	} else {
		// No trusted proxies configured: use the direct connection address only.
		// Echo's default RealIP otherwise trusts X-Forwarded-For / X-Real-IP from
		// ANY client, letting an attacker spoof their IP and bypass per-IP rate
		// limits, IP allow-lists / ip-rules, and risk scoring. Deployments behind a
		// reverse proxy MUST set http.trusted_proxies so XFF is honoured securely.
		e.IPExtractor = echo.ExtractIPDirect()
	}

	// ── Global middleware ─────────────────────────────────────────────────────
	e.Use(otelecho.Middleware(cfg.Telemetry.ServiceName))
	e.Use(middleware.RequestLogger())
	e.Use(echomw.Recover())
	e.Use(echomw.RequestID())
	e.Use(middleware.PrometheusMiddleware())
	e.Use(echomw.SecureWithConfig(echomw.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
		HSTSMaxAge:         31536000,
		HSTSPreloadEnabled: true,
		// Strict default for API routes — HTML-serving tenant routes override
		// this with a nonce-based CSP via the HTMLPageCSP per-group middleware.
		ContentSecurityPolicy: "default-src 'none'; frame-ancestors 'none'",
	}))
	e.Use(middleware.ExtraSecurityHeaders())

	// ── Custom domain resolver ────────────────────────────────────────────────
	// Reads the Host header, resolves it against the org_custom_domains table
	// (with a Redis cache), and stores the org_id in the Echo context so
	// downstream tenant routes can pick up the correct issuer.
	customDomainRepo := repository.NewCustomDomainRepository(pool)
	customDomainResolver := middleware.NewCustomDomainResolver(customDomainRepo, rdb)
	e.Use(customDomainResolver.Middleware())

	// ── License warning header (global — added before the server is returned) ──
	// Applied lazily in Start() after WithLicense() may have been called.

	for _, o := range cfg.HTTP.CORSAllowedOrigins {
		if o == "*" {
			log.Warn().Msg("http.cors_allowed_origins contains \"*\": the admin console now uses credentialed cookie auth, so any origin could drive credentialed cross-origin requests. Set an explicit origin allow-list in production.")
			break
		}
	}
	e.Use(echomw.CORSWithConfig(echomw.CORSConfig{
		AllowOriginFunc: cfg.HTTP.CORSAllowOrigin,
		AllowMethods:    []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete},
		AllowHeaders:    []string{echo.HeaderAuthorization, echo.HeaderContentType, echo.HeaderAccept, middleware.CSRFHeaderName},
		// The browser console authenticates with the HttpOnly session cookie;
		// credentialed CORS is required for cross-origin (subdomain) deploys.
		// echo echoes the specific request origin (never "*") when this is set.
		AllowCredentials: true,
	}))

	// ── Compute base URL for OID4VCI / OID4VP ────────────────────────────────
	// Prefer auth.issuer_base (set when TLS is terminated by an upstream proxy)
	// so that credential_issuer URLs always use the public https:// scheme.
	var baseURL string
	if cfg.Auth.IssuerBase != "" {
		baseURL = strings.TrimRight(cfg.Auth.IssuerBase, "/")
	} else {
		scheme := "https"
		if cfg.HTTP.TLSCertFile == "" {
			scheme = "http"
		}
		baseURL = scheme + "://" + cfg.HTTP.BaseDomain
	}
	walletBaseURL := handler.StaticBaseURL(baseURL)

	// ── Handler instances ─────────────────────────────────────────────────────
	health := handler.NewHealthHandler(pool)
	oidcH := handler.NewOIDCHandler(cfg, pool, rdb, keys)
	if len(orgSigners) > 0 && orgSigners[0] != nil {
		oidcH.WithOrgSigners(orgSigners[0])
	}
	saml := handler.NewSAMLHandler(cfg, pool, rdb)
	auth := handler.NewAuthHandler(cfg, pool)
	webhooks := handler.NewWebhookHandler(pool)
	// actionsRunner is created once and shared by the flow engine (sync pre_login)
	// and the user handler (async user.created/updated/deleted).
	sharedActionsRunner := actionsrunner.New(repository.NewActionsRepository(pool))
	users := handler.NewUserHandler(pool, rdb, webhooks.Dispatcher()).
		WithAsyncActionRunner(sharedActionsRunner)
	orgs := handler.NewOrgHandler(pool)
	clients := handler.NewClientHandler(pool)
	healthDash := handler.NewHealthDashboardHandler(pool)

	// Encryption key: prefer dedicated key, fall back to admin_secret.
	encKey := cfg.Auth.EncryptionKey
	if encKey == "" {
		encKey = cfg.Auth.AdminSecret
	}
	enc := crypto.NewEncryptor(encKey)

	// PAM alerting notifier — constructed once and shared by the handler and
	// the rotation worker. A no-op notifier (empty URLs) is safe and cheap.
	pamNotifier := alerting.NewPAMNotifier(alerting.PAMAlertConfig{
		SlackWebhookURL:     cfg.PAMAlerts.SlackWebhookURL,
		TeamsWebhookURL:     cfg.PAMAlerts.TeamsWebhookURL,
		StaleCredentialDays: cfg.PAMAlerts.StaleCredentialDays,
		SessionMaxHours:     cfg.PAMAlerts.SessionMaxHours,
		AdminBaseURL:        cfg.PAMAlerts.AdminBaseURL,
	})

	webhookRepo := repository.NewWebhookRepositoryWithEnc(pool, enc)
	ldap := handler.NewLDAPHandlerWithEnc(pool, enc)
	groups := handler.NewGroupHandler(pool)
	scimPush := handler.NewScimPushHandlerWithEnc(pool, enc)
	merkleSealer := merkle.NewSealer(repository.NewAuditRepository(pool), merkle.SealOptions{
		BatchSize: merkle.CheckpointSize,
		Key:       keys.PrivateKey(),
		KID:       keys.KID(),
	})
	auditH := handler.NewAuditHandlerV2WithSealer(pool, merkleSealer)
	streamH := handler.NewStreamHandler(pool, cfg)
	branding := handler.NewBrandingHandler(pool)
	sessions := handler.NewSessionHandler(pool)
	mappers := handler.NewMapperHandler(pool)
	apiKeys := handler.NewAdminAPIKeyHandler(pool)
	grantsH := handler.NewGrantHandler(pool)
	enrichmentH := handler.NewEnrichmentHandler(pool)
	loginTmplH := handler.NewLoginTemplateHandler(pool)
	delegationH := handler.NewAdminDelegationHandler(pool)
	store := session.NewStore(rdb)
	emailOTPH := handler.NewEmailOTPHandler(pool, store)
	phoneOTPH := handler.NewPhoneOTPHandler(pool, store)
	mfa := handler.NewMFAHandler(cfg, pool, rdb, store)
	passkeyEnrollH := handler.NewPasskeyEnrollLoginHandler(
		store,
		repository.NewOrgRepository(pool),
		repository.NewUserRepository(pool),
		repository.NewMFARepository(pool),
		mfa.WebAuthn(),
		rdb,
	)
	passwordPolicy := handler.NewPasswordPolicyHandler(pool)
	smtpH := handler.NewSMTPHandler(pool)
	smsSettingsH := handler.NewSMSSettingsHandler(pool)
	idpH := handler.NewIDPHandler(pool, store)
	scimPusher := scimpush.New(repository.NewScimPushRepositoryWithEnc(pool, enc)).
		WithDeliveryRepo(repository.NewScimPushDeliveryRepository(pool)).
		WithUserRepo(repository.NewUserRepository(pool)).
		WithGroupRepo(repository.NewGroupRepository(pool))
	scimH := scim.New(pool).WithOutboundPusher(scimPusher).
		WithAuditEmitter(audit.NewEmitter(baseURL, repository.NewAuditRepository(pool)))
	scimPush.WithPusher(scimPusher)

	// SSRF: outbound dispatchers block private/loopback targets by default. When
	// the operator opts in (http.allow_private_outbound_targets) override all three
	// with an SSRF-relaxed client so internal webhook targets are reachable.
	if cfg.HTTP.AllowPrivateOutboundTargets {
		relaxed := safehttp.Client(30*time.Second, true)
		scimPusher.WithHTTPClient(relaxed)
		ssf.SetPushHTTPClient(relaxed)
		webhooks.Dispatcher().WithHTTPClient(relaxed)
		enrichment.SetHTTPClient(relaxed)
		// Same opt-out for the SSRF-guarded fetchers: federation trust-chain
		// resolution, OIDC request_uri/jwks_uri, and Vault SSH CA.
		federation.SetDefaultHTTPClient(relaxed)
		oidc.SetJARHTTPClient(relaxed)
		handler.SetVaultHTTPClient(relaxed)
		// Same opt-out for admin-configured upstream IdP (token/userinfo) and
		// SMS-gateway targets.
		handler.SetUpstreamHTTPClient(relaxed)
		connectorregistry.SetSMSHTTPClient(relaxed)
	}
	fwdAuth := forwardauth.New(cfg, pool)
	impersonation := handler.NewImpersonationHandler(cfg, pool)
	invitations := handler.NewInvitationHandler(pool)
	captchaH := handler.NewCaptchaHandler(pool)
	importH := handler.NewImportHandler(pool)
	accountH := handler.NewAccountHandler(cfg, pool, rdb, store)
	accountCenterH := handler.NewAccountCenterHandler(pool)
	policyH := handler.NewPolicyHandler(pool, nil) // nil = no YAML-level default rules
	spidH := handler.NewSPIDHandler(pool, store, baseURL)
	oidcH.WithSPIDRepository(repository.NewSPIDRepository(pool))
	oidcH.WithEidasRepository(repository.NewEidasRepository(pool))
	oidcH.WithBundIDSAMLRepository(repository.NewBundIDSAMLRepository(pool))
	cieH := handler.NewCIEHandler(pool, store, baseURL)
	franceConnectH := handler.NewFranceConnectHandler(pool, store, baseURL)
	itsmeH := handler.NewItsmeHandler(pool, store, keys)
	bundidH := handler.NewBundIDHandler(pool, store)
	claveH := handler.NewClaveHandler(pool, store)
	digidH := handler.NewDigiDHandler(pool, store)
	bundidSAMLH := handler.NewBundIDSAMLHandler(pool, store)
	eidasH := handler.NewEidasHandler(pool, store)

	// ── eIDAS 2.0 / OID4VCI / OID4VP / Compliance handlers ──────────────────
	oid4vciH := handler.NewOID4VCIHandler(pool, keys, walletBaseURL).
		WithRedis(rdb).
		WithStatusDispatcher(oid4w.NewCredStatusDispatcher())
	analyticsH := handler.NewCredentialAnalyticsHandler(pool)
	oid4vpH := handler.NewOID4VPHandler(pool, keys, walletBaseURL, parseTrustedIssuers(cfg.OID4VP.TrustedCredentialIssuers), cfg.OID4VP.RequireTrustedIssuer, repository.NewCIBARepository(pool), cfg.OID4VP.JARCertFile, cfg.OID4VP.JARKeyFile)
	walletH := handler.NewWalletHandler(repository.NewOID4WRepository(pool))
	mdocProximityH := handler.NewMdocProximityHandler(pool, keys, walletBaseURL)
	complianceH := handler.NewComplianceHandler(pool, keys)
	loginHistoryH := handler.NewLoginHistoryHandler(pool)
	deviceTrustH := handler.NewDeviceTrustHandler(pool)
	clientBrandingH := handler.NewClientBrandingHandler(pool)
	crossOrgTrustH := handler.NewCrossOrgTrustHandler(pool)
	usageH := handler.NewUsageHandler(pool)
	ssfH := handler.NewSSFHandler(pool, keys, func(c echo.Context, slug string) string {
		return oidcH.IssuerFromRequest(c, slug)
	})
	// security events (account-disabled, sessions-revoked, credential-change).
	ssfBaseConfig := &ssf.SETConfig{
		PrivateKey: keys.PrivateKey(),
		KID:        keys.KID(),
	}
	ssfDisp := ssf.NewDynamicDispatcher(
		repository.NewSSFStreamRepository(pool),
		ssfBaseConfig,
		func(slug string) string { return cfg.HTTP.IssuerURLFromBase(cfg.Auth.IssuerBase, slug) },
	).WithRedis(rdb)
	users.WithSSFDispatcher(ssfDisp)
	sessions.WithSSFDispatcher(ssfDisp)
	accountH.WithSSFDispatcher(ssfDisp)
	oidcH.WithSSFDispatcher(ssfDisp)
	oidcH.WithOID4VPHandler(oid4vpH)
	oidcH.WithOID4VCIHandler(oid4vciH)
	walletStepUpH := handler.NewWalletStepUpHandler(pool, store, keys, walletBaseURL).
		WithSSFDispatcher(ssfDisp)
	oidcH.WithWalletStepUp(walletStepUpH)
	// Opt-in: score agent-token usage for anomalies on introspection and reuse
	// the wallet step-up above for the delegating user when a token is anomalous.
	if cfg.AgentTokens.UEBAStepUpEnabled {
		oidcH.WithAgentUEBA(repository.NewAgentTokenRepository(pool), repository.NewAgentUsageRepository(pool))
	}
	ssfH.WithDispatcher(ssfDisp)

	// CAEPReceiverHandler accepts inbound CAEP SETs from upstream providers
	// (e.g. SPID/CIE national IDP, UEBA broker) and creates wallet step-up
	// challenges so affected sessions are silently re-authenticated.
	caepReceiverH := handler.NewCAEPReceiverHandler(
		repository.NewOrgRepository(pool),
		repository.NewUserRepository(pool),
		walletStepUpH,
		ssfDisp,
	).WithTrustedTransmitters(cfg.SSF.TrustedTransmitters)
	_ = caepReceiverH // registered below in tenant routes

	// IdentityImportHandler handles POST …/users/:user_id/identity/import —
	// verified identity portability between Clavex installations via OID4VP.
	identityImportH := handler.NewIdentityImportHandler(repository.NewUserRepository(pool))
	if cfg.HTTP.AllowPrivateOutboundTargets {
		identityImportH.WithHTTPClient(safehttp.Client(10*time.Second, true))
	}

	// MarketplaceHandler — Credential Marketplace public catalog + org management.
	marketplaceH := handler.NewMarketplaceHandler(repository.NewMarketplaceRepository(pool))

	oidcH.WithServiceAccountRepository(repository.NewServiceAccountRepository(pool))

	// ── JML Lifecycle Engine ─────────────────────────────────────────────────
	jmlEngine := lifecycle.NewEngine(
		repository.NewLifecycleRepository(pool),
		repository.NewUserRepository(pool),
		repository.NewGroupRepository(pool),
		repository.NewRefreshTokenRepository(pool),
		ssfDisp,
	)
	scimH.WithLifecycleEngine(jmlEngine)
	scimH.WithAnomalyDetector(scim.NewAnomalyDetector(
		rdb,
		ssfDisp,
		webhooks.Dispatcher(),
		func(slug string) string { return cfg.HTTP.IssuerURLFromBase(cfg.Auth.IssuerBase, slug) },
	))
	lifecycleH := handler.NewLifecycleHandler(pool)

	// ── Access Review / Certification ────────────────────────────────────────
	accessReviewBaseURL := cfg.Auth.IssuerBase
	if accessReviewBaseURL == "" {
		scheme := "https"
		if cfg.HTTP.TLSCertFile == "" {
			scheme = "http"
		}
		accessReviewBaseURL = fmt.Sprintf("%s://%s", scheme, cfg.HTTP.BaseDomain)
	}
	// Strip trailing slash so all URL concatenations use a clean base.
	for len(accessReviewBaseURL) > 0 && accessReviewBaseURL[len(accessReviewBaseURL)-1] == '/' {
		accessReviewBaseURL = accessReviewBaseURL[:len(accessReviewBaseURL)-1]
	}
	accessReviewH := handler.NewAccessReviewHandler(pool, accessReviewBaseURL)

	// ── Login Flow Step Builder ───────────────────────────────────────────────
	loginFlowH := handler.NewLoginFlowHandler(pool)
	{
		flowRepo := repository.NewLoginFlowRepository(pool)
		mfaRepo := repository.NewMFARepository(pool)
		fe := flowengine.New(flowRepo, repository.NewUserRepository(pool), mfaRepo).
			WithOrgRepository(repository.NewOrgRepository(pool)).
			WithAuditEmitter(audit.NewEmitter(baseURL, repository.NewAuditRepository(pool))).
			WithSMTPRepository(repository.NewSMTPRepository(pool)).
			WithSMSSettingsRepository(repository.NewSMSSettingsRepository(pool)).
			WithDeviceFactsRepository(repository.NewDeviceFactsRepository(pool)).
			WithActionsRunner(sharedActionsRunner)
		oidcH.WithFlowEngine(fe)
	}

	// ── Clavex AI — AI-assisted admin features ────────────────────────────────
	aiH := handler.NewAIHandler(pool)

	// ── Clavex Shield — Threat Intelligence (optional) ──────────────────────────────
	// When auth.abuseipdb_key is configured the risk scorer enriches every
	// login-IP check with AbuseIPDB confidence scores + Tor exit-node data.
	if cfg.Auth.AbuseIPDBKey != "" {
		sc := shield.New(shield.Options{
			AbuseIPDBKey:       cfg.Auth.AbuseIPDBKey,
			AbuseIPDBThreshold: cfg.Auth.AbuseIPDBThreshold,
		})
		oidcH.WithShieldClient(sc)
		users.WithShieldClient(sc)
	}

	waPolicy := handler.NewWebAuthnPolicyHandler(pool)

	// Passkey portability — FIDO Alliance Credential Exchange Format (CXF).
	passkeyExchangeH := handler.NewPasskeyExchangeHandler(
		repository.NewMFARepository(pool),
		repository.NewUserRepository(pool),
		cfg.Auth.WebAuthnRPID,
		cfg.Auth.WebAuthnRPName,
	)

	// OpenID Federation 1.0 handler.
	fedH := federation.NewHandler(cfg, pool, keys).
		WithAuditor(audit.NewEmitter(baseURL, repository.NewAuditRepository(pool)))

	// AuthZen Authorization API 1.0 handler (OpenID Foundation).
	authzenH := handler.NewAuthZenHandler(cfg, pool, session.NewStore(rdb), keys)

	// ── Clavex Shield — Distributed threat feed (opt-in) ─────────────────────
	// License JWT is not available yet at New() time; it is injected in Start()
	// via UpdateLicenseJWT once WithLicense() has been called by the caller.
	var feedClient *shield.FeedClient
	if cfg.Shield.ThreatFeed.Enabled {
		fc, fcErr := shield.NewFeedClient(cfg.Shield.ThreatFeed, "")
		if fcErr != nil {
			log.Warn().Err(fcErr).Msg("shield: threat feed disabled (config error)")
		} else {
			feedClient = fc
			oidcH.WithFeedClient(fc)
			users.WithFeedClient(fc)
			authzenH.WithFeedClient(fc)
		}
	}

	// GDPR retention repository (used both for the handler and the worker below).
	gdprRepo := repository.NewGDPRRetentionRepository(pool)

	// ── Per-org rate limiter ─────────────────────────────────────────────────
	loginHistoryRepo := repository.NewLoginHistoryRepository(pool)
	orgRateLimiter := middleware.NewOrgRateLimiter(rdb, loginHistoryRepo)
	// OrgResolver resolves a slug to a UUID for the rate limiter.
	orgResolver := func(ctx context.Context, slug string) (uuid.UUID, error) {
		return repository.NewOrgRepository(pool).GetIDBySlug(ctx, slug)
	}

	// ── Clavex Guard — Adaptive Lockout ──────────────────────────────────────
	// Scales lockout duration with the real-time risk score: low-risk accounts
	// get a 30 s timeout; high-risk (Tor + new country + many failures) get up
	// to 60 min. Config is per-org via PUT /api/v1/organizations/:id/lockout.
	lockoutRepo := repository.NewLockoutRepository(pool)
	guard := lockout.New(rdb, lockoutRepo.Bands)
	oidcH.WithGuard(guard)
	emailOTPH.WithGuard(guard)
	phoneOTPH.WithGuard(guard)
	oidcH.WithIPRules(repository.NewIPRulesRepository(pool))
	oidcH.WithFeatureFlagRepository(repository.NewFeatureFlagRepository(pool))
	lockoutH := handler.NewLockoutHandler(lockoutRepo).
		WithGuard(guard).
		WithSessionStore(store).
		WithSMTP(repository.NewSMTPRepository(pool)).
		WithOrgRepository(repository.NewOrgRepository(pool)).
		WithConfig(cfg)
	// Health / readiness (no auth)
	e.GET("/healthz", health.Liveness)
	e.GET("/readyz", health.Readiness)
	// Prometheus metrics — protected by token or network policy in production
	e.GET("/metrics", echo.WrapHandler(promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{
		Registry: metrics.Registry(),
	})))
	// OpenAPI specification (no auth — enables Postman / Insomnia import)
	e.GET("/api/v1/openapi.json", handler.OpenAPI)
	// Branding cascade (no auth — called by login page to get merged branding)
	e.GET("/api/v1/branding", clientBrandingH.ResolveBranding)

	// ── Credential Marketplace — public discovery catalog (no auth) ───────────
	// GET /api/v1/marketplace/credentials          — list all verified listings
	// GET /api/v1/marketplace/credentials/:id      — single listing detail
	e.GET("/api/v1/marketplace/credentials", marketplaceH.ListPublic)
	e.GET("/api/v1/marketplace/credentials/:id", marketplaceH.GetPublic)

	// OID4VCI Final §12.2.2: suffix-form credential issuer metadata discovery.
	// The spec requires {scheme}://{host}/.well-known/openid-credential-issuer{path}
	// when the issuer identifier has a path component (e.g. /conformance).
	e.GET("/.well-known/openid-credential-issuer/:org_slug", oid4vciH.IssuerMetadata)

	// RFC 8414 §3: suffix-form OAuth Authorization Server metadata discovery.
	// When the AS issuer has a path component the metadata URL is:
	//   {scheme}://{host}/.well-known/oauth-authorization-server{path}
	// e.g. https://id.clavex.eu/.well-known/oauth-authorization-server/conformance
	e.GET("/.well-known/oauth-authorization-server/:org_slug", oidcH.Discovery)

	// SD-JWT VC Type Metadata (draft-ietf-oauth-sd-jwt-vc §6): a credential's
	// `vct` HTTPS URL must dereference to its Type Metadata document. VCTs are
	// minted under {base}/vct/<id>; the wildcard captures multi-segment ids.
	e.GET("/vct/*", oid4vciH.VCTTypeMetadata)

	// ── SPID global endpoints ─────────────────────────────────────────────────
	// Single instance-level metadata URL registered with AgID.
	e.GET("/spid/metadata", spidH.Metadata)
	// Single ACS callback URL (org identified via RelayState session).
	e.POST("/spid/callback", spidH.CallbackSSO)

	// OIDC / OAuth2 endpoints (RFC 8414 well-known + standard flows)
	// These are per-tenant: /{org_slug}/...
	tenant := e.Group("/:org_slug", middleware.HTMLPageCSP())
	{
		// Clavex Stream — real-time IAM event WebSocket feed for developers.
		// Auth via Bearer JWT header or ?token=<jwt> query param.
		tenant.GET("/events", streamH.Connect)

		// Discovery
		tenant.GET("/.well-known/openid-configuration", oidcH.Discovery)
		tenant.GET("/.well-known/oauth-authorization-server", oidcH.Discovery) // RFC 8414 prefix form
		tenant.GET("/.well-known/jwks.json", oidcH.JWKS)
		// Shared Signals Framework (SSF) transmitter metadata (RFC 8935/8936)
		tenant.GET("/.well-known/ssf-configuration", ssfH.TransmitterMetadata)
		// SSF poll endpoint — authenticated via access token (RFC 8936)
		tenant.POST("/ssf/poll", ssfH.Poll)
		// SSF receiver — accepts inbound CAEP SETs from upstream providers
		// (e.g. SPID/CIE national IDP) to trigger silent wallet step-up.
		// RFC 8935 §4: Content-Type: application/secevent+jwt
		tenant.POST("/ssf/events", caepReceiverH.ReceiveEvent)
		// OpenID Federation 1.0 — Entity Configuration (OIDF §6)
		// Returns a signed entity-statement+jwt when federation is enabled.
		tenant.GET("/.well-known/openid-federation", fedH.EntityConfiguration)
		// Explicit federation client registration (OIDF §9.6)
		tenant.POST("/federation/register", fedH.Register)
		// Trust Anchor federation endpoints (active only when federation.trust_anchor_mode = true)
		// OIDF §7.3.2 — fetch signed entity statement about a subordinate
		tenant.GET("/federation/fetch", fedH.FetchSubordinateStatement)
		// OIDF §7.3.1 — list immediate subordinate entity IDs
		tenant.GET("/federation/list", fedH.ListSubordinates)
		// Clavex extension — rich discovery list: Entity Statements + metadata for all active subordinates
		tenant.GET("/federation/subordinates", fedH.SubordinatesDiscovery)
		// OIDF §7.4 — issue a trust mark to a subject entity
		tenant.POST("/federation/trust-mark", fedH.TrustMarkEndpoint)
		// OIDF §7.5 — list subjects holding a given trust mark
		tenant.GET("/federation/trust-mark/list", fedH.TrustMarkListEndpoint)
		// OIDF §7.6 — check trust mark active/revoked status
		tenant.GET("/federation/trust-mark/status", fedH.TrustMarkStatusEndpoint)

		// AuthZen Authorization API 1.0 (OpenID Foundation)
		// POST /access/v1/evaluation  — single authorization decision (PDP)
		// POST /access/v1/evaluations — batch authorization decisions
		// GET  /access/v1/subject/:sub/attributes — PIP: subject attribute fetch
		tenant.POST("/access/v1/evaluation", authzenH.Evaluate)
		tenant.POST("/access/v1/evaluations", authzenH.EvaluateBatch)
		tenant.GET("/access/v1/subject/:sub/attributes", authzenH.SubjectAttributes)

		// Dynamic Client Registration (RFC 7591)
		tenant.POST("/register", oidcH.Register)

		// PAR (RFC 9126)
		tenant.POST("/par", oidcH.PushedAuthorizationRequest)

		// Device Authorization (RFC 8628)
		tenant.POST("/device_authorization", oidcH.DeviceAuthorization)
		tenant.GET("/device", oidcH.DeviceUserPage)
		tenant.POST("/device", oidcH.DeviceUserSubmit)
		tenant.GET("/device/login", oidcH.DeviceLoginPage)
		tenant.POST("/device/login", oidcH.DeviceLoginSubmit)
		tenant.GET("/device/consent", oidcH.DeviceConsentPage)
		tenant.POST("/device/consent", oidcH.DeviceConsentSubmit)

		// CIBA backchannel authentication endpoint (CIBA Core 1.0 — poll mode)
		tenant.POST("/bc-authorize", oidcH.BackchannelAuthorize)

		// Automated CIBA approval endpoint — OIDF conformance only (gated to the
		// conformance org slug inside the handler; 404 for any real tenant).
		tenant.POST("/ciba/automate", oidcH.ConformanceCIBAAutomate)

		// Authorization flow
		// Per-org login rate limit: max N password-submit attempts per IP per minute.
		tenant.GET("/authorize", oidcH.Authorize)
		// POST /authorize handles two cases (OIDC Core §3.1.2.1):
		//   1. A form-encoded authorization request from an RP (has response_type / client_id)
		//   2. A login form submission from our own login page (has login_session_id)
		// The dispatcher routes based on the presence of login_session_id in the body.
		tenant.POST("/authorize", oidcH.AuthorizeDispatch,
			orgRateLimiter.OrgLoginRateLimit("org_slug", orgResolver))

		// Token exchange — per-org token rate limit (prevents brute-force via client_credentials).
		tenant.POST("/token", oidcH.Token,
			orgRateLimiter.OrgTokenRateLimit("org_slug", orgResolver))

		// Token introspection & revocation (RFC 7662 / RFC 7009)
		tenant.POST("/introspect", oidcH.Introspect)
		tenant.POST("/revoke", oidcH.Revoke)

		// UserInfo (RFC 9068)
		tenant.GET("/userinfo", oidcH.UserInfo)
		tenant.POST("/userinfo", oidcH.UserInfo)

		// Push device token self-registration (mobile apps, bearer auth)
		tenant.POST("/push/device-token", oidcH.PushRegisterDeviceToken)
		tenant.DELETE("/push/device-token", oidcH.PushDeleteDeviceToken)

		// End-session (OIDC RP-Initiated Logout)
		tenant.GET("/logout", oidcH.Logout)
		tenant.POST("/logout", oidcH.Logout)

		// Session Management iframe (OIDC Session Management 1.0 §3.3)
		tenant.GET("/check-session", oidcH.CheckSession)

		// MFA step-up (TOTP challenge after password in the authorize flow)
		tenant.POST("/mfa-challenge", oidcH.MFAChallengeSubmit)

		// Post-login continuation (IdP callback, email verification, etc.)
		tenant.GET("/authorize/cancel", oidcH.CancelLogin)
		tenant.GET("/authorize/resume", oidcH.AuthorizeResume)
		tenant.GET("/verify-email", oidcH.VerifyEmail)
		tenant.GET("/reset-password", oidcH.ResetPasswordPage)
		tenant.POST("/reset-password", oidcH.ResetPasswordSubmit)
		tenant.GET("/update-password", oidcH.UpdatePasswordPage)
		tenant.POST("/update-password", oidcH.UpdatePasswordSubmit)
		tenant.GET("/breach-warning", oidcH.BreachWarningPage)
		tenant.POST("/breach-warning", oidcH.BreachWarningAcknowledge)

		// ── Passkey enroll-on-next-login (ENROLL_PASSKEY required action) ────
		tenant.GET("/enroll-passkey", passkeyEnrollH.EnrollPage)
		tenant.POST("/enroll-passkey/begin", passkeyEnrollH.EnrollBegin)
		tenant.POST("/enroll-passkey/finish", passkeyEnrollH.EnrollFinish)

		// ── Email OTP passwordless flow ────────────────────────────────────────
		tenant.GET("/otp", emailOTPH.RequestPage)
		tenant.POST("/otp/send", emailOTPH.Send)
		tenant.GET("/otp/verify", emailOTPH.VerifyPage)
		tenant.POST("/otp/verify", emailOTPH.VerifySubmit)

		// ── Phone (SMS) OTP first-factor login ────────────────────────────────
		tenant.GET("/phone-otp", phoneOTPH.RequestPage)
		tenant.POST("/phone-otp/send", phoneOTPH.Send)
		tenant.GET("/phone-otp/verify", phoneOTPH.VerifyPage)
		tenant.POST("/phone-otp/verify", phoneOTPH.VerifySubmit)

		// Invite accept (public tenant route)
		tenant.GET("/invite/accept", invitations.ShowAcceptPage)
		tenant.POST("/invite/accept", invitations.Accept)

		// SAML 2.0 IdP endpoints
		tenant.GET("/saml/metadata", saml.Metadata)
		tenant.GET("/saml/sso", saml.SSO)
		tenant.POST("/saml/sso", saml.SSO)
		tenant.POST("/saml/slo", saml.SLO)

		// ── SPID SP endpoints ─────────────────────────────────────────────────
		// Metadata (public — required by AgID registrar)
		tenant.GET("/spid/metadata", spidH.Metadata)
		// IdP picker (returns list of active SPID IdPs with logos)
		tenant.GET("/spid/idps", spidH.ListIdPs)
		// SSO: browser submits a signed AuthnRequest via HTTP-POST to the chosen IdP
		tenant.GET("/spid/sso/:idp_id", spidH.StartSSO)
		// Level upgrade: flow engine redirects here to re-authenticate at a higher SPID level
		tenant.GET("/spid/upgrade", spidH.UpgradeSSO)
		// Callback: IdP POSTs the SAMLResponse back here
		tenant.POST("/spid/callback", spidH.CallbackSSO)

		// ── CIE OIDC endpoints ────────────────────────────────────────────────
		tenant.GET("/cie/:idp_id", cieH.StartSSO)
		tenant.GET("/cie/upgrade", cieH.UpgradeSSO)
		tenant.GET("/cie/:idp_id/callback", cieH.CallbackSSO)

		// ── FranceConnect v2 OIDC endpoints ──────────────────────────────────
		tenant.GET("/franceconnect/:idp_id", franceConnectH.StartSSO)
		tenant.GET("/franceconnect/:idp_id/callback", franceConnectH.CallbackSSO)

		// ── itsme® OIDC endpoints (Belgium / Luxembourg) ─────────────────────
		tenant.GET("/itsme/:idp_id", itsmeH.StartSSO)
		tenant.GET("/itsme/:idp_id/callback", itsmeH.CallbackSSO)

		// ── BundID OIDC endpoints (Germany / FITKO) ──────────────────────────
		tenant.GET("/bundid/:idp_id", bundidH.StartSSO)
		tenant.GET("/bundid/:idp_id/callback", bundidH.CallbackSSO)

		// ── Cl@ve OIDC endpoints (Spain / SGAD) ──────────────────────────────
		tenant.GET("/clave/:idp_id", claveH.StartSSO)
		tenant.GET("/clave/:idp_id/callback", claveH.CallbackSSO)

		// ── DigiD OIDC endpoints (Netherlands / Logius) ──────────────────────
		tenant.GET("/digid/:idp_id", digidH.StartSSO)
		tenant.GET("/digid/:idp_id/callback", digidH.CallbackSSO)

		// ── BundID SAML SP endpoints (Germany / FITKO) ──────────────────────
		// Public SP metadata (submit URL to FITKO during registration)
		tenant.GET("/bundidsaml/metadata", bundidSAMLH.Metadata)
		// SSO entry point (browser is POSTed to BundID via HTTP-POST binding)
		tenant.GET("/bundidsaml/sso", bundidSAMLH.StartSSO)
		// ACS callback (BundID POSTs SAMLResponse here)
		tenant.POST("/bundidsaml/callback", bundidSAMLH.CallbackSSO)

		// ── eIDAS node integration (27 EU member states) ──────────────────────
		tenant.GET("/eidas/sso", eidasH.StartSSO)
		tenant.POST("/eidas/callback", eidasH.CallbackSSO)

		// ── Passkey (discoverable credential / conditional UI) ────────────────
		// Public endpoints — no session required; user is resolved from credential ID.
		tenant.POST("/passkey/login/begin", mfa.BeginPasskeyLogin)
		tenant.POST("/passkey/login/finish", mfa.FinishPasskeyLogin)

		// ── OID4VCI (Verifiable Credential Issuance) ──────────────────────────
		// Credential issuer metadata (OID4VCI §10.2)
		tenant.GET("/.well-known/openid-credential-issuer", oid4vciH.IssuerMetadata)
		// Trust anchor for credential x5c chains (HAIP-6.1 / EnsureCredentialTrustAnchorConfigured).
		// Configure this URL in the conformance suite "Credential Trust Anchor" field.
		tenant.GET("/.well-known/credential-issuer-ca.pem", oid4vciH.CredentialIssuerCA)
		// Pre-authorized code token exchange
		tenant.POST("/oid4vci/token", oid4vciH.Token)
		// OID4VCI Final Appendix A: nonce endpoint; returns c_nonce for key proof JWTs.
		tenant.POST("/oid4vci/nonce", oid4vciH.Nonce)
		// Credential issuance (pre-auth flow and authorization_code wallet-initiated flow)
		tenant.POST("/oid4vci/credential", oid4vciH.Credential)
		tenant.POST("/oid4vci/batch-credential", oid4vciH.BatchCredential)
		tenant.POST("/oid4vci/deferred-credential", oid4vciH.DeferredCredential)
		// OID4VCI Final §7: post-issuance wallet notifications (accepted/deleted/failure).
		tenant.POST("/oid4vci/notification", oid4vciH.Notification)
		// Status list (Token Status List — IETF draft-ietf-oauth-status-list)
		tenant.GET("/oid4vci/status-list/:list_id", oid4vciH.StatusList)
		// SSE push for credential lifecycle events (revoked / restored).
		// Wallet subscribes by presenting its SD-JWT as a Bearer token.
		tenant.GET("/oid4vci/status-updates", oid4vciH.StatusUpdates)
		// Privacy-preserving analytics (blind signature scheme)
		tenant.GET("/oid4vci/analytics/public-key", analyticsH.PublicKey)
		tenant.POST("/oid4vci/analytics/token", analyticsH.IssueBlindToken)
		tenant.POST("/oid4vci/analytics/report", analyticsH.Report)
		// Credential offer JSON (by-reference) — wallets fetch this via credential_offer_uri
		tenant.GET("/oid4vci/offers/:offer_id", oid4vciH.OfferJSON)
		// QR code for credential offers — wallet scans to start the pre-authorized code flow
		tenant.GET("/oid4vci/offers/:offer_id/qr", oid4vciH.OfferQR)

		// ── OID4VP (Verifiable Presentations) ────────────────────────────────
		// Create a presentation request (verifier creates a request URI)
		tenant.POST("/wallet/request", oid4vpH.CreateRequest)
		// Wallet fetches the request object
		tenant.GET("/wallet/request/:req_id", oid4vpH.GetRequest)
		// QR code for the verifier front-office UI — IT-Wallet / EUDIW scans this
		tenant.GET("/wallet/request/:req_id/qr", oid4vpH.RequestQR)
		// Wallet POSTs the vp_token response
		tenant.POST("/wallet/response", oid4vpH.Response)

		// ── Wallet step-up (Continuous Adaptive Authentication) ──────────────
		// Wallet fetches the OID4VP authorization request for the step-up challenge
		tenant.GET("/wallet/stepup/:challenge_id", walletStepUpH.GetRequest)
		// Wallet POSTs the vp_token to complete the step-up challenge
		tenant.POST("/wallet/stepup/:challenge_id/response", walletStepUpH.SubmitResponse)
		// OID4VP presentation status polling (used by in-login challenge page)
		tenant.GET("/wallet/request/:req_id/status", oid4vpH.RequestStatus)
		// OID4VP in-login challenge page (oid4vp_challenge flow step)
		tenant.GET("/authorize/oid4vp-challenge", oidcH.OID4VPChallengePage)
		// OID4VP resume (browser redirects here after wallet presentation is verified)
		tenant.GET("/authorize/oid4vp-resume", oidcH.OID4VPResume)

		// ── eIDAS 2.0 mdoc proximity flow (ISO 18013-5 / OID4VP+QR) ─────────
		// Operator/counter starts a session and gets a QR URI to display
		tenant.POST("/mdoc/proximity/start", mdocProximityH.StartSession)
		// Browser-rendered QR page with live status polling
		tenant.GET("/mdoc/proximity/:req_id/qr", mdocProximityH.QRPage)
		// Wallet fetches the signed OID4VP AuthorizationRequest
		tenant.GET("/mdoc/request/:req_id", mdocProximityH.GetRequest)
		// Wallet POSTs the CBOR DeviceResponse
		tenant.POST("/mdoc/response", mdocProximityH.Response)
		// Browser polls for session completion
		tenant.GET("/mdoc/proximity/:req_id/status", mdocProximityH.StatusPoll)

		// ── User self-service portal (/account/...) ──────────────────────────
		// Public: Account Center widget config — consumed by <ClavexAccountCenter />
		// before the user is authenticated; no auth required.
		tenant.GET("/account-center/config", accountCenterH.GetConfig)
		// Public login/logout (no cookie required)
		tenant.GET("/account/login", accountH.LoginPage)
		tenant.POST("/account/login", accountH.LoginSubmit)
		tenant.POST("/account/logout", accountH.Logout)
		// GDPR erasure confirm/cancel — token-authenticated, no session required
		tenant.GET("/account/erasure/confirm", accountH.ConfirmErasure)
		tenant.GET("/account/erasure/cancel", accountH.CancelErasure)

		// Access Review one-time decision links — token-authenticated, no session required.
		// Reviewers click these links from their email to approve or revoke access.
		tenant.GET("/access-review/decide", accessReviewH.Decide)

		// Cookie-authenticated routes
		acct := tenant.Group("/account", accountH.RequireAccountSession)
		acct.GET("", accountH.Profile)
		acct.POST("/profile", accountH.UpdateProfile)
		acct.POST("/password", accountH.ChangePassword)
		acct.GET("/sessions", accountH.Sessions)
		acct.POST("/sessions/:id/revoke", accountH.RevokeSession)
		acct.POST("/sessions/revoke-all", accountH.RevokeAllSessions)
		acct.GET("/security", accountH.Security)
		acct.POST("/security/mfa/:id/delete", accountH.DeleteMFA)
		// Self-service device trust management
		acct.POST("/security/devices/:id/revoke", accountH.RevokeDevice)
		acct.POST("/security/devices/revoke-all", accountH.RevokeAllDevices)
		// TOTP self-enrollment (session-cookie auth, no JWT needed)
		acct.POST("/security/totp/enroll", accountH.BeginTOTPEnrollment)
		acct.GET("/security/totp/:cred_id/qr", accountH.TOTPQRImage)
		acct.POST("/security/totp/confirm", accountH.ConfirmTOTPEnrollment)
		// Hybrid passkey enrollment — FIDO2 cross-device via QR (CTAP 2.2 caBLE)
		acct.POST("/security/passkey/hybrid/begin", accountH.BeginHybridPasskeyRegistration)
		acct.POST("/security/passkey/hybrid/finish", accountH.FinishHybridPasskeyRegistration)
		acct.GET("/activity", accountH.Activity)
		// GDPR self-service erasure (cookie-auth, within grace period)
		acct.POST("/erasure/request", accountH.RequestErasure)
	}

	// ── OID4VP endpoints under /api/v1 (for frontend API client compatibility) ──
	apiTenant := e.Group("/api/v1/:org_slug")
	{
		apiTenant.POST("/wallet/request", oid4vpH.CreateRequest)
		apiTenant.GET("/wallet/request/:req_id", oid4vpH.GetRequest)
		apiTenant.GET("/wallet/request/:req_id/qr", oid4vpH.RequestQR)
		apiTenant.POST("/wallet/response", oid4vpH.Response)
	}

	// ── Admin authentication (no JWT required) ───────────────────────────────
	loginGroup := e.Group("/api/v1/auth")
	loginGroup.Use(echomw.RateLimiterWithConfig(echomw.RateLimiterConfig{
		Skipper: echomw.DefaultSkipper,
		Store: echomw.NewRateLimiterMemoryStoreWithConfig(
			echomw.RateLimiterMemoryStoreConfig{Rate: 5, Burst: 10, ExpiresIn: 1 * 60 * 1000000000},
		),
		IdentifierExtractor: func(ctx echo.Context) (string, error) {
			return ctx.RealIP(), nil
		},
		ErrorHandler: func(context echo.Context, err error) error {
			return context.JSON(http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		},
		DenyHandler: func(context echo.Context, identifier string, err error) error {
			return context.JSON(http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		},
	}))
	loginGroup.POST("/login", auth.Login)
	loginGroup.POST("/logout", auth.Logout)

	// Build the API-key verifier used by RequireAdminJWT.
	apiKeyRepo := repository.NewAdminAPIKeyRepository(pool)
	apiKeyVerifier := middleware.APIKeyVerifyFunc(func(ctx context.Context, rawKey string) (*middleware.Claims, error) {
		auth, err := apiKeyRepo.VerifyKey(ctx, rawKey)
		if err != nil {
			return nil, err
		}
		if auth == nil {
			return nil, nil // not our format, fall through to JWT
		}
		return &middleware.Claims{
			IsAdmin:      true,
			IsSuperAdmin: true,
		}, nil
	})

	// ── Admin API (JWT-authenticated) ─────────────────────────────────────────
	admin := e.Group("/api/v1", middleware.RequireAdminJWT(cfg, apiKeyVerifier), middleware.CSRFProtect(cfg))
	{
		// Organizations — superadmin only
		adminOrgs := admin.Group("/organizations", middleware.RequireSuperAdmin())
		adminOrgs.POST("", orgs.Create)
		adminOrgs.POST("/provision", orgs.Provision)
		adminOrgs.GET("", orgs.List)
		adminOrgs.GET("/:id", orgs.Get)
		adminOrgs.PATCH("/:id", orgs.Update)
		adminOrgs.GET("/:id/security-posture", orgs.SecurityPosture)
		adminOrgs.DELETE("/:id", orgs.Delete)
		// Email policy (blocklist / allowlist)
		adminOrgs.GET("/:id/email-policy", orgs.GetEmailPolicy)
		adminOrgs.PUT("/:id/email-policy", orgs.SetEmailPolicy)
		// Feature flags
		adminOrgs.GET("/:id/feature-flags", orgs.ListFeatureFlags)
		adminOrgs.POST("/:id/feature-flags", orgs.UpsertFeatureFlag)
		adminOrgs.DELETE("/:id/feature-flags/:key", orgs.DeleteFeatureFlag)
		adminOrgs.GET("/:id/feature-flags/:key/overrides", orgs.ListFlagOverrides)
		adminOrgs.PUT("/:id/feature-flags/:key/overrides", orgs.SetFlagOverride)
		adminOrgs.DELETE("/:id/feature-flags/:key/overrides", orgs.DeleteFlagOverride)
		// BYOK: per-org signing key management (only available with key_backend=db)
		if len(orgSigners) > 0 && orgSigners[0] != nil {
			orgKeyH := handler.NewOrgSigningKeyHandler(pool, orgSigners[0])
			adminOrgs.GET("/:id/signing-key", orgKeyH.Get)
			adminOrgs.PUT("/:id/signing-key", orgKeyH.Upsert)
			adminOrgs.DELETE("/:id/signing-key", orgKeyH.Delete)
		}

		// Admin API keys — superadmin only
		adminAPIKeys := admin.Group("/superadmin/api-keys", middleware.RequireSuperAdmin())
		adminAPIKeys.POST("", apiKeys.Create)
		adminAPIKeys.GET("", apiKeys.List)
		adminAPIKeys.DELETE("/:id", apiKeys.Revoke)

		// Installation health dashboard + license status — superadmin only
		adminSuperadmin := admin.Group("/superadmin", middleware.RequireSuperAdmin())
		adminSuperadmin.GET("/health", healthDash.Get)
		// License status is wired in Start() once the checker is known.

		// Impersonation — generate a short-lived token as a target user (superadmin only)
		impersonateH := handler.NewImpersonationHandler(cfg, pool)
		adminSuperadmin.POST("/impersonate/:user_id", impersonateH.Impersonate)

		// Signing-key rotation — generates a new RSA key; the old key stays in
		// the JWKS so existing tokens remain verifiable.  Used before running
		// the oidcc-server-rotate-keys conformance test.
		adminSuperadmin.POST("/rotate-signing-key", func(c echo.Context) error {
			if err := keys.Rotate(); err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}
			return c.JSON(http.StatusOK, map[string]string{"kid": keys.KID()})
		})

		// PQC (ML-DSA-65) signing-key rotation. Returns 404 when pqc_enabled=false.
		adminSuperadmin.POST("/rotate-pqc-signing-key", oidcH.RotatePQCSigningKey)

		// Request-object encryption-key rotation — generates a new RSA enc key;
		// the old key is retained for the decryption grace window. Returns 404
		// when request-object encryption is not enabled (key_backend != db).
		adminSuperadmin.POST("/rotate-enc-key", oidcH.RotateEncKey)

		// Installation-level signing-key rotation policy (OIDC/PQC). These keys
		// are global singletons; only a superadmin may change their policy.
		// Manual immediate rotation is the rotate-signing-key endpoints above.
		srKeyRotH := handler.NewKeyRotationHandler(cfg, pool)
		adminSuperadmin.GET("/signing-keys", srKeyRotH.InstallationStatus)
		adminSuperadmin.PUT("/signing-keys/:kind", srKeyRotH.InstallationSetPolicy)

		// SPID instance config — global, not org-scoped (singleton SP identity + keypair)
		admin.GET("/spid/instance-config", spidH.GetInstanceConfig)
		admin.PUT("/spid/instance-config", spidH.UpsertInstanceConfig)
		admin.GET("/spid/metadata", spidH.GetMetadataAdmin)

		// Per-org resources — scoped to caller's org (or superadmin)
		orgScoped := admin.Group("/organizations/:org_id", middleware.RequireOrgAccess())

		// Social provider presets — returns canonical endpoints for all known provider types.
		// Not org-scoped: the presets are global and do not depend on org configuration.
		admin.GET("/social-providers/presets", idpH.Presets)

		// Permission catalogue — list all valid permission tokens (no org scope needed).
		admin.GET("/admin-roles/permissions", delegationH.ListPermissions)

		// Delegated admin roles (CRUD) — protected by delegated_admins permission.
		adminDelegation := orgScoped.Group("/admin-roles", middleware.RequireResourcePermission("delegated_admins"))
		adminDelegation.POST("", delegationH.Create)
		adminDelegation.GET("", delegationH.List)
		adminDelegation.GET("/:role_id", delegationH.Get)
		adminDelegation.PATCH("/:role_id", delegationH.Update)
		adminDelegation.DELETE("/:role_id", delegationH.Delete)
		// Idempotently seed the built-in system roles for the org.
		adminDelegation.POST("/system/ensure", delegationH.EnsureSystemRoles)

		// User admin-role assignments (nested under /users/:user_id)
		// These sit inside the users permission domain.
		adminUsers := orgScoped.Group("/users", middleware.RequireResourcePermission("users"))
		adminUsers.POST("", users.Create)
		adminUsers.GET("", users.List)
		adminUsers.GET("/:id", users.Get)
		adminUsers.PATCH("/:id", users.Update)
		adminUsers.DELETE("/:id", users.Delete)
		adminUsers.POST("/:id/password-reset", users.SendPasswordReset)
		adminUsers.PUT("/:id/required-actions", users.SetRequiredActions)
		adminUsers.PUT("/:id/attributes", users.PatchAttributes)
		adminUsers.POST("/:id/impersonate", impersonation.Impersonate)
		// Bulk import (CSV or JSON)
		adminUsers.POST("/import", importH.ImportUsers)
		// Identity Continuity: import verified identity claims from another Clavex installation.
		// The user presents an SD-JWT-VC issued by a remote Clavex ("Clavex A") and this
		// installation verifies it via JWKS discovery, then stores the claims in the user's profile.
		adminUsers.POST("/:user_id/identity/import", identityImportH.ImportIdentity)

		// User sessions (scoped to user)
		adminUsers.GET("/:user_id/sessions", sessions.ListUserSessions)
		adminUsers.DELETE("/:user_id/sessions", sessions.RevokeAllUserSessions)
		adminUsers.DELETE("/:user_id/sessions/others", sessions.RevokeAllUserSessionsExcept)
		// Login history + anomaly signals (per user)
		adminUsers.GET("/:user_id/login-history", loginHistoryH.ListUserLoginHistory)
		adminUsers.GET("/:user_id/anomaly-signals", loginHistoryH.GetAnomalySignals)
		adminUsers.GET("/:user_id/risk-score", users.RiskScore)
		// RAR grant revocation (PSD2 §66) — revoke all grants for a user.
		adminUsers.DELETE("/:id/grants", grantsH.RevokeAll)

		// Wallet step-up — Continuous Adaptive Authentication (CAA):
		// admin/RS creates a step-up challenge; backend/RS polls for completion.
		adminUsers.POST("/:user_id/wallet-stepup", walletStepUpH.CreateChallenge)
		orgScoped.GET("/wallet-stepup/:challenge_id", walletStepUpH.GetChallengeStatus,
			middleware.RequireResourcePermission("users"))

		// Delegated admin role assignments per user (requires delegated_admins permission).
		adminUsers.GET("/:user_id/admin-roles", delegationH.ListUserRoles,
			middleware.RequireResourcePermission("delegated_admins"))
		adminUsers.PUT("/:user_id/admin-roles/:role_id", delegationH.AssignUserRole,
			middleware.RequireResourcePermission("delegated_admins"))
		adminUsers.DELETE("/:user_id/admin-roles/:role_id", delegationH.UnassignUserRole,
			middleware.RequireResourcePermission("delegated_admins"))

		// Org-level risk dashboard (aggregated across all users)
		orgScoped.GET("/risk-dashboard", users.RiskDashboard, middleware.RequireResourcePermission("audit"))

		// Breached-password security dashboard
		breachDashH := handler.NewBreachDashboardHandler(pool)
		orgScoped.GET("/security/breached-passwords", breachDashH.GetDashboard, middleware.RequireResourcePermission("security"))

		// Fleet connector — device-fact ingestion + device listing
		fleetH := handler.NewFleetHandler(pool)
		orgScoped.POST("/fleet/ingest", fleetH.Ingest) // public: authenticated by X-Fleet-Token
		orgScoped.GET("/fleet/devices", fleetH.ListDevices, middleware.RequireResourcePermission("users"))

		// Clavex Shield threat-intelligence ops dashboard
		shieldDashH := handler.NewShieldDashboardHandler(pool, cfg.Auth.AbuseIPDBKey != "")
		orgScoped.GET("/shield-dashboard", shieldDashH.Dashboard, middleware.RequireResourcePermission("audit"))

		// RAR / consent grant management (PSD2 §66 — granular grant visibility & revocation)
		orgScoped.GET("/grants", grantsH.List, middleware.RequireResourcePermission("compliance"))
		orgScoped.GET("/grants/:grant_id", grantsH.Get, middleware.RequireResourcePermission("compliance"))
		orgScoped.DELETE("/grants/:grant_id", grantsH.Revoke, middleware.RequireResourcePermission("compliance"))

		// Invitations
		orgScoped.GET("/invitations", invitations.List, middleware.RequireResourcePermission("users"))
		orgScoped.POST("/invitations", invitations.Create, middleware.RequireResourcePermission("users"))
		orgScoped.DELETE("/invitations/:id", invitations.Delete, middleware.RequireResourcePermission("users"))

		// IP allowlist
		ipAllowlist := handler.NewIPAllowlistHandler(pool)
		orgScoped.GET("/ip-allowlist", ipAllowlist.List, middleware.RequireResourcePermission("security"))
		orgScoped.POST("/ip-allowlist", ipAllowlist.Add, middleware.RequireResourcePermission("security"))
		orgScoped.DELETE("/ip-allowlist/:entry_id", ipAllowlist.Delete, middleware.RequireResourcePermission("security"))

		// Custom domains (SaaS Enterprise — CNAME + Let's Encrypt / Traefik)
		customDomainH := handler.NewCustomDomainHandler(pool, enc)
		orgScoped.GET("/custom-domains", customDomainH.List, middleware.RequireResourcePermission("security"))
		orgScoped.POST("/custom-domains", customDomainH.Create, middleware.RequireResourcePermission("security"))
		orgScoped.DELETE("/custom-domains/:domain_id", customDomainH.Delete, middleware.RequireResourcePermission("security"))
		orgScoped.POST("/custom-domains/:domain_id/verify", customDomainH.Verify, middleware.RequireResourcePermission("security"))
		orgScoped.PUT("/custom-domains/:domain_id/certificate", customDomainH.UploadCert, middleware.RequireResourcePermission("security"))
		orgScoped.DELETE("/custom-domains/:domain_id/certificate", customDomainH.RevertCert, middleware.RequireResourcePermission("security"))

		// IP rules (allow/deny CIDR list)
		ipRulesH := handler.NewIPRulesHandler(repository.NewIPRulesRepository(pool))
		orgScoped.GET("/ip-rules", ipRulesH.List, middleware.RequireResourcePermission("security"))
		orgScoped.POST("/ip-rules", ipRulesH.Create, middleware.RequireResourcePermission("security"))
		orgScoped.DELETE("/ip-rules/:rule_id", ipRulesH.Delete, middleware.RequireResourcePermission("security"))

		// Roles
		adminRoles := orgScoped.Group("/roles", middleware.RequireResourcePermission("roles"))
		adminRoles.POST("", users.CreateRole)
		adminRoles.GET("", users.ListRoles)
		adminRoles.DELETE("/:role_id", users.DeleteRole)
		adminRoles.PUT("/:role_id/users/:user_id", users.AssignRole)
		adminRoles.DELETE("/:role_id/users/:user_id", users.UnassignRole)
		// Composite roles
		adminRoles.GET("/:role_id/children", users.ListChildRoles)
		adminRoles.PUT("/:role_id/children/:child_id", users.AddChildRole)
		adminRoles.DELETE("/:role_id/children/:child_id", users.RemoveChildRole)

		// Groups
		adminGroups := orgScoped.Group("/groups", middleware.RequireResourcePermission("groups"))
		adminGroups.POST("", groups.Create)
		adminGroups.GET("", groups.List)
		adminGroups.GET("/:id", groups.Get)
		adminGroups.DELETE("/:id", groups.Delete)
		adminGroups.GET("/:id/members", groups.ListMembers)
		adminGroups.POST("/:id/members", groups.AddMember)
		adminGroups.DELETE("/:id/members/:user_id", groups.RemoveMember)
		adminGroups.GET("/:id/roles", groups.ListRoles)
		adminGroups.POST("/:id/roles", groups.AssignRole)
		adminGroups.DELETE("/:id/roles/:role_id", groups.RemoveRole)

		// OIDC clients
		adminClients := orgScoped.Group("/clients", middleware.RequireResourcePermission("clients"))
		adminClients.POST("", clients.Create)
		adminClients.GET("", clients.List)
		adminClients.GET("/:id", clients.Get)
		adminClients.PATCH("/:id", clients.Update)
		adminClients.DELETE("/:id", clients.Delete)
		adminClients.POST("/:id/secret", clients.RotateSecret)

		// Quick-register: derive redirect URIs from an app URL and create an OIDC client in one step.
		// Designed for the create-clavex-app CLI and the onboarding wizard.
		orgScoped.POST("/quick-register", clients.QuickRegister, middleware.RequireResourcePermission("clients"))

		// Client scope assignments (per-client)
		scopesH := handler.NewClientScopeHandler(pool)
		adminClients.GET("/:client_id/scopes", scopesH.ListByClient)
		adminClients.PUT("/:client_id/scopes/:scope_id", scopesH.AssignToClient)
		adminClients.DELETE("/:client_id/scopes/:scope_id", scopesH.UnassignFromClient)

		// Org-level client scope definitions
		adminScopes := orgScoped.Group("/client-scopes", middleware.RequireResourcePermission("clients"))
		adminScopes.POST("", scopesH.Create)
		adminScopes.GET("", scopesH.List)
		adminScopes.PUT("/:scope_id", scopesH.Update)
		adminScopes.DELETE("/:scope_id", scopesH.Delete)

		// Protocol mappers (per-client)
		adminMappers := orgScoped.Group("/clients/:client_id/mappers", middleware.RequireResourcePermission("clients"))
		adminMappers.POST("", mappers.Create)
		adminMappers.GET("", mappers.List)
		adminMappers.PATCH("/:id", mappers.Update)
		adminMappers.DELETE("/:id", mappers.Delete)

		// Org-level sessions
		orgScoped.GET("/sessions", sessions.ListOrgSessions, middleware.RequireResourcePermission("sessions"))
		orgScoped.DELETE("/sessions/:id", sessions.RevokeSession, middleware.RequireResourcePermission("sessions"))

		// Security posture (accessible to org admins, not superadmin-only)
		orgScoped.GET("/security-posture", orgs.SecurityPostureOrgAdmin, middleware.RequireResourcePermission("security"))

		// Email policy — org admins can configure blocklist/allowlist
		orgScoped.GET("/email-policy", orgs.GetEmailPolicyOrgAdmin, middleware.RequireResourcePermission("security"))
		orgScoped.PUT("/email-policy", orgs.SetEmailPolicyOrgAdmin, middleware.RequireResourcePermission("security"))
		// Feature flags — org admins can manage flags and overrides
		orgScoped.GET("/feature-flags", orgs.ListFeatureFlagsOrgAdmin, middleware.RequireResourcePermission("security"))
		orgScoped.POST("/feature-flags", orgs.UpsertFeatureFlagOrgAdmin, middleware.RequireResourcePermission("security"))
		orgScoped.DELETE("/feature-flags/:key", orgs.DeleteFeatureFlagOrgAdmin, middleware.RequireResourcePermission("security"))
		orgScoped.GET("/feature-flags/:key/overrides", orgs.ListFlagOverridesOrgAdmin, middleware.RequireResourcePermission("security"))
		orgScoped.PUT("/feature-flags/:key/overrides", orgs.SetFlagOverrideOrgAdmin, middleware.RequireResourcePermission("security"))
		orgScoped.DELETE("/feature-flags/:key/overrides", orgs.DeleteFlagOverrideOrgAdmin, middleware.RequireResourcePermission("security"))

		// Usage analytics — MAU/DAU, logins by method, top clients.
		// Used by the Cloud billing dashboard and enterprise Security Posture report.
		orgScoped.GET("/usage", usageH.GetOrgUsage, middleware.RequireResourcePermission("audit"))

		// LDAP connections
		adminLDAP := orgScoped.Group("/ldap")
		adminLDAP.POST("", ldap.Create)
		adminLDAP.GET("", ldap.List)
		adminLDAP.GET("/:id", ldap.Get)
		adminLDAP.PATCH("/:id", ldap.Update)
		adminLDAP.DELETE("/:id", ldap.Delete)
		adminLDAP.POST("/:id/test", ldap.TestConnection)
		adminLDAP.POST("/:id/sync", ldap.Sync)

		// MFA admin (unrestricted — admins can always wipe credentials for recovery)
		adminMFA := orgScoped.Group("/users/:user_id/mfa", middleware.RequireResourcePermission("users"))
		adminMFA.GET("", mfa.List)
		adminMFA.DELETE("/:cred_id", mfa.Delete)

		// WebAuthn attestation policy — enterprise BYOD / zero-trust passkey enforcement
		waP := orgScoped.Group("/webauthn-policy", middleware.RequireResourcePermission("security"))
		waP.GET("", waPolicy.Get)
		waP.PUT("", waPolicy.Upsert)
		waP.DELETE("", waPolicy.Delete)
		// Preview: GET /webauthn-policy/preview?min_cert_level=L2&exclude_revoked=true
		// Returns all MDS3 catalog entries satisfying the cert-level constraint —
		// so admins can see "N devices qualify at L2+" without knowing any AAGUIDs.
		waP.GET("/preview", waPolicy.PreviewPolicy)
		// Built-in attestation policy presets (hardware-key-only, phishing-resistant, fido2-certified)
		waP.GET("/presets", waPolicy.ListPresets)
		waP.POST("/presets/:preset_name", waPolicy.ApplyPreset)
		// Scoped policies: per-group or per-role attestation overrides.
		waP.GET("/scoped", waPolicy.ListScoped)
		waP.GET("/scoped/:scope_type/:scope_id", waPolicy.GetScoped)
		waP.PUT("/scoped/:scope_type/:scope_id", waPolicy.UpsertScoped)
		waP.DELETE("/scoped/:scope_type/:scope_id", waPolicy.DeleteScoped)

		// FIDO MDS3 catalog — browse certified authenticators and trigger refresh
		mdsH := handler.NewMDSHandler(pool)
		mdsG := orgScoped.Group("/mds", middleware.RequireResourcePermission("security"))
		mdsG.GET("/entries", mdsH.ListEntries)
		mdsG.GET("/entries/:aaguid", mdsH.GetEntry)
		mdsG.GET("/sync", mdsH.GetSyncStatus)
		mdsG.POST("/sync", mdsH.TriggerSync)

		// Audit log (structured, CloudEvents, cursor-paginated)
		auditG := orgScoped.Group("/audit", middleware.RequireResourcePermission("audit"))
		auditG.GET("", auditH.List)
		auditG.GET("/export", auditH.Export)
		auditG.GET("/stream", auditH.StreamLive)
		auditG.GET("/retention", auditH.GetRetention)
		auditG.PUT("/retention", auditH.UpdateRetention)
		auditSinks := auditG.Group("/sinks")
		auditSinks.GET("", auditH.ListSinks)
		auditSinks.POST("", auditH.CreateSink)
		auditSinks.GET("/:sink_id", auditH.GetSink)
		auditSinks.PATCH("/:sink_id", auditH.UpdateSink)
		auditSinks.DELETE("/:sink_id", auditH.DeleteSink)
		auditSinks.POST("/:sink_id/test", auditH.TestSink)
		auditG.GET("/proof", auditH.ListProofs)
		auditG.POST("/proof/seal", auditH.SealProof)
		auditG.GET("/snapshot", auditH.Snapshot)

		// Login history (event-sourced immutable log of authentication events)
		orgScoped.GET("/login-history", loginHistoryH.ListOrgLoginHistory, middleware.RequireResourcePermission("audit"))

		// Per-org rate limit configuration
		orgScoped.GET("/rate-limits", loginHistoryH.GetRateLimits, middleware.RequireResourcePermission("security"))
		orgScoped.PUT("/rate-limits", loginHistoryH.UpdateRateLimits, middleware.RequireResourcePermission("security"))

		// Clavex Guard — adaptive lockout configuration
		// GET  returns current bands (or defaults if not customised)
		// PUT  replaces bands (score → max_attempts + lockout_seconds mapping)
		// DELETE resets to global defaults
		orgScoped.GET("/lockout", lockoutH.GetLockoutConfig, middleware.RequireResourcePermission("security"))
		orgScoped.PUT("/lockout", lockoutH.UpsertLockoutConfig, middleware.RequireResourcePermission("security"))
		orgScoped.DELETE("/lockout", lockoutH.DeleteLockoutConfig, middleware.RequireResourcePermission("security"))
		// PUT  /lockout/unlock/:email    → immediate admin unlock (clears Redis)
		// POST /lockout/unlock-link      → send 15-min one-time magic-link email to user
		orgScoped.PUT("/lockout/unlock/:email", lockoutH.UnlockUser, middleware.RequireResourcePermission("security"))
		orgScoped.POST("/lockout/unlock-link", lockoutH.SendUnlockMagicLink, middleware.RequireResourcePermission("security"))

		// Cross-org token exchange trust relationships (RFC 8693 multi-tenant)
		crossOrgG := orgScoped.Group("/cross-org-trusts", middleware.RequireResourcePermission("security"))
		crossOrgG.GET("", crossOrgTrustH.List)
		crossOrgG.GET("/inbound", crossOrgTrustH.ListInbound)
		crossOrgG.POST("", crossOrgTrustH.Create)
		crossOrgG.DELETE("/:trust_id", crossOrgTrustH.Revoke)
		orgScoped.GET("/auth-policies", policyH.List, middleware.RequireResourcePermission("security"))
		orgScoped.POST("/auth-policies", policyH.Create, middleware.RequireResourcePermission("security"))
		orgScoped.PUT("/auth-policies/:rule_id", policyH.Update, middleware.RequireResourcePermission("security"))
		orgScoped.DELETE("/auth-policies/:rule_id", policyH.Delete, middleware.RequireResourcePermission("security"))
		orgScoped.POST("/auth-policies/simulate", policyH.Simulate, middleware.RequireResourcePermission("security"))
		orgScoped.POST("/auth-policies/simulate/batch", policyH.SimulateBatch, middleware.RequireResourcePermission("security"))

		// ── Clavex AI Assistant ────────────────────────────────────────────
		aiGroup := orgScoped.Group("/ai", middleware.RequireResourcePermission("security"))
		aiGroup.GET("/config", aiH.GetAIConfig)
		aiGroup.PUT("/config", aiH.UpsertAIConfig)
		aiGroup.POST("/suggest-policy", aiH.SuggestPolicy)
		aiGroup.POST("/suggest-fga-model", aiH.SuggestFGAModel)
		aiGroup.POST("/explain-anomaly", aiH.ExplainAnomaly)
		aiGroup.POST("/nl-audit-query", aiH.NLAuditQuery)
		aiGroup.POST("/suggest-access-review", aiH.SuggestAccessReview)
		aiGroup.POST("/suggest-lifecycle-rule", aiH.SuggestLifecycleRule)
		aiGroup.POST("/suggest-dpia", aiH.SuggestDPIA)
		aiGroup.POST("/suggest-dcql", aiH.SuggestDCQL)
		aiGroup.POST("/suggest-credential-schema", aiH.SuggestCredentialSchema)
		aiGroup.POST("/explain-error", aiH.ExplainError)
		aiGroup.POST("/audit-copilot", aiH.AuditCopilot)
		aiGroup.POST("/explain-conformance", aiH.ExplainConformanceFailure)

		// ── MCP (Model Context Protocol) server ────────────────────────────────
		// Exposes AI tools (clavex_audit_copilot) to MCP-compatible clients.
		// Auth: same security permission as the AI group.
		mcpH := mcpserver.New(pool)
		orgScoped.POST("/mcp", mcpH.Handle, middleware.RequireResourcePermission("security"))
		// Branding
		orgScoped.GET("/branding", branding.Get, middleware.RequireResourcePermission("branding"))
		orgScoped.PUT("/branding", branding.Put, middleware.RequireResourcePermission("branding"))
		// Account Center widget configuration (ISV feature toggles per section)
		orgScoped.GET("/account-center", accountCenterH.AdminGetConfig, middleware.RequireResourcePermission("branding"))
		orgScoped.PUT("/account-center", accountCenterH.AdminUpdateConfig, middleware.RequireResourcePermission("branding"))

		// Per-client branding (cascades: client → org → default)
		adminClients.GET("/:client_id/branding", clientBrandingH.Get)
		adminClients.PUT("/:client_id/branding", clientBrandingH.Put)
		adminClients.DELETE("/:client_id/branding", clientBrandingH.Delete)

		// Trusted devices (device trust / zero-trust session binding)
		adminUsers.GET("/:user_id/trusted-devices", deviceTrustH.ListDevices)
		adminUsers.DELETE("/:user_id/trusted-devices", deviceTrustH.RevokeAllDevices)
		adminUsers.DELETE("/:user_id/trusted-devices/:device_id", deviceTrustH.RevokeDevice)

		// Password policy
		orgScoped.GET("/password-policy", passwordPolicy.Get, middleware.RequireResourcePermission("security"))
		orgScoped.PUT("/password-policy", passwordPolicy.Put, middleware.RequireResourcePermission("security"))

		// SMTP settings
		orgScoped.GET("/smtp", smtpH.Get, middleware.RequireResourcePermission("smtp"))
		orgScoped.PUT("/smtp", smtpH.Put, middleware.RequireResourcePermission("smtp"))
		orgScoped.POST("/smtp/test", smtpH.Test, middleware.RequireResourcePermission("smtp"))

		// SMS gateway settings (org admin only — see "sms" resource permission)
		orgScoped.GET("/sms", smsSettingsH.Get, middleware.RequireResourcePermission("sms"))
		orgScoped.PUT("/sms", smsSettingsH.Put, middleware.RequireResourcePermission("sms"))
		orgScoped.POST("/sms/test", smsSettingsH.Test, middleware.RequireResourcePermission("sms"))

		// CAPTCHA settings
		orgScoped.GET("/captcha", captchaH.Get, middleware.RequireResourcePermission("security"))
		orgScoped.PUT("/captcha", captchaH.Put, middleware.RequireResourcePermission("security"))
		orgScoped.DELETE("/captcha", captchaH.Delete, middleware.RequireResourcePermission("security"))

		// Identity providers (admin CRUD) — OAuth2/OIDC social providers
		adminIDPs := orgScoped.Group("/identity-providers", middleware.RequireResourcePermission("identity_providers"))
		adminIDPs.POST("", idpH.Create)
		adminIDPs.GET("", idpH.List)
		adminIDPs.PATCH("/:id", idpH.Update)
		adminIDPs.DELETE("/:id", idpH.Delete)
		adminIDPs.PUT("/:id/promote", idpH.SetPromoted) // promoted-source UX

		// Connector marketplace catalog — lists all available social, SMS, and email connectors.
		// ?category=social|sms|email narrows to a specific connector type.
		catalogH := handler.NewConnectorCatalogHandler()
		orgScoped.GET("/connector-catalog", catalogH.List, middleware.RequireResourcePermission("identity_providers"))

		// Domain-based auto-enrollment config
		autoEnrollH := handler.NewAutoEnrollHandler(pool)
		orgScoped.GET("/auto-enroll", autoEnrollH.Get, middleware.RequireResourcePermission("users"))
		orgScoped.PUT("/auto-enroll", autoEnrollH.Put, middleware.RequireResourcePermission("users"))
		// CIE provider admin (shortcut: pre-fills CIE-specific endpoints by environment)
		orgScoped.POST("/cie", cieH.CreateCIE, middleware.RequireResourcePermission("identity_providers"))

		// FranceConnect provider admin (pre-fills FC v2 endpoints by environment)
		orgScoped.POST("/franceconnect", franceConnectH.CreateFC, middleware.RequireResourcePermission("identity_providers"))

		// itsme® provider admin (pre-fills itsme endpoints by environment)
		orgScoped.POST("/itsme", itsmeH.CreateItsme, middleware.RequireResourcePermission("identity_providers"))

		// BundID provider admin (pre-fills BundID endpoints by environment)
		orgScoped.POST("/bundid", bundidH.CreateBundID, middleware.RequireResourcePermission("identity_providers"))

		// Cl@ve provider admin (pre-fills Cl@ve endpoints by environment)
		orgScoped.POST("/clave", claveH.CreateClave, middleware.RequireResourcePermission("identity_providers"))

		// DigiD provider admin (pre-fills DigiD endpoints by environment)
		orgScoped.POST("/digid", digidH.CreateDigiD, middleware.RequireResourcePermission("identity_providers"))

		// BundID SAML SP config + metadata download (pre-fills BundID IdP metadata URL by environment)
		orgScoped.GET("/bundid-saml/config", bundidSAMLH.GetConfig, middleware.RequireResourcePermission("identity_providers"))
		orgScoped.PUT("/bundid-saml/config", bundidSAMLH.UpsertConfig, middleware.RequireResourcePermission("identity_providers"))
		orgScoped.GET("/bundid-saml/metadata", bundidSAMLH.GetMetadataAdmin, middleware.RequireResourcePermission("identity_providers"))

		// SPID per-org authentication preferences
		orgScoped.GET("/spid/config", spidH.GetConfig, middleware.RequireResourcePermission("identity_providers"))
		orgScoped.PUT("/spid/config", spidH.UpsertConfig, middleware.RequireResourcePermission("identity_providers"))

		// eIDAS node integration (SAML SP config + metadata download)
		orgScoped.GET("/eidas", eidasH.GetConfig, middleware.RequireResourcePermission("identity_providers"))
		orgScoped.PUT("/eidas", eidasH.UpsertConfig, middleware.RequireResourcePermission("identity_providers"))
		orgScoped.GET("/eidas/metadata", eidasH.Metadata, middleware.RequireResourcePermission("identity_providers"))

		// Webhooks
		adminWebhooks := orgScoped.Group("/webhooks", middleware.RequireResourcePermission("webhooks"))
		adminWebhooks.POST("", webhooks.Create)
		adminWebhooks.GET("", webhooks.List)
		adminWebhooks.PATCH("/:id", webhooks.Update)
		adminWebhooks.DELETE("/:id", webhooks.Delete)
		adminWebhooks.GET("/:id/deliveries", webhooks.Deliveries)
		adminWebhooks.POST("/:id/deliveries/:delivery_id/retry", webhooks.RetryDelivery)

		// Claims enrichment hook (synchronous, per-org)
		orgScoped.GET("/enrichment-hook", enrichmentH.Get, middleware.RequireResourcePermission("branding"))
		orgScoped.PUT("/enrichment-hook", enrichmentH.Put, middleware.RequireResourcePermission("branding"))
		orgScoped.DELETE("/enrichment-hook", enrichmentH.Delete, middleware.RequireResourcePermission("branding"))

		// Universal Login custom template (per-org)
		orgScoped.GET("/login-template", loginTmplH.Get, middleware.RequireResourcePermission("branding"))
		orgScoped.PUT("/login-template", loginTmplH.Put, middleware.RequireResourcePermission("branding"))
		orgScoped.DELETE("/login-template", loginTmplH.Delete, middleware.RequireResourcePermission("branding"))
		orgScoped.GET("/login-template/raw", loginTmplH.GetRaw, middleware.RequireResourcePermission("branding"))

		// Shared Signals Framework (SSF/CAEP) — RFC 8935/8936
		// Stream configuration endpoint (SSF spec §6)
		ssfStreams := orgScoped.Group("/ssf", middleware.RequireResourcePermission("security"))
		ssfStreams.GET("/streams", ssfH.AdminListStreams) // admin: all streams + delivery health
		ssfStreams.POST("/stream", ssfH.CreateStream)
		ssfStreams.GET("/stream", ssfH.GetStream)
		ssfStreams.PATCH("/stream", ssfH.UpdateStream)
		ssfStreams.DELETE("/stream", ssfH.DeleteStream)
		ssfStreams.GET("/stream/status", ssfH.GetStatus)
		ssfStreams.POST("/stream/verify", ssfH.Verify)

		// SCIM push (outbound provisioning to external directories)
		adminScimPush := orgScoped.Group("/scim-push", middleware.RequireResourcePermission("identity_providers"))
		adminScimPush.POST("", scimPush.Create)
		adminScimPush.GET("", scimPush.List)
		adminScimPush.PATCH("/:id", scimPush.Update)
		adminScimPush.DELETE("/:id", scimPush.Delete)
		// Delivery log + retry (enterprise SCIM hub observability)
		adminScimPush.GET("/:id/deliveries", scimPush.ListDeliveries)
		adminScimPush.POST("/:id/deliveries/:did/retry", scimPush.RetryDelivery)

		// JML lifecycle rules (Joiner/Mover/Leaver workflow engine)
		lcRules := orgScoped.Group("/lifecycle-rules", middleware.RequireResourcePermission("users"))
		lcRules.GET("", lifecycleH.List)
		lcRules.POST("", lifecycleH.Create)
		lcRules.GET("/:rule_id", lifecycleH.Get)
		lcRules.PUT("/:rule_id", lifecycleH.Update)
		lcRules.DELETE("/:rule_id", lifecycleH.Delete)

		// Access Review / Certification campaigns (Identity Governance)
		arCampaigns := orgScoped.Group("/access-reviews", middleware.RequireResourcePermission("users"))
		arCampaigns.GET("", accessReviewH.List)
		arCampaigns.POST("", accessReviewH.Create)
		arCampaigns.GET("/:campaign_id", accessReviewH.Get)
		arCampaigns.POST("/:campaign_id/launch", accessReviewH.Launch)
		arCampaigns.DELETE("/:campaign_id", accessReviewH.Cancel)
		arCampaigns.GET("/:campaign_id/items", accessReviewH.ListItems)
		arCampaigns.GET("/:campaign_id/report", accessReviewH.Report)

		// Login Flow Step Builder (no-code visual auth flow editor)
		lf := orgScoped.Group("/login-flows", middleware.RequireResourcePermission("clients"))
		lf.GET("", loginFlowH.List)
		lf.POST("", loginFlowH.Create)
		lf.GET("/:flow_id", loginFlowH.Get)
		lf.PUT("/:flow_id", loginFlowH.Update)
		lf.DELETE("/:flow_id", loginFlowH.Delete)
		lf.PUT("/:flow_id/steps", loginFlowH.ReplaceSteps)
		lf.POST("/:flow_id/clients", loginFlowH.AssignClient)
		lf.DELETE("/:flow_id/clients/:client_id", loginFlowH.UnassignClient)
		lf.GET("/:flow_id/clients", loginFlowH.ListClients)

		// SAML service providers
		adminSAML := orgScoped.Group("/saml/sps", middleware.RequireResourcePermission("identity_providers"))
		adminSAML.POST("", saml.CreateSP)
		adminSAML.GET("", saml.ListSPs)
		adminSAML.DELETE("/:sp_id", saml.DeleteSP)

		// SCIM token management (admin issues/revokes SCIM bearer tokens)
		adminSCIM := orgScoped.Group("/scim/tokens", middleware.RequireResourcePermission("identity_providers"))
		adminSCIM.POST("", scimH.CreateToken)
		adminSCIM.GET("", scimH.ListTokens)
		adminSCIM.DELETE("/:token_id", scimH.DeleteToken)

		// ── OID4VCI admin endpoints ───────────────────────────────────────────
		adminVCI := orgScoped.Group("/oid4vci", middleware.RequireResourcePermission("clients"))
		adminVCI.GET("/configs", oid4vciH.ListConfigs)
		adminVCI.POST("/configs", oid4vciH.CreateConfig)
		adminVCI.PATCH("/configs/:config_id", oid4vciH.PatchConfig)
		adminVCI.DELETE("/configs/:config_id", oid4vciH.DeleteConfig)
		// Delegated issuance (ARF EUDIW §6.3.4): configure a delegation proof grant
		// from a parent issuer (e.g. central university) so this sub-issuer (a faculty)
		// can issue credentials under the parent's VCT with a verifiable trust chain.
		adminVCI.PUT("/configs/:config_id/delegation", oid4vciH.SetDelegation)
		// IssueDelegationGrant: the delegating issuer generates a signed grant JWS
		// to hand to the sub-issuer who then configures it via PUT /delegation.
		adminVCI.POST("/configs/:config_id/delegation/issue", oid4vciH.IssueDelegationGrant)
		adminVCI.GET("/analytics/summary", analyticsH.Summary)
		adminVCI.GET("/issued", oid4vciH.ListIssued)
		adminVCI.POST("/issued/:cred_id/revoke", oid4vciH.RevokeCredential)
		adminVCI.POST("/issued/:cred_id/restore", oid4vciH.RestoreCredential)
		// /offers is rate-limited per-endpoint (configurable via endpoint_limits)
		adminVCIOffers := adminVCI.Group("/offers")
		adminVCIOffers.Use(orgRateLimiter.OrgEndpointRateLimit("/oid4vci/offers", "org_id", nil))
		adminVCIOffers.GET("", oid4vciH.ListOffers)
		adminVCIOffers.POST("", oid4vciH.CreateOffer)
		adminVCIOffers.POST("/:offer_id/send", oid4vciH.SendOffer)
		adminVCIOffers.GET("/:offer_id/qr", oid4vciH.OfferQRByOrgID)
		// Deferred credential management (OID4VCI Final §11 — PA review workflow)
		adminVCI.GET("/deferred", oid4vciH.ListDeferredCredentials)
		adminVCI.POST("/deferred/:txn_id/approve", oid4vciH.ApproveDeferredCredential)
		// Clavex Verified credential catalog (training, qualification, badge)
		verifiedCatalogH := handler.NewVerifiedCatalogHandler(pool, walletBaseURL)
		adminVCI.GET("/catalog", verifiedCatalogH.GetCatalog)
		adminVCI.POST("/catalog/seed", verifiedCatalogH.SeedCatalog)
		// Identity presets — one-click credential config for SPID, CIE, mDL, IT-Wallet.
		adminVCI.POST("/catalog/seed-spid", verifiedCatalogH.SeedSpidPreset)
		adminVCI.POST("/catalog/seed-cie", verifiedCatalogH.SeedCiePreset)
		adminVCI.POST("/catalog/seed-mdl", verifiedCatalogH.SeedMdlPreset)
		// IT-Wallet / EUDIW EU PID: SPID login → auto-offer of eu.europa.ec.eudi.pid.1.
		// Positions Clavex as an IT-Wallet-compatible self-hosted PID Provider.
		adminVCI.POST("/catalog/seed-it-wallet", verifiedCatalogH.SeedItWalletPreset)
		// IT-Wallet / EUDIW EU PID via CIE (eIDAS High): CIE login → auto-offer.
		// Preferred source per AgID IT-Wallet spec (higher assurance than SPID L2).
		adminVCI.POST("/catalog/seed-cie-wallet", verifiedCatalogH.SeedCieItWalletPreset)
		// MIT IT-Wallet mDL: SPID login → auto-offer of ISO 18013-5 mobile Driving Licence.
		adminVCI.POST("/catalog/seed-spid-mdl", verifiedCatalogH.SeedSpidMdlPreset)
		// Anonymous age attestation: SPID/CIE login → age_over_18: true only.
		// GDPR Art.5(1)(c) data minimization — no name, no fiscal code, no birth date.
		adminVCI.POST("/catalog/seed-age-over-18", verifiedCatalogH.SeedAgePreset)
		adminVP := orgScoped.Group("/oid4vp", middleware.RequireResourcePermission("clients"))
		adminVP.GET("/sessions", oid4vpH.ListSessions)
		adminVP.GET("/sessions/:session_id", oid4vpH.GetSession)
		adminVP.POST("/batch-verify", oid4vpH.BatchVerify)

		// ── eIDAS 2.0 mdoc proximity (ISO 18013-5 / OID4VP) ──────────────────
		adminMdoc := orgScoped.Group("/mdoc", middleware.RequireResourcePermission("clients"))
		adminMdoc.GET("/sessions", mdocProximityH.ListSessions)
		adminMdoc.GET("/sessions/:session_id", mdocProximityH.GetSession)
		// IACA trust anchors — upload / list / remove per-org CA certs for
		// IssuerAuth chain validation (ISO 18013-5 §9.3.3).
		iacaH := handler.NewIACAHandler(pool)
		adminMdoc.POST("/iaca-roots", iacaH.Upload)
		adminMdoc.GET("/iaca-roots", iacaH.List)
		adminMdoc.DELETE("/iaca-roots/:root_id", iacaH.Delete)
		// mdoc issuer DS keys — manage DS keypairs used for OID4VCI mso_mdoc issuance.
		mdocIssuerH := handler.NewMdocIssuerHandler(pool)
		adminMdoc.POST("/issuers/generate", mdocIssuerH.Generate)
		adminMdoc.POST("/issuers", mdocIssuerH.Create)
		adminMdoc.GET("/issuers", mdocIssuerH.List)
		adminMdoc.DELETE("/issuers/:issuer_id", mdocIssuerH.Delete)

		// ── CIBA admin — approve/deny backchannel auth requests ──────────────
		cibaG := orgScoped.Group("/ciba", middleware.RequireResourcePermission("sessions"))
		cibaG.GET("/pending", oidcH.CIBAListPending)
		cibaG.POST("/:auth_req_id/approve", oidcH.CIBAApprove)
		cibaG.POST("/:auth_req_id/deny", oidcH.CIBADeny)
		cibaG.GET("/notification-config", oidcH.GetCIBANotificationConfig)
		cibaG.PUT("/notification-config", oidcH.UpsertCIBANotificationConfig)
		cibaG.DELETE("/notification-config", oidcH.DeleteCIBANotificationConfig)
		// Push device token management (admin)
		cibaG.GET("/device-tokens", oidcH.CIBAListDeviceTokens)
		cibaG.POST("/device-tokens", oidcH.CIBARegisterDeviceToken)
		cibaG.DELETE("/device-tokens/:token_id", oidcH.CIBADeleteDeviceToken)

		// ── GDPR / NIS2 / DSAR compliance endpoints ───────────────────────────
		complianceG := orgScoped.Group("/compliance", middleware.RequireResourcePermission("compliance"))
		complianceG.GET("/gdpr", complianceH.GDPRSummary)
		complianceG.POST("/gdpr/export", complianceH.GDPRExport)
		complianceG.GET("/nis2", complianceH.NIS2Evidence)
		complianceG.GET("/dsar/:user_id", complianceH.DSAR)
		complianceG.DELETE("/gdpr-erasure/:user_id", complianceH.GDPRErasure) // Art.17 right to erasure
		complianceG.POST("/audit/export-signed", complianceH.ExportSignedAudit)
		complianceG.GET("/processing-records", complianceH.ListProcessingRecords)
		complianceG.POST("/processing-records", complianceH.CreateProcessingRecord)
		complianceG.PUT("/processing-records/:record_id", complianceH.UpdateProcessingRecord)
		complianceG.DELETE("/processing-records/:record_id", complianceH.DeleteProcessingRecord)
		complianceG.GET("/scim/audit", complianceH.SCIMCompliance)
		// Comprehensive offline audit pack for NIS2/ISO 27001 external auditors
		complianceG.POST("/audit-pack", complianceH.AuditPack)
		// ── Continuous Assurance: real-time conformance score ─────────────────
		conformanceScoreH := handler.NewConformanceScoreHandler(
			repository.NewConformanceScoreRepository(pool),
		)
		complianceG.GET("/score", conformanceScoreH.GetScore)
		complianceG.GET("/score/history", conformanceScoreH.GetScoreHistory)
		complianceG.PATCH("/score/config", conformanceScoreH.PatchConfig)
		// Public-score token management (admin-only — stays under complianceG).
		complianceG.POST("/score/public-token", conformanceScoreH.RotatePublicToken)
		complianceG.GET("/score/public-token", conformanceScoreH.GetPublicTokenInfo)
		complianceG.DELETE("/score/public-token", conformanceScoreH.RevokePublicToken)
		// Public score endpoint — authenticated by the clv_pub_... token, NOT by
		// the org admin JWT. Registered outside complianceG so the compliance
		// permission middleware does not apply. ISVs embed this in their product.
		orgScoped.GET("/compliance/score/public", conformanceScoreH.GetPublicScore)

		// ── GDPR Art.5(1)(e) user data retention policy ──────────────────
		gdprRetentionH := handler.NewGDPRRetentionHandler(gdprRepo)
		gdprG := orgScoped.Group("/gdpr", middleware.RequireResourcePermission("compliance"))
		gdprG.GET("/retention-policy", gdprRetentionH.GetRetentionPolicy)
		gdprG.PUT("/retention-policy", gdprRetentionH.UpsertRetentionPolicy)
		gdprG.DELETE("/retention-policy", gdprRetentionH.DeleteRetentionPolicy)
		// ── Step-up MFA (Elevate) ─────────────────────────────────────────────
		elevateH := handler.NewElevateHandler(cfg, pool, rdb, keys, mfa.WebAuthn())
		elevateG := orgScoped.Group("/elevate", middleware.RequireResourcePermission("security"))
		elevateG.Use(orgRateLimiter.OrgEndpointRateLimit("/elevate", "org_id", nil))
		elevateG.POST("", elevateH.Create)
		elevateG.GET("/:challenge_id", elevateH.Get)
		elevateG.POST("/:challenge_id/verify", elevateH.Verify)
		elevateG.POST("/:challenge_id/webauthn/begin", elevateH.BeginWebAuthn)

		// ── Organization Analytics (per-org growth, DAU, retention) ──────────
		orgScoped.GET("/analytics", usageH.GetOrgAnalytics, middleware.RequireResourcePermission("audit"))

		// ── Object Lifecycle Management — stale clients + empty groups ────────
		lifecycleReportH := handler.NewLifecycleReportHandler(pool)
		orgScoped.GET("/lifecycle-report", lifecycleReportH.Get, middleware.RequireResourcePermission("clients"))

		// ── Entity Review Campaigns (periodic object-lifecycle review) ────────
		entityReviewH := handler.NewEntityReviewHandler(pool)
		erCampaigns := orgScoped.Group("/entity-review-campaigns", middleware.RequireResourcePermission("clients"))
		erCampaigns.GET("", entityReviewH.ListCampaigns)
		erCampaigns.POST("", entityReviewH.CreateCampaign)
		erCampaigns.GET("/:campaign_id", entityReviewH.GetCampaign)
		erCampaigns.POST("/:campaign_id/activate", entityReviewH.ActivateCampaign)
		erCampaigns.DELETE("/:campaign_id", entityReviewH.CancelCampaign)
		erCampaigns.GET("/:campaign_id/items", entityReviewH.ListItems)
		// Token-based decision endpoint — no auth, authenticated by review token
		orgScoped.POST("/entity-review/decide", entityReviewH.Decide)

		// ── Actions V2 — generic HTTP hooks on auth/user events ──────────────
		actionsH := handler.NewActionsHandler(pool)
		actionsG := orgScoped.Group("/actions", middleware.RequireResourcePermission("clients"))
		actionsG.GET("/targets", actionsH.ListTargets)
		actionsG.PUT("/targets/:name", actionsH.UpsertTarget)
		actionsG.DELETE("/targets/:target_id", actionsH.DeleteTarget)
		actionsG.GET("/executions", actionsH.ListExecutions)
		actionsG.POST("/executions", actionsH.CreateExecution)
		actionsG.PUT("/executions/:execution_id", actionsH.UpdateExecution)
		actionsG.DELETE("/executions/:execution_id", actionsH.DeleteExecution)

		// ── Agent Tokens — machine identity for AI agents (MCP OAuth 2.0) ────
		// POST  /agent-tokens              — issue a token (admin, scoped to a user+agent pair)
		// GET   /agent-tokens              — list tokens (?user_id=<uuid> to filter by user)
		// DELETE /agent-tokens/:id         — revoke a specific token
		// GET   /agent-tokens/mcp-scopes   — public discovery of predefined MCP OAuth 2.0 scopes
		agentTokenH := handler.NewAgentTokenHandler(cfg, pool, keys, webhooks.Dispatcher())
		agentTokens := orgScoped.Group("/agent-tokens", middleware.RequireResourcePermission("users"))
		agentTokens.POST("", agentTokenH.Issue)
		agentTokens.GET("", agentTokenH.List)
		agentTokens.DELETE("/:id", agentTokenH.Revoke)
		// Public scope-discovery endpoint (no auth guard — safe, read-only, no PII).
		orgScoped.GET("/agent-tokens/mcp-scopes", agentTokenH.MCPScopes)

		// ── Signing-key rotation policy (global OIDC/PQC keys) ────────────────
		keyRotationH := handler.NewKeyRotationHandler(cfg, pool)
		keyRotation := orgScoped.Group("/key-rotation", middleware.RequireResourcePermission("security"))
		keyRotation.GET("", keyRotationH.Status)
		// OIDC keys are now per-org, so an org's security admin manages their own
		// OIDC rotation policy here. PQC is still a process-global singleton, so
		// SetPolicy enforces superadmin-only for kind=pqc internally.
		keyRotation.PUT("/:kind", keyRotationH.SetPolicy)

		// ── Fine-Grained Authorization (OpenFGA ReBAC) ────────────────────────
		var fgaClient *fga.Client
		if cfg.FGA.Enabled && cfg.FGA.Endpoint != "" {
			fgaClient = fga.NewClient(cfg.FGA.Endpoint, cfg.FGA.APIKey)
		}
		fgaH := handler.NewFGAHandler(pool, fgaClient)
		fgaG := orgScoped.Group("/fga", middleware.RequireResourcePermission("clients"))
		fgaG.POST("/stores", fgaH.InitStore)
		fgaG.GET("/stores", fgaH.GetStoreInfo)
		fgaG.PUT("/model", fgaH.WriteModel)
		fgaG.GET("/model", fgaH.GetModel)
		fgaG.POST("/check", fgaH.Check)
		fgaG.POST("/write", fgaH.Write)
		fgaG.GET("/read", fgaH.Read)
		// Template library — available even when FGA client is disabled (static data).
		fgaG.GET("/templates", fgaH.GetTemplates)
		fgaG.GET("/templates/:template_id", fgaH.GetTemplate)
		fgaG.POST("/templates/:template_id/import", fgaH.ImportTemplate)

		// ── WS-Federation relying party management ────────────────────────────
		wsfedH := handler.NewWSFedHandler(cfg, pool, rdb)
		wsfedRPs := orgScoped.Group("/wsfed/relying-parties", middleware.RequireResourcePermission("identity_providers"))
		wsfedRPs.GET("", wsfedH.ListRPs)
		wsfedRPs.POST("", wsfedH.CreateRP)
		wsfedRPs.GET("/:rp_id", wsfedH.GetRP)
		wsfedRPs.PUT("/:rp_id", wsfedH.UpdateRP)
		wsfedRPs.DELETE("/:rp_id", wsfedH.DeleteRP)

		// ── EUDIW Trust Anchor admin API ──────────────────────────────────────
		// Manage subordinate entities and trust mark types for private eIDAS 2.0
		// federation ecosystems. Protected by the "federation" resource permission.
		fedTAH := handler.NewFederationTAHandler(pool, audit.NewEmitter(baseURL, repository.NewAuditRepository(pool)))
		fedTAG := orgScoped.Group("/federation", middleware.RequireResourcePermission("federation"))
		// Subordinate management
		fedTAG.POST("/subordinates", fedTAH.RegisterSubordinate)
		fedTAG.GET("/subordinates", fedTAH.ListSubordinatesAdmin) // full records; ?status=active|suspended|revoked|all
		fedTAG.GET("/subordinates/detail", fedTAH.GetSubordinate) // single record; ?entity_id=<uri>
		fedTAG.PUT("/subordinates", fedTAH.UpdateSubordinate)     // update; ?entity_id=<uri>
		fedTAG.DELETE("/subordinates", fedTAH.RevokeSubordinate)
		// Trust mark type management
		fedTAG.POST("/trust-mark-types", fedTAH.UpsertTrustMarkType)
		fedTAG.GET("/trust-mark-types", fedTAH.ListTrustMarkTypes)
		// Trust mark revocation (issuance is done via the public endpoint)
		fedTAG.DELETE("/trust-marks", fedTAH.RevokeTrustMark)

		// ── Org binary assets (S3-backed logo, favicon, background) ──────────
		orgAssetsH := handler.NewOrgAssetHandler(pool, cfg)
		assetsG := orgScoped.Group("/assets", middleware.RequireResourcePermission("branding"))
		assetsG.GET("", orgAssetsH.List)
		assetsG.PUT("/:asset_type", orgAssetsH.Upload)
		assetsG.DELETE("/:asset_type", orgAssetsH.Delete)

		// ── Service accounts (M2M / machine credentials) ──────────────────────
		svcAcctH := handler.NewServiceAccountHandler(pool)
		svcAcctG := orgScoped.Group("/service-accounts", middleware.RequireResourcePermission("clients"))
		svcAcctG.GET("", svcAcctH.List)
		svcAcctG.POST("", svcAcctH.Create)
		svcAcctG.GET("/:id", svcAcctH.Get)
		svcAcctG.PATCH("/:id", svcAcctH.Update)
		svcAcctG.DELETE("/:id", svcAcctH.Delete)
		svcAcctG.POST("/:id/secret", svcAcctH.RotateSecret)

		// ── Application families (cross-app seamless SSO + coordinated logout) ─
		appFamilyH := handler.NewAppFamilyHandler(pool)
		appFamiliesG := orgScoped.Group("/app-families", middleware.RequireResourcePermission("clients"))
		appFamiliesG.GET("", appFamilyH.List)
		appFamiliesG.POST("", appFamilyH.Create)
		appFamiliesG.GET("/:family_id", appFamilyH.Get)
		appFamiliesG.PUT("/:family_id", appFamilyH.Update)
		appFamiliesG.DELETE("/:family_id", appFamilyH.Delete)
		appFamiliesG.POST("/:family_id/members", appFamilyH.AddMember)
		appFamiliesG.DELETE("/:family_id/members/:client_id", appFamilyH.RemoveMember)

		// ── QTSP readiness assessment (eIDAS 2.0) ──────────────────────────────
		// Returns a structured checklist of QTSP criteria with auto / manual status.
		qtspH := handler.NewQTSPHandler(pool)
		orgScoped.GET("/qtsp-assessment", qtspH.Assessment,
			middleware.RequireResourcePermission("settings"))

		// ── Privileged Access Management (PAM) ───────────────────────────────
		// JIT access with approval workflow, privileged session recording,
		// encrypted credential vault, and Vault SSH CA (agentless Platform SSO
		// for Linux — no proprietary agent needed, unlike Authentik).
		pamH := handler.NewPAMHandler(pool, enc, webhooks.Dispatcher(), pamNotifier)
		pamG := orgScoped.Group("/pam", middleware.RequireResourcePermission("security"))
		pamG.POST("/access-requests", pamH.CreateRequest)
		pamG.GET("/access-requests", pamH.ListRequests)
		pamG.GET("/access-requests/:req_id", pamH.GetRequest)
		pamG.POST("/access-requests/:req_id/approve", pamH.Approve)
		pamG.POST("/access-requests/:req_id/deny", pamH.Deny)
		pamG.POST("/access-requests/:req_id/revoke", pamH.Revoke)
		pamG.POST("/access-requests/break-glass", pamH.BreakGlass)
		pamG.GET("/break-glass/config", pamH.GetBreakGlassConfig)
		pamG.PUT("/break-glass/config", pamH.UpsertBreakGlassConfig)
		pamG.POST("/sessions", pamH.StartSession)
		pamG.GET("/sessions", pamH.ListSessions)
		pamG.GET("/sessions/:session_id", pamH.GetSession)
		pamG.POST("/sessions/:session_id/events", pamH.AddEvent)
		pamG.GET("/sessions/:session_id/events", pamH.ListEvents)
		pamG.POST("/sessions/:session_id/end", pamH.EndSession)
		pamG.GET("/credentials", pamH.ListCredentials)
		pamG.POST("/credentials", pamH.CreateCredential)
		pamG.PUT("/credentials/:cred_id", pamH.UpdateCredential)
		pamG.DELETE("/credentials/:cred_id", pamH.DeleteCredential)
		pamG.POST("/credentials/:cred_id/checkout", pamH.Checkout)
		pamG.POST("/credentials/:cred_id/return", pamH.ReturnCheckout)
		pamG.GET("/credentials/:cred_id/rotation-log", pamH.ListRotationLog)
		pamG.GET("/ssh-ca", pamH.GetSSHCA)
		pamG.PUT("/ssh-ca", pamH.UpsertSSHCA)
		pamG.DELETE("/ssh-ca", pamH.DeleteSSHCA)
		pamG.GET("/ssh-ca/public-key", pamH.GetCAPublicKey)
		pamG.POST("/ssh-ca/sign", pamH.SignSSHPublicKey)

		// ── SSH CA staged rotation ────────────────────────────────────────────
		// start/status/abort are admin (under pamG's admin JWT). mark-ready and
		// complete are Agent-Token only and therefore registered on a separate
		// group (below) that bypasses the admin-JWT/CSRF middleware.
		sshcaRotH := handler.NewPAMSSHCARotationHandler(cfg, pool, enc, keys, webhooks.Dispatcher())
		pamG.POST("/ssh-ca/rotation/start", sshcaRotH.Start)
		pamG.GET("/ssh-ca/rotation", sshcaRotH.Status)
		pamG.POST("/ssh-ca/rotation/:rotation_id/abort", sshcaRotH.Abort)

		// mark-ready/complete accept EITHER an agent token (bearer, scope
		// pam:ssh_ca:rotation:manage) OR an admin org session (cookie + CSRF,
		// "security" permission). A bearer Authorization header routes to the
		// agent path; otherwise the admin middleware chain runs (cookie auth +
		// CSRF, so it is not registered under a bearer-only or CSRF-less group).
		adminRotMW := []echo.MiddlewareFunc{
			middleware.RequireAdminJWT(cfg),
			middleware.CSRFProtect(cfg),
			middleware.RequireOrgAccess(),
			middleware.RequireResourcePermission("security"),
		}
		agentRotMW := sshcaRotH.RequireAgentScope(handler.ScopeSSHCARotationManage)
		dualRotation := func(real echo.HandlerFunc) echo.HandlerFunc {
			adminH := real
			for i := len(adminRotMW) - 1; i >= 0; i-- {
				adminH = adminRotMW[i](adminH)
			}
			agentH := agentRotMW(real)
			return func(c echo.Context) error {
				if hasBearerAuth(c.Request()) {
					return agentH(c)
				}
				return adminH(c)
			}
		}
		rotationGroup := e.Group("/api/v1/organizations/:org_id/pam/ssh-ca/rotation")
		rotationGroup.POST("/:rotation_id/mark-ready", dualRotation(sshcaRotH.MarkReady))
		rotationGroup.POST("/:rotation_id/complete", dualRotation(sshcaRotH.Complete))

		// ── Credential Marketplace — org-admin listing management ─────────────────
		// GET    /api/v1/organizations/:org_id/marketplace/listings         — list org's listings
		// POST   /api/v1/organizations/:org_id/marketplace/listings         — publish new listing
		// PUT    /api/v1/organizations/:org_id/marketplace/listings/:id     — update listing
		// DELETE /api/v1/organizations/:org_id/marketplace/listings/:id     — delete listing
		// Publishing (create/update/delete listings) is a Business feature and is
		// gated behind an active Business/Enterprise license (402 otherwise).
		// Reading — ListForOrg here, plus the public ListPublic/GetPublic — stays
		// open so an org can always see its own listings and browse the catalog.
		marketplaceGate := middleware.RequireBusinessLicense(func() license.State {
			if srvRef == nil || srvRef.licenseChecker == nil {
				return license.State{Tier: "community"}
			}
			return srvRef.licenseChecker.State()
		})
		orgScoped.GET("/marketplace/listings", marketplaceH.ListForOrg)
		orgScoped.POST("/marketplace/listings", marketplaceH.Publish, marketplaceGate)
		orgScoped.PUT("/marketplace/listings/:id", marketplaceH.UpdateListing, marketplaceGate)
		orgScoped.DELETE("/marketplace/listings/:id", marketplaceH.DeleteListing, marketplaceGate)
	}

	// Identity provider OAuth2 SSO flow (tenant-scoped, no admin JWT)
	tenant.GET("/idp/:id", idpH.StartSSO)
	tenant.GET("/idp/:id/callback", idpH.CallbackSSO)

	// ── WS-Federation passive requestor endpoints (public, per-tenant) ────────
	// Used by SharePoint, legacy Windows applications and other WS-Fed consumers.
	// Both GET (initial redirect) and POST (form POST response) must be handled.
	wsfedPublicH := handler.NewWSFedHandler(cfg, pool, rdb)
	tenant.GET("/wsfed", wsfedPublicH.Endpoint)
	tenant.POST("/wsfed", wsfedPublicH.Endpoint)
	tenant.GET("/wsfed/metadata", wsfedPublicH.FederationMetadata)

	// ── Local asset file serving (fallback when S3 is not configured) ─────────
	// Files are served from cfg.Storage.LocalDir when set.
	// The prefix /_assets/ is chosen to avoid collisions with API routes.
	if cfg.Storage.LocalDir != "" {
		e.Static("/_assets", cfg.Storage.LocalDir)
	}

	// ── Forward Auth Proxy endpoints ──────────────────────────────────────────
	// Reverse proxies (nginx/Traefik/Caddy) call /verify on every request.
	// Sign-in flow: /auth/sign-in → OIDC authorize → /auth/callback → set cookie → redirect.
	tenant.GET("/auth/verify", fwdAuth.Verify)
	tenant.GET("/auth/sign-in", fwdAuth.SignIn)
	tenant.GET("/auth/callback", fwdAuth.Callback)
	tenant.GET("/auth/sign-out", fwdAuth.SignOut)

	// ── SCIM 2.0 (per-tenant, SCIM Bearer token auth) ────────────────────────
	scimGroup := tenant.Group("/scim/v2", scimH.ResolveOrg(), scimH.RequireSCIMToken())
	{
		scimGroup.GET("/ServiceProviderConfig", scimH.ServiceProviderConfig)
		scimGroup.GET("/Schemas", scimH.Schemas)
		scimGroup.GET("/Schemas/:id", scimH.Schema)
		scimGroup.GET("/Users", scimH.ListUsers)
		scimGroup.GET("/Users/:id", scimH.GetUser)
		scimGroup.POST("/Users", scimH.CreateUser)
		scimGroup.PUT("/Users/:id", scimH.ReplaceUser)
		scimGroup.PATCH("/Users/:id", scimH.PatchUser)
		scimGroup.DELETE("/Users/:id", scimH.DeleteUser)
		scimGroup.GET("/Groups", scimH.ListGroups)
		scimGroup.GET("/Groups/:id", scimH.GetGroup)
		scimGroup.POST("/Groups", scimH.CreateGroup)
		scimGroup.PUT("/Groups/:id", scimH.ReplaceGroup)
		scimGroup.PATCH("/Groups/:id", scimH.PatchGroup)
		scimGroup.DELETE("/Groups/:id", scimH.DeleteGroup)
	}

	// ── Public audit Merkle-proof endpoint (no auth — auditors verify chain offline) ──
	e.GET("/api/v1/organizations/:org_id/audit/merkle-proof", auditH.MerkleProofPublic)
	// Latest checkpoint as a self-contained proof bundle (save & verify with clavexctl audit verify)
	e.GET("/api/v1/organizations/:org_id/audit/proof/latest", auditH.LatestProof)
	// Slug-based alias: auditors can use the human-readable org slug instead of UUID.
	//   curl https://id.clavex.eu/api/v1/organizations/by-slug/acme/audit/proof/latest -o proof.json
	//   clavexctl audit verify --proof proof.json
	e.GET("/api/v1/organizations/by-slug/:slug/audit/proof/latest", auditH.LatestProofBySlug)

	// ── Clavex Guard — public account-unlock redeem endpoint ─────────────────
	// One-time link from admin-sent magic-link email; no auth required.
	e.GET("/api/v1/lockout/redeem", lockoutH.RedeemUnlockToken)

	// ── Self-service API (user JWT) ───────────────────────────────────────────
	me := e.Group("/api/v1/me", middleware.RequireUserJWT(cfg))
	{
		me.GET("", users.Me)
		me.PATCH("", users.UpdateMe)
		me.POST("/password", users.ChangePassword)

		// Self-service agent grants: a user reviews and revokes the AI agents
		// acting on their behalf (their own tokens only, never the org's).
		meAgentTokenH := handler.NewAgentTokenHandler(cfg, pool, keys, webhooks.Dispatcher())
		me.GET("/agent-tokens", meAgentTokenH.ListMine)
		me.DELETE("/agent-tokens/:id", meAgentTokenH.RevokeMine)

		// Verifiable credentials (web wallet)
		me.GET("/credentials", walletH.ListCredentials)
		me.POST("/mfa/totp/enroll", mfa.EnrollTOTP)
		me.GET("/mfa/totp/:cred_id/qr", mfa.GetTOTPQR)
		me.POST("/mfa/totp/confirm", mfa.ConfirmTOTP)
		me.POST("/mfa/webauthn/register/begin", mfa.BeginWebAuthnRegistration)
		me.POST("/mfa/webauthn/register/finish", mfa.FinishWebAuthnRegistration)
		// Passkey registration (residentKey=required, syncs to iCloud/Google)
		me.POST("/mfa/passkey/register/begin", mfa.BeginPasskeyRegistration)
		me.POST("/mfa/passkey/register/finish", mfa.FinishPasskeyRegistration)
		// Hybrid passkey registration (cross-device QR via FIDO2 CTAP 2.2)
		me.POST("/mfa/passkey/register/begin-hybrid", mfa.BeginHybridPasskeyRegistration)
		me.POST("/mfa/passkey/register/finish-hybrid", mfa.FinishHybridPasskeyRegistration)
		me.DELETE("/mfa/:cred_id", mfa.SelfServiceDelete)

		// Passkey portability — FIDO Alliance Credential Exchange Format (CXF)
		me.GET("/passkeys", passkeyExchangeH.List)
		me.POST("/passkeys/export", passkeyExchangeH.Export)
		me.POST("/passkeys/import", passkeyExchangeH.Import)
		me.DELETE("/passkeys/:cred_id", passkeyExchangeH.Revoke)
	}

	e.HTTPErrorHandler = errorHandler

	// ── Audit fan-out pipeline ────────────────────────────────────────────────
	auditRepo := repository.NewAuditRepository(pool)
	dispatcher := audit.NewDispatcher(auditRepo, auditRepo)
	repository.SetDispatcher(dispatcher)
	// Attach dispatcher to the audit handler so StreamLive can subscribe.
	auditH.WithDispatcher(dispatcher)
	// Attach dispatcher to the WebSocket stream handler.
	streamH.WithDispatcher(dispatcher)
	streamH.WithAuditRepository(auditRepo)
	retentionWorker := audit.NewRetentionWorker(auditRepo, 1*time.Hour)
	gdprWorker := gdprpkg.NewRetentionWorker(gdprRepo, 7*24*time.Hour)

	log.Info().
		Int("routes", len(e.Routes())).
		Msg("routes registered")

	srvRef = &Server{
		echo:         e,
		cfg:          cfg,
		pool:         pool,
		enc:          enc,
		dispatcher:   dispatcher,
		retention:    retentionWorker,
		gdprWorker:   gdprWorker,
		webhookDisp:  webhooks.Dispatcher(),
		webhookRepo:  webhookRepo,
		ssfDisp:      ssfDisp,
		pamNotifier:  pamNotifier,
		feedClient:   feedClient,
		merkleSealer: merkleSealer,
		oidcH:        oidcH,
		fedH:         fedH,
	}
	// Keep a typed reference to the DB signer (if that is the active backend)
	// so the scheduled key-rotation worker can call Rotate() on it.
	srvRef.dbSigner, _ = keys.(*oidc.DBSigner)
	// Keep the per-org signer cache so the worker can rotate per-org OIDC keys.
	if len(orgSigners) > 0 {
		srvRef.orgSigners = orgSigners[0]
	}
	return srvRef
}

// WithPQCSigner attaches a PQCSigner so its ML-DSA-65 public key appears in
// the JWKS endpoint alongside the classical RSA key (hybrid / passive mode).
// Must be called after New() and before Start().
func (s *Server) WithPQCSigner(signer *oidc.PQCSigner) *Server {
	if s.oidcH != nil {
		s.oidcH.WithPQCSigner(signer)
	}
	s.pqcSigner = signer // target of scheduled PQC rotation
	return s
}

// WithOrgPQCSigners attaches the per-org PQC signer cache so each org's JWKS
// exposes its own ML-DSA-65 key and the worker can rotate per-org PQC keys.
// Must be called after New() and before Start().
func (s *Server) WithOrgPQCSigners(cache *oidc.OrgPQCSignerCache) *Server {
	if s.oidcH != nil {
		s.oidcH.WithOrgPQCSigners(cache)
	}
	s.orgPQCSigners = cache
	return s
}

// WithEncKeys attaches the request-object encryption key set so its public key
// (use=enc) is published in the JWKS endpoint and encrypted (JWE) request
// objects are decrypted at the authorization endpoint. Must be called after
// New() and before Start().
func (s *Server) WithEncKeys(enc *oidc.EncKeySet) *Server {
	if s.oidcH != nil {
		s.oidcH.WithEncKeys(enc)
	}
	if s.fedH != nil {
		s.fedH.WithEncKeys(enc)
	}
	return s
}

// addLicenseRoutes registers license-specific middleware and routes.
// Called from Start() after all WithXxx() options have been applied.
func (s *Server) addLicenseRoutes() {
	if s.licenseChecker == nil {
		return
	}
	// Warning header on all responses (reads from memory cache — near-zero cost).
	s.echo.Use(middleware.LicenseWarning(s.licenseChecker))
	// Block OIDC auth endpoints when grace period has expired.
	s.echo.Use(middleware.RequireLicenseNotBlocked(s.licenseChecker))

	// Superadmin license status endpoint — JWT + superadmin required.
	licH := handler.NewLicenseHandler(s.licenseChecker).WithPool(s.pool)
	licGroup := s.echo.Group("/api/v1/superadmin",
		middleware.RequireAdminJWT(s.cfg),
		middleware.RequireSuperAdmin(),
	)
	licGroup.GET("/license", licH.Get)
	// PUT /api/v1/superadmin/license — hot-upload a new license JWT at runtime
	licGroup.PUT("/license", licH.Upload)
	// GET /api/v1/superadmin/license/installation-id — installation ID for the license portal
	licGroup.GET("/license/installation-id", licH.InstallationID)
}

// Start begins accepting connections. Blocks until the server stops.
// hasBearerAuth reports whether the request carries a Bearer Authorization
// header — used to route the dual-auth rotation endpoints to the agent path.
func hasBearerAuth(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	return len(h) >= 7 && strings.EqualFold(h[:7], "bearer ")
}

func (s *Server) Start() error {
	ctx := context.Background()
	s.dispatcher.Start(ctx)
	s.retention.Start(ctx)
	s.gdprWorker.Start(ctx)
	s.webhookDisp.StartRetryWorker(ctx, s.webhookRepo)
	entityReviewBaseURL := s.cfg.Auth.IssuerBase
	if entityReviewBaseURL == "" {
		scheme := "https"
		if s.cfg.HTTP.TLSCertFile == "" {
			scheme = "http"
		}
		entityReviewBaseURL = fmt.Sprintf("%s://%s", scheme, s.cfg.HTTP.BaseDomain)
	}
	for len(entityReviewBaseURL) > 0 && entityReviewBaseURL[len(entityReviewBaseURL)-1] == '/' {
		entityReviewBaseURL = entityReviewBaseURL[:len(entityReviewBaseURL)-1]
	}
	if s.merkleSealer != nil {
		go s.merkleSealer.RunAllOrgs(ctx, 5*time.Minute)
	}
	go worker.RunEntityReviewWorker(ctx, s.pool, entityReviewBaseURL)
	go worker.RunPAMRotationWorker(ctx, s.pool, s.enc, s.pamNotifier, s.webhookDisp)
	go worker.RunKeyRotationWorker(ctx, s.pool, s.dbSigner, s.pqcSigner, s.orgSigners, s.orgPQCSigners)
	go worker.RunEntityEventsProjectionWorker(ctx, s.pool)

	// Custom-domain ingress reconciler (opt-in, in-cluster only) + re-verify.
	if ir, enabled, err := ingressreconcile.NewFromEnv(s.pool, s.enc); err != nil {
		log.Error().Err(err).Msg("ingress-reconcile: disabled — config error")
	} else if enabled {
		go worker.RunIngressReconcileWorker(ctx, s.pool, ir)
	}
	go worker.RunDomainVerifyWorker(ctx, s.pool, net.DefaultResolver)
	if s.feedClient != nil {
		if s.licenseChecker != nil {
			s.feedClient.UpdateLicenseJWT(s.licenseChecker.RawToken())
		}
		s.feedClient.Start(ctx)
		go worker.RunShieldFeedWorker(ctx, s.feedClient)
	}
	s.addLicenseRoutes()

	if s.cfg.HTTP.TLSCertFile != "" && s.cfg.HTTP.TLSKeyFile != "" {
		// Build a custom *tls.Config that optionally enforces mutual-TLS client
		// authentication (RFC 8705). When MTLSClientCACertFile is provided,
		// tls.RequireAndVerifyClientCert is set; otherwise tls.RequestClientCert
		// is used so clients may present a cert for certificate-bound access tokens
		// without being required to do so.
		tlsCfg, err := crypto.BuildServerTLSConfig(
			s.cfg.HTTP.TLSCertFile,
			s.cfg.HTTP.TLSKeyFile,
			s.cfg.HTTP.MTLSClientCACertFile,
		)
		if err != nil {
			return fmt.Errorf("build TLS config: %w", err)
		}
		srv := &http.Server{
			Addr:      s.cfg.HTTP.Addr,
			TLSConfig: tlsCfg,
		}
		return s.echo.StartServer(srv)
	}
	return s.echo.Start(s.cfg.HTTP.Addr)
}

// Shutdown gracefully drains in-flight requests and audit workers.
func (s *Server) Shutdown(ctx context.Context) error {
	s.retention.Stop()
	s.gdprWorker.Stop()
	s.dispatcher.Stop()
	return s.echo.Shutdown(ctx)
}

// errorHandler maps domain errors to HTTP responses consistently.
func errorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}
	he, ok := err.(*echo.HTTPError)
	if !ok {
		he = &echo.HTTPError{Code: http.StatusInternalServerError, Message: "internal server error"}
		log.Error().Err(err).Str("path", c.Path()).Msg("unhandled error")
	}
	_ = c.JSON(he.Code, map[string]interface{}{
		"error":   http.StatusText(he.Code),
		"message": he.Message,
	})
}

// parseTrustedIssuers converts the OID4VP config's trusted issuers slice into
// a map of issuerURL → crypto.PublicKey. Entries that cannot be parsed are
// logged and skipped. Using a slice (not a map) avoids Viper's dot-in-key
// issue: URL keys containing "." would be silently mis-parsed by Viper.
func parseTrustedIssuers(issuers []config.TrustedCredentialIssuer) map[string]gocrypto.PublicKey {
	result := make(map[string]gocrypto.PublicKey, len(issuers))
	for _, entry := range issuers {
		if entry.Issuer == "" {
			continue
		}
		// Build a JWK JSON object from the flat fields.
		jwkFields := map[string]string{"kty": entry.Kty}
		if entry.Crv != "" {
			jwkFields["crv"] = entry.Crv
		}
		if entry.Alg != "" {
			jwkFields["alg"] = entry.Alg
		}
		if entry.X != "" {
			jwkFields["x"] = entry.X
		}
		if entry.Y != "" {
			jwkFields["y"] = entry.Y
		}
		if entry.N != "" {
			jwkFields["n"] = entry.N
		}
		if entry.E != "" {
			jwkFields["e"] = entry.E
		}
		jwkJSON, err := json.Marshal(jwkFields)
		if err != nil {
			log.Warn().Str("issuer", entry.Issuer).Err(err).Msg("oid4vp: skip trusted issuer (marshal error)")
			continue
		}
		key, err := jwk.ParseKey(jwkJSON)
		if err != nil {
			log.Warn().Str("issuer", entry.Issuer).Err(err).Msg("oid4vp: skip trusted issuer (jwk parse error)")
			continue
		}
		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			log.Warn().Str("issuer", entry.Issuer).Err(err).Msg("oid4vp: skip trusted issuer (raw key error)")
			continue
		}
		if pk, ok := rawKey.(gocrypto.PublicKey); ok {
			result[entry.Issuer] = pk
			log.Info().Str("issuer", entry.Issuer).Str("kty", entry.Kty).Msg("oid4vp: loaded trusted credential issuer")
		}
	}
	return result
}

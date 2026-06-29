package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/connector"
	"github.com/clavex-eu/clavex/internal/db"
	"github.com/clavex-eu/clavex/internal/license"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/redisconn"
	"github.com/clavex-eu/clavex/internal/server"
	"github.com/clavex-eu/clavex/internal/tracing"
	"github.com/clavex-eu/clavex/internal/usage_reporting"
	"github.com/clavex-eu/clavex/internal/worker"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// version is stamped at build time via -ldflags "-X main.version=x.y.z".
// Falls back to "dev" for local builds.
var version = "dev"

func main() {
	cfgPath := flag.String("config", "", "path to config file (default: config.yaml)")
	flag.Parse()
	if v := os.Getenv("CLAVEX_CONFIG"); v != "" {
		*cfgPath = v
	}

	cfg, err := config.LoadFrom(*cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	if cfg.Dev {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	// ── Distributed tracing (OTEL) ────────────────────────────────────────────
	tracingShutdown, err := tracing.Init(tracing.Config{
		Enabled:      cfg.Telemetry.Enabled,
		OTLPEndpoint: cfg.Telemetry.OTLPEndpoint,
		ServiceName:  cfg.Telemetry.ServiceName,
		SampleRate:   cfg.Telemetry.SampleRate,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise tracing")
	}
	defer func() {
		if err := tracingShutdown(context.Background()); err != nil {
			log.Error().Err(err).Msg("tracing shutdown error")
		}
	}()

	// ── Database ──────────────────────────────────────────────────────────────
	dbMgr, err := db.Open(cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open database")
	}
	defer dbMgr.Close()

	if os.Getenv("CLAVEX_RUN_MIGRATIONS") != "false" {
		if err := db.Migrate(dbMgr.Pool); err != nil {
			log.Fatal().Err(err).Msg("failed to run migrations")
		}
	} else {
		log.Info().Msg("skipping migrations (delegated to initContainer)")
	}

	// ── Redis ─────────────────────────────────────────────────────────────────
	rdb, err := redisconn.Open(cfg.Redis)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to Redis")
	}
	defer rdb.Close()

	// ── Signing keys ──────────────────────────────────────────────────────────
	var keys oidc.Signer
	var orgSigners *oidc.OrgSignerCache // non-nil only for key_backend=db
	var encKeys *oidc.EncKeySet         // non-nil only for key_backend=db (request-object encryption)
	switch cfg.Auth.KeyBackend {
	case "db":
		kek, kekErr := oidc.DecodeKEK(cfg.Auth.KeyEncryptionKey)
		if kekErr != nil {
			log.Fatal().Err(kekErr).Msg("invalid key_encryption_key for db key backend")
		}
		dbSigner, dbErr := oidc.NewDBSigner(context.Background(), dbMgr.Pool, kek)
		if dbErr != nil {
			log.Fatal().Err(dbErr).Msg("failed to initialise DB signing key")
		}
		keys = dbSigner
		// Enable per-org BYOK signing keys.
		orgSigners = oidc.NewOrgSignerCacheFromKEK(dbMgr.Pool, kek, dbSigner)
		log.Info().Str("kid", keys.KID()).Msg("signing key loaded from database")
		// Request-object encryption key (RFC 9101 §6.2): published with use=enc
		// so RPs can encrypt their JAR request objects to the OP.
		ek, ekErr := oidc.NewEncKeySet(context.Background(), dbMgr.Pool, kek)
		if ekErr != nil {
			log.Fatal().Err(ekErr).Msg("failed to initialise request-object encryption key")
		}
		encKeys = ek
		log.Info().Str("kid", encKeys.KID()).Str("alg", oidc.EncKeyAlgorithm).
			Msg("request-object encryption key loaded — public key exposed in JWKS (use=enc)")
	case "vault":
		if cfg.Auth.VaultAddress == "" {
			log.Fatal().Msg("auth.vault_address is required for key_backend=vault")
		}
		if cfg.Auth.VaultToken == "" {
			log.Fatal().Msg("auth.vault_token is required for key_backend=vault (or set VAULT_TOKEN)")
		}
		vaultSigner, vaultErr := oidc.NewVaultSigner(context.Background(), oidc.VaultConfig{
			Address:      cfg.Auth.VaultAddress,
			Token:        cfg.Auth.VaultToken,
			Namespace:    cfg.Auth.VaultNamespace,
			TransitKey:   cfg.Auth.VaultTransitKey,
			TransitMount: cfg.Auth.VaultTransitMount,
		})
		if vaultErr != nil {
			log.Fatal().Err(vaultErr).Msg("failed to initialise Vault Transit signing key")
		}
		keys = vaultSigner
		log.Info().Str("kid", keys.KID()).Msg("signing key loaded from Vault Transit")
	case "awskms":
		if cfg.Auth.AWSKMSKeyID == "" {
			log.Fatal().Msg("auth.aws_kms_key_id is required for key_backend=awskms")
		}
		kmsSigner, kmsErr := oidc.NewAWSSigner(context.Background(), oidc.AWSKMSConfig{
			KeyID:  cfg.Auth.AWSKMSKeyID,
			Region: cfg.Auth.AWSKMSRegion,
		})
		if kmsErr != nil {
			log.Fatal().Err(kmsErr).Msg("failed to initialise AWS KMS signing key")
		}
		keys = kmsSigner
		log.Info().Str("kid", keys.KID()).Msg("signing key loaded from AWS KMS")
	default: // "file" or unset
		if cfg.Auth.SigningKeyFile != "" {
			keys, err = oidc.LoadKeySet(cfg.Auth.SigningKeyFile)
			if err != nil {
				log.Fatal().Err(err).Str("path", cfg.Auth.SigningKeyFile).Msg("failed to load signing key")
			}
			log.Info().Str("kid", keys.KID()).Msg("signing key loaded")
		} else if !cfg.Dev {
			log.Fatal().Msg("auth.signing_key_file is required in production; run 'make generate-keys'")
		} else {
			log.Warn().Msg("no signing key configured — OIDC token endpoints will not work")
		}
	}

	// ── PQC signing key (NIST FIPS 204 / ML-DSA-65, passive JWKS mode) ──────
	var pqcSigner *oidc.PQCSigner
	if cfg.Auth.PQCEnabled {
		if cfg.Auth.PQCAlgorithm != oidc.PQCAlgorithmMLDSA65 {
			log.Fatal().
				Str("pqc_algorithm", cfg.Auth.PQCAlgorithm).
				Str("supported", oidc.PQCAlgorithmMLDSA65).
				Msg("unsupported auth.pqc_algorithm — only ml-dsa-65 is currently implemented")
		}
		pqcKEK, pqcKEKErr := oidc.DecodeKEK(cfg.Auth.KeyEncryptionKey)
		if pqcKEKErr != nil {
			log.Fatal().Err(pqcKEKErr).
				Msg("auth.key_encryption_key is required when pqc_enabled=true")
		}
		ps, psErr := oidc.NewPQCSigner(context.Background(), dbMgr.Pool, pqcKEK)
		if psErr != nil {
			log.Fatal().Err(psErr).Msg("failed to initialise PQC (ML-DSA-65) signing key")
		}
		pqcSigner = ps
		log.Info().
			Str("kid", pqcSigner.KID()).
			Str("alg", oidc.PQCJWAAlgorithm).
			Msg("PQC signing key loaded — ML-DSA-65 public key exposed in JWKS (passive mode)")
	}

	// ── Connectors ────────────────────────────────────────────────────────────
	for _, hc := range cfg.Connectors.HTTP {
		connector.Register(connector.NewHTTP(connector.HTTPConfig{
			URL:    hc.URL,
			Secret: hc.Secret,
			Events: hc.Events,
		}))
		log.Info().Str("url", hc.URL).Msg("connector/http registered")
	}
	for _, mc := range cfg.Connectors.MQTT {
		mqttConn, err := connector.NewMQTT(connector.MQTTConfig{
			BrokerURL:    mc.BrokerURL,
			ClientID:     mc.ClientID,
			Username:     mc.Username,
			Password:     mc.Password,
			TopicPattern: mc.TopicPattern,
			QoS:          mc.QoS,
			Events:       mc.Events,
		})
		if err != nil {
			log.Error().Err(err).Str("broker", mc.BrokerURL).Msg("connector/mqtt: failed to connect — skipping")
		} else {
			connector.Register(mqttConn)
			log.Info().Str("broker", mc.BrokerURL).Msg("connector/mqtt registered")
		}
	}
	defer connector.CloseAll()

	// ── HTTP server ───────────────────────────────────────────────────────────
	// workerCtx is cancelled on SIGINT/SIGTERM so background goroutines stop
	// gracefully before the process exits.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()

	// ── GDPR Art.17 erasure worker ────────────────────────────────────────────
	// Processes gdpr_erasure_requests WHERE status='scheduled' AND scheduled_for
	// <= NOW(). Runs once on startup (to clear any backlog) then every hour.
	// Idempotent: concurrent instances are safe due to conditional UPDATE.
	go worker.RunGDPRErasureWorker(workerCtx, dbMgr.Pool)

	// ── Access Review worker ──────────────────────────────────────────────────
	// Defined here (baseURL computed before server.New), launched after it so
	// srv.SSFDispatcher() is available for CAEP credential-change events.
	var accessReviewBaseURL string
	{
		baseURL := cfg.Auth.IssuerBase
		if baseURL == "" {
			scheme := "https"
			if cfg.HTTP.TLSCertFile == "" {
				scheme = "http"
			}
			baseURL = scheme + "://" + cfg.HTTP.BaseDomain
		}
		accessReviewBaseURL = baseURL
	}

	// ── License ────────────────────────────────────────────────────────────────────
	// Priority: 1) config file  2) DB (uploaded via admin frontend)  3) community.
	var lic *license.License
	if cfg.License.KeyFile != "" {
		var lerr error
		lic, lerr = license.ParseLicenseFile(cfg.License.KeyFile)
		if lerr != nil {
			log.Warn().Err(lerr).Str("path", cfg.License.KeyFile).
				Msg("license: parse failed — running in community mode")
		} else {
			log.Info().Str("tier", lic.Tier).Int("org_limit", lic.OrgLimit).
				Time("expires", lic.ExpiresAt).Msg("license loaded from file")
		}
	}
	var licRawToken string
	if lic == nil {
		// Try the token persisted via the admin frontend (migration 000135).
		dbLic, rawToken, dbErr := license.LoadFromDB(workerCtx, dbMgr.Pool)
		if dbErr != nil {
			log.Warn().Err(dbErr).Msg("license: DB load failed — running in community mode")
		} else if dbLic != nil {
			lic = dbLic
			licRawToken = rawToken
			log.Info().Str("tier", lic.Tier).Int("org_limit", lic.OrgLimit).
				Time("expires", lic.ExpiresAt).Msg("license loaded from DB")
		}
	}
	licChecker := license.NewChecker(dbMgr.Pool, lic, cfg.License.EnforceInstallationBinding)
	if licRawToken != "" {
		_ = licChecker.Reload(workerCtx, licRawToken)
	}
	// Log the installation binding id so the operator can supply it to the
	// licensor when purchasing/renewing a license.
	if bid, bErr := license.LicenseBindingID(workerCtx, dbMgr.Pool); bErr == nil {
		log.Info().Str("installation_id", bid).
			Msg("license: installation binding id — provide this when purchasing a license")
	}
	licChecker.Start(workerCtx)

	// ── Usage reporting (opt-in) ───────────────────────────────────────────────────
	// Sends anonymous installation statistics every 24 h.
	// Enable with: usage_reporting.enabled: true in config.
	if cfg.UsageReporting.Enabled {
		reporter := usagereporting.New(dbMgr.Pool, cfg.UsageReporting.Endpoint, version)
		go worker.RunUsageReportingWorker(workerCtx, reporter)
	}

	srv := server.New(cfg, dbMgr.Pool, rdb, keys, orgSigners).WithLicense(licChecker)
	if pqcSigner != nil {
		srv.WithPQCSigner(pqcSigner)
	}
	if encKeys != nil {
		srv.WithEncKeys(encKeys)
	}

	// ── MDS3 catalog refresh + post-refresh policy enforcement ──────────────────
	// After each successful catalog upsert, non-compliant WebAuthn credentials
	// are automatically revoked and CAEP credential-change SETs dispatched.
	// SSF dispatcher is available after server.New().
	go worker.RunMDS3WorkerFull(workerCtx, dbMgr.Pool, "", worker.PolicyEnforcerDeps{
		Pool:        dbMgr.Pool,
		SSFDispatch: srv.SSFDispatcher(),
	})

	// ── Access Review worker ──────────────────────────────────────────────────
	// Activates due campaigns, sends reminder emails, auto-revokes expired items,
	// and dispatches CAEP credential-change SETs for each revoked role.
	// Runs every 15 minutes; idempotent under concurrent instances.
	go worker.RunAccessReviewWorker(workerCtx, dbMgr.Pool, worker.AccessReviewDeps{
		BaseURL:     accessReviewBaseURL,
		SSFDispatch: srv.SSFDispatcher(),
	})

	// ── Compliance Drift worker ───────────────────────────────────────────────
	// Scans all active orgs every hour and detects changes in NIS2 / zero-trust
	// security controls (MFA enforcement, TTLs, admin counts, password policy).
	// Alerts via Slack/Teams and emits SSF SET events on drift detection.
	go worker.RunComplianceDriftWorker(workerCtx, dbMgr.Pool, worker.ComplianceDriftDeps{
		Notifier:    srv.PAMNotifier(),
		SSFDispatch: srv.SSFDispatcher(),
	})

	// Computes a real-time conformance score (0-100) per org every 5 minutes.
	// Tracks: MFA adoption (30 pts), PKCE clients (25 pts), DPoP clients (25 pts),
	// NIS2 policy checklist (20 pts). Alerts when score drops below threshold.
	go worker.RunConformanceScoreWorker(workerCtx, dbMgr.Pool, worker.ConformanceScoreDeps{
		Notifier:    srv.PAMNotifier(),
		SSFDispatch: srv.SSFDispatcher(),
	})

	// ── AI Identity Advisor worker ────────────────────────────────────────────
	// Every Monday at ~08:00 UTC: gathers security signals for each org (login
	// anomalies, admin hygiene, OAuth2 risks, conformance score, policy drift),
	// calls Claude via the org's Anthropic API key, and delivers a prioritised
	// CISO-level risk report by email to all active admin users.
	// Silently skipped for orgs without an Anthropic key or SMTP configuration.
	// Also available on-demand via the MCP tool: clavex_identity_advisor.
	go worker.RunIdentityAdvisorWorker(workerCtx, dbMgr.Pool, worker.IdentityAdvisorDeps{
		BaseURL: accessReviewBaseURL,
	})

	go func() {
		log.Info().Str("addr", cfg.HTTP.Addr).Msg("clavex starting")
		if err := srv.Start(); err != nil {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Cancel background workers before HTTP shutdown so they get a clean exit.
	workerCancel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("graceful shutdown failed")
	}
	log.Info().Msg("clavex stopped")
}

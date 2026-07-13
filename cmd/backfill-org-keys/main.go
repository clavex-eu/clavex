// cmd/backfill-org-keys migrates an existing installation from the shared
// global OIDC signing key to per-org signing keys (the new default).
//
// It is a one-shot, idempotent, safe-to-rerun command:
//
//   - Every organisation gets a freshly GENERATED per-org OIDC key.
//   - The outgoing global key is NOT copied per-org — kid is globally UNIQUE, so
//     it cannot live in more than one row. It does not need copying: the org
//     JWKS query (GetJWKSKeysForOrg) surfaces the global key in every org's
//     JWKS, so tokens signed with the global kid keep verifying.
//   - At the end the global OIDC key is retired with a grace window (default
//     72h). It stays in every org's JWKS for that window (continuity for
//     in-flight tokens), then drops out.
//   - Orgs that already have an active org key are skipped (idempotent rerun).
//
// The PQC (ML-DSA-65) key gets the same per-org generation when PQC is enabled,
// but with no global-exposure / grace / retirement step: PQC is discovery-only
// (no real token is signed with it), so there is nothing to keep verifying.
//
// Usage:
//
//	go run ./cmd/backfill-org-keys -config config.yaml
//	go run ./cmd/backfill-org-keys -transition=72h -dry-run
package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/db"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	cfgPath := flag.String("config", "", "path to config file (default: config.yaml or env)")
	transition := flag.Duration("transition", 72*time.Hour, "grace window during which the retired global OIDC key stays in every org's JWKS")
	dryRun := flag.Bool("dry-run", false, "log the planned actions without writing anything")
	flag.Parse()

	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	var cfg *config.Config
	var err error
	if *cfgPath == "" && os.Getenv("CLAVEX_DATABASE_DSN") != "" {
		cfg, err = config.LoadFrom("")
	} else {
		cfg, err = config.LoadFrom(*cfgPath)
	}
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	if cfg.Auth.KeyBackend != "db" {
		log.Warn().Str("key_backend", cfg.Auth.KeyBackend).
			Msg("per-org signing keys apply only to key_backend=db; nothing to migrate")
		return
	}

	dbMgr, err := db.Open(cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open database")
	}
	defer dbMgr.Close()

	kek, err := oidc.DecodeKEK(cfg.Auth.KeyEncryptionKey)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid key_encryption_key")
	}

	ctx := context.Background()
	keyRepo := repository.NewSigningKeyRepository(dbMgr.Pool)
	orgRepo := repository.NewOrgRepository(dbMgr.Pool)
	// global signer is unused by GenerateForOrg; nil is safe here.
	signers := oidc.NewOrgSignerCacheFromKEK(dbMgr.Pool, kek, nil)

	// The outgoing global OIDC key. If none exists, this is a fresh install.
	globalKey, err := keyRepo.GetActive(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Info().Msg("no active global signing key — fresh install, nothing to migrate")
			return
		}
		log.Fatal().Err(err).Msg("failed to read global signing key")
	}

	orgs, err := orgRepo.List(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to list organizations")
	}

	log.Info().
		Str("global_kid", globalKey.KID).
		Dur("transition", *transition).
		Int("orgs", len(orgs)).
		Bool("dry_run", *dryRun).
		Msg("backfill: plan — generate a per-org OIDC key per org, then retire the global key with a grace window")

	// Generate a per-org OIDC key for every org that lacks one.
	//
	// The outgoing global key is deliberately NOT copied into each org: kid is
	// globally UNIQUE, so the same kid cannot exist in multiple rows. It is also
	// unnecessary — GetJWKSKeysForOrg surfaces the global key in every org's
	// JWKS until it is retired below, so tokens signed with the global kid keep
	// verifying throughout the transition window.
	var generated, skipped int
	for _, org := range orgs {
		lg := log.With().Str("org_id", org.ID.String()).Str("slug", org.Slug).Logger()

		if _, gerr := keyRepo.GetActiveForOrg(ctx, org.ID); gerr == nil {
			lg.Info().Msg("backfill: org already has an active key — skipping")
			skipped++
			continue
		} else if !errors.Is(gerr, pgx.ErrNoRows) {
			log.Fatal().Err(gerr).Str("org_id", org.ID.String()).Msg("failed to check org key")
		}

		if *dryRun {
			lg.Info().Msg("backfill: [dry-run] would generate a fresh per-org OIDC key")
			generated++
			continue
		}
		newKID, err := signers.GenerateForOrg(ctx, org.ID)
		if err != nil {
			log.Fatal().Err(err).Str("org_id", org.ID.String()).Msg("failed to generate org key")
		}
		lg.Info().Str("new_kid", newKID).Msg("backfill: org got a fresh OIDC key")
		generated++
	}

	// End the transition: retire the global OIDC key with the grace window. It
	// keeps verifying in-flight tokens for `transition`, then drops out of every
	// org's JWKS. Idempotent — a rerun after retirement updates 0 rows.
	if *dryRun {
		log.Info().Dur("grace", *transition).Msg("backfill: [dry-run] would retire the global OIDC key with a grace window")
	} else if err := keyRepo.RetireActiveGlobalOIDCWithGrace(ctx, *transition); err != nil {
		log.Fatal().Err(err).Msg("failed to retire the global OIDC key")
	} else {
		log.Info().Dur("grace", *transition).Msg("backfill: global OIDC key retired with grace window")
	}

	// ── PQC (ML-DSA-65) per-org backfill ────────────────────────────────────────
	//
	// PQC is discovery-only today (no real token is signed with the PQC key), so
	// there is no token-continuity concern at all — no global-key exposure, no
	// grace window, no global retirement. Just give every org its own PQC key.
	var pqcGenerated, pqcSkipped int
	if _, pqcErr := keyRepo.GetActivePQC(ctx); errors.Is(pqcErr, pgx.ErrNoRows) {
		log.Info().Msg("backfill: no active global PQC key (PQC disabled) — skipping PQC")
	} else if pqcErr != nil {
		log.Fatal().Err(pqcErr).Msg("failed to read global PQC key")
	} else {
		pqcSigners := oidc.NewOrgPQCSignerCacheFromKEK(dbMgr.Pool, kek, nil)
		for _, org := range orgs {
			lg := log.With().Str("org_id", org.ID.String()).Str("slug", org.Slug).Logger()

			if _, gerr := keyRepo.GetActivePQCForOrg(ctx, org.ID); gerr == nil {
				lg.Info().Msg("backfill(pqc): org already has an active PQC key — skipping")
				pqcSkipped++
				continue
			} else if !errors.Is(gerr, pgx.ErrNoRows) {
				log.Fatal().Err(gerr).Str("org_id", org.ID.String()).Msg("failed to check org PQC key")
			}

			if *dryRun {
				lg.Info().Msg("backfill(pqc): [dry-run] would generate a fresh PQC key")
				pqcGenerated++
				continue
			}
			newKID, err := pqcSigners.GenerateForOrg(ctx, org.ID)
			if err != nil {
				log.Fatal().Err(err).Str("org_id", org.ID.String()).Msg("failed to generate org PQC key")
			}
			lg.Info().Str("new_kid", newKID).Msg("backfill(pqc): org got a fresh PQC key")
			pqcGenerated++
		}
	}

	log.Info().
		Int("oidc_generated", generated).
		Int("oidc_skipped", skipped).
		Int("pqc_generated", pqcGenerated).
		Int("pqc_skipped", pqcSkipped).
		Bool("dry_run", *dryRun).
		Msg("backfill: complete")
}

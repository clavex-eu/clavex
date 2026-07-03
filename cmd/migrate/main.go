// cmd/migrate — standalone CLI per la gestione delle migrazioni del database.
//
// Usage:
//
//	migrate [-config config.yaml] <command> [args]
//
// Commands:
//
//	up              Applica tutte le migrazioni pending
//	down [N]        Rollback di N step (default 1; -1 = tutto)
//	to <version>    Migra alla versione specificata (up o down)
//	version         Stampa la versione corrente dello schema
//	force <version> Forza la versione nel DB (usare solo per recovery)
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/db"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	// Override config path via env variable for container convenience.
	if v := os.Getenv("CLAVEX_CONFIG"); v != "" {
		*cfgPath = v
	}

	// If no config file is specified explicitly and CLAVEX_DATABASE_DSN is set,
	// build a minimal config from environment variables only (no file needed).
	var (
		cfg *config.Config
		err error
	)
	if *cfgPath == "config.yaml" && os.Getenv("CLAVEX_DATABASE_DSN") != "" {
		cfg, err = config.LoadFrom("")
	} else {
		cfg, err = config.LoadFrom(*cfgPath)
	}
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	mgr, err := db.Open(cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open database")
	}
	defer mgr.Close()

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "up":
		if err := db.Migrate(mgr.Pool); err != nil {
			log.Fatal().Err(err).Msg("migrate up failed")
		}

	case "down":
		steps := 1
		if len(cmdArgs) > 0 {
			n, err := strconv.Atoi(cmdArgs[0])
			if err != nil {
				log.Fatal().Msgf("invalid steps argument %q: must be an integer", cmdArgs[0])
			}
			steps = n
		}
		if err := db.MigrateDown(mgr.Pool, steps); err != nil {
			log.Fatal().Err(err).Msg("migrate down failed")
		}

	case "to":
		if len(cmdArgs) == 0 {
			log.Fatal().Msg("migrate to: missing version argument")
		}
		v, err := strconv.ParseUint(cmdArgs[0], 10, 64)
		if err != nil {
			log.Fatal().Msgf("invalid version %q: must be a non-negative integer", cmdArgs[0])
		}
		if v > math.MaxInt32 {
			log.Fatal().Msgf("version %d out of range", v)
		}
		if err := db.MigrateTo(mgr.Pool, uint(v)); err != nil {
			log.Fatal().Err(err).Msg("migrate to failed")
		}

	case "version":
		v, dirty, err := db.MigrateVersion(mgr.Pool)
		if err != nil {
			log.Fatal().Err(err).Msg("get version failed")
		}
		fmt.Printf("version: %d  dirty: %v\n", v, dirty)

	case "force":
		if len(cmdArgs) == 0 {
			log.Fatal().Msg("migrate force: missing version argument")
		}
		v, err := strconv.ParseUint(cmdArgs[0], 10, 64)
		if err != nil {
			log.Fatal().Msgf("invalid version %q: must be a non-negative integer", cmdArgs[0])
		}
		if v > math.MaxInt32 {
			log.Fatal().Msgf("version %d out of range", v)
		}
		if err := db.MigrateForce(mgr.Pool, int(v)); err != nil {
			log.Fatal().Err(err).Msg("migrate force failed")
		}
		fmt.Printf("forced version to %d\n", v)

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: migrate [-config <path>] <command> [args]

Commands:
  up              Apply all pending migrations
  down [N]        Roll back N steps (default 1; use -1 for all)
  to <version>    Migrate to the specified version
  version         Print current schema version
  force <version> Force-set version without running SQL (recovery only)`)
}

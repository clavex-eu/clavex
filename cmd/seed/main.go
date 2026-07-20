// cmd/seed creates an initial organization, admin user, and demo OIDC client
// for local development / first-run setup.
//
// Usage:
//
//	go run ./cmd/seed -org=demo -email=admin@demo.local -password=Admin1234!
//
// Or via Make:
//
//	make seed
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/db"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	cfgPath := flag.String("config", "", "path to config file (default: config.yaml)")
	orgSlug := flag.String("org", "demo", "Organization slug (URL-safe, lowercase)")
	orgName := flag.String("org-name", "", "Organization display name (defaults to slug)")
	email := flag.String("email", "admin@demo.local", "Admin user email")
	password := flag.String("password", "", "Admin user password (required, or set CLAVEX_SEED_PASSWORD)")
	superAdmin := flag.Bool("superadmin", false, "Assign the super_admin role instead of admin (grants access to all orgs)")
	confidential := flag.Bool("confidential", false, "also create a confidential client for client_credentials tests")
	flag.Parse()

	// Fall back to env variable so the seed Job can receive the password from a Secret.
	if *password == "" {
		*password = os.Getenv("CLAVEX_SEED_PASSWORD")
	}
	if *password == "" {
		fmt.Fprintln(os.Stderr, "error: -password is required (or set CLAVEX_SEED_PASSWORD)")
		os.Exit(1)
	}
	if *orgName == "" {
		*orgName = *orgSlug
	}

	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	// If no config file is given and CLAVEX_DATABASE_DSN is set, rely on env vars only.
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

	dbMgr, err := db.Open(cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open database")
	}
	defer dbMgr.Close()

	// Run migrations so the schema is up-to-date.
	if err := db.Migrate(dbMgr.Pool); err != nil {
		log.Fatal().Err(err).Msg("migrations failed")
	}

	ctx := context.Background()
	orgRepo := repository.NewOrgRepository(dbMgr.Pool)
	userRepo := repository.NewUserRepository(dbMgr.Pool)
	clientRepo := repository.NewClientRepository(dbMgr.Pool)

	// ── Organization ─────────────────────────────────────────────────────────
	org, err := orgRepo.GetBySlug(ctx, *orgSlug)
	if err != nil {
		org, err = orgRepo.Create(ctx, *orgName, *orgSlug, nil)
		if err != nil {
			log.Fatal().Err(err).Str("slug", *orgSlug).Msg("create org failed")
		}
		log.Info().Str("slug", org.Slug).Str("id", org.ID.String()).Msg("organization created")
	} else {
		log.Info().Str("slug", org.Slug).Msg("organization already exists — skipping")
	}

	// ── Admin user ────────────────────────────────────────────────────────────
	firstName := "Admin"
	user, err := userRepo.GetByEmail(ctx, org.ID, *email)
	if err != nil {
		user, err = userRepo.Create(ctx, org.ID, *email, &firstName, nil)
		if err != nil {
			log.Fatal().Err(err).Str("email", *email).Msg("create user failed")
		}
		if err := userRepo.SetPassword(ctx, user.ID, *password); err != nil {
			log.Fatal().Err(err).Msg("set password failed")
		}
		log.Info().Str("email", user.Email).Str("id", user.ID.String()).Msg("admin user created")
	} else {
		log.Info().Str("email", user.Email).Msg("user already exists — skipping")
	}

	// ── Admin role ────────────────────────────────────────────────────────────
	roleName := "admin"
	roleDesc := "Full administrative access"
	if *superAdmin {
		roleName = "super_admin"
		roleDesc = "Full superadmin access across all organizations"
	}

	roles, _ := userRepo.ListRoles(ctx, org.ID)
	var adminRoleID uuid.UUID
	for _, r := range roles {
		if r.Name == roleName {
			adminRoleID = r.ID
			break
		}
	}
	if adminRoleID == uuid.Nil {
		role, err := userRepo.CreateRole(ctx, org.ID, roleName, &roleDesc)
		if err != nil {
			log.Fatal().Err(err).Msg("create role failed")
		}
		adminRoleID = role.ID
		log.Info().Str("role", role.Name).Msg("role created")
	}

	// Assign role (no-op if already assigned due to ON CONFLICT DO NOTHING).
	if err := userRepo.AssignRole(ctx, user.ID, adminRoleID); err == nil {
		log.Info().Str("role", roleName).Msg("role assigned to user")
	}

	// ── Demo OIDC clients ────────────────────────────────────────────────────
	clients, _ := clientRepo.ListByOrg(ctx, org.ID)
	hasPublic := false
	hasConfidential := false
	for _, c := range clients {
		if c.ClientSecretHash == nil {
			hasPublic = true
		} else {
			hasConfidential = true
		}
	}

	var ccClientID, ccSecret string

	if !hasPublic {
		redirectURIs := []string{
			"http://localhost:5173/callback",
			"http://localhost:8080/callback",
		}
		client, _, err := clientRepo.Create(ctx, org.ID, "", "Demo SPA (public)", redirectURIs, nil, nil, nil, nil, true)
		if err != nil {
			log.Fatal().Err(err).Msg("create demo public client failed")
		}
		log.Info().Str("client_id", client.ClientID).Msg("demo public OIDC client created (no secret — use PKCE)")
	} else {
		log.Info().Msg("public OIDC client already exists — skipping")
	}

	if *confidential && !hasConfidential {
		cc, secret, err := clientRepo.Create(ctx, org.ID, "", "Demo M2M (confidential)", []string{}, nil, nil, nil, nil, false)
		if err != nil {
			log.Fatal().Err(err).Msg("create demo confidential client failed")
		}
		ccClientID = cc.ClientID
		ccSecret = secret
		log.Info().Str("client_id", cc.ClientID).Msg("demo confidential OIDC client created")
	} else if *confidential {
		log.Info().Msg("confidential OIDC client already exists — skipping")
	}

	log.Info().Msg("seed complete")
	printSummary(*orgSlug, *email, *password, ccClientID, ccSecret)
}

func printSummary(orgSlug, email, password, ccClientID, ccSecret string) {
	fmt.Printf(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 clavex — first-run seed complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Organization slug : %s
  Admin email       : %s
  Admin password    : %s

  OIDC discovery    : http://localhost:8080/%s/.well-known/openid-configuration
  Admin login       : POST http://localhost:8080/api/v1/auth/login
  Test script       : bash scripts/test-oidc.sh
`, orgSlug, email, password, orgSlug)
	if ccClientID != "" {
		fmt.Printf(`
  Confidential client:
    client_id     : %s
    client_secret : %s

  Test client_credentials:
    curl -s -X POST http://localhost:8080/%s/token \\
      -d grant_type=client_credentials \\
      -d client_id=%s \\
      -d client_secret=%s \\
      -d scope=openid | jq
`, ccClientID, ccSecret, orgSlug, ccClientID, ccSecret)
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/clavex-eu/clavex/internal/config"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Manager holds the connection pool and, when running in embedded mode,
// the lifecycle handle for the bundled PostgreSQL process.
type Manager struct {
	Pool     *pgxpool.Pool
	embedded *embeddedpostgres.EmbeddedPostgres // nil in external mode
}

// Close shuts down the connection pool and, in embedded mode, stops the
// PostgreSQL process cleanly.
func (m *Manager) Close() {
	m.Pool.Close()
	if m.embedded != nil {
		if err := m.embedded.Stop(); err != nil {
			log.Error().Err(err).Msg("failed to stop embedded postgres")
		} else {
			log.Info().Msg("embedded postgres stopped")
		}
	}
}

// Open initialises the database according to the configuration:
//   - "external": connects to the user-supplied DSN.
//   - "embedded": starts a managed PostgreSQL process and connects to it.
func Open(cfg config.DatabaseConfig) (*Manager, error) {
	switch cfg.Mode {
	case config.DatabaseModeEmbedded:
		return openEmbedded(cfg)
	case config.DatabaseModeExternal, "": // default to external
		return openExternal(cfg)
	default:
		return nil, fmt.Errorf("unknown database.mode %q (valid: external, embedded)", cfg.Mode)
	}
}

// openExternal connects to a pre-existing PostgreSQL server using the DSN
// supplied in the configuration.
func openExternal(cfg config.DatabaseConfig) (*Manager, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("database.dsn must be set when database.mode is \"external\"")
	}
	pool, err := newPool(cfg.DSN, cfg.MaxConns, cfg.MinConns)
	if err != nil {
		return nil, err
	}
	log.Info().Str("mode", "external").Msg("database connected")
	return &Manager{Pool: pool}, nil
}

// openEmbedded starts an embedded PostgreSQL instance managed by the process,
// then returns a connected pool. The binary is cached in the system cache
// directory and re-used across restarts; data files persist in DataDir.
func openEmbedded(cfg config.DatabaseConfig) (*Manager, error) {
	dataDir := cfg.Embedded.DataDir
	if dataDir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			cacheDir = os.TempDir()
		}
		dataDir = filepath.Join(cacheDir, "clavex", "pgdata")
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create embedded postgres data dir: %w", err)
	}

	pg := embeddedpostgres.NewDatabase(
		embeddedpostgres.DefaultConfig().
			Username(cfg.Embedded.Username).
			Password(cfg.Embedded.Password).
			Database(cfg.Embedded.Database).
			Port(cfg.Embedded.Port).
			DataPath(dataDir).
			Logger(&embeddedPostgresLogger{}),
	)

	log.Info().
		Str("data_dir", dataDir).
		Uint32("port", cfg.Embedded.Port).
		Msg("starting embedded postgres")

	if err := pg.Start(); err != nil {
		return nil, fmt.Errorf("start embedded postgres: %w", err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@localhost:%d/%s?sslmode=disable",
		cfg.Embedded.Username,
		cfg.Embedded.Password,
		cfg.Embedded.Port,
		cfg.Embedded.Database,
	)

	pool, err := newPool(dsn, cfg.MaxConns, cfg.MinConns)
	if err != nil {
		_ = pg.Stop()
		return nil, err
	}

	log.Info().Str("mode", "embedded").Msg("database connected")
	return &Manager{Pool: pool, embedded: pg}, nil
}

func newPool(dsn string, maxConns, minConns int32) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	if maxConns > 0 {
		poolCfg.MaxConns = maxConns
	}
	if minConns > 0 {
		poolCfg.MinConns = minConns
	}
	// Set search_path so queries work transparently after migration 000017 moves
	// tables into the identity / sessions / audit schemas.
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path = identity, sessions, audit, public`)
		return err
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending up-migrations using golang-migrate.
// Migrations are embedded at compile time from internal/db/migrations/.
func Migrate(pool *pgxpool.Pool) error {
	m, err := newMigrator(pool)
	if err != nil {
		return err
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("run migrations: %w", err)
	}

	v, _, _ := m.Version()
	log.Info().Uint("version", uint(v)).Msg("database schema up to date")
	return nil
}

// MigrateDown rolls back n migration steps (pass -1 for all).
func MigrateDown(pool *pgxpool.Pool, steps int) error {
	m, err := newMigrator(pool)
	if err != nil {
		return err
	}
	defer m.Close()

	if steps < 0 {
		return m.Down()
	}
	return m.Steps(-steps)
}

// MigrateTo migrates to a specific version (up or down).
func MigrateTo(pool *pgxpool.Pool, version uint) error {
	m, err := newMigrator(pool)
	if err != nil {
		return err
	}
	defer m.Close()
	return m.Migrate(version)
}

// MigrateVersion returns the current applied migration version.
func MigrateVersion(pool *pgxpool.Pool) (uint, bool, error) {
	m, err := newMigrator(pool)
	if err != nil {
		return 0, false, err
	}
	defer m.Close()
	return m.Version()
}

// MigrateForce force-sets the schema version without executing SQL.
// Use only to recover from a failed migration that left the DB in a dirty state.
func MigrateForce(pool *pgxpool.Pool, version int) error {
	m, err := newMigrator(pool)
	if err != nil {
		return err
	}
	defer m.Close()
	return m.Force(version)
}

func newMigrator(pool *pgxpool.Pool) (*migrate.Migrate, error) {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("create migration source: %w", err)
	}

	// Build a pgx5:// URL for golang-migrate from the pool's connection config.
	// Include the same search_path used by the application pool so that
	// migrations after 000017 (which moves tables into identity/sessions/audit
	// schemas) can reference tables without schema-qualifying every name.
	cc := pool.Config().ConnConfig
	q := url.Values{}
	q.Set("search_path", "identity,sessions,audit,public")
	u := &url.URL{
		Scheme:   "pgx5",
		User:     url.UserPassword(cc.User, cc.Password),
		Host:     fmt.Sprintf("%s:%d", cc.Host, cc.Port),
		Path:     "/" + cc.Database,
		RawQuery: q.Encode(),
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, u.String())
	if err != nil {
		return nil, fmt.Errorf("create migrator: %w", err)
	}
	m.Log = &migrateLogger{}
	return m, nil
}

// migrateLogger bridges golang-migrate log output to zerolog.
type migrateLogger struct{}

func (l *migrateLogger) Printf(format string, v ...interface{}) {
	log.Info().Str("component", "migrate").Msgf(format, v...)
}
func (l *migrateLogger) Verbose() bool { return false }

// embeddedPostgresLogger bridges embedded-postgres output to zerolog.
type embeddedPostgresLogger struct{}

func (l *embeddedPostgresLogger) Write(p []byte) (int, error) {
	log.Debug().Str("component", "embedded-postgres").Msg(string(p))
	return len(p), nil
}

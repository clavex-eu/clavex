// Package usagereporting sends anonymous installation telemetry to Clavex.
//
// The payload contains no personal data:
//
//	{"installation_id": "<sha256>", "version": "...", "orgs": N, "users": M, "arch": "linux/amd64"}
//
// The installation_id is derived as hex(sha256(hostname + installation_uuid)) so it
// is stable across restarts but cannot be reversed to identify the operator.
// Telemetry is opt-in and can be disabled via usage_reporting.enabled: false.
package usagereporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/clavex-eu/clavex/internal/license"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	defaultEndpoint = "https://telemetry.clavex.eu/v1/report"
	httpTimeout     = 15 * time.Second
)

// Reporter collects installation stats and POSTs them to the telemetry endpoint.
type Reporter struct {
	pool     *pgxpool.Pool
	endpoint string
	version  string
	client   *http.Client
}

// New creates a Reporter. If endpoint is empty the default Clavex endpoint is used.
func New(pool *pgxpool.Pool, endpoint, version string) *Reporter {
	ep := endpoint
	if ep == "" {
		ep = defaultEndpoint
	}
	return &Reporter{
		pool:     pool,
		endpoint: ep,
		version:  version,
		client:   &http.Client{Timeout: httpTimeout},
	}
}

// report is the JSON payload sent to the telemetry endpoint.
type report struct {
	InstallationID string `json:"installation_id"`
	Version        string `json:"version"`
	Orgs           int64  `json:"orgs"`
	Users          int64  `json:"users"`
	Arch           string `json:"arch"`
}

// Send collects current stats and posts a telemetry report.
// Errors are non-fatal — the caller logs and continues.
func (r *Reporter) Send(ctx context.Context) error {
	installID, err := license.InstallationID(ctx, r.pool)
	if err != nil {
		return fmt.Errorf("usage_reporting: installation_id: %w", err)
	}

	var orgs, users int64
	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM organizations WHERE is_active = TRUE`).Scan(&orgs)
	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE is_active = TRUE`).Scan(&users)

	payload := report{
		InstallationID: installID,
		Version:        r.version,
		Orgs:           orgs,
		Users:          users,
		Arch:           runtime.GOOS + "/" + runtime.GOARCH,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("usage_reporting: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("usage_reporting: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "clavex/"+r.version)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("usage_reporting: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("usage_reporting: server returned %d", resp.StatusCode)
	}

	log.Info().
		Str("installation_id", installID[:8]+"...").
		Int64("orgs", orgs).
		Int64("users", users).
		Str("arch", payload.Arch).
		Msg("usage_reporting: telemetry sent")
	return nil
}

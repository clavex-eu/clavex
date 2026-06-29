package worker

import (
	"context"
	"time"

	usagereporting "github.com/clavex-eu/clavex/internal/usage_reporting"
	"github.com/rs/zerolog/log"
)

const usageReportInterval = 24 * time.Hour

// RunUsageReportingWorker sends anonymous installation telemetry every 24 hours.
// An initial report is sent immediately on startup to populate dashboards quickly.
// The worker stops gracefully when ctx is cancelled.
func RunUsageReportingWorker(ctx context.Context, reporter *usagereporting.Reporter) {
	log.Info().Msg("usage-reporting-worker: started (interval=24h)")

	// Fire immediately on startup (catches any backlog from previous crashes).
	if err := reporter.Send(ctx); err != nil {
		log.Warn().Err(err).Msg("usage-reporting-worker: initial send failed — will retry in 24h")
	}

	ticker := time.NewTicker(usageReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("usage-reporting-worker: stopping")
			return
		case <-ticker.C:
			if err := reporter.Send(ctx); err != nil {
				log.Warn().Err(err).Msg("usage-reporting-worker: send failed")
			}
		}
	}
}

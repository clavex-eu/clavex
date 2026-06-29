package worker

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/shield"
	"github.com/rs/zerolog/log"
)

// RunShieldFeedWorker refreshes the Clavex Shield distributed threat feed
// every 15 minutes. It refreshes immediately on startup so the first
// login-risk computation benefits from current threat intelligence.
func RunShieldFeedWorker(ctx context.Context, client *shield.FeedClient) {
	if err := client.Refresh(ctx); err != nil {
		log.Warn().Err(err).Msg("shield: initial feed refresh failed")
	}
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := client.Refresh(ctx); err != nil {
				log.Warn().Err(err).Msg("shield: feed refresh failed")
			}
		}
	}
}

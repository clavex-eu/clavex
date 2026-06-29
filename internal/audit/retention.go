package audit

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

// ── Retention worker ──────────────────────────────────────────────────────────

// RetentionStore is implemented by the audit repository.
type RetentionStore interface {
	// DeleteExpiredEvents removes all audit_log rows older than retentionDays
	// for every org that has a retention policy set.
	DeleteExpiredEvents(ctx context.Context) (deleted int64, err error)
}

// RetentionWorker runs periodic cleanup of old audit events.
type RetentionWorker struct {
	store    RetentionStore
	interval time.Duration
	stop     chan struct{}
	stopped  chan struct{}
}

// NewRetentionWorker creates a RetentionWorker that runs every interval.
// A typical value is 1 * time.Hour.
func NewRetentionWorker(store RetentionStore, interval time.Duration) *RetentionWorker {
	return &RetentionWorker{
		store:    store,
		interval: interval,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
}

// Start begins the retention ticker in a background goroutine.
func (w *RetentionWorker) Start(ctx context.Context) {
	go func() {
		defer close(w.stopped)
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		// Run once immediately at startup.
		w.run(ctx)

		for {
			select {
			case <-ticker.C:
				w.run(ctx)
			case <-w.stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop signals the worker to stop and waits for the current run to finish.
func (w *RetentionWorker) Stop() {
	close(w.stop)
	<-w.stopped
}

func (w *RetentionWorker) run(ctx context.Context) {
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	n, err := w.store.DeleteExpiredEvents(runCtx)
	if err != nil {
		log.Error().Err(err).Msg("audit retention: cleanup failed")
		return
	}
	if n > 0 {
		log.Info().Int64("deleted", n).Msg("audit retention: expired events removed")
	}
}

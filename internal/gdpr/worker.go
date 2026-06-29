// Package gdpr provides background workers that enforce GDPR data retention
// policies configured per organisation.
package gdpr

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

// AnonymizationStore is the interface the worker uses to anonymise inactive users.
// Implemented by repository.GDPRRetentionRepository.
type AnonymizationStore interface {
	AnonymizeInactiveUsers(ctx context.Context) (int64, error)
}

// RetentionWorker runs periodic user anonymisation according to the GDPR
// Art.5(1)(e) retention policies configured for each organisation.
type RetentionWorker struct {
	store    AnonymizationStore
	interval time.Duration
	stop     chan struct{}
	stopped  chan struct{}
}

// NewRetentionWorker creates a RetentionWorker that runs every interval.
// A typical value is 7 * 24 * time.Hour (weekly).
func NewRetentionWorker(store AnonymizationStore, interval time.Duration) *RetentionWorker {
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

		// Run once immediately at startup so the first anonymisation pass
		// happens on server start rather than after the full interval.
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
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	n, err := w.store.AnonymizeInactiveUsers(runCtx)
	if err != nil {
		log.Error().Err(err).Msg("gdpr retention: anonymisation run failed")
		return
	}
	if n > 0 {
		log.Info().Int64("anonymised", n).Msg("gdpr retention: inactive users anonymised")
	}
}

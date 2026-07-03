package worker

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/ingressreconcile"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// ingressReconcileInterval is how often custom-domain ingress state is synced.
// Reconciliation is idempotent (Server-Side Apply), so frequent ticks are cheap.
const ingressReconcileInterval = 2 * time.Minute

// RunIngressReconcileWorker keeps the k8s Ingresses/Secrets for active custom
// domains in sync with the database. It reconciles once on startup then every
// couple of minutes. Under multiple replicas an advisory lock ensures only one
// replica reconciles per tick. Stops gracefully when ctx is cancelled.
func RunIngressReconcileWorker(ctx context.Context, pool *pgxpool.Pool, r *ingressreconcile.Reconciler) {
	log.Info().Msg("ingress-reconcile-worker: started (interval=2m)")

	reconcile := func() {
		withLeaderLock(ctx, pool, lockIngressReconcile, func() {
			if err := r.Reconcile(ctx); err != nil {
				log.Warn().Err(err).Msg("ingress-reconcile-worker: reconcile failed")
			}
		})
	}

	reconcile()

	ticker := time.NewTicker(ingressReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("ingress-reconcile-worker: stopping")
			return
		case <-ticker.C:
			reconcile()
		}
	}
}

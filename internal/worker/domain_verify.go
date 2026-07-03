package worker

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/domainverify"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const domainVerifyInterval = 3 * time.Minute

const lockDomainVerify int64 = 0x636c_7876_7269_6600 // "clxvrif"

// RunDomainVerifyWorker re-checks pending custom domains as their CNAME
// propagates and activates the ones that now point at the Clavex target. It runs
// only when a CNAME target is configured. Under multiple replicas an advisory
// lock ensures a single reconciler per tick.
func RunDomainVerifyWorker(ctx context.Context, pool *pgxpool.Pool, resolver domainverify.Resolver) {
	target := strings.TrimSuffix(os.Getenv("CLAVEX_CLOUD_CNAME_TARGET"), ".")
	if target == "" {
		return // verification not configured — nothing to poll
	}
	log.Info().Msg("domain-verify-worker: started (interval=3m)")

	repo := repository.NewCustomDomainRepository(pool)
	tick := func() {
		withLeaderLock(ctx, pool, lockDomainVerify, func() {
			pending, err := repo.ListPending(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("domain-verify-worker: list pending failed")
				return
			}
			for _, d := range pending {
				lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				resolved, lookupErr := resolver.LookupCNAME(lctx, d.Domain)
				cancel()
				if lookupErr != nil || !domainverify.Matches(resolved, target) {
					continue // still not pointing at us; leave pending for retry
				}
				if err := repo.Activate(ctx, d.ID, nil); err != nil {
					log.Warn().Err(err).Str("domain", d.Domain).Msg("domain-verify-worker: activate failed")
					continue
				}
				log.Info().Str("domain", d.Domain).Msg("domain-verify-worker: domain auto-verified")
			}
		})
	}

	tick()
	ticker := time.NewTicker(domainVerifyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("domain-verify-worker: stopping")
			return
		case <-ticker.C:
			tick()
		}
	}
}

package worker

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// Advisory-lock keys for singleton workers. Each must be globally unique across
// the app's use of pg_advisory_lock. Arbitrary but stable constants.
const lockIngressReconcile int64 = 0x636c_7869_6e67_7200 // "clxingr"

// withLeaderLock runs fn only if this replica can grab the Postgres advisory
// lock `key` for the duration of the call. With multiple replicas exactly one
// wins each tick and the others skip — so singleton work (reconciling ingress,
// re-verifying domains) isn't duplicated. The lock is session-scoped on a single
// pooled connection and released when fn returns; if the holder crashes the
// connection closes and the lock frees, so another replica takes over next tick.
func withLeaderLock(ctx context.Context, pool *pgxpool.Pool, key int64, fn func()) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("leader-lock: acquire connection failed")
		return
	}
	defer conn.Release()

	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
		log.Warn().Err(err).Msg("leader-lock: try_advisory_lock failed")
		return
	}
	if !got {
		return
	}
	defer func() {
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, key); err != nil {
			log.Warn().Err(err).Msg("leader-lock: advisory_unlock failed")
		}
	}()

	fn()
}

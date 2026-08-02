package worker

// DeviceCARotationWorker mirrors the SSH CA scheduled-rotation subset of
// RunPAMRotationWorker: it triggers scheduled rotation Starts and sweeps
// grace-expired old Vault PKI mounts for the Device CA. It never advances a
// rotation past Start — mark-ready/complete are always explicit
// operator/agent steps (see internal/handler/devicepki_rotation.go).

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/devicepki"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const deviceCARotationWorkerInterval = 6 * time.Hour

// deviceCARotationStarter is the StartRotation subset the scheduler uses.
type deviceCARotationStarter interface {
	StartRotation(ctx context.Context, orgID uuid.UUID, startedBy, policy string, intervalDays *int) (*repository.DeviceCARotation, string, error)
}

// RunDeviceCARotationWorker starts the Device CA scheduled-rotation and
// grace-cleanup goroutine. Blocks until ctx is cancelled.
func RunDeviceCARotationWorker(ctx context.Context, pool *pgxpool.Pool, enc *crypto.Encryptor, disp devicepki.Dispatcher) {
	repo := repository.NewDevicePKIRepository(pool)
	svc := devicepki.NewService(repo, enc, disp)

	log.Info().Str("interval", deviceCARotationWorkerInterval.String()).
		Msg("device-ca-rotation-worker: started")

	processDeviceCAScheduledStarts(ctx, repo, svc)
	svc.CleanupExpiredGrace(ctx)

	ticker := time.NewTicker(deviceCARotationWorkerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("device-ca-rotation-worker: stopping")
			return
		case <-ticker.C:
			processDeviceCAScheduledStarts(ctx, repo, svc)
			svc.CleanupExpiredGrace(ctx)
		}
	}
}

func processDeviceCAScheduledStarts(ctx context.Context, repo *repository.DevicePKIRepository, svc deviceCARotationStarter) {
	due, err := repo.ListDeviceCAConfigsForScheduledRotation(ctx, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("device-ca-rotation-worker: list scheduled rotations")
		return
	}
	for i := range due {
		cfg := due[i]
		interval := cfg.IntervalDays
		if _, _, err := svc.StartRotation(ctx, cfg.OrgID, "scheduler", "scheduled", &interval); err != nil {
			log.Warn().Err(err).Str("org_id", cfg.OrgID.String()).
				Msg("device-ca-rotation-worker: scheduled rotation start")
			continue
		}
		log.Info().Str("org_id", cfg.OrgID.String()).
			Msg("device-ca-rotation-worker: scheduled rotation started")
	}
}

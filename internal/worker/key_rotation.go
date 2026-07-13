package worker

// key_rotation.go — Scheduled signing-key rotation worker.
//
// Periodically rotates the GLOBAL OIDC (RSA) and PQC (ML-DSA-65) signing keys
// for installations that opted into rotation_policy=scheduled. It reuses each
// signer's existing Rotate(), which already retires the old key into the JWKS
// grace window so outstanding tokens stay verifiable.
//
// Per-org BYOK keys (OrgSignerCache) are never touched here: the policy table
// cannot even hold a BYOK row (key_kind CHECK), and this worker only ever
// dispatches on the "oidc"/"pqc" kinds.

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const keyRotationWorkerInterval = 1 * time.Hour

// rsaRotator is the classical signing key's rotation method (DBSigner).
type rsaRotator interface{ Rotate() error }

// pqcRotator is the PQC signing key's rotation method (PQCSigner takes a ctx).
type pqcRotator interface{ Rotate(ctx context.Context) error }

// keyRotationStore is the policy subset the worker needs. Interface so the tick
// is unit-testable without a database.
type keyRotationStore interface {
	ListDue(ctx context.Context, now time.Time) ([]repository.KeyRotationPolicy, error)
	MarkRotated(ctx context.Context, keyKind string, at time.Time) error
}

// RunKeyRotationWorker starts the scheduled key-rotation goroutine. Pass nil
// for a signer that is not configured (e.g. PQC disabled); the worker skips
// kinds whose signer is absent. Call as `go RunKeyRotationWorker(...)`.
func RunKeyRotationWorker(ctx context.Context, pool *pgxpool.Pool, dbSigner *oidc.DBSigner, pqcSigner *oidc.PQCSigner) {
	repo := repository.NewKeyRotationPolicyRepository(pool)

	// Convert to interfaces only when non-nil so a typed-nil pointer never
	// becomes a non-nil interface (which would panic on call).
	var rsa rsaRotator
	if dbSigner != nil {
		rsa = dbSigner
	}
	var pqc pqcRotator
	if pqcSigner != nil {
		pqc = pqcSigner
	}

	log.Info().Str("interval", keyRotationWorkerInterval.String()).
		Msg("key-rotation-worker: started")

	tickKeyRotation(ctx, repo, rsa, pqc)

	ticker := time.NewTicker(keyRotationWorkerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("key-rotation-worker: stopping")
			return
		case <-ticker.C:
			tickKeyRotation(ctx, repo, rsa, pqc)
		}
	}
}

func tickKeyRotation(ctx context.Context, repo keyRotationStore, rsa rsaRotator, pqc pqcRotator) {
	due, err := repo.ListDue(ctx, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("key-rotation-worker: list due policies")
		return
	}
	for _, p := range due {
		var rotErr error
		switch p.KeyKind {
		case repository.KeyKindOIDC:
			if rsa == nil {
				continue // signer not configured on this installation
			}
			rotErr = rsa.Rotate()
		case repository.KeyKindPQC:
			if pqc == nil {
				continue
			}
			rotErr = pqc.Rotate(ctx)
		default:
			// Defensive: never rotate anything that is not a known global key
			// (the DB CHECK already prevents BYOK rows from existing).
			continue
		}
		if rotErr != nil {
			log.Error().Err(rotErr).Str("key_kind", p.KeyKind).
				Msg("key-rotation-worker: rotate failed")
			continue
		}
		if err := repo.MarkRotated(ctx, p.KeyKind, time.Now()); err != nil {
			log.Error().Err(err).Str("key_kind", p.KeyKind).
				Msg("key-rotation-worker: mark rotated")
			continue
		}
		log.Info().Str("key_kind", p.KeyKind).Msg("key-rotation-worker: key rotated")
	}
}

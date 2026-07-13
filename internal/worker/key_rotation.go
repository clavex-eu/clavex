package worker

// key_rotation.go — Scheduled signing-key rotation worker.
//
// Periodically rotates signing keys for installations/orgs that opted into
// rotation_policy=scheduled. It reuses each signer's existing Rotate(), which
// already retires the old key into the JWKS grace window so outstanding tokens
// stay verifiable.
//
// Dispatch is driven by the policy row's scope (KeyRotationPolicy.OrgID):
//   - OIDC + OrgID set  → rotate THAT org's key via OrgSignerCache.RotateForOrg.
//     Every org now signs with its own OIDC key, so OIDC rotation is per-org.
//   - OIDC + OrgID nil  → rotate the legacy GLOBAL RSA signer (DBSigner).
//   - PQC  + OrgID set  → rotate THAT org's ML-DSA-65 key via
//     OrgPQCSignerCache.RotateForOrg. PQC keys are now per-org too.
//   - PQC  + OrgID nil  → rotate the GLOBAL ML-DSA-65 signer (legacy / fallback).
//
// Imported (BYOK / external-custody) org keys are never scheduled for rotation:
// the SetPolicy handler refuses to enable scheduled rotation for them, so no
// due row can reach this worker for an imported key.

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const keyRotationWorkerInterval = 1 * time.Hour

// rsaRotator is the classical global signing key's rotation method (DBSigner).
type rsaRotator interface{ Rotate() error }

// pqcRotator is the PQC signing key's rotation method (PQCSigner takes a ctx).
type pqcRotator interface {
	Rotate(ctx context.Context) error
}

// orgRotator rotates a single org's OIDC key (OrgSignerCache).
type orgRotator interface {
	RotateForOrg(ctx context.Context, orgID uuid.UUID) (string, error)
}

// orgPQCRotator rotates a single org's PQC key (OrgPQCSignerCache).
type orgPQCRotator interface {
	RotateForOrg(ctx context.Context, orgID uuid.UUID) (string, error)
}

// keyRotationStore is the policy subset the worker needs. Interface so the tick
// is unit-testable without a database.
type keyRotationStore interface {
	ListDue(ctx context.Context, now time.Time) ([]repository.KeyRotationPolicy, error)
	MarkRotated(ctx context.Context, keyKind string, at time.Time) error
	MarkRotatedForOrg(ctx context.Context, keyKind string, orgID uuid.UUID, at time.Time) error
}

// RunKeyRotationWorker starts the scheduled key-rotation goroutine. Pass nil
// for a signer that is not configured (e.g. PQC disabled, or orgSigners only on
// key_backend=db); the worker skips policies whose signer is absent. Call as
// `go RunKeyRotationWorker(...)`.
func RunKeyRotationWorker(ctx context.Context, pool *pgxpool.Pool, dbSigner *oidc.DBSigner, pqcSigner *oidc.PQCSigner, orgSigners *oidc.OrgSignerCache, orgPQCSigners *oidc.OrgPQCSignerCache) {
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
	var orgs orgRotator
	if orgSigners != nil {
		orgs = orgSigners
	}
	var orgPQC orgPQCRotator
	if orgPQCSigners != nil {
		orgPQC = orgPQCSigners
	}

	log.Info().Str("interval", keyRotationWorkerInterval.String()).
		Msg("key-rotation-worker: started")

	tickKeyRotation(ctx, repo, rsa, pqc, orgs, orgPQC)

	ticker := time.NewTicker(keyRotationWorkerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("key-rotation-worker: stopping")
			return
		case <-ticker.C:
			tickKeyRotation(ctx, repo, rsa, pqc, orgs, orgPQC)
		}
	}
}

func tickKeyRotation(ctx context.Context, repo keyRotationStore, rsa rsaRotator, pqc pqcRotator, orgs orgRotator, orgPQC orgPQCRotator) {
	due, err := repo.ListDue(ctx, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("key-rotation-worker: list due policies")
		return
	}
	for _, p := range due {
		var rotErr error
		switch {
		case p.KeyKind == repository.KeyKindOIDC && p.OrgID != nil:
			if orgs == nil {
				continue // per-org signing not configured (non-db key backend)
			}
			_, rotErr = orgs.RotateForOrg(ctx, *p.OrgID)
		case p.KeyKind == repository.KeyKindOIDC:
			if rsa == nil {
				continue // signer not configured on this installation
			}
			rotErr = rsa.Rotate()
		case p.KeyKind == repository.KeyKindPQC && p.OrgID != nil:
			if orgPQC == nil {
				continue // per-org PQC not configured (PQC disabled or non-db backend)
			}
			_, rotErr = orgPQC.RotateForOrg(ctx, *p.OrgID)
		case p.KeyKind == repository.KeyKindPQC:
			if pqc == nil {
				continue
			}
			rotErr = pqc.Rotate(ctx)
		default:
			continue
		}
		if rotErr != nil {
			log.Error().Err(rotErr).Str("key_kind", p.KeyKind).
				Msg("key-rotation-worker: rotate failed")
			continue
		}

		var markErr error
		if p.OrgID != nil {
			markErr = repo.MarkRotatedForOrg(ctx, p.KeyKind, *p.OrgID, time.Now())
		} else {
			markErr = repo.MarkRotated(ctx, p.KeyKind, time.Now())
		}
		if markErr != nil {
			log.Error().Err(markErr).Str("key_kind", p.KeyKind).
				Msg("key-rotation-worker: mark rotated")
			continue
		}
		log.Info().Str("key_kind", p.KeyKind).Msg("key-rotation-worker: key rotated")
	}
}

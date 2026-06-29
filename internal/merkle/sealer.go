package merkle

// Sealer seals batches of audit_log rows into Merkle checkpoints.
// It is designed to be called periodically (e.g. every 5 minutes) or
// on-demand via the admin API.
//
// Concurrency: Sealer is safe for concurrent callers — it uses DB-level
// row counting to avoid double-sealing the same rows.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"crypto/rsa"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
)

// SealOptions configures the sealer.
type SealOptions struct {
	// BatchSize is the number of audit rows per checkpoint. Default: 100.
	BatchSize int
	// Key is the RSA private key used to sign checkpoints.
	Key *rsa.PrivateKey
	// KID identifies the signing key in the JWKS.
	KID string
}

// Sealer seals pending audit rows into checkpoints.
type Sealer struct {
	repo *repository.AuditRepository
	opts SealOptions
}

// NewSealer creates a Sealer with the given options.
func NewSealer(repo *repository.AuditRepository, opts SealOptions) *Sealer {
	if opts.BatchSize <= 0 {
		opts.BatchSize = CheckpointSize
	}
	return &Sealer{repo: repo, opts: opts}
}

// SealOrg seals any pending rows for a single org.
// Returns the number of new checkpoints created.
func (s *Sealer) SealOrg(ctx context.Context, orgID uuid.UUID) (int, error) {
	// Find the last sealed row ID.
	last, err := s.repo.LatestCheckpoint(ctx, orgID)
	if err != nil {
		return 0, fmt.Errorf("sealer: latest checkpoint: %w", err)
	}
	var afterID int64
	prevRoot := ""
	if last != nil {
		afterID = last.LastLogID
		prevRoot = last.MerkleRoot
	}

	created := 0
	for {
		_, jsons, ids, err := s.repo.UnsealedAuditRows(ctx, orgID, afterID, s.opts.BatchSize)
		if err != nil {
			return created, fmt.Errorf("sealer: fetch rows: %w", err)
		}
		if len(ids) < s.opts.BatchSize {
			// Not enough rows for a full batch yet.
			break
		}

		root := RebuildRoot(jsons)
		proof, err := Sign(root, prevRoot, s.opts.Key, s.opts.KID, orgID.String(),
			ids[0], ids[len(ids)-1], len(ids))
		if err != nil {
			return created, fmt.Errorf("sealer: sign: %w", err)
		}

		cp := &repository.AuditMerkleCheckpoint{
			OrgID:      orgID,
			FirstLogID: proof.FirstLogID,
			LastLogID:  proof.LastLogID,
			LogCount:   proof.LogCount,
			MerkleRoot: proof.MerkleRoot,
			PrevRoot:   proof.PrevRoot,
			ChainHash:  proof.ChainHash,
			Signature:  proof.Signature,
			KID:        proof.KID,
		}
		if err := s.repo.InsertMerkleCheckpoint(ctx, cp); err != nil {
			return created, fmt.Errorf("sealer: insert checkpoint: %w", err)
		}

		afterID = ids[len(ids)-1]
		prevRoot = proof.MerkleRoot
		created++
	}
	return created, nil
}

// Run starts a blocking loop that seals all orgs every interval.
// Intended to be called in a goroutine.
func (s *Sealer) Run(ctx context.Context, orgs []uuid.UUID, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, orgID := range orgs {
				n, err := s.SealOrg(ctx, orgID)
				if err != nil {
					slog.Error("merkle sealer", "org_id", orgID, "error", err)
					continue
				}
				if n > 0 {
					slog.Info("merkle sealer: sealed", "org_id", orgID, "checkpoints", n)
				}
			}
		}
	}
}

// RunAllOrgs starts a blocking loop that discovers all orgs from the DB on
// every tick and seals their pending audit rows, including partial batches.
// This is the preferred entry point: orgs are discovered dynamically so
// the sealer works even when orgs are created after server startup.
//
// Partial batches (< BatchSize) are sealed on each tick so that recent
// audit rows are always anchored in the chain within one interval.
func (s *Sealer) RunAllOrgs(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			orgs, err := s.repo.DistinctOrgIDsWithAuditLogs(ctx)
			if err != nil {
				slog.Error("merkle sealer: list orgs", "error", err)
				continue
			}
			for _, orgID := range orgs {
				// Full batches first.
				n, err := s.SealOrg(ctx, orgID)
				if err != nil {
					slog.Error("merkle sealer", "org_id", orgID, "error", err)
					continue
				}
				// Then seal any remaining partial batch so recent logs are anchored.
				np, err := s.sealPartial(ctx, orgID)
				if err != nil {
					slog.Error("merkle sealer: partial", "org_id", orgID, "error", err)
					continue
				}
				if total := n + np; total > 0 {
					slog.Info("merkle sealer: sealed", "org_id", orgID, "checkpoints", total)
				}
			}
		}
	}
}

// sealPartial seals the remaining unsealed rows for an org even if they don't
// fill a full batch. Called after SealOrg so that full batches are always
// preferred and partial ones only cover the tail.
func (s *Sealer) sealPartial(ctx context.Context, orgID uuid.UUID) (int, error) {
	last, err := s.repo.LatestCheckpoint(ctx, orgID)
	if err != nil {
		return 0, fmt.Errorf("sealer partial: latest checkpoint: %w", err)
	}
	var afterID int64
	prevRoot := ""
	if last != nil {
		afterID = last.LastLogID
		prevRoot = last.MerkleRoot
	}

	_, jsons, ids, err := s.repo.UnsealedAuditRows(ctx, orgID, afterID, s.opts.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("sealer partial: fetch rows: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}

	root := RebuildRoot(jsons)
	proof, err := Sign(root, prevRoot, s.opts.Key, s.opts.KID, orgID.String(),
		ids[0], ids[len(ids)-1], len(ids))
	if err != nil {
		return 0, fmt.Errorf("sealer partial: sign: %w", err)
	}
	cp := &repository.AuditMerkleCheckpoint{
		OrgID:      orgID,
		FirstLogID: proof.FirstLogID,
		LastLogID:  proof.LastLogID,
		LogCount:   proof.LogCount,
		MerkleRoot: proof.MerkleRoot,
		PrevRoot:   proof.PrevRoot,
		ChainHash:  proof.ChainHash,
		Signature:  proof.Signature,
		KID:        proof.KID,
	}
	if err := s.repo.InsertMerkleCheckpoint(ctx, cp); err != nil {
		return 0, fmt.Errorf("sealer partial: insert: %w", err)
	}
	return 1, nil
}

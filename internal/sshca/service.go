// Package sshca orchestrates the staged Vault SSH CA rotation across Vault and
// the database. It is shared by the HTTP handler (manual Start/Complete/Abort)
// and the background worker (scheduled Start, grace cleanup) so the Vault + DB
// choreography lives in exactly one place.
//
// Rotation uses a NEW Vault mount per rotation: the new CA is provisioned on a
// fresh mount so the old and new CAs can both sign during propagation. Complete
// promotes the new mount to primary; the old mount is retired after a grace
// window by CleanupExpiredGrace.
package sshca

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/vaultssh"
	"github.com/clavex-eu/clavex/internal/webhook"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// ErrNotConfigured is returned when the org has no SSH CA config.
var ErrNotConfigured = errors.New("SSH CA not configured")

// ErrVaultMountCapability is returned when the Vault token lacks the sys/mounts
// capability required to provision (or retire) a rotation mount. Its message is
// operator-facing.
var ErrVaultMountCapability = errors.New(`missing sys/mounts capability required for SSH CA rotation: grant Clavex's Vault token a policy including path "sys/mounts/*" { capabilities = ["create", "read", "delete"] } and try again`)

// Dispatcher is the webhook subset the service needs.
type Dispatcher interface {
	Dispatch(orgID uuid.UUID, event string, data any)
}

// Service performs SSH CA rotation orchestration.
type Service struct {
	repo *repository.PAMRepository
	enc  *crypto.Encryptor
	disp Dispatcher
}

// NewService builds the service. disp may be nil (webhooks skipped).
func NewService(repo *repository.PAMRepository, enc *crypto.Encryptor, disp Dispatcher) *Service {
	return &Service{repo: repo, enc: enc, disp: disp}
}

// DefaultGracePeriod is the window the retired CA stays trusted after Complete.
const DefaultGracePeriod = 72 * time.Hour

// baseMount strips any prior "-rot-<id>" suffix so mount names stay bounded
// across successive rotations.
func baseMount(mount string) string {
	if i := strings.Index(mount, "-rot-"); i > 0 {
		return mount[:i]
	}
	return mount
}

func (s *Service) tokenFor(ctx context.Context, orgID uuid.UUID) (*repository.PAMSSHCAConfig, string, error) {
	cfg, encToken, err := s.repo.GetSSHCAConfigWithToken(ctx, orgID)
	if err != nil || cfg == nil {
		return nil, "", ErrNotConfigured
	}
	token, err := s.enc.Decrypt(encToken)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt vault token: %w", err)
	}
	return cfg, token, nil
}

// Start provisions a new Vault mount + CA + signing role, records a rotation in
// the 'rotating' state, and dispatches rotation_started. Returns the rotation
// and the new CA public key.
func (s *Service) Start(ctx context.Context, orgID uuid.UUID, startedBy, policy string, intervalDays *int) (*repository.PAMSSHCARotation, string, error) {
	cfg, token, err := s.tokenFor(ctx, orgID)
	if err != nil {
		return nil, "", err
	}

	// Old fingerprint (best effort).
	var oldFP *string
	if cfg.CAPublicKey != nil && *cfg.CAPublicKey != "" {
		if fp, ferr := vaultssh.FingerprintSHA256(*cfg.CAPublicKey); ferr == nil {
			oldFP = &fp
		}
	}

	newMount := fmt.Sprintf("%s-rot-%s", baseMount(cfg.VaultMount), uuid.NewString()[:8])

	// Preflight: fail early with a clear error if the token can't create mounts,
	// rather than a generic 502 mid-provisioning.
	caps, err := vaultssh.CheckCapabilities(ctx, cfg.VaultAddr, token, "sys/mounts/"+newMount)
	if err != nil {
		return nil, "", fmt.Errorf("vault capability preflight: %w", err)
	}
	if !vaultssh.HasCapability(caps, "create") {
		return nil, "", ErrVaultMountCapability
	}

	if err := vaultssh.EnableSSHMount(ctx, cfg.VaultAddr, newMount, token); err != nil {
		return nil, "", fmt.Errorf("enable new vault mount: %w", err)
	}
	newPub, err := vaultssh.GenerateCASigningKey(ctx, cfg.VaultAddr, newMount, token)
	if err != nil {
		s.bestEffortDisable(ctx, cfg.VaultAddr, newMount, token)
		return nil, "", fmt.Errorf("generate new CA key: %w", err)
	}
	if err := vaultssh.ConfigureSignRole(ctx, cfg.VaultAddr, newMount, cfg.VaultRole, token, cfg.CertTTLSeconds); err != nil {
		s.bestEffortDisable(ctx, cfg.VaultAddr, newMount, token)
		return nil, "", fmt.Errorf("configure sign role: %w", err)
	}

	newFP, err := vaultssh.FingerprintSHA256(newPub)
	if err != nil {
		s.bestEffortDisable(ctx, cfg.VaultAddr, newMount, token)
		return nil, "", fmt.Errorf("fingerprint new CA key: %w", err)
	}

	rot, err := s.repo.CreateRotation(ctx, repository.CreateRotationParams{
		OrgID:                orgID,
		OldCAFingerprint:     oldFP,
		NewCAFingerprint:     newFP,
		OldVaultMount:        cfg.VaultMount,
		NewVaultMount:        newMount,
		RotationPolicy:       policy,
		RotationIntervalDays: intervalDays,
		StartedBy:            startedBy,
	})
	if err != nil {
		s.bestEffortDisable(ctx, cfg.VaultAddr, newMount, token)
		return nil, "", err
	}

	if s.disp != nil {
		payload := map[string]any{
			"rotation_id":       rot.ID,
			"org_id":            orgID,
			"new_ca_public_key": newPub,
			"new_fingerprint":   newFP,
		}
		if oldFP != nil {
			payload["previous_fingerprint"] = *oldFP
		}
		s.disp.Dispatch(orgID, webhook.EventPAMSSHCARotationStarted, payload)
	}
	return rot, newPub, nil
}

// Complete promotes the new mount to primary (cutover), caches its CA key, and
// sets the grace window. Only valid from cutover_ready.
func (s *Service) Complete(ctx context.Context, orgID, rotationID uuid.UUID) (*repository.PAMSSHCARotation, error) {
	cfg, token, err := s.tokenFor(ctx, orgID)
	if err != nil {
		return nil, err
	}
	rot, err := s.repo.GetRotation(ctx, orgID, rotationID)
	if err != nil {
		return nil, err
	}
	if rot == nil {
		return nil, nil
	}
	if rot.NewVaultMount == nil {
		return nil, fmt.Errorf("rotation has no new mount")
	}
	newPub, err := vaultssh.FetchCAPublicKey(ctx, cfg.VaultAddr, *rot.NewVaultMount, token)
	if err != nil {
		return nil, fmt.Errorf("fetch new CA key: %w", err)
	}

	// State guard first (atomic). Only promote if the transition succeeded.
	updated, err := s.repo.CompleteRotation(ctx, orgID, rotationID, time.Now().Add(DefaultGracePeriod))
	if err != nil {
		return nil, err
	}
	if err := s.repo.PromoteSSHCAMount(ctx, orgID, *rot.NewVaultMount, newPub); err != nil {
		return nil, fmt.Errorf("promote new mount: %w", err)
	}
	return updated, nil
}

// Abort rolls back an in-flight rotation and discards the new mount. The old CA
// is never touched.
func (s *Service) Abort(ctx context.Context, orgID, rotationID uuid.UUID) (*repository.PAMSSHCARotation, error) {
	rot, err := s.repo.GetRotation(ctx, orgID, rotationID)
	if err != nil {
		return nil, err
	}
	if rot == nil {
		return nil, nil
	}
	updated, err := s.repo.AbortRotation(ctx, orgID, rotationID)
	if err != nil {
		return nil, err
	}
	// Best-effort teardown of the discarded new mount.
	if rot.NewVaultMount != nil {
		if cfg, token, terr := s.tokenFor(ctx, orgID); terr == nil {
			s.bestEffortDisable(ctx, cfg.VaultAddr, *rot.NewVaultMount, token)
		}
	}
	return updated, nil
}

// CleanupExpiredGrace retires old mounts whose grace window has elapsed.
func (s *Service) CleanupExpiredGrace(ctx context.Context) {
	rows, err := s.repo.ListRotationsForGraceCleanup(ctx, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("sshca: list grace-cleanup rotations")
		return
	}
	for i := range rows {
		rot := rows[i]
		if rot.OldVaultMount == nil {
			_ = s.repo.MarkOldMountRemoved(ctx, rot.ID)
			continue
		}
		cfg, token, terr := s.tokenFor(ctx, rot.OrgID)
		if terr != nil {
			log.Warn().Err(terr).Str("org_id", rot.OrgID.String()).Msg("sshca: grace cleanup token")
			continue
		}
		// Preflight the delete capability. This is a background worker, so on
		// failure we log at Error level (visible/alertable) and retry next tick
		// rather than blocking — but we never silently mark the mount removed.
		caps, cerr := vaultssh.CheckCapabilities(ctx, cfg.VaultAddr, token, "sys/mounts/"+*rot.OldVaultMount)
		if cerr != nil || !vaultssh.HasCapability(caps, "delete") {
			log.Error().Err(cerr).
				Str("org_id", rot.OrgID.String()).
				Str("rotation_id", rot.ID.String()).
				Str("mount", *rot.OldVaultMount).
				Msg("sshca: grace cleanup blocked — Vault token lacks sys/mounts delete capability; old CA NOT retired (grant sys/mounts/* delete)")
			continue
		}
		if err := vaultssh.DisableSSHMount(ctx, cfg.VaultAddr, *rot.OldVaultMount, token); err != nil {
			log.Warn().Err(err).Str("mount", *rot.OldVaultMount).Msg("sshca: disable old mount")
			continue
		}
		if err := s.repo.MarkOldMountRemoved(ctx, rot.ID); err != nil {
			log.Error().Err(err).Str("rotation_id", rot.ID.String()).Msg("sshca: mark old mount removed")
		}
	}
}

func (s *Service) bestEffortDisable(ctx context.Context, addr, mount, token string) {
	if err := vaultssh.DisableSSHMount(ctx, addr, mount, token); err != nil {
		log.Warn().Err(err).Str("mount", mount).Msg("sshca: best-effort mount teardown failed")
	}
}

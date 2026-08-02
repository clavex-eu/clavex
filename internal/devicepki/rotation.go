package devicepki

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/vaultpki"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// baseMount strips any prior "-rot-<id>" suffix so mount names stay bounded
// across successive rotations — mirrors sshca's baseMount.
func baseMount(mount string) string {
	if i := strings.Index(mount, "-rot-"); i > 0 {
		return mount[:i]
	}
	return mount
}

// StartRotation provisions a new Vault PKI mount + root CA + device-signing
// role, records a rotation in the 'rotating' state, and dispatches
// device_ca.rotation_started. Returns the rotation and the new CA certificate
// PEM (for the operator/agent to propagate to the external MQTT broker before
// cutover).
func (s *Service) StartRotation(ctx context.Context, orgID uuid.UUID, startedBy, policy string, intervalDays *int) (*repository.DeviceCARotation, string, error) {
	cfg, token, err := s.tokenFor(ctx, orgID)
	if err != nil {
		return nil, "", err
	}

	var oldFP *string
	if cfg.CACertificatePEM != nil && *cfg.CACertificatePEM != "" {
		if fp, ferr := vaultpki.FingerprintSHA256(*cfg.CACertificatePEM); ferr == nil {
			oldFP = &fp
		}
	}

	newMount := fmt.Sprintf("%s-rot-%s", baseMount(cfg.VaultMount), uuid.NewString()[:8])

	caps, err := vaultpki.CheckCapabilities(ctx, cfg.VaultAddr, token, "sys/mounts/"+newMount)
	if err != nil {
		return nil, "", fmt.Errorf("vault capability preflight: %w", err)
	}
	if !vaultpki.HasCapability(caps, "create") {
		return nil, "", ErrVaultMountCapability
	}

	if err := vaultpki.EnablePKIMount(ctx, cfg.VaultAddr, newMount, token); err != nil {
		return nil, "", fmt.Errorf("enable new vault PKI mount: %w", err)
	}
	newCert, err := vaultpki.GenerateRootCA(ctx, cfg.VaultAddr, newMount, token,
		fmt.Sprintf("Clavex Device CA - %s", orgID), 87600*3600)
	if err != nil {
		s.bestEffortDisable(ctx, cfg.VaultAddr, newMount, token)
		return nil, "", fmt.Errorf("generate new root CA: %w", err)
	}
	if err := vaultpki.ConfigureDeviceRole(ctx, cfg.VaultAddr, newMount, cfg.VaultRole, token, cfg.CertTTLSeconds); err != nil {
		s.bestEffortDisable(ctx, cfg.VaultAddr, newMount, token)
		return nil, "", fmt.Errorf("configure device signing role: %w", err)
	}

	newFP, err := vaultpki.FingerprintSHA256(newCert)
	if err != nil {
		s.bestEffortDisable(ctx, cfg.VaultAddr, newMount, token)
		return nil, "", fmt.Errorf("fingerprint new CA certificate: %w", err)
	}

	rot, err := s.repo.CreateDeviceCARotation(ctx, repository.CreateDeviceCARotationParams{
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
			"rotation_id":     rot.ID,
			"org_id":          orgID,
			"new_ca_cert":     newCert,
			"new_fingerprint": newFP,
		}
		if oldFP != nil {
			payload["previous_fingerprint"] = *oldFP
		}
		s.disp.Dispatch(orgID, "device_ca.rotation_started", payload)
	}
	return rot, newCert, nil
}

// CompleteRotation promotes the new mount to primary (cutover), caches its CA
// certificate, and sets the grace window. Only valid from cutover_ready.
func (s *Service) CompleteRotation(ctx context.Context, orgID, rotationID uuid.UUID) (*repository.DeviceCARotation, error) {
	cfg, token, err := s.tokenFor(ctx, orgID)
	if err != nil {
		return nil, err
	}
	rot, err := s.repo.GetDeviceCARotation(ctx, orgID, rotationID)
	if err != nil {
		return nil, err
	}
	if rot == nil {
		return nil, nil
	}
	if rot.NewVaultMount == nil {
		return nil, fmt.Errorf("rotation has no new mount")
	}
	newCert, err := vaultpki.FetchCACertificate(ctx, cfg.VaultAddr, *rot.NewVaultMount, token)
	if err != nil {
		return nil, fmt.Errorf("fetch new CA certificate: %w", err)
	}

	updated, err := s.repo.CompleteDeviceCARotation(ctx, orgID, rotationID, time.Now().Add(DefaultGracePeriod))
	if err != nil {
		return nil, err
	}
	if err := s.repo.PromoteDeviceCAMount(ctx, orgID, *rot.NewVaultMount, newCert); err != nil {
		return nil, fmt.Errorf("promote new mount: %w", err)
	}
	return updated, nil
}

// AbortRotation rolls back an in-flight rotation and discards the new mount.
// The old CA is never touched.
func (s *Service) AbortRotation(ctx context.Context, orgID, rotationID uuid.UUID) (*repository.DeviceCARotation, error) {
	rot, err := s.repo.GetDeviceCARotation(ctx, orgID, rotationID)
	if err != nil {
		return nil, err
	}
	if rot == nil {
		return nil, nil
	}
	updated, err := s.repo.AbortDeviceCARotation(ctx, orgID, rotationID)
	if err != nil {
		return nil, err
	}
	if rot.NewVaultMount != nil {
		if cfg, token, terr := s.tokenFor(ctx, orgID); terr == nil {
			s.bestEffortDisable(ctx, cfg.VaultAddr, *rot.NewVaultMount, token)
		}
	}
	return updated, nil
}

// CleanupExpiredGrace retires old mounts whose grace window has elapsed.
func (s *Service) CleanupExpiredGrace(ctx context.Context) {
	rows, err := s.repo.ListDeviceCARotationsForGraceCleanup(ctx, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("devicepki: list grace-cleanup rotations")
		return
	}
	for i := range rows {
		rot := rows[i]
		if rot.OldVaultMount == nil {
			_ = s.repo.MarkOldDeviceMountRemoved(ctx, rot.ID)
			continue
		}
		cfg, token, terr := s.tokenFor(ctx, rot.OrgID)
		if terr != nil {
			log.Warn().Err(terr).Str("org_id", rot.OrgID.String()).Msg("devicepki: grace cleanup token")
			continue
		}
		caps, cerr := vaultpki.CheckCapabilities(ctx, cfg.VaultAddr, token, "sys/mounts/"+*rot.OldVaultMount)
		if cerr != nil || !vaultpki.HasCapability(caps, "delete") {
			log.Error().Err(cerr).
				Str("org_id", rot.OrgID.String()).
				Str("rotation_id", rot.ID.String()).
				Str("mount", *rot.OldVaultMount).
				Msg("devicepki: grace cleanup blocked — Vault token lacks sys/mounts delete capability; old CA NOT retired")
			continue
		}
		if err := vaultpki.DisableMount(ctx, cfg.VaultAddr, *rot.OldVaultMount, token); err != nil {
			log.Warn().Err(err).Str("mount", *rot.OldVaultMount).Msg("devicepki: disable old mount")
			continue
		}
		if err := s.repo.MarkOldDeviceMountRemoved(ctx, rot.ID); err != nil {
			log.Error().Err(err).Str("rotation_id", rot.ID.String()).Msg("devicepki: mark old mount removed")
		}
	}
}

func (s *Service) bestEffortDisable(ctx context.Context, addr, mount, token string) {
	if err := vaultpki.DisableMount(ctx, addr, mount, token); err != nil {
		log.Warn().Err(err).Str("mount", mount).Msg("devicepki: best-effort mount teardown failed")
	}
}

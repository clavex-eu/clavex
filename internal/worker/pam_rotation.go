package worker

// PAMRotationWorker periodically rotates vault credentials whose
// rotation_interval_days is set and whose last_rotated_at is past due.
//
// PCI DSS 8.6.3 and NIS2 Art.21 require periodic rotation of privileged
// credentials. The worker runs every 6 hours. On each tick it:
//
//  1. Fetches all credentials where rotation is due.
//  2. For password/api_key/token types: generates a cryptographically random
//     32-character password, encrypts it with the org's Encryptor, updates
//     the vault, and writes a rotation log entry.
//  3. For ssh_key/certificate types: logs a "manual rotation required" warning
//     (automated PKI rotation is not in scope here).
//
// Multi-instance safety: the RotateCredentialSecret UPDATE is idempotent — only
// one instance will win the row if both process it at the same tick. The rotation
// log may get a duplicate entry, but the secrets stay consistent.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/clavex-eu/clavex/internal/alerting"
	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/sshca"
	"github.com/clavex-eu/clavex/internal/vaultssh"
	"github.com/clavex-eu/clavex/internal/webhook"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	pamRotationWorkerInterval = 6 * time.Hour
	// pamRotationPasswordBytes is the number of random bytes to use for
	// generated passwords. 24 bytes = 32 base64url characters ≈ 192 bits.
	pamRotationPasswordBytes = 24
)

// webhookDispatcher is the subset of *webhook.Dispatcher the worker needs.
// Declared as an interface so the worker can be unit-tested with a fake
// (the concrete Dispatcher's fields are unexported).
type webhookDispatcher interface {
	Dispatch(orgID uuid.UUID, event string, data any)
}

// rotationStore is the subset of *repository.PAMRepository that
// rotatePAMCredential needs. Declared as an interface so the rotation
// decision (dispatch vs. skip, per credential type) is unit-testable
// without a database.
type rotationStore interface {
	RotateCredentialSecret(ctx context.Context, credID uuid.UUID, encryptedSecret string) error
	LogRotation(ctx context.Context, credID, orgID uuid.UUID, rotatedBy, rotationType, note string) error
}

// sshCAStore is the subset of *repository.PAMRepository the SSH CA
// reconciliation needs. Interface for the same unit-testing reason as above.
type sshCAStore interface {
	ListSSHCAConfigsForReconcile(ctx context.Context) ([]repository.SSHCAReconcileRow, error)
	UpdateSSHCAPublicKey(ctx context.Context, orgID uuid.UUID, pubKey string) error
}

// caKeyFetcher fetches the current CA public key from Vault. Declared as a
// type so tests can stub the network call; production uses
// vaultssh.FetchCAPublicKey.
type caKeyFetcher func(ctx context.Context, vaultAddr, mount, token string) (string, error)

// RunPAMRotationWorker starts the credential auto-rotation goroutine.
// Blocks until ctx is cancelled. Call as `go RunPAMRotationWorker(ctx, pool, enc, notifier, disp)`.
// Pass a zero-enabled notifier (alerting.NewPAMNotifier with empty URLs) to disable alerts.
func RunPAMRotationWorker(ctx context.Context, pool *pgxpool.Pool, enc *crypto.Encryptor, notifier *alerting.PAMNotifier, disp webhookDispatcher) {
	repo := repository.NewPAMRepository(pool)
	sshCASvc := sshca.NewService(repo, enc, disp)

	log.Info().Str("interval", pamRotationWorkerInterval.String()).
		Msg("pam-rotation-worker: started")

	// Run immediately on startup to clear any backlog.
	processPAMRotations(ctx, repo, enc, disp)
	processStaleCredentialAlerts(ctx, repo, notifier)
	processLongSessionAlerts(ctx, repo, notifier)
	processSSHCARotations(ctx, repo, enc, disp, vaultssh.FetchCAPublicKey)
	processSSHCAScheduledStarts(ctx, repo, sshCASvc)
	sshCASvc.CleanupExpiredGrace(ctx)

	ticker := time.NewTicker(pamRotationWorkerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("pam-rotation-worker: stopping")
			return
		case <-ticker.C:
			processPAMRotations(ctx, repo, enc, disp)
			processStaleCredentialAlerts(ctx, repo, notifier)
			processLongSessionAlerts(ctx, repo, notifier)
			processSSHCARotations(ctx, repo, enc, disp, vaultssh.FetchCAPublicKey)
			processSSHCAScheduledStarts(ctx, repo, sshCASvc)
			sshCASvc.CleanupExpiredGrace(ctx)
		}
	}
}

// sshCARotationStarter is the Start subset the scheduler uses (interface for
// unit-testing the "start-only, never complete" guarantee).
type sshCARotationStarter interface {
	Start(ctx context.Context, orgID uuid.UUID, startedBy, policy string, intervalDays *int) (*repository.PAMSSHCARotation, string, error)
}

// processSSHCAScheduledStarts triggers ONLY the Start step for orgs whose
// scheduled SSH CA rotation interval has elapsed. It never advances a rotation
// to cutover_ready or complete — those are always explicit operator/agent steps.
func processSSHCAScheduledStarts(ctx context.Context, repo *repository.PAMRepository, svc sshCARotationStarter) {
	due, err := repo.ListSSHCAConfigsForScheduledRotation(ctx, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("pam-rotation-worker: list scheduled ssh ca rotations")
		return
	}
	for i := range due {
		cfg := due[i]
		interval := cfg.IntervalDays
		if _, _, err := svc.Start(ctx, cfg.OrgID, "scheduler", "scheduled", &interval); err != nil {
			log.Warn().Err(err).Str("org_id", cfg.OrgID.String()).
				Msg("pam-rotation-worker: scheduled ssh ca rotation start")
			continue
		}
		log.Info().Str("org_id", cfg.OrgID.String()).
			Msg("pam-rotation-worker: scheduled ssh ca rotation started")
	}
}

// processSSHCARotations re-fetches each org's Vault SSH CA public key and, when
// it differs from the last cached value, caches the new key and dispatches a
// pam.ssh_ca.rotated webhook. The first successful fetch for an org just seeds
// the cache (no event — nothing to compare against).
func processSSHCARotations(ctx context.Context, repo sshCAStore, enc *crypto.Encryptor, disp webhookDispatcher, fetch caKeyFetcher) {
	rows, err := repo.ListSSHCAConfigsForReconcile(ctx)
	if err != nil {
		log.Error().Err(err).Msg("pam-rotation-worker: failed to list ssh ca configs")
		return
	}
	for _, row := range rows {
		token, err := enc.Decrypt(row.EncryptedToken)
		if err != nil {
			log.Error().Err(err).Str("org_id", row.OrgID.String()).
				Msg("pam-rotation-worker: decrypt ssh ca token")
			continue
		}
		fetched, err := fetch(ctx, row.VaultAddr, row.VaultMount, token)
		if err != nil {
			log.Warn().Err(err).Str("org_id", row.OrgID.String()).
				Msg("pam-rotation-worker: fetch ssh ca public key")
			continue
		}
		if fetched == "" {
			continue
		}

		// First observation for this org: seed the cache, do not alert.
		if row.CAPublicKey == nil || *row.CAPublicKey == "" {
			if err := repo.UpdateSSHCAPublicKey(ctx, row.OrgID, fetched); err != nil {
				log.Error().Err(err).Str("org_id", row.OrgID.String()).
					Msg("pam-rotation-worker: cache initial ssh ca key")
			}
			continue
		}
		if fetched == *row.CAPublicKey {
			continue // no rotation
		}

		// Rotation detected.
		newFP, err := vaultssh.FingerprintSHA256(fetched)
		if err != nil {
			log.Error().Err(err).Str("org_id", row.OrgID.String()).
				Msg("pam-rotation-worker: fingerprint rotated ssh ca key")
			continue
		}
		prevFP, _ := vaultssh.FingerprintSHA256(*row.CAPublicKey) // best effort

		// Persist before dispatching so a persist failure retries next tick
		// without emitting a duplicate event.
		if err := repo.UpdateSSHCAPublicKey(ctx, row.OrgID, fetched); err != nil {
			log.Error().Err(err).Str("org_id", row.OrgID.String()).
				Msg("pam-rotation-worker: cache rotated ssh ca key")
			continue
		}

		log.Info().Str("org_id", row.OrgID.String()).
			Str("new_fingerprint", newFP).
			Msg("pam-rotation-worker: ssh ca rotated")

		if disp != nil {
			disp.Dispatch(row.OrgID, webhook.EventPAMSSHCARotated, map[string]any{
				"org_id":               row.OrgID,
				"new_fingerprint":      newFP,
				"previous_fingerprint": prevFP,
				"rotated_at":           time.Now().UTC(),
			})
		}
	}
}

func processPAMRotations(ctx context.Context, repo *repository.PAMRepository, enc *crypto.Encryptor, disp webhookDispatcher) {
	due, err := repo.ListDueForRotation(ctx)
	if err != nil {
		log.Error().Err(err).Msg("pam-rotation-worker: failed to list due credentials")
		return
	}
	if len(due) == 0 {
		return
	}

	log.Info().Int("count", len(due)).Msg("pam-rotation-worker: rotating due credentials")

	for _, cred := range due {
		if err := rotatePAMCredential(ctx, repo, enc, disp, cred); err != nil {
			log.Error().Err(err).
				Str("credential_id", cred.ID.String()).
				Str("org_id", cred.OrgID.String()).
				Str("name", cred.Name).
				Msg("pam-rotation-worker: rotation failed")
		}
	}
}

func rotatePAMCredential(ctx context.Context, repo rotationStore, enc *crypto.Encryptor, disp webhookDispatcher, cred repository.PAMCredential) error {
	// SSH keys and certificates cannot be auto-rotated — they require PKI.
	// Log a warning and return without error so the loop continues.
	switch cred.CredentialType {
	case "ssh_key", "certificate":
		log.Warn().
			Str("credential_id", cred.ID.String()).
			Str("credential_type", cred.CredentialType).
			Str("name", cred.Name).
			Msg("pam-rotation-worker: manual rotation required — ssh_key/certificate cannot be auto-rotated")
		return repo.LogRotation(ctx, cred.ID, cred.OrgID, "system", "manual_required",
			"ssh_key and certificate types require manual rotation")
	}

	// Generate a cryptographically random password.
	rawBytes := make([]byte, pamRotationPasswordBytes)
	if _, err := rand.Read(rawBytes); err != nil {
		return err
	}
	newSecret := base64.RawURLEncoding.EncodeToString(rawBytes)

	// Encrypt before storage.
	encSecret, err := enc.Encrypt(newSecret)
	if err != nil {
		return err
	}

	// Persist the rotated secret.
	if err := repo.RotateCredentialSecret(ctx, cred.ID, encSecret); err != nil {
		return err
	}

	// Write audit log entry.
	if err := repo.LogRotation(ctx, cred.ID, cred.OrgID, "system", "auto", ""); err != nil {
		// Non-fatal: the secret has already been rotated successfully.
		log.Warn().Err(err).Str("credential_id", cred.ID.String()).
			Msg("pam-rotation-worker: failed to write rotation log entry")
	}

	log.Info().
		Str("credential_id", cred.ID.String()).
		Str("org_id", cred.OrgID.String()).
		Str("name", cred.Name).
		Str("type", cred.CredentialType).
		Msg("pam-rotation-worker: credential rotated")

	// Notify subscribers so they can refresh downstream copies without polling.
	if disp != nil {
		disp.Dispatch(cred.OrgID, webhook.EventPAMCredentialRotated, map[string]any{
			"org_id":          cred.OrgID,
			"credential_id":   cred.ID,
			"credential_type": cred.CredentialType,
			"rotated_at":      time.Now().UTC(),
			"rotated_by":      "system",
		})
	}

	return nil
}

// processStaleCredentialAlerts queries for credentials that are past their own
// rotation_interval_days and fires an alert for each one. Using the per-credential
// interval (rather than a global threshold) means a credential configured to rotate
// every 7 days fires at day 7, while one configured for 90 days fires at day 90.
func processStaleCredentialAlerts(ctx context.Context, repo *repository.PAMRepository, notifier *alerting.PAMNotifier) {
	if !notifier.IsEnabled() {
		return
	}
	due, err := repo.ListDueForRotation(ctx)
	if err != nil {
		log.Error().Err(err).Msg("pam-rotation-worker: failed to list overdue credentials for alerts")
		return
	}
	for i := range due {
		// Compute effective staleness: days since last rotation (or full interval
		// when never rotated) so the alert message shows a meaningful number.
		staleDays := *due[i].RotationIntervalDays
		if due[i].LastRotatedAt != nil {
			staleDays = int(time.Since(*due[i].LastRotatedAt).Hours() / 24)
		}
		notifier.AlertStaleCredential(&due[i], staleDays)
	}
}

// processLongSessionAlerts queries for privileged sessions that have exceeded
// the configured maxHours and fires an alert for each one.
func processLongSessionAlerts(ctx context.Context, repo *repository.PAMRepository, notifier *alerting.PAMNotifier) {
	if !notifier.IsEnabled() {
		return
	}
	maxHours := notifier.SessionMaxHours()
	sessions, err := repo.ListLongRunningSessions(ctx, maxHours)
	if err != nil {
		log.Error().Err(err).Msg("pam-rotation-worker: failed to list long-running sessions")
		return
	}
	for i := range sessions {
		duration := time.Since(sessions[i].StartedAt).Hours()
		notifier.AlertLongSession(&sessions[i], duration)
	}
}

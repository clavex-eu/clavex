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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	pamRotationWorkerInterval = 6 * time.Hour
	// pamRotationPasswordBytes is the number of random bytes to use for
	// generated passwords. 24 bytes = 32 base64url characters ≈ 192 bits.
	pamRotationPasswordBytes = 24
)

// RunPAMRotationWorker starts the credential auto-rotation goroutine.
// Blocks until ctx is cancelled. Call as `go RunPAMRotationWorker(ctx, pool, enc, notifier)`.
// Pass a zero-enabled notifier (alerting.NewPAMNotifier with empty URLs) to disable alerts.
func RunPAMRotationWorker(ctx context.Context, pool *pgxpool.Pool, enc *crypto.Encryptor, notifier *alerting.PAMNotifier) {
	repo := repository.NewPAMRepository(pool)

	log.Info().Str("interval", pamRotationWorkerInterval.String()).
		Msg("pam-rotation-worker: started")

	// Run immediately on startup to clear any backlog.
	processPAMRotations(ctx, repo, enc)
	processStaleCredentialAlerts(ctx, repo, notifier)
	processLongSessionAlerts(ctx, repo, notifier)

	ticker := time.NewTicker(pamRotationWorkerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("pam-rotation-worker: stopping")
			return
		case <-ticker.C:
			processPAMRotations(ctx, repo, enc)
			processStaleCredentialAlerts(ctx, repo, notifier)
			processLongSessionAlerts(ctx, repo, notifier)
		}
	}
}

func processPAMRotations(ctx context.Context, repo *repository.PAMRepository, enc *crypto.Encryptor) {
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
		if err := rotatePAMCredential(ctx, repo, enc, cred); err != nil {
			log.Error().Err(err).
				Str("credential_id", cred.ID.String()).
				Str("org_id", cred.OrgID.String()).
				Str("name", cred.Name).
				Msg("pam-rotation-worker: rotation failed")
		}
	}
}

func rotatePAMCredential(ctx context.Context, repo *repository.PAMRepository, enc *crypto.Encryptor, cred repository.PAMCredential) error {
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

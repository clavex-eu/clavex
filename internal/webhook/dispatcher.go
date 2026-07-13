package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	// ── User lifecycle ────────────────────────────────────────────────────────
	EventUserCreated         = "user.created"
	EventUserUpdated         = "user.updated"
	EventUserDeleted         = "user.deleted"
	EventUserSuspended       = "user.suspended"      // is_active → false
	EventUserReactivated     = "user.reactivated"    // is_active → true
	EventUserEmailVerified   = "user.email.verified"
	EventUserPasswordChanged = "user.password.changed"

	// ── Authentication events ─────────────────────────────────────────────────
	EventUserLogin              = "user.login"
	EventUserLoginFailed        = "user.login.failed"
	EventUserLoginNewDevice     = "user.login.new_device"     // first auth from this device fingerprint
	EventUserLoginSuspicious    = "user.login.suspicious"     // anomaly-score above threshold
	EventUserLoginNewCountry    = "user.login.new_country"    // first login from country for this user
	EventUserLoginBlocked       = "user.login.blocked"        // IP rule / lockout denied
	EventUserLogout             = "user.logout"
	EventUserLogoutAllSessions  = "user.logout.all_sessions"

	// ── MFA events ────────────────────────────────────────────────────────────
	EventMFASuccess     = "mfa.success"
	EventMFAFailed      = "mfa.failed"
	EventMFAEnrolled    = "mfa.enrolled"    // new TOTP / passkey credential added
	EventMFARemoved     = "mfa.removed"     // credential deleted (by user or admin)
	EventMFAPasskeyUsed = "mfa.passkey.used"

	// ── Password / credential events ─────────────────────────────────────────
	EventPasswordReset         = "password.reset"
	EventPasswordResetSent     = "password.reset.sent"   // reset email dispatched
	EventPasswordBreachWarning = "password.breach_warning"

	// ── Token events ─────────────────────────────────────────────────────────
	EventTokenIssued       = "token.issued"
	EventTokenRevoked      = "token.revoked"
	EventTokenRefreshed    = "token.refreshed"
	EventAgentTokenIssued  = "agent.token.issued"   // machine identity for AI agents
	EventAgentTokenRevoked = "agent.token.revoked"

	// ── Organization membership ───────────────────────────────────────────────
	EventOrgMemberAdded            = "org.member.added"
	EventOrgMemberRemoved          = "org.member.removed"
	EventOrgMemberJoinedViaDomain  = "org.member.joined_via_domain"  // auto-enroll
	EventOrgMemberJoinedViaInvite  = "org.member.joined_via_invite"

	// ── Role / group events ───────────────────────────────────────────────────
	EventRoleAssigned   = "role.assigned"
	EventRoleUnassigned = "role.unassigned"
	EventGroupMemberAdded   = "group.member.added"
	EventGroupMemberRemoved = "group.member.removed"

	// ── Invitation events ─────────────────────────────────────────────────────
	EventInvitationCreated  = "invitation.created"
	EventInvitationAccepted = "invitation.accepted"
	EventInvitationExpired  = "invitation.expired"

	// ── SCIM / provisioning events ────────────────────────────────────────────
	EventSCIMUserProvisioned        = "scim.user.provisioned"
	EventSCIMUserDeprovisioned      = "scim.user.deprovisioned"
	EventSCIMDeprovisioningAnomaly  = "scim.deprovisioning.anomaly"

	// ── Access review events ──────────────────────────────────────────────────
	EventAccessReviewLaunched  = "access_review.launched"
	EventAccessReviewCompleted = "access_review.completed"
	EventAccessReviewRevoked   = "access_review.access_revoked"

	// ── PAM / Privileged Access events ────────────────────────────────────────
	// EventPAMBreakGlassUsed fires whenever a break-glass emergency access
	// request is created (PCI DSS 8.2.6 — immediate admin notification required).
	EventPAMBreakGlassUsed = "pam.break_glass.used"
	// EventPAMCredentialStale fires when a vault credential has not been rotated
	// within the configured stale threshold (NIS2 Art.21 — rotation hygiene).
	EventPAMCredentialStale = "pam.credential.stale"
	// EventPAMSessionLong fires when a privileged session has been running
	// longer than the configured SessionMaxHours threshold.
	EventPAMSessionLong = "pam.session.long_running"
	// EventPAMCredentialRotated fires when a vault credential's secret has been
	// rotated successfully (auto-rotation by the PAM worker, or an explicit
	// rotation). Lets consumers refresh downstream copies without polling.
	EventPAMCredentialRotated = "pam.credential.rotated"
	// EventPAMSSHCARotated fires when the Vault SSH CA public key for an org has
	// changed (detected by the reconciliation worker). Lets trust-anchor
	// consumers refresh their pinned CA key without polling Vault themselves.
	EventPAMSSHCARotated = "pam.ssh_ca.rotated"
	// EventPAMSSHCARotationStarted fires when a staged SSH CA rotation begins.
	// Payload carries rotation_id and new_ca_public_key so consumers can begin
	// trusting the new CA before cutover.
	EventPAMSSHCARotationStarted = "pam.ssh_ca.rotation_started"

	dispatchTimeout     = 10 * time.Second
	maxRetries          = 3
	maxPermanentRetries = 10
	retryPollInterval   = 30 * time.Second
	maxRetryDelay       = 2 * time.Hour
)

// Payload is the JSON body sent to the webhook endpoint.
type Payload struct {
	ID        string          `json:"id"` // unique delivery ID
	Event     string          `json:"event"`
	OccuredAt time.Time       `json:"occurred_at"`
	Data      json.RawMessage `json:"data"`
}

// HookLister is the repository subset needed by the Dispatcher.
// *repository.WebhookRepository satisfies this interface.
type HookLister interface {
	ListActiveByOrgAndEvent(ctx context.Context, orgID uuid.UUID, event string) ([]*models.Webhook, error)
}

// WebhookGetter can look up a single webhook by ID.
// *repository.WebhookRepository satisfies this interface.
type WebhookGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Webhook, error)
}

// Dispatcher fires webhook deliveries asynchronously.
type Dispatcher struct {
	lister    HookLister
	delivRepo *repository.WebhookDeliveryRepository
	client    *http.Client
	backoff   func(time.Duration) // injectable; defaults to time.Sleep
}

// New creates a Dispatcher with an SSRF-safe HTTP client (private/loopback/
// link-local targets are blocked). Use WithHTTPClient to override (e.g. to allow
// internal targets when http.allow_private_outbound_targets is set).
func New(lister HookLister, delivRepo *repository.WebhookDeliveryRepository) *Dispatcher {
	return &Dispatcher{
		lister:    lister,
		delivRepo: delivRepo,
		client:    safehttp.Client(dispatchTimeout, false),
		backoff:   time.Sleep,
	}
}

// WithHTTPClient overrides the outbound HTTP client (e.g. an SSRF-relaxed client
// when the operator has opted into private outbound targets).
func (d *Dispatcher) WithHTTPClient(c *http.Client) *Dispatcher {
	if c != nil {
		d.client = c
	}
	return d
}

// Dispatch looks up all active webhooks for the org/event pair and fires them in
// background goroutines. It intentionally does not block the caller.
func (d *Dispatcher) Dispatch(orgID uuid.UUID, event string, data any) {
	payload, deliveryID, err := buildPayload(event, data)
	if err != nil {
		log.Error().Err(err).Str("event", event).Msg("webhook: failed to build payload")
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		hooks, err := d.lister.ListActiveByOrgAndEvent(ctx, orgID, event)
		if err != nil {
			log.Error().Err(err).Str("event", event).Msg("webhook: failed to list hooks")
			return
		}

		for _, h := range hooks {
			d.deliver(h, payload, deliveryID, event)
		}
	}()
}

// deliver attempts delivery with up to maxRetries retries using exponential back-off.
// Each attempt runs synchronously within the goroutine started by Dispatch.
func (d *Dispatcher) deliver(h *models.Webhook, payload []byte, deliveryID string, event string) {
	sig := sign(payload, h.Secret)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		start := time.Now()
		httpStatus, err := d.postWithStatus(h.URL, sig, payload)
		durMs := int(time.Since(start).Milliseconds())

		status := "success"
		var errStr *string
		if err != nil {
			status = "failed"
			s := err.Error()
			errStr = &s
		}

		// Record this attempt; ignore write errors — delivery must not block on observability.
		if d.delivRepo != nil {
			var httpSt *int
			if httpStatus > 0 {
				httpSt = &httpStatus
			}
			_ = d.delivRepo.Record(context.Background(), repository.RecordDeliveryParams{
				WebhookID:  h.ID,
				OrgID:      h.OrgID,
				DeliveryID: deliveryID,
				Event:      event,
				Payload:    payload,
				Attempt:    attempt,
				Status:     status,
				HTTPStatus: httpSt,
				Error:      errStr,
				DurationMs: &durMs,
			})
		}

		if err == nil {
			return
		}
		if attempt < maxRetries {
			d.backoff(time.Duration(attempt*attempt) * time.Second) // 1s, 4s
		} else {
			log.Warn().
				Str("webhook_id", h.ID.String()).
				Str("url", h.URL).
				Msg("webhook: all delivery attempts failed")
		}
	}
}

// postWithStatus sends the HTTP POST and returns (httpStatusCode, error).
// statusCode is 0 if a network error prevented receiving a response.
func (d *Dispatcher) postWithStatus(url, signature string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Clavex-Signature", "sha256="+signature)

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("non-2xx status: %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// RedeliverRaw fires an existing payload (e.g. from a manual retry) through the
// same exponential back-off delivery path but reuses the original delivery_id.
// This ensures the delivery row history is linked to the same idempotency key.
func (d *Dispatcher) RedeliverRaw(h *models.Webhook, payload []byte, deliveryID string, event string) {
	d.deliver(h, payload, deliveryID, event)
}

// StartRetryWorker launches a background goroutine that periodically scans for
// failed deliveries and re-attempts them using exponential back-off. The
// goroutine exits when ctx is cancelled. Call once from server startup.
//
// Back-off schedule (per delivery):
//   attempt 1 failed → retry after  1 min
//   attempt 2 failed → retry after  2 min
//   attempt 3 failed → retry after  4 min
//   …
//   attempt 7+ failed → retry after 2 h (capped)
//   after maxPermanentRetries total attempts: no further retries
func (d *Dispatcher) StartRetryWorker(ctx context.Context, getter WebhookGetter) {
	go func() {
		ticker := time.NewTicker(retryPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.retryOnce(ctx, getter)
			}
		}
	}()
}

func (d *Dispatcher) retryOnce(ctx context.Context, getter WebhookGetter) {
	if d.delivRepo == nil {
		return
	}
	candidates, err := d.delivRepo.ListRetriable(ctx, maxPermanentRetries)
	if err != nil {
		log.Error().Err(err).Msg("webhook retry: list retriable failed")
		return
	}
	for _, c := range candidates {
		if !retryBackoffElapsed(c.AttemptCount, c.LastAttempt) {
			continue
		}
		h, err := getter.GetByID(ctx, c.WebhookID)
		if err != nil || !h.IsActive {
			continue
		}
		// Deliver in its own goroutine so one slow endpoint doesn't block others.
		go d.deliver(h, c.Payload, c.DeliveryID, c.Event)
	}
}

// retryBackoffElapsed returns true if enough time has elapsed since lastAttempt
// to warrant a retry. Delay = 2^(attempts−1) minutes, capped at maxRetryDelay.
func retryBackoffElapsed(attempts int, lastAttempt time.Time) bool {
	if attempts <= 0 {
		return true
	}
	shift := attempts - 1
	if shift > 7 { // 2^7 min = 128 min > maxRetryDelay cap
		shift = 7
	}
	delay := time.Duration(1<<uint(shift)) * time.Minute
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	return time.Since(lastAttempt) >= delay
}

// sign produces a hex-encoded HMAC-SHA256 digest of the payload using the webhook secret.
func sign(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func buildPayload(event string, data any) ([]byte, string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, "", err
	}
	id := uuid.NewString()
	p := Payload{
		ID:        id,
		Event:     event,
		OccuredAt: time.Now().UTC(),
		Data:      raw,
	}
	b, err := json.Marshal(p)
	return b, id, err
}

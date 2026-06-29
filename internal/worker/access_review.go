package worker

// AccessReviewWorker drives the Joiner/Mover/Leaver access certification workflow.
//
// On every tick (default: 15 min) it:
//  1. Activates pending campaigns whose starts_at ≤ NOW() and generates items.
//  2. Sends reminder emails for pending items that have passed a reminder threshold.
//  3. Auto-revokes pending items in campaigns that have passed ends_at.
//  4. Closes campaigns that have no remaining pending items.
//
// Idempotency: all DB mutations use conditional UPDATEs / ON CONFLICT DO NOTHING,
// so concurrent worker instances (multi-replica) converge safely.

import (
	"context"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const accessReviewWorkerInterval = 15 * time.Minute

// AccessReviewDeps are external collaborators the worker needs.
type AccessReviewDeps struct {
	// BaseURL is the public root URL (e.g. "https://id.example.com").
	// Review decision links are built as BaseURL + "/access-review/decide?token=..."
	BaseURL string
	// SSFDispatch is the SSF/CAEP event dispatcher.  When non-nil, a
	// CAEP credential-change (revoke) SET is fired for each auto-revoked
	// user so that registered resource servers can invalidate tokens
	// immediately (zero-trust enforcement).
	SSFDispatch *ssf.Dispatcher // may be nil — events simply not sent
}

// RunAccessReviewWorker starts the background goroutine for access review processing.
// Call as `go RunAccessReviewWorker(ctx, pool, deps)`.
func RunAccessReviewWorker(ctx context.Context, pool *pgxpool.Pool, deps AccessReviewDeps) {
	repo := repository.NewAccessReviewRepository(pool)
	smtpRepo := repository.NewSMTPRepository(pool)
	userRepo := repository.NewUserRepository(pool)
	ticker := time.NewTicker(accessReviewWorkerInterval)
	defer ticker.Stop()

	log.Info().Str("interval", accessReviewWorkerInterval.String()).
		Msg("access-review-worker: started")

	// Run once immediately on startup to clear any backlog.
	processAccessReviews(ctx, pool, repo, smtpRepo, userRepo, deps)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("access-review-worker: stopping")
			return
		case <-ticker.C:
			processAccessReviews(ctx, pool, repo, smtpRepo, userRepo, deps)
		}
	}
}

func processAccessReviews(
	ctx context.Context,
	pool *pgxpool.Pool,
	repo *repository.AccessReviewRepository,
	smtpRepo *repository.SMTPRepository,
	userRepo *repository.UserRepository,
	deps AccessReviewDeps,
) {
	// Step 1: Activate pending campaigns that are due to start.
	activated, err := repo.ActivateDueCampaigns(ctx)
	if err != nil {
		log.Error().Err(err).Msg("access-review-worker: activate campaigns failed")
	}
	for _, c := range activated {
		if err := generateCampaignItems(ctx, c, repo, userRepo); err != nil {
			log.Error().Err(err).Str("campaign_id", c.ID.String()).
				Msg("access-review-worker: generate items failed")
		}
	}

	// Step 2: Send reminder emails.
	dueReminders, err := repo.ListPendingItemsDueForReminder(ctx)
	if err != nil {
		log.Error().Err(err).Msg("access-review-worker: list reminders failed")
	} else {
		sendReminders(ctx, dueReminders, repo, smtpRepo, deps)
	}

	// Step 3: Auto-revoke expired pending items.
	expiredItems, err := repo.ListExpiredPendingItems(ctx)
	if err != nil {
		log.Error().Err(err).Msg("access-review-worker: list expired items failed")
	} else {
		autoRevoke(ctx, expiredItems, pool, repo, smtpRepo, deps.BaseURL, deps.SSFDispatch)
	}

	// Step 4: Complete campaigns with no remaining pending items.
	if err := repo.CompleteCampaignsWithNoRemainingPending(ctx); err != nil {
		log.Error().Err(err).Msg("access-review-worker: complete campaigns failed")
	}
}

// generateCampaignItems creates one review item per (user, role) assignment in the org.
// The reviewer is set to the user themselves as a safe default; admins can re-assign
// via the API before the campaign is used.
func generateCampaignItems(
	ctx context.Context,
	c *models.AccessReviewCampaign,
	repo *repository.AccessReviewRepository,
	userRepo *repository.UserRepository,
) error {
	assignments, err := repo.ListUserRoleAssignmentsForOrg(ctx, c.OrgID)
	if err != nil {
		return fmt.Errorf("list assignments: %w", err)
	}
	if len(assignments) == 0 {
		return nil
	}

	// Determine a default reviewer for the org: the first admin user.
	// In practice operators override via the API; this is a sensible fallback.
	var defaultReviewerID uuid.UUID
	users, err := userRepo.ListByOrg(ctx, c.OrgID)
	if err == nil {
		for _, u := range users {
			if u.IsActive {
				defaultReviewerID = u.ID
				break
			}
		}
	}
	if defaultReviewerID == uuid.Nil {
		return fmt.Errorf("no active users found in org %s", c.OrgID)
	}

	params := make([]repository.CreateItemParams, 0, len(assignments))
	for _, a := range assignments {
		params = append(params, repository.CreateItemParams{
			CampaignID: c.ID,
			OrgID:      c.OrgID,
			UserID:     a.UserID,
			RoleID:     a.RoleID,
			ReviewerID: defaultReviewerID,
		})
	}

	if err := repo.BulkCreateItems(ctx, params); err != nil {
		return fmt.Errorf("bulk create items: %w", err)
	}
	log.Info().
		Str("campaign_id", c.ID.String()).
		Int("items", len(params)).
		Msg("access-review-worker: campaign items generated")
	return nil
}

func sendReminders(
	ctx context.Context,
	items []*models.AccessReviewItem,
	repo *repository.AccessReviewRepository,
	smtpRepo *repository.SMTPRepository,
	deps AccessReviewDeps,
) {
	if len(items) == 0 {
		return
	}

	// Group items by reviewer email to avoid duplicate mailer lookups.
	type orgReviewer struct {
		orgID      uuid.UUID
		reviewerID uuid.UUID
	}
	byReviewer := map[orgReviewer][]*models.AccessReviewItem{}
	for _, item := range items {
		key := orgReviewer{item.OrgID, item.ReviewerID}
		byReviewer[key] = append(byReviewer[key], item)
	}

	var reminded []uuid.UUID
	for key, batch := range byReviewer {
		m, err := mailer.ForOrg(ctx, smtpRepo, key.orgID)
		if err != nil {
			// SMTP not configured for this org — skip silently
			continue
		}
		subject := fmt.Sprintf("Access Review Reminder: %d items pending your decision", len(batch))
		body := buildReminderEmailHTML(batch, deps.BaseURL)
		if err := m.Send(batch[0].ReviewerEmail, subject, body); err != nil {
			log.Warn().Err(err).
				Str("reviewer", batch[0].ReviewerEmail).
				Msg("access-review-worker: reminder email failed")
			continue
		}
		for _, item := range batch {
			reminded = append(reminded, item.ID)
		}
	}
	if len(reminded) > 0 {
		if err := repo.MarkReminded(ctx, reminded); err != nil {
			log.Error().Err(err).Msg("access-review-worker: mark reminded failed")
		}
		log.Info().Int("count", len(reminded)).Msg("access-review-worker: reminders sent")
	}
}

func autoRevoke(
	ctx context.Context,
	items []*models.AccessReviewItem,
	pool *pgxpool.Pool,
	repo *repository.AccessReviewRepository,
	smtpRepo *repository.SMTPRepository,
	baseURL string,
	ssfDisp *ssf.Dispatcher,
) {
	if len(items) == 0 {
		return
	}
	userRepo := repository.NewUserRepository(pool)
	orgRepo := repository.NewOrgRepository(pool)

	// Cache org slugs so we don't hit the DB once per item.
	orgSlugs := make(map[uuid.UUID]string)
	for _, item := range items {
		if _, ok := orgSlugs[item.OrgID]; !ok {
			if org, err := orgRepo.GetByID(ctx, item.OrgID); err == nil {
				orgSlugs[item.OrgID] = org.Slug
			}
		}
	}

	for _, item := range items {
		// 1. Revoke the role assignment.
		if err := userRepo.UnassignRole(ctx, item.UserID, item.RoleID); err != nil {
			log.Error().Err(err).
				Str("item_id", item.ID.String()).
				Msg("access-review-worker: unassign role failed")
			continue
		}
		// 2. Mark item as auto_revoked (conditional UPDATE — idempotent).
		if err := repo.AutoRevokeItem(ctx, item.ID); err != nil {
			log.Error().Err(err).
				Str("item_id", item.ID.String()).
				Msg("access-review-worker: mark auto_revoked failed")
		}
		// 3. Dispatch CAEP credential-change (revoke) SET so registered
		// resource servers invalidate any access token for this user
		// immediately (zero-trust enforcement per CAEP spec §3.3).
		if ssfDisp != nil {
			slug := orgSlugs[item.OrgID]
			eventBody := ssf.CredentialChangeBody("access-role", "revoke")
			eventBody["initiating_entity"] = "policy"
			eventBody["reason_admin"] = map[string]interface{}{
				"en": fmt.Sprintf("Access review campaign expired without a decision; role %q automatically revoked", item.RoleName),
			}
			ssfDisp.Dispatch(item.OrgID, slug, item.UserID.String(),
				ssf.EventCredentialChange, eventBody)
		}
	}

	// 4. Notify affected users by org via email.
	byOrg := map[uuid.UUID][]*models.AccessReviewItem{}
	for _, item := range items {
		byOrg[item.OrgID] = append(byOrg[item.OrgID], item)
	}
	for orgID, batch := range byOrg {
		m, err := mailer.ForOrg(ctx, smtpRepo, orgID)
		if err != nil {
			continue
		}
		for _, item := range batch {
			body := buildAutoRevokeEmailHTML(item)
			_ = m.Send(item.UserEmail,
				"Access Review: your role has been automatically revoked",
				body,
			)
		}
	}
	log.Info().Int("count", len(items)).Msg("access-review-worker: auto-revocations processed")
}

// ── Email templates ───────────────────────────────────────────────────────────

func buildReminderEmailHTML(items []*models.AccessReviewItem, baseURL string) string {
	rows := ""
	for _, item := range items {
		approveURL := baseURL + "/access-review/decide?token=" + item.Token + "&decision=approved"
		revokeURL := baseURL + "/access-review/decide?token=" + item.Token + "&decision=revoked"
		rows += fmt.Sprintf(`
		<tr>
		  <td style="padding:8px;border-bottom:1px solid #eee">%s</td>
		  <td style="padding:8px;border-bottom:1px solid #eee">%s</td>
		  <td style="padding:8px;border-bottom:1px solid #eee">%s</td>
		  <td style="padding:8px;border-bottom:1px solid #eee">
		    <a href="%s" style="background:#16a34a;color:#fff;padding:5px 12px;border-radius:4px;text-decoration:none;margin-right:6px">Approve</a>
		    <a href="%s" style="background:#dc2626;color:#fff;padding:5px 12px;border-radius:4px;text-decoration:none">Revoke</a>
		  </td>
		</tr>`,
			item.UserName, item.UserEmail, item.RoleName,
			approveURL, revokeURL,
		)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;color:#111;max-width:700px;margin:0 auto">
<h2 style="border-bottom:2px solid #4f46e5;padding-bottom:8px">Access Review — Action Required</h2>
<p>The following access assignments require your review. Please approve or revoke each one before the deadline.</p>
<table style="width:100%%;border-collapse:collapse">
  <thead><tr style="background:#f3f4f6">
    <th style="padding:8px;text-align:left">User</th>
    <th style="padding:8px;text-align:left">Email</th>
    <th style="padding:8px;text-align:left">Role</th>
    <th style="padding:8px;text-align:left">Decision</th>
  </tr></thead>
  <tbody>%s</tbody>
</table>
<p style="color:#6b7280;font-size:12px;margin-top:24px">
  These links are single-use and expire when the campaign closes.<br>
  If you have questions, contact your organization administrator.
</p>
</body></html>`, rows)
}

func buildDecisionConfirmationEmailHTML(item *models.AccessReviewItem) string {
	action := "approved"
	color := "#16a34a"
	if item.Decision == "revoked" {
		action = "revoked"
		color = "#dc2626"
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;color:#111;max-width:600px;margin:0 auto">
<h2 style="border-bottom:2px solid #4f46e5;padding-bottom:8px">Access Review — Decision Recorded</h2>
<p>Your decision has been recorded:</p>
<table style="width:100%%;border-collapse:collapse">
  <tr><td style="padding:8px;color:#6b7280">User</td><td style="padding:8px"><strong>%s</strong> (%s)</td></tr>
  <tr><td style="padding:8px;color:#6b7280">Role</td><td style="padding:8px"><strong>%s</strong></td></tr>
  <tr><td style="padding:8px;color:#6b7280">Decision</td><td style="padding:8px"><span style="color:%s;font-weight:bold">%s</span></td></tr>
</table>
</body></html>`,
		item.UserName, item.UserEmail, item.RoleName, color, action,
	)
}

func buildAutoRevokeEmailHTML(item *models.AccessReviewItem) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;color:#111;max-width:600px;margin:0 auto">
<h2 style="border-bottom:2px solid #dc2626;padding-bottom:8px">Access Review — Role Automatically Revoked</h2>
<p>Your access to the role <strong>%s</strong> has been automatically revoked because the access review campaign ended without a decision from your reviewer.</p>
<p>Please contact your administrator if you believe this is an error.</p>
</body></html>`, item.RoleName)
}

// BuildDecisionConfirmationEmailHTML is exported for use by the HTTP handler.
func BuildDecisionConfirmationEmailHTML(item *models.AccessReviewItem) string {
	return buildDecisionConfirmationEmailHTML(item)
}

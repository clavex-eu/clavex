package worker

// EntityReviewWorker drives the Object Lifecycle Management entity review
// certification workflow.
//
// On every tick (default: 15 min) it:
//  1. Activates pending campaigns whose starts_at ≤ NOW() (items generated
//     by the handler at creation time; worker only flips status).
//  2. Sends reminder emails for pending items within the reminder window.
//  3. Auto-deprecates pending items in campaigns that have passed ends_at.
//  4. Disables entities that have been auto_deprecated (when auto_disable=true).
//  5. Closes campaigns that have no remaining pending items.

import (
	"context"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const entityReviewWorkerInterval = 15 * time.Minute

// RunEntityReviewWorker starts the background goroutine for entity review
// processing. Call as `go RunEntityReviewWorker(ctx, pool, baseURL)`.
func RunEntityReviewWorker(ctx context.Context, pool *pgxpool.Pool, baseURL string) {
	repo := repository.NewEntityReviewRepository(pool)
	smtpRepo := repository.NewSMTPRepository(pool)
	ticker := time.NewTicker(entityReviewWorkerInterval)
	defer ticker.Stop()

	log.Info().Str("interval", entityReviewWorkerInterval.String()).
		Msg("entity-review-worker: started")

	processEntityReviews(ctx, repo, smtpRepo, baseURL)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("entity-review-worker: stopping")
			return
		case <-ticker.C:
			processEntityReviews(ctx, repo, smtpRepo, baseURL)
		}
	}
}

func processEntityReviews(ctx context.Context, repo *repository.EntityReviewRepository, smtpRepo *repository.SMTPRepository, baseURL string) {
	// 1. Activate pending campaigns whose starts_at has passed.
	pendingCampaigns, err := repo.ListPendingToActivate(ctx)
	if err != nil {
		log.Error().Err(err).Msg("entity-review-worker: list pending campaigns failed")
	}
	for _, c := range pendingCampaigns {
		if err := repo.UpdateStatus(ctx, c.OrgID, c.ID, "active"); err != nil {
			log.Warn().Err(err).Str("campaign_id", c.ID.String()).Msg("entity-review-worker: activate failed")
		} else {
			log.Info().Str("campaign_id", c.ID.String()).Str("name", c.Name).Msg("entity-review-worker: campaign activated")
		}
	}

	// 2. Send reminders for pending items in the reminder window.
	reminderItems, err := repo.ListPendingItemsDueReminder(ctx)
	if err != nil {
		log.Error().Err(err).Msg("entity-review-worker: list reminder items failed")
	}
	sendEntityReminders(ctx, reminderItems, repo, smtpRepo, baseURL)

	// 3. Auto-deprecate pending items in expired campaigns.
	expiredItems, err := repo.ListPendingExpiredItems(ctx)
	if err != nil {
		log.Error().Err(err).Msg("entity-review-worker: list expired items failed")
	}
	for _, item := range expiredItems {
		if err := repo.AutoDeprecateItem(ctx, item.ID); err != nil {
			log.Warn().Err(err).Str("item_id", item.ID.String()).Msg("entity-review-worker: auto-deprecate failed")
			continue
		}
		log.Info().
			Str("entity_type", item.EntityType).
			Str("entity_name", item.EntityName).
			Msg("entity-review-worker: auto-deprecated")

		// 4. Disable the entity when auto_disable is set on the campaign.
		disableEntity(ctx, repo, item.OrgID, item.EntityType, item.EntityID)
	}

	// 5. Close campaigns with no remaining pending items.
	if err := repo.CompleteFinishedCampaigns(ctx); err != nil {
		log.Warn().Err(err).Msg("entity-review-worker: complete finished campaigns failed")
	}
}

// sendEntityReminders sends reminder emails to reviewers for pending entity
// review items and marks them as reminded. Grouped by reviewer to avoid
// repeated mailer lookups.
func sendEntityReminders(
	ctx context.Context,
	items []*models.EntityReviewItem,
	repo *repository.EntityReviewRepository,
	smtpRepo *repository.SMTPRepository,
	baseURL string,
) {
	if len(items) == 0 {
		return
	}

	type orgReviewer struct {
		orgID      uuid.UUID
		reviewerID uuid.UUID
	}
	byReviewer := map[orgReviewer][]*models.EntityReviewItem{}
	for _, item := range items {
		key := orgReviewer{item.OrgID, item.ReviewerID}
		byReviewer[key] = append(byReviewer[key], item)
	}

	var reminded []uuid.UUID
	for key, batch := range byReviewer {
		m, err := mailer.ForOrg(ctx, smtpRepo, key.orgID)
		if err != nil {
			// SMTP not configured for this org — skip silently.
			for _, item := range batch {
				reminded = append(reminded, item.ID)
			}
			continue
		}
		subject := fmt.Sprintf("Entity Review Reminder: %d item(s) pending your decision", len(batch))
		body := buildEntityReminderEmailHTML(batch, baseURL)
		if err := m.Send(batch[0].ReviewerEmail, subject, body); err != nil {
			log.Warn().Err(err).
				Str("reviewer", batch[0].ReviewerEmail).
				Msg("entity-review-worker: reminder email failed")
			continue
		}
		log.Info().
			Str("reviewer", batch[0].ReviewerEmail).
			Int("items", len(batch)).
			Msg("entity-review-worker: reminder sent")
		for _, item := range batch {
			reminded = append(reminded, item.ID)
		}
	}
	if len(reminded) > 0 {
		if err := repo.MarkReminded(ctx, reminded); err != nil {
			log.Warn().Err(err).Msg("entity-review-worker: mark reminded failed")
		}
	}
}

func buildEntityReminderEmailHTML(items []*models.EntityReviewItem, baseURL string) string {
	rows := ""
	for _, item := range items {
		confirmURL := baseURL + "/entity-review/decide?token=" + item.Token + "&decision=confirmed"
		deprecateURL := baseURL + "/entity-review/decide?token=" + item.Token + "&decision=deprecated"
		rows += fmt.Sprintf(`
		<tr>
		  <td style="padding:8px;border-bottom:1px solid #eee">%s</td>
		  <td style="padding:8px;border-bottom:1px solid #eee">%s</td>
		  <td style="padding:8px;border-bottom:1px solid #eee">
		    <a href="%s" style="background:#16a34a;color:#fff;padding:5px 12px;border-radius:4px;text-decoration:none;margin-right:6px">Confirm</a>
		    <a href="%s" style="background:#dc2626;color:#fff;padding:5px 12px;border-radius:4px;text-decoration:none">Deprecate</a>
		  </td>
		</tr>`,
			item.EntityType, item.EntityName, confirmURL, deprecateURL,
		)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;color:#111;max-width:700px;margin:0 auto">
<h2 style="border-bottom:2px solid #4f46e5;padding-bottom:8px">Entity Review — Action Required</h2>
<p>The following entities require your certification decision.</p>
<table style="width:100%%;border-collapse:collapse">
  <thead><tr style="background:#f3f4f6">
    <th style="padding:8px;text-align:left">Type</th>
    <th style="padding:8px;text-align:left">Name</th>
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

// disableEntity deactivates an OIDC client, group, or role that was not
// confirmed during the review window.
func disableEntity(ctx context.Context, repo *repository.EntityReviewRepository, orgID uuid.UUID, entityType, entityID string) {
	switch entityType {
	case "client":
		if err := repo.DisableClient(ctx, orgID, entityID); err != nil {
			log.Warn().Err(err).Str("client_id", entityID).Msg("entity-review-worker: disable client failed")
		} else {
			log.Info().Str("client_id", entityID).Msg("entity-review-worker: client disabled (auto-deprecated)")
		}
	case "group":
		gID, err := uuid.Parse(entityID)
		if err != nil {
			return
		}
		if err := repo.DisableGroup(ctx, orgID, gID); err != nil {
			log.Warn().Err(err).Str("group_id", entityID).Msg("entity-review-worker: disable group failed")
		} else {
			log.Info().Str("group_id", entityID).Msg("entity-review-worker: group disabled (auto-deprecated)")
		}
	case "role":
		rID, err := uuid.Parse(entityID)
		if err != nil {
			return
		}
		if err := repo.DisableRole(ctx, orgID, rID); err != nil {
			log.Warn().Err(err).Str("role_id", entityID).Msg("entity-review-worker: disable role failed")
		} else {
			log.Info().Str("role_id", entityID).Msg("entity-review-worker: role disabled (auto-deprecated)")
		}
	}
}

package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AccessReviewRepository manages access review campaigns and items.
type AccessReviewRepository struct {
	pool *pgxpool.Pool
}

func NewAccessReviewRepository(pool *pgxpool.Pool) *AccessReviewRepository {
	return &AccessReviewRepository{pool: pool}
}

// ── Campaigns ─────────────────────────────────────────────────────────────────

const campaignCols = `id, org_id, name, description, frequency, status, starts_at, ends_at, reminder_days, auto_revoke, created_by, created_at, updated_at`

func (r *AccessReviewRepository) scanCampaign(row interface{ Scan(...interface{}) error }) (*models.AccessReviewCampaign, error) {
	c := &models.AccessReviewCampaign{}
	err := row.Scan(
		&c.ID, &c.OrgID, &c.Name, &c.Description,
		&c.Frequency, &c.Status,
		&c.StartsAt, &c.EndsAt,
		&c.ReminderDays, &c.AutoRevoke,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	return c, err
}

func (r *AccessReviewRepository) ListCampaigns(ctx context.Context, orgID uuid.UUID) ([]*models.AccessReviewCampaign, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+campaignCols+`
		 FROM identity.access_review_campaigns
		 WHERE org_id = $1
		 ORDER BY starts_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var campaigns []*models.AccessReviewCampaign
	for rows.Next() {
		c, err := r.scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		campaigns = append(campaigns, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Attach item stats
	for _, c := range campaigns {
		r.populateStats(ctx, c)
	}
	return campaigns, nil
}

func (r *AccessReviewRepository) GetCampaign(ctx context.Context, orgID, id uuid.UUID) (*models.AccessReviewCampaign, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+campaignCols+`
		 FROM identity.access_review_campaigns
		 WHERE id = $1 AND org_id = $2`,
		id, orgID,
	)
	c, err := r.scanCampaign(row)
	if err != nil {
		return nil, err
	}
	r.populateStats(ctx, c)
	return c, nil
}

func (r *AccessReviewRepository) populateStats(ctx context.Context, c *models.AccessReviewCampaign) {
	_ = r.pool.QueryRow(ctx,
		`SELECT
		    COUNT(*),
		    COUNT(*) FILTER (WHERE decision = 'pending'),
		    COUNT(*) FILTER (WHERE decision = 'approved'),
		    COUNT(*) FILTER (WHERE decision IN ('revoked','auto_revoked'))
		 FROM identity.access_review_items WHERE campaign_id = $1`,
		c.ID,
	).Scan(&c.TotalItems, &c.PendingItems, &c.ApprovedItems, &c.RevokedItems)
}

type CreateCampaignParams struct {
	OrgID        uuid.UUID
	Name         string
	Description  *string
	Frequency    string
	StartsAt     time.Time
	EndsAt       time.Time
	ReminderDays []int
	AutoRevoke   bool
	CreatedBy    *uuid.UUID
}

func (r *AccessReviewRepository) CreateCampaign(ctx context.Context, p CreateCampaignParams) (*models.AccessReviewCampaign, error) {
	row := r.pool.QueryRow(ctx,
		`INSERT INTO identity.access_review_campaigns
		   (org_id, name, description, frequency, status, starts_at, ends_at, reminder_days, auto_revoke, created_by)
		 VALUES ($1,$2,$3,$4,'pending',$5,$6,$7,$8,$9)
		 RETURNING `+campaignCols,
		p.OrgID, p.Name, p.Description, p.Frequency,
		p.StartsAt, p.EndsAt, p.ReminderDays, p.AutoRevoke, p.CreatedBy,
	)
	return r.scanCampaign(row)
}

func (r *AccessReviewRepository) UpdateCampaignStatus(ctx context.Context, orgID, id uuid.UUID, status string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE identity.access_review_campaigns
		 SET status = $3, updated_at = NOW()
		 WHERE id = $1 AND org_id = $2`,
		id, orgID, status,
	)
	return err
}

// ListActiveCampaigns returns campaigns that are 'active' and not yet expired.
// Used by the worker to check for reminders and auto-revocations.
func (r *AccessReviewRepository) ListActiveCampaigns(ctx context.Context) ([]*models.AccessReviewCampaign, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+campaignCols+`
		 FROM identity.access_review_campaigns
		 WHERE status = 'active'
		 ORDER BY ends_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.AccessReviewCampaign
	for rows.Next() {
		c, err := r.scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ActivateDueCampaigns transitions 'pending' campaigns whose starts_at <= NOW()
// to 'active'. Returns the newly activated campaigns so items can be generated.
func (r *AccessReviewRepository) ActivateDueCampaigns(ctx context.Context) ([]*models.AccessReviewCampaign, error) {
	rows, err := r.pool.Query(ctx,
		`UPDATE identity.access_review_campaigns
		 SET status = 'active', updated_at = NOW()
		 WHERE status = 'pending' AND starts_at <= NOW()
		 RETURNING `+campaignCols,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.AccessReviewCampaign
	for rows.Next() {
		c, err := r.scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ── Items ─────────────────────────────────────────────────────────────────────

const itemCols = `
    i.id, i.campaign_id, i.org_id, i.user_id, i.role_id, i.reviewer_id,
    i.decision, i.token, i.decided_at, i.comment, i.last_reminded_at,
    i.created_at, i.updated_at,
    u.email, COALESCE(u.first_name,'') || ' ' || COALESCE(u.last_name,''),
    ro.name,
    rv.email, COALESCE(rv.first_name,'') || ' ' || COALESCE(rv.last_name,'')`

func (r *AccessReviewRepository) scanItem(row interface{ Scan(...interface{}) error }) (*models.AccessReviewItem, error) {
	i := &models.AccessReviewItem{}
	err := row.Scan(
		&i.ID, &i.CampaignID, &i.OrgID, &i.UserID, &i.RoleID, &i.ReviewerID,
		&i.Decision, &i.Token, &i.DecidedAt, &i.Comment, &i.LastRemindedAt,
		&i.CreatedAt, &i.UpdatedAt,
		&i.UserEmail, &i.UserName, &i.RoleName, &i.ReviewerEmail, &i.ReviewerName,
	)
	return i, err
}

const itemJoin = `
    FROM identity.access_review_items i
    JOIN identity.users  u  ON u.id  = i.user_id
    JOIN identity.roles  ro ON ro.id = i.role_id
    JOIN identity.users  rv ON rv.id = i.reviewer_id`

func (r *AccessReviewRepository) ListItems(ctx context.Context, campaignID uuid.UUID) ([]*models.AccessReviewItem, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+itemCols+itemJoin+`
		 WHERE i.campaign_id = $1
		 ORDER BY rv.email, u.email`,
		campaignID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []*models.AccessReviewItem
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListPendingItemsForReviewer returns all pending items assigned to a reviewer.
func (r *AccessReviewRepository) ListPendingItemsForReviewer(ctx context.Context, reviewerID uuid.UUID) ([]*models.AccessReviewItem, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+itemCols+itemJoin+`
		 WHERE i.reviewer_id = $1 AND i.decision = 'pending'
		 ORDER BY i.campaign_id, u.email`,
		reviewerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []*models.AccessReviewItem
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// GetItemByToken fetches a review item by its one-time token (used in email links).
func (r *AccessReviewRepository) GetItemByToken(ctx context.Context, token string) (*models.AccessReviewItem, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+itemCols+itemJoin+` WHERE i.token = $1`,
		token,
	)
	return r.scanItem(row)
}

type CreateItemParams struct {
	CampaignID uuid.UUID
	OrgID      uuid.UUID
	UserID     uuid.UUID
	RoleID     uuid.UUID
	ReviewerID uuid.UUID
}

// BulkCreateItems inserts items for a campaign (one per user × role assignment).
// Duplicate (campaign_id, user_id, role_id) combinations are silently skipped.
func (r *AccessReviewRepository) BulkCreateItems(ctx context.Context, items []CreateItemParams) error {
	for _, p := range items {
		tok, err := generateReviewToken()
		if err != nil {
			return err
		}
		_, err = r.pool.Exec(ctx,
			`INSERT INTO identity.access_review_items
			   (campaign_id, org_id, user_id, role_id, reviewer_id, token)
			 VALUES ($1,$2,$3,$4,$5,$6)
			 ON CONFLICT DO NOTHING`,
			p.CampaignID, p.OrgID, p.UserID, p.RoleID, p.ReviewerID, tok,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// DecideItem records the reviewer's approve/revoke decision on a single item.
func (r *AccessReviewRepository) DecideItem(ctx context.Context, token, decision, comment string) (*models.AccessReviewItem, error) {
	row := r.pool.QueryRow(ctx,
		`UPDATE identity.access_review_items
		 SET decision = $2, comment = $3, decided_at = NOW(), updated_at = NOW()
		 WHERE token = $1 AND decision = 'pending'
		 RETURNING `+`id, campaign_id, org_id, user_id, role_id, reviewer_id,
		            decision, token, decided_at, comment, last_reminded_at, created_at, updated_at`,
		token, decision, comment,
	)
	i := &models.AccessReviewItem{}
	err := row.Scan(
		&i.ID, &i.CampaignID, &i.OrgID, &i.UserID, &i.RoleID, &i.ReviewerID,
		&i.Decision, &i.Token, &i.DecidedAt, &i.Comment, &i.LastRemindedAt,
		&i.CreatedAt, &i.UpdatedAt,
	)
	return i, err
}

// ListPendingItemsDueForReminder returns pending items whose campaign has a
// reminder threshold that is now past (based on ends_at - reminder_days).
func (r *AccessReviewRepository) ListPendingItemsDueForReminder(ctx context.Context) ([]*models.AccessReviewItem, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+itemCols+itemJoin+`
		 JOIN identity.access_review_campaigns c ON c.id = i.campaign_id
		 WHERE i.decision = 'pending'
		   AND c.status = 'active'
		   AND EXISTS (
		       SELECT 1 FROM unnest(c.reminder_days) AS rd(d)
		       WHERE NOW() >= c.ends_at - (rd.d * INTERVAL '1 day')
		         AND (i.last_reminded_at IS NULL
		              OR i.last_reminded_at < c.ends_at - (rd.d * INTERVAL '1 day'))
		   )`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []*models.AccessReviewItem
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// MarkReminded updates last_reminded_at for a list of item IDs.
func (r *AccessReviewRepository) MarkReminded(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := r.pool.Exec(ctx,
		`UPDATE identity.access_review_items
		 SET last_reminded_at = NOW(), updated_at = NOW()
		 WHERE id = ANY($1::uuid[])`,
		ids,
	)
	return err
}

// ListExpiredPendingItems returns pending items in campaigns that have passed ends_at.
func (r *AccessReviewRepository) ListExpiredPendingItems(ctx context.Context) ([]*models.AccessReviewItem, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+itemCols+itemJoin+`
		 JOIN identity.access_review_campaigns c ON c.id = i.campaign_id
		 WHERE i.decision = 'pending'
		   AND c.status = 'active'
		   AND c.auto_revoke = TRUE
		   AND c.ends_at <= NOW()`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []*models.AccessReviewItem
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// AutoRevokeItem marks a single item as auto_revoked.
func (r *AccessReviewRepository) AutoRevokeItem(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE identity.access_review_items
		 SET decision = 'auto_revoked', decided_at = NOW(), updated_at = NOW()
		 WHERE id = $1 AND decision = 'pending'`,
		id,
	)
	return err
}

// CompleteCampaignsWithNoRemainingPending closes active campaigns that have no
// more pending items (all decided or auto-revoked).
func (r *AccessReviewRepository) CompleteCampaignsWithNoRemainingPending(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE identity.access_review_campaigns
		SET status = 'completed', updated_at = NOW()
		WHERE status = 'active'
		  AND NOT EXISTS (
		      SELECT 1 FROM identity.access_review_items
		      WHERE campaign_id = identity.access_review_campaigns.id
		        AND decision = 'pending'
		  )
	`)
	return err
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// generateReviewToken creates a cryptographically random 32-byte hex string
// used as the one-time approve/revoke token in email links.
func generateReviewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ListUserRoleAssignmentsForOrg returns all (user_id, role_id) pairs for an org.
// Used when generating campaign items.
func (r *AccessReviewRepository) ListUserRoleAssignmentsForOrg(ctx context.Context, orgID uuid.UUID) ([]struct{ UserID, RoleID uuid.UUID }, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT ur.user_id, ur.role_id
		FROM user_roles ur
		JOIN identity.users u ON u.id = ur.user_id
		WHERE u.org_id = $1 AND u.is_active = TRUE
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct{ UserID, RoleID uuid.UUID }
	for rows.Next() {
		var pair struct{ UserID, RoleID uuid.UUID }
		if err := rows.Scan(&pair.UserID, &pair.RoleID); err != nil {
			return nil, err
		}
		out = append(out, pair)
	}
	return out, rows.Err()
}

package repository

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EntityReviewRepository provides CRUD access to entity review campaigns
// and their items (Object Lifecycle Management).
type EntityReviewRepository struct {
	pool *pgxpool.Pool
}

func NewEntityReviewRepository(pool *pgxpool.Pool) *EntityReviewRepository {
	return &EntityReviewRepository{pool: pool}
}

// ── Campaigns ─────────────────────────────────────────────────────────────────

const entityCampaignCols = `id, org_id, name, description, entity_type, frequency_days,
	status, starts_at, ends_at, reminder_days, auto_disable, created_by, created_at, updated_at`

func (r *EntityReviewRepository) scanCampaign(row interface{ Scan(...any) error }) (*models.EntityReviewCampaign, error) {
	var c models.EntityReviewCampaign
	err := row.Scan(
		&c.ID, &c.OrgID, &c.Name, &c.Description, &c.EntityType, &c.FrequencyDays,
		&c.Status, &c.StartsAt, &c.EndsAt, &c.ReminderDays, &c.AutoDisable,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	return &c, err
}

func (r *EntityReviewRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.EntityReviewCampaign, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+entityCampaignCols+`
		 FROM entity_review_campaigns
		 WHERE org_id = $1
		 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.EntityReviewCampaign
	for rows.Next() {
		c, err := r.scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *EntityReviewRepository) GetByID(ctx context.Context, orgID, id uuid.UUID) (*models.EntityReviewCampaign, error) {
	return r.scanCampaign(r.pool.QueryRow(ctx,
		`SELECT `+entityCampaignCols+`
		 FROM entity_review_campaigns WHERE id = $1 AND org_id = $2`, id, orgID))
}

type CreateEntityReviewCampaignParams struct {
	OrgID         uuid.UUID
	Name          string
	Description   *string
	EntityType    string
	FrequencyDays int
	StartsAt      time.Time
	EndsAt        time.Time
	ReminderDays  []int
	AutoDisable   bool
	CreatedBy     *uuid.UUID
}

func (r *EntityReviewRepository) Create(ctx context.Context, p CreateEntityReviewCampaignParams) (*models.EntityReviewCampaign, error) {
	rd := p.ReminderDays
	if rd == nil {
		rd = []int{7, 1}
	}
	return r.scanCampaign(r.pool.QueryRow(ctx,
		`INSERT INTO entity_review_campaigns
		   (org_id, name, description, entity_type, frequency_days,
		    starts_at, ends_at, reminder_days, auto_disable, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING `+entityCampaignCols,
		p.OrgID, p.Name, p.Description, p.EntityType, p.FrequencyDays,
		p.StartsAt, p.EndsAt, rd, p.AutoDisable, p.CreatedBy,
	))
}

func (r *EntityReviewRepository) UpdateStatus(ctx context.Context, orgID, id uuid.UUID, status string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE entity_review_campaigns SET status=$3, updated_at=NOW()
		 WHERE id=$1 AND org_id=$2`, id, orgID, status)
	return err
}

// ListPendingToActivate returns campaigns whose starts_at has passed but are
// still in 'pending' state — they should be activated by the worker.
func (r *EntityReviewRepository) ListPendingToActivate(ctx context.Context) ([]*models.EntityReviewCampaign, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+entityCampaignCols+`
		 FROM entity_review_campaigns
		 WHERE status = 'pending' AND starts_at <= NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.EntityReviewCampaign
	for rows.Next() {
		c, err := r.scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListExpiredActive returns active campaigns whose ends_at has passed.
func (r *EntityReviewRepository) ListExpiredActive(ctx context.Context) ([]*models.EntityReviewCampaign, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+entityCampaignCols+`
		 FROM entity_review_campaigns
		 WHERE status = 'active' AND ends_at <= NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.EntityReviewCampaign
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

const itemCols2 = `i.id, i.campaign_id, i.org_id, i.entity_type, i.entity_id,
	i.entity_name, i.reviewer_id, i.decision, i.token,
	i.decided_at, i.comment, i.last_reminded_at, i.created_at, i.updated_at,
	COALESCE(u.email,'') AS reviewer_email,
	COALESCE(u.first_name||' '||u.last_name, u.email, '') AS reviewer_name`

const itemJoin2 = ` FROM entity_review_items i LEFT JOIN users u ON u.id = i.reviewer_id `

func (r *EntityReviewRepository) scanItem(row interface{ Scan(...any) error }) (*models.EntityReviewItem, error) {
	var it models.EntityReviewItem
	err := row.Scan(
		&it.ID, &it.CampaignID, &it.OrgID, &it.EntityType, &it.EntityID,
		&it.EntityName, &it.ReviewerID, &it.Decision, &it.Token,
		&it.DecidedAt, &it.Comment, &it.LastRemindedAt, &it.CreatedAt, &it.UpdatedAt,
		&it.ReviewerEmail, &it.ReviewerName,
	)
	return &it, err
}

func (r *EntityReviewRepository) ListItemsByCampaign(ctx context.Context, campaignID uuid.UUID) ([]*models.EntityReviewItem, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+itemCols2+itemJoin2+`WHERE i.campaign_id = $1 ORDER BY i.entity_name`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.EntityReviewItem
	for rows.Next() {
		it, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

type CreateEntityReviewItemParams struct {
	CampaignID uuid.UUID
	OrgID      uuid.UUID
	EntityType string
	EntityID   string
	EntityName string
	ReviewerID uuid.UUID
}

func (r *EntityReviewRepository) CreateItem(ctx context.Context, p CreateEntityReviewItemParams) (*models.EntityReviewItem, error) {
	return r.scanItem(r.pool.QueryRow(ctx,
		`INSERT INTO entity_review_items
		   (campaign_id, org_id, entity_type, entity_id, entity_name, reviewer_id)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT DO NOTHING
		 RETURNING `+itemCols2+itemJoin2+`WHERE i.campaign_id=$1 AND i.entity_id=$4 LIMIT 1`,
		p.CampaignID, p.OrgID, p.EntityType, p.EntityID, p.EntityName, p.ReviewerID,
	))
}

// GetItemByToken looks up a review item by its one-time decision token.
func (r *EntityReviewRepository) GetItemByToken(ctx context.Context, token string) (*models.EntityReviewItem, error) {
	return r.scanItem(r.pool.QueryRow(ctx,
		`SELECT `+itemCols2+itemJoin2+`WHERE i.token = $1`, token))
}

// DecideItem records the reviewer's decision on an item.
func (r *EntityReviewRepository) DecideItem(ctx context.Context, token, decision, comment string) (*models.EntityReviewItem, error) {
	return r.scanItem(r.pool.QueryRow(ctx,
		`UPDATE entity_review_items
		 SET decision=$2, comment=$3, decided_at=NOW(), updated_at=NOW()
		 WHERE token=$1 AND decision='pending'
		 RETURNING `+itemCols2+itemJoin2+`WHERE i.token=$1`,
		token, decision, comment,
	))
}

// ListPendingExpiredItems returns all 'pending' items in campaigns that have
// passed their ends_at deadline with auto_disable=true.
func (r *EntityReviewRepository) ListPendingExpiredItems(ctx context.Context) ([]*models.EntityReviewItem, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+itemCols2+itemJoin2+`
		 JOIN entity_review_campaigns c ON c.id = i.campaign_id
		 WHERE i.decision = 'pending'
		   AND c.status = 'active'
		   AND c.auto_disable = TRUE
		   AND c.ends_at <= NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.EntityReviewItem
	for rows.Next() {
		it, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// AutoDeprecateItem marks a pending item as auto_deprecated.
func (r *EntityReviewRepository) AutoDeprecateItem(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE entity_review_items
		 SET decision='auto_deprecated', decided_at=NOW(), updated_at=NOW()
		 WHERE id=$1 AND decision='pending'`, id)
	return err
}

// CompleteFinishedCampaigns closes active campaigns with no remaining pending items.
func (r *EntityReviewRepository) CompleteFinishedCampaigns(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE entity_review_campaigns SET status='completed', updated_at=NOW()
		WHERE status='active'
		  AND NOT EXISTS (
		      SELECT 1 FROM entity_review_items
		      WHERE campaign_id = entity_review_campaigns.id AND decision='pending'
		  )`)
	return err
}

// ── Counts (for campaign summary) ────────────────────────────────────────────

type EntityReviewCounts struct {
	Total      int
	Pending    int
	Confirmed  int
	Deprecated int
}

func (r *EntityReviewRepository) GetCampaignCounts(ctx context.Context, campaignID uuid.UUID) (EntityReviewCounts, error) {
	var c EntityReviewCounts
	row := r.pool.QueryRow(ctx,
		`SELECT COUNT(*),
		        SUM(CASE WHEN decision='pending'          THEN 1 ELSE 0 END),
		        SUM(CASE WHEN decision='confirmed'        THEN 1 ELSE 0 END),
		        SUM(CASE WHEN decision IN ('deprecated','auto_deprecated') THEN 1 ELSE 0 END)
		 FROM entity_review_items WHERE campaign_id=$1`, campaignID)
	err := row.Scan(&c.Total, &c.Pending, &c.Confirmed, &c.Deprecated)
	return c, err
}

// ── Stale item reminder queries ───────────────────────────────────────────────

// ListPendingItemsDueReminder returns pending items in active campaigns that
// are within a reminder window (based on campaign.reminder_days and ends_at)
// and have not yet been reminded in the last 22 hours.
func (r *EntityReviewRepository) ListPendingItemsDueReminder(ctx context.Context) ([]*models.EntityReviewItem, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+itemCols2+itemJoin2+`
		 JOIN entity_review_campaigns c ON c.id = i.campaign_id
		 WHERE i.decision = 'pending'
		   AND c.status = 'active'
		   AND c.ends_at > NOW()
		   AND (i.last_reminded_at IS NULL OR i.last_reminded_at < NOW() - INTERVAL '22 hours')
		   AND EXISTS (
		       SELECT 1 FROM unnest(c.reminder_days) rd
		       WHERE NOW() >= c.ends_at - (rd * INTERVAL '1 day')
		   )`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.EntityReviewItem
	for rows.Next() {
		it, err := r.scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (r *EntityReviewRepository) MarkReminded(ctx context.Context, ids []uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE entity_review_items SET last_reminded_at=NOW(), updated_at=NOW() WHERE id=ANY($1::uuid[])`, ids)
	return err
}

// ── Item bulk insert (called when activating a campaign) ─────────────────────

// UpsertItem inserts a review item, ignoring conflicts (idempotent for re-runs).
func (r *EntityReviewRepository) UpsertItem(ctx context.Context, p CreateEntityReviewItemParams) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO entity_review_items
		   (campaign_id, org_id, entity_type, entity_id, entity_name, reviewer_id)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT DO NOTHING`,
		p.CampaignID, p.OrgID, p.EntityType, p.EntityID, p.EntityName, p.ReviewerID,
	)
	return err
}

// ListClientsForOrg returns (client_id, name) for all OIDC clients in the org.
func (r *EntityReviewRepository) ListClientsForOrg(ctx context.Context, orgID uuid.UUID) ([]struct{ ID, Name string }, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT client_id, name FROM oidc_clients WHERE org_id=$1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct{ ID, Name string }
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out = append(out, struct{ ID, Name string }{id, name})
	}
	return out, rows.Err()
}

// ListGroupsForOrg returns (id, name) for all groups in the org.
func (r *EntityReviewRepository) ListGroupsForOrg(ctx context.Context, orgID uuid.UUID) ([]struct {
	ID   uuid.UUID
	Name string
}, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name FROM groups WHERE org_id=$1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		ID   uuid.UUID
		Name string
	}
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out = append(out, struct {
			ID   uuid.UUID
			Name string
		}{id, name})
	}
	return out, rows.Err()
}

// ListRolesForOrg returns (id, name) for all roles in the org.
func (r *EntityReviewRepository) ListRolesForOrg(ctx context.Context, orgID uuid.UUID) ([]struct {
	ID   uuid.UUID
	Name string
}, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name FROM roles WHERE org_id=$1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		ID   uuid.UUID
		Name string
	}
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out = append(out, struct {
			ID   uuid.UUID
			Name string
		}{id, name})
	}
	return out, rows.Err()
}

// DisableClient sets is_active=false for the given OIDC client.
func (r *EntityReviewRepository) DisableClient(ctx context.Context, orgID uuid.UUID, clientID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE oidc_clients SET is_active=FALSE, updated_at=NOW()
		 WHERE client_id=$1 AND org_id=$2`, clientID, orgID)
	return err
}

// DisableGroup sets is_active=false for the given group.
func (r *EntityReviewRepository) DisableGroup(ctx context.Context, orgID, groupID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE groups SET is_active=FALSE, updated_at=NOW()
		 WHERE id=$1 AND org_id=$2`, groupID, orgID)
	return err
}

// DisableRole sets is_active=false for the given role.
func (r *EntityReviewRepository) DisableRole(ctx context.Context, orgID, roleID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE roles SET is_active=FALSE, updated_at=NOW()
		 WHERE id=$1 AND org_id=$2`, roleID, orgID)
	return err
}


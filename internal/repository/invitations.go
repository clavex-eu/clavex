package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// Invitation represents a pending org invitation.
type Invitation struct {
	ID         uuid.UUID  `db:"id"          json:"id"`
	OrgID      uuid.UUID  `db:"org_id"      json:"org_id"`
	Email      string     `db:"email"       json:"email"`
	RoleID     *uuid.UUID `db:"role_id"     json:"role_id,omitempty"`
	InvitedBy  *uuid.UUID `db:"invited_by"  json:"invited_by,omitempty"`
	AcceptedAt *time.Time `db:"accepted_at" json:"accepted_at,omitempty"`
	ExpiresAt  time.Time  `db:"expires_at"  json:"expires_at"`
	CreatedAt  time.Time  `db:"created_at"  json:"created_at"`
}

// InvitationRepository manages org invitations.
type InvitationRepository struct {
	pool *pgxpool.Pool
}

func NewInvitationRepository(pool *pgxpool.Pool) *InvitationRepository {
	return &InvitationRepository{pool: pool}
}

// Create issues a new invitation and returns the (invitation, raw token) pair.
// The raw token is displayed/sent once — only the hash is stored.
func (r *InvitationRepository) Create(ctx context.Context, orgID uuid.UUID, email string, roleID, invitedBy *uuid.UUID) (*Invitation, string, error) {
	raw, err := generateInviteToken()
	if err != nil {
		return nil, "", err
	}
	hash := hashInviteToken(raw)
	inv := &Invitation{}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO org_invitations (org_id, email, role_id, token_hash, invited_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, org_id, email, role_id, invited_by, accepted_at, expires_at, created_at
	`, orgID, email, roleID, hash, invitedBy).Scan(
		&inv.ID, &inv.OrgID, &inv.Email, &inv.RoleID, &inv.InvitedBy,
		&inv.AcceptedAt, &inv.ExpiresAt, &inv.CreatedAt,
	)
	return inv, raw, err
}

// GetByToken looks up a pending invitation by raw token.
func (r *InvitationRepository) GetByToken(ctx context.Context, rawToken string) (*Invitation, error) {
	hash := hashInviteToken(rawToken)
	inv := &Invitation{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, email, role_id, invited_by, accepted_at, expires_at, created_at
		FROM org_invitations WHERE token_hash = $1
	`, hash).Scan(
		&inv.ID, &inv.OrgID, &inv.Email, &inv.RoleID, &inv.InvitedBy,
		&inv.AcceptedAt, &inv.ExpiresAt, &inv.CreatedAt,
	)
	return inv, err
}

// ListByOrg returns all invitations for an org.
func (r *InvitationRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*Invitation, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, email, role_id, invited_by, accepted_at, expires_at, created_at
		FROM org_invitations WHERE org_id = $1 ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Invitation
	for rows.Next() {
		inv := &Invitation{}
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.RoleID, &inv.InvitedBy,
			&inv.AcceptedAt, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// Accept marks an invitation as accepted and provisions the user in one transaction.
// Returns the provisioned User.
func (r *InvitationRepository) Accept(ctx context.Context, inv *Invitation, firstName, lastName, password *string) (*models.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `UPDATE org_invitations SET accepted_at = NOW() WHERE id = $1`, inv.ID); err != nil {
		return nil, err
	}

	u := &models.User{}
	err = tx.QueryRow(ctx, `
		INSERT INTO users (org_id, email, first_name, last_name, is_email_verified)
		VALUES ($1, $2, $3, $4, TRUE)
		ON CONFLICT (org_id, email) DO UPDATE
		  SET is_active = TRUE, updated_at = NOW()
		RETURNING id, org_id, email, first_name, last_name, avatar_url, is_active, is_email_verified,
		          mfa_required, required_actions, metadata, created_at, updated_at, last_login_at
	`, inv.OrgID, inv.Email, firstName, lastName).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.FirstName, &u.LastName, &u.AvatarURL,
		&u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions,
		&u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	if err != nil {
		return nil, err
	}

	if password != nil && *password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*password), 12)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1`, u.ID, string(hash)); err != nil {
			return nil, err
		}
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE users SET required_actions = array_append(required_actions, 'set_password')
			WHERE id = $1 AND NOT ('set_password' = ANY(required_actions))
		`, u.ID); err != nil {
			return nil, err
		}
	}

	if inv.RoleID != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING
		`, u.ID, *inv.RoleID); err != nil {
			return nil, err
		}
	}

	return u, tx.Commit(ctx)
}

// Delete revokes a pending invitation.
func (r *InvitationRepository) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM org_invitations WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("invitation not found")
	}
	return nil
}

func generateInviteToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashInviteToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

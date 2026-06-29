package repository

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ServiceAccountRepository manages org-scoped service accounts.
type ServiceAccountRepository struct{ pool *pgxpool.Pool }

func NewServiceAccountRepository(pool *pgxpool.Pool) *ServiceAccountRepository {
	return &ServiceAccountRepository{pool: pool}
}

const saCols = `id, org_id, name, description, client_id, client_secret_hash, scopes, is_active, last_used_at, created_at, updated_at`

func (r *ServiceAccountRepository) scan(row interface{ Scan(...any) error }) (*models.ServiceAccount, error) {
	sa := &models.ServiceAccount{}
	err := row.Scan(&sa.ID, &sa.OrgID, &sa.Name, &sa.Description, &sa.ClientID,
		&sa.ClientSecretHash, &sa.Scopes, &sa.IsActive, &sa.LastUsedAt, &sa.CreatedAt, &sa.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return sa, nil
}

func (r *ServiceAccountRepository) List(ctx context.Context, orgID uuid.UUID) ([]*models.ServiceAccount, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+saCols+`
		FROM service_accounts WHERE org_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.ServiceAccount
	for rows.Next() {
		sa, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sa)
	}
	return out, rows.Err()
}

func (r *ServiceAccountRepository) GetByID(ctx context.Context, orgID, id uuid.UUID) (*models.ServiceAccount, error) {
	return r.scan(r.pool.QueryRow(ctx, `SELECT `+saCols+`
		FROM service_accounts WHERE id = $1 AND org_id = $2`, id, orgID))
}

func (r *ServiceAccountRepository) GetByClientID(ctx context.Context, clientID string) (*models.ServiceAccount, error) {
	return r.scan(r.pool.QueryRow(ctx, `SELECT `+saCols+`
		FROM service_accounts WHERE client_id = $1`, clientID))
}

// GenerateSecret creates a new random client secret and returns (plaintext, bcryptHash).
func GenerateServiceAccountSecret() (plain, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate secret: %w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(raw)
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hash secret: %w", err)
	}
	return plain, string(h), nil
}

// GenerateClientID creates a unique client_id prefixed with "sa_".
func GenerateServiceAccountClientID() string {
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	return "sa_" + base64.RawURLEncoding.EncodeToString(raw)
}

type CreateServiceAccountParams struct {
	OrgID       uuid.UUID
	Name        string
	Description *string
	Scopes      []string
}

// Create inserts a new service account and returns it along with the plaintext secret.
func (r *ServiceAccountRepository) Create(ctx context.Context, p CreateServiceAccountParams) (*models.ServiceAccount, string, error) {
	clientID := GenerateServiceAccountClientID()
	plain, hash, err := GenerateServiceAccountSecret()
	if err != nil {
		return nil, "", err
	}
	if p.Scopes == nil {
		p.Scopes = []string{}
	}
	sa, err := r.scan(r.pool.QueryRow(ctx, `
		INSERT INTO service_accounts (org_id, name, description, client_id, client_secret_hash, scopes)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING `+saCols,
		p.OrgID, p.Name, p.Description, clientID, hash, p.Scopes))
	if err != nil {
		return nil, "", err
	}
	return sa, plain, nil
}

// RotateSecret generates a new secret for the service account.
func (r *ServiceAccountRepository) RotateSecret(ctx context.Context, orgID, id uuid.UUID) (*models.ServiceAccount, string, error) {
	plain, hash, err := GenerateServiceAccountSecret()
	if err != nil {
		return nil, "", err
	}
	sa, err := r.scan(r.pool.QueryRow(ctx, `
		UPDATE service_accounts SET client_secret_hash=$1, updated_at=now()
		WHERE id=$2 AND org_id=$3
		RETURNING `+saCols,
		hash, id, orgID))
	if err != nil {
		return nil, "", err
	}
	return sa, plain, nil
}

type UpdateServiceAccountParams struct {
	Name        string
	Description *string
	Scopes      []string
	IsActive    *bool
}

func (r *ServiceAccountRepository) Update(ctx context.Context, orgID, id uuid.UUID, p UpdateServiceAccountParams) (*models.ServiceAccount, error) {
	return r.scan(r.pool.QueryRow(ctx, `
		UPDATE service_accounts SET
			name=$1, description=$2, scopes=$3, is_active=COALESCE($4,is_active), updated_at=now()
		WHERE id=$5 AND org_id=$6
		RETURNING `+saCols,
		p.Name, p.Description, p.Scopes, p.IsActive, id, orgID))
}

func (r *ServiceAccountRepository) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM service_accounts WHERE id=$1 AND org_id=$2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// VerifySecret checks a plaintext secret against the stored bcrypt hash.
// Returns the service account if valid, ErrNotFound if the client_id does not exist,
// or an error if the secret is wrong.
func (r *ServiceAccountRepository) VerifySecret(ctx context.Context, clientID, secret string) (*models.ServiceAccount, error) {
	sa, err := r.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrNotFound
	}
	if !sa.IsActive {
		return nil, ErrNotFound
	}
	if err := bcrypt.CompareHashAndPassword([]byte(sa.ClientSecretHash), []byte(secret)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, err
	}
	_ = subtle.ConstantTimeCompare // ensure import is used via bcrypt
	return sa, nil
}

// TouchLastUsed updates last_used_at asynchronously (best-effort).
func (r *ServiceAccountRepository) TouchLastUsed(ctx context.Context, id uuid.UUID) {
	_, _ = r.pool.Exec(ctx, `UPDATE service_accounts SET last_used_at=now() WHERE id=$1`, id)
}

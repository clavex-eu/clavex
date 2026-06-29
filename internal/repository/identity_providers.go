package repository

import (
	"context"
	"fmt"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IDPRepository manages identity provider configurations.
type IDPRepository struct {
	pool *pgxpool.Pool
}

func NewIDPRepository(pool *pgxpool.Pool) *IDPRepository {
	return &IDPRepository{pool: pool}
}

const idpColumns = `id, org_id, name, provider_type, client_id, authorization_url, token_url,
	userinfo_url, scopes, email_claim, first_name_claim, last_name_claim, is_active,
	allow_jit, roles_claim, role_claim_mappings,
	apple_team_id, apple_key_id, apple_private_key,
	is_promoted,
	created_at, updated_at`

func scanIDP(row interface{ Scan(...any) error }) (*models.IdentityProvider, error) {
	p := &models.IdentityProvider{}
	return p, row.Scan(
		&p.ID, &p.OrgID, &p.Name, &p.ProviderType, &p.ClientID,
		&p.AuthorizationURL, &p.TokenURL, &p.UserinfoURL, &p.Scopes,
		&p.EmailClaim, &p.FirstNameClaim, &p.LastNameClaim,
		&p.IsActive, &p.AllowJIT, &p.RolesClaim, &p.RoleClaimMappings,
		&p.AppleTeamID, &p.AppleKeyID, &p.ApplePrivateKey,
		&p.IsPromoted,
		&p.CreatedAt, &p.UpdatedAt,
	)
}

func (r *IDPRepository) Create(ctx context.Context, p *models.IdentityProvider, clientSecret string) (*models.IdentityProvider, error) {
	if p.RoleClaimMappings == nil {
		p.RoleClaimMappings = map[string]string{}
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO identity_providers
			(org_id, name, provider_type, client_id, client_secret,
			 authorization_url, token_url, userinfo_url, scopes,
			 email_claim, first_name_claim, last_name_claim, is_active,
			 allow_jit, roles_claim, role_claim_mappings,
			 apple_team_id, apple_key_id, apple_private_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		RETURNING `+idpColumns,
		p.OrgID, p.Name, p.ProviderType, p.ClientID, clientSecret,
		p.AuthorizationURL, p.TokenURL, p.UserinfoURL, p.Scopes,
		p.EmailClaim, p.FirstNameClaim, p.LastNameClaim, p.IsActive,
		p.AllowJIT, p.RolesClaim, p.RoleClaimMappings,
		p.AppleTeamID, p.AppleKeyID, p.ApplePrivateKey,
	)
	created, err := scanIDP(row)
	if err != nil {
		return nil, fmt.Errorf("create idp: %w", err)
	}
	return created, nil
}

func (r *IDPRepository) List(ctx context.Context, orgID uuid.UUID) ([]*models.IdentityProvider, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+idpColumns+` FROM identity_providers WHERE org_id = $1 ORDER BY name`, orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.IdentityProvider
	for rows.Next() {
		p, err := scanIDP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []*models.IdentityProvider{}
	}
	return out, rows.Err()
}

func (r *IDPRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.IdentityProvider, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+idpColumns+` FROM identity_providers WHERE id = $1`, id)
	return scanIDP(row)
}

// GetForOrg loads an IdP only when it belongs to orgID (ErrNoRows otherwise).
// Admin handlers MUST guard on this before mutating an IdP by id.
func (r *IDPRepository) GetForOrg(ctx context.Context, id, orgID uuid.UUID) (*models.IdentityProvider, error) {
	p, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.OrgID != orgID {
		return nil, pgx.ErrNoRows
	}
	return p, nil
}

// GetClientSecret returns the stored secret for an IdP (used during OAuth2 flow).
// For Apple providers, it also returns the JWT signing credentials so the caller
// can generate a fresh ES256 client_secret JWT instead of using a static string.
func (r *IDPRepository) GetClientSecret(ctx context.Context, id uuid.UUID) (secret string, appleTeamID, appleKeyID, applePrivateKey *string, err error) {
	err = r.pool.QueryRow(ctx,
		`SELECT client_secret, apple_team_id, apple_key_id, apple_private_key FROM identity_providers WHERE id = $1`, id,
	).Scan(&secret, &appleTeamID, &appleKeyID, &applePrivateKey)
	return
}

// UpdateParams holds all fields for an identity provider update.
type UpdateIDPParams struct {
	ID                uuid.UUID
	Name              string
	ProviderType      string
	ClientID          string
	ClientSecret      string // empty = keep existing
	AuthURL           string
	TokenURL          string
	UserinfoURL       *string
	Scopes            string
	EmailClaim        string
	FirstNameClaim    string
	LastNameClaim     string
	IsActive          bool
	AllowJIT          bool
	RolesClaim        *string
	RoleClaimMappings map[string]string
	// Apple-specific JWT signing credentials (optional; only relevant when ProviderType == "apple")
	AppleTeamID     *string
	AppleKeyID      *string
	ApplePrivateKey *string // nil = keep existing key
}

func (r *IDPRepository) Update(ctx context.Context, p UpdateIDPParams) (*models.IdentityProvider, error) {
	if p.RoleClaimMappings == nil {
		p.RoleClaimMappings = map[string]string{}
	}
	var row interface{ Scan(...any) error }
	if p.ClientSecret != "" && p.ApplePrivateKey != nil {
		// Update secret AND Apple private key
		row = r.pool.QueryRow(ctx, `
			UPDATE identity_providers SET
				name=$2, provider_type=$3, client_id=$4, client_secret=$5,
				authorization_url=$6, token_url=$7, userinfo_url=$8, scopes=$9,
				email_claim=$10, first_name_claim=$11, last_name_claim=$12,
				is_active=$13, allow_jit=$14, roles_claim=$15, role_claim_mappings=$16,
				apple_team_id=$17, apple_key_id=$18, apple_private_key=$19,
				updated_at=NOW()
			WHERE id=$1 RETURNING `+idpColumns,
			p.ID, p.Name, p.ProviderType, p.ClientID, p.ClientSecret,
			p.AuthURL, p.TokenURL, p.UserinfoURL, p.Scopes,
			p.EmailClaim, p.FirstNameClaim, p.LastNameClaim, p.IsActive,
			p.AllowJIT, p.RolesClaim, p.RoleClaimMappings,
			p.AppleTeamID, p.AppleKeyID, p.ApplePrivateKey,
		)
	} else if p.ClientSecret != "" {
		row = r.pool.QueryRow(ctx, `
			UPDATE identity_providers SET
				name=$2, provider_type=$3, client_id=$4, client_secret=$5,
				authorization_url=$6, token_url=$7, userinfo_url=$8, scopes=$9,
				email_claim=$10, first_name_claim=$11, last_name_claim=$12,
				is_active=$13, allow_jit=$14, roles_claim=$15, role_claim_mappings=$16,
				apple_team_id=$17, apple_key_id=$18,
				updated_at=NOW()
			WHERE id=$1 RETURNING `+idpColumns,
			p.ID, p.Name, p.ProviderType, p.ClientID, p.ClientSecret,
			p.AuthURL, p.TokenURL, p.UserinfoURL, p.Scopes,
			p.EmailClaim, p.FirstNameClaim, p.LastNameClaim, p.IsActive,
			p.AllowJIT, p.RolesClaim, p.RoleClaimMappings,
			p.AppleTeamID, p.AppleKeyID,
		)
	} else if p.ApplePrivateKey != nil {
		row = r.pool.QueryRow(ctx, `
			UPDATE identity_providers SET
				name=$2, provider_type=$3, client_id=$4,
				authorization_url=$5, token_url=$6, userinfo_url=$7, scopes=$8,
				email_claim=$9, first_name_claim=$10, last_name_claim=$11,
				is_active=$12, allow_jit=$13, roles_claim=$14, role_claim_mappings=$15,
				apple_team_id=$16, apple_key_id=$17, apple_private_key=$18,
				updated_at=NOW()
			WHERE id=$1 RETURNING `+idpColumns,
			p.ID, p.Name, p.ProviderType, p.ClientID,
			p.AuthURL, p.TokenURL, p.UserinfoURL, p.Scopes,
			p.EmailClaim, p.FirstNameClaim, p.LastNameClaim, p.IsActive,
			p.AllowJIT, p.RolesClaim, p.RoleClaimMappings,
			p.AppleTeamID, p.AppleKeyID, p.ApplePrivateKey,
		)
	} else {
		row = r.pool.QueryRow(ctx, `
			UPDATE identity_providers SET
				name=$2, provider_type=$3, client_id=$4,
				authorization_url=$5, token_url=$6, userinfo_url=$7, scopes=$8,
				email_claim=$9, first_name_claim=$10, last_name_claim=$11,
				is_active=$12, allow_jit=$13, roles_claim=$14, role_claim_mappings=$15,
				apple_team_id=$16, apple_key_id=$17,
				updated_at=NOW()
			WHERE id=$1 RETURNING `+idpColumns,
			p.ID, p.Name, p.ProviderType, p.ClientID,
			p.AuthURL, p.TokenURL, p.UserinfoURL, p.Scopes,
			p.EmailClaim, p.FirstNameClaim, p.LastNameClaim, p.IsActive,
			p.AllowJIT, p.RolesClaim, p.RoleClaimMappings,
			p.AppleTeamID, p.AppleKeyID,
		)
	}
	updated, err := scanIDP(row)
	if err != nil {
		return nil, fmt.Errorf("update idp: %w", err)
	}
	return updated, nil
}

func (r *IDPRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM identity_providers WHERE id = $1`, id)
	return err
}

// SetPromoted marks a single IdP as promoted (or clears the flag).
// Only one promoted IdP per org is recommended; callers can enforce this by
// calling SetPromoted(false) on the previous one before setting the new one.
func (r *IDPRepository) SetPromoted(ctx context.Context, orgID, idpID uuid.UUID, promoted bool) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE identity_providers
		   SET is_promoted = $3, updated_at = NOW()
		 WHERE id = $2 AND org_id = $1
	`, orgID, idpID, promoted)
	return err
}

// ListActivePromoted returns all active IdPs for an org ordered so that promoted
// ones come first. Used by the login page renderer.
func (r *IDPRepository) ListActivePromoted(ctx context.Context, orgID uuid.UUID) ([]*models.IdentityProvider, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+idpColumns+`
		 FROM identity_providers
		 WHERE org_id = $1 AND is_active = true
		 ORDER BY is_promoted DESC, name ASC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.IdentityProvider
	for rows.Next() {
		p, err := scanIDP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []*models.IdentityProvider{}
	}
	return out, rows.Err()
}

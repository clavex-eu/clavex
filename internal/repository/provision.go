package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ProvisionParams is the input for the atomic org bootstrap endpoint.
type ProvisionParams struct {
	// Required
	Name       string
	Slug       string
	AdminEmail string
	Plan       string // stored in org metadata

	// Optional: if empty a random password is generated and returned
	TempPassword string

	// Optional SMTP — nil means skip
	SMTP *ProvisionSMTP

	// Optional first OIDC client — nil means skip
	OIDCClient *ProvisionClient
}

type ProvisionSMTP struct {
	Host        string
	Port        int
	Username    *string
	Password    string
	FromAddress string
	FromName    string
	UseTLS      bool
}

type ProvisionClient struct {
	Name         string
	RedirectURIs []string
	IsPublic     bool
}

// ProvisionResult contains every resource created during provisioning.
type ProvisionResult struct {
	Organization *models.Organization  `json:"organization"`
	AdminUser    *models.User          `json:"admin_user"`
	TempPassword string                `json:"temp_password,omitempty"` // plaintext, shown once
	RateLimits   *models.OrgRateLimits `json:"rate_limits"`
	SMTP         *models.SMTPSettings  `json:"smtp,omitempty"`
	OIDCClient   *models.OIDCClient    `json:"oidc_client,omitempty"`
	ClientSecret string                `json:"client_secret,omitempty"` // plaintext, shown once
}

// ProvisionOrg atomically creates an org with an admin user, default rate limits,
// and optionally SMTP settings and a first OIDC client. All writes run inside a
// single pgx transaction; on any error the transaction is rolled back.
func ProvisionOrg(ctx context.Context, pool *pgxpool.Pool, p ProvisionParams) (*ProvisionResult, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	result := &ProvisionResult{}

	// ── 1. Create organization ────────────────────────────────────────────────
	settings := map[string]any{"plan": p.Plan}
	org := &models.Organization{}
	err = tx.QueryRow(ctx, `
		INSERT INTO organizations (name, slug, settings)
		VALUES ($1, $2, $3)
		RETURNING id, name, slug, logo_url, settings, is_active, mfa_required, created_at, updated_at
	`, p.Name, p.Slug, settings).Scan(
		&org.ID, &org.Name, &org.Slug, &org.LogoURL, &org.Settings,
		&org.IsActive, &org.MFARequired, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create org: %w", err)
	}
	result.Organization = org

	// ── 2. Create admin user ──────────────────────────────────────────────────
	user := &models.User{}
	err = tx.QueryRow(ctx, `
		INSERT INTO users (org_id, email, is_active, is_email_verified, required_actions)
		VALUES ($1, $2, TRUE, TRUE, $3)
		RETURNING id, org_id, email, first_name, last_name, avatar_url,
		          is_active, is_email_verified, mfa_required, required_actions, metadata,
		          created_at, updated_at, last_login_at
	`, org.ID, p.AdminEmail, []string{}).Scan(
		&user.ID, &user.OrgID, &user.Email, &user.FirstName, &user.LastName,
		&user.AvatarURL, &user.IsActive, &user.IsEmailVerified, &user.MFARequired,
		&user.RequiredActions, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
		&user.LastLoginAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create admin user: %w", err)
	}
	result.AdminUser = user

	// ── 3. Set password ───────────────────────────────────────────────────────
	pwd := p.TempPassword
	if pwd == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate password: %w", err)
		}
		pwd = hex.EncodeToString(b)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), 12)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE users SET password_hash = $2 WHERE id = $1`, user.ID, string(hash),
	); err != nil {
		return nil, fmt.Errorf("set password: %w", err)
	}
	result.TempPassword = pwd

	// ── 4. Default rate limits ─────────────────────────────────────────────────
	rl := &models.OrgRateLimits{}
	err = tx.QueryRow(ctx, `
		INSERT INTO org_rate_limits (org_id, login_per_ip_per_min, token_per_client_per_min, global_per_ip_per_min)
		VALUES ($1, 10, 60, 120)
		ON CONFLICT (org_id) DO NOTHING
		RETURNING org_id, login_per_ip_per_min, token_per_client_per_min, global_per_ip_per_min, updated_at
	`, org.ID).Scan(&rl.OrgID, &rl.LoginPerIPPerMin, &rl.TokenPerClientPerMin, &rl.GlobalPerIPPerMin, &rl.UpdatedAt)
	if err != nil {
		// ON CONFLICT DO NOTHING returns no rows; that's fine
		rl = &models.OrgRateLimits{
			OrgID:                org.ID,
			LoginPerIPPerMin:     10,
			TokenPerClientPerMin: 60,
			GlobalPerIPPerMin:    120,
		}
	}
	result.RateLimits = rl

	// ── 5. Optional SMTP ─────────────────────────────────────────────────────
	if p.SMTP != nil {
		smtp := &models.SMTPSettings{}
		if p.SMTP.Password != "" {
			err = tx.QueryRow(ctx, `
				INSERT INTO org_smtp_settings
				    (org_id, host, port, username, password, from_address, from_name, use_tls, is_active)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE)
				ON CONFLICT (org_id) DO UPDATE SET
				    host=EXCLUDED.host, port=EXCLUDED.port, username=EXCLUDED.username,
				    password=EXCLUDED.password, from_address=EXCLUDED.from_address,
				    from_name=EXCLUDED.from_name, use_tls=EXCLUDED.use_tls, updated_at=NOW()
				RETURNING org_id, host, port, username, from_address, from_name, use_tls, is_active, updated_at
			`, org.ID, p.SMTP.Host, p.SMTP.Port, p.SMTP.Username, p.SMTP.Password,
				p.SMTP.FromAddress, p.SMTP.FromName, p.SMTP.UseTLS,
			).Scan(&smtp.OrgID, &smtp.Host, &smtp.Port, &smtp.Username,
				&smtp.FromAddress, &smtp.FromName, &smtp.UseTLS, &smtp.IsActive, &smtp.UpdatedAt)
		} else {
			err = tx.QueryRow(ctx, `
				INSERT INTO org_smtp_settings
				    (org_id, host, port, username, from_address, from_name, use_tls, is_active)
				VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE)
				ON CONFLICT (org_id) DO UPDATE SET
				    host=EXCLUDED.host, port=EXCLUDED.port, username=EXCLUDED.username,
				    from_address=EXCLUDED.from_address,
				    from_name=EXCLUDED.from_name, use_tls=EXCLUDED.use_tls, updated_at=NOW()
				RETURNING org_id, host, port, username, from_address, from_name, use_tls, is_active, updated_at
			`, org.ID, p.SMTP.Host, p.SMTP.Port, p.SMTP.Username,
				p.SMTP.FromAddress, p.SMTP.FromName, p.SMTP.UseTLS,
			).Scan(&smtp.OrgID, &smtp.Host, &smtp.Port, &smtp.Username,
				&smtp.FromAddress, &smtp.FromName, &smtp.UseTLS, &smtp.IsActive, &smtp.UpdatedAt)
		}
		if err != nil {
			return nil, fmt.Errorf("create smtp: %w", err)
		}
		result.SMTP = smtp
	}

	// ── 6. Optional first OIDC client ─────────────────────────────────────────
	if p.OIDCClient != nil {
		rawSecret := ""
		secretHash := (*string)(nil)
		if !p.OIDCClient.IsPublic {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return nil, fmt.Errorf("generate client secret: %w", err)
			}
			rawSecret = hex.EncodeToString(b)
			h, err := bcrypt.GenerateFromPassword([]byte(rawSecret), 12)
			if err != nil {
				return nil, fmt.Errorf("hash client secret: %w", err)
			}
			s := string(h)
			secretHash = &s
		}

		clientID := uuid.NewString()
		authMethod := "client_secret_post"
		if p.OIDCClient.IsPublic {
			authMethod = "none"
		}

		client := &models.OIDCClient{}
		err = tx.QueryRow(ctx, `
			INSERT INTO oidc_clients
			    (client_id, org_id, client_secret_hash, name, redirect_uris,
			     grant_types, response_types, scopes, token_endpoint_auth_method, is_active)
			VALUES ($1,$2,$3,$4,$5,
			        ARRAY['authorization_code','refresh_token'],
			        ARRAY['code'],
			        ARRAY['openid','profile','email'],
			        $6, TRUE)
			RETURNING client_id, org_id, name, redirect_uris, grant_types, response_types,
			          scopes, token_endpoint_auth_method, is_active, logo_url,
			          mfa_required, keycloak_compat, metadata, jwks_uri,
			          request_object_signing_alg, created_at, updated_at
		`, clientID, org.ID, secretHash, p.OIDCClient.Name,
			p.OIDCClient.RedirectURIs, authMethod,
		).Scan(
			&client.ClientID, &client.OrgID, &client.Name, &client.RedirectURIs,
			&client.GrantTypes, &client.ResponseTypes, &client.Scopes,
			&client.TokenEndpointAuthMethod, &client.IsActive, &client.LogoURL,
			&client.MFARequired, &client.KeycloakCompat, &client.Metadata,
			&client.JWKSUri, &client.RequestObjectSigningAlg,
			&client.CreatedAt, &client.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("create oidc client: %w", err)
		}
		result.OIDCClient = client
		result.ClientSecret = rawSecret
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return result, nil
}

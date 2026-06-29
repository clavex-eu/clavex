package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MdocProximityRepository persists ISO 18013-5 proximity verification sessions.
type MdocProximityRepository struct {
	pool *pgxpool.Pool
}

func NewMdocProximityRepository(pool *pgxpool.Pool) *MdocProximityRepository {
	return &MdocProximityRepository{pool: pool}
}

// Create inserts a new proximity session and returns it.
func (r *MdocProximityRepository) Create(
	ctx context.Context,
	orgID uuid.UUID,
	requestID string,
	nonce string,
	clientID string,
	responseURI string,
	requestedDocTypes []string,
	presentationDefinition map[string]interface{},
	redirectURI *string,
	expiresAt time.Time,
) (*models.MdocProximitySession, error) {
	docTypesJSON, err := json.Marshal(requestedDocTypes)
	if err != nil {
		return nil, err
	}
	defJSON, err := json.Marshal(presentationDefinition)
	if err != nil {
		return nil, err
	}

	s := &models.MdocProximitySession{}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO mdoc_proximity_sessions
		  (org_id, request_id, nonce, client_id, response_uri,
		   requested_doc_types, presentation_definition, redirect_uri, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, org_id, request_id, nonce, client_id, response_uri,
		          requested_doc_types, presentation_definition, status,
		          redirect_uri, created_at, expires_at`,
		orgID, requestID, nonce, clientID, responseURI,
		docTypesJSON, defJSON, redirectURI, expiresAt,
	).Scan(
		&s.ID, &s.OrgID, &s.RequestID, &s.Nonce, &s.ClientID, &s.ResponseURI,
		&s.RequestedDocTypes, &s.PresentationDefinition, &s.Status,
		&s.RedirectURI, &s.CreatedAt, &s.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// GetByRequestID fetches a session by its request_id (embedded in the QR URI).
func (r *MdocProximityRepository) GetByRequestID(ctx context.Context, requestID string) (*models.MdocProximitySession, error) {
	s := &models.MdocProximitySession{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, request_id, nonce, client_id, response_uri,
		       requested_doc_types, presentation_definition, status,
		       vp_claims, issuer_country, error_message, redirect_uri,
		       created_at, expires_at, completed_at
		FROM mdoc_proximity_sessions
		WHERE request_id = $1`, requestID,
	).Scan(
		&s.ID, &s.OrgID, &s.RequestID, &s.Nonce, &s.ClientID, &s.ResponseURI,
		&s.RequestedDocTypes, &s.PresentationDefinition, &s.Status,
		&s.VPClaims, &s.IssuerCountry, &s.ErrorMessage, &s.RedirectURI,
		&s.CreatedAt, &s.ExpiresAt, &s.CompletedAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// GetByID fetches a session by primary key.
func (r *MdocProximityRepository) GetByID(ctx context.Context, id uuid.UUID, orgID uuid.UUID) (*models.MdocProximitySession, error) {
	s := &models.MdocProximitySession{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, request_id, nonce, client_id, response_uri,
		       requested_doc_types, presentation_definition, status,
		       vp_claims, issuer_country, error_message, redirect_uri,
		       created_at, expires_at, completed_at
		FROM mdoc_proximity_sessions
		WHERE id = $1 AND org_id = $2`, id, orgID,
	).Scan(
		&s.ID, &s.OrgID, &s.RequestID, &s.Nonce, &s.ClientID, &s.ResponseURI,
		&s.RequestedDocTypes, &s.PresentationDefinition, &s.Status,
		&s.VPClaims, &s.IssuerCountry, &s.ErrorMessage, &s.RedirectURI,
		&s.CreatedAt, &s.ExpiresAt, &s.CompletedAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// MarkScanned updates the status to 'scanned' when the wallet fetches the request.
func (r *MdocProximityRepository) MarkScanned(ctx context.Context, requestID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE mdoc_proximity_sessions
		SET status = 'scanned'
		WHERE request_id = $1 AND status = 'pending'`, requestID)
	return err
}

// Complete updates the session with verified claims and marks it completed.
func (r *MdocProximityRepository) Complete(
	ctx context.Context,
	requestID string,
	vpClaims map[string]interface{},
	issuerCountry *string,
) error {
	claimsJSON, err := json.Marshal(vpClaims)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		UPDATE mdoc_proximity_sessions
		SET status = 'completed',
		    vp_claims = $2,
		    issuer_country = $3,
		    completed_at = NOW()
		WHERE request_id = $1 AND status IN ('pending','scanned')`,
		requestID, claimsJSON, issuerCountry,
	)
	return err
}

// Fail marks the session as failed with an error message.
func (r *MdocProximityRepository) Fail(ctx context.Context, requestID string, errMsg string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE mdoc_proximity_sessions
		SET status = 'failed', error_message = $2, completed_at = NOW()
		WHERE request_id = $1 AND status IN ('pending','scanned')`,
		requestID, errMsg,
	)
	return err
}

// ListByOrg returns recent sessions for an organisation (newest first).
func (r *MdocProximityRepository) ListByOrg(ctx context.Context, orgID uuid.UUID, limit int) ([]*models.MdocProximitySession, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, request_id, nonce, client_id, response_uri,
		       requested_doc_types, presentation_definition, status,
		       vp_claims, issuer_country, error_message, redirect_uri,
		       created_at, expires_at, completed_at
		FROM mdoc_proximity_sessions
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2`, orgID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.MdocProximitySession
	for rows.Next() {
		s := &models.MdocProximitySession{}
		if err := rows.Scan(
			&s.ID, &s.OrgID, &s.RequestID, &s.Nonce, &s.ClientID, &s.ResponseURI,
			&s.RequestedDocTypes, &s.PresentationDefinition, &s.Status,
			&s.VPClaims, &s.IssuerCountry, &s.ErrorMessage, &s.RedirectURI,
			&s.CreatedAt, &s.ExpiresAt, &s.CompletedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

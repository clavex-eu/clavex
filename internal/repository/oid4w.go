package repository

import (
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OID4WRepository handles persistence for OID4VCI and OID4VP flows.
type OID4WRepository struct {
	pool *pgxpool.Pool
}

func NewOID4WRepository(pool *pgxpool.Pool) *OID4WRepository {
	return &OID4WRepository{pool: pool}
}

// ── Credential Configs ────────────────────────────────────────────────────────

func (r *OID4WRepository) CreateCredentialConfig(
	ctx context.Context,
	orgID uuid.UUID,
	vct, displayName string,
	description *string,
	claimsMapping map[string]interface{},
	ttlSeconds int,
	category string,
	schemaFields []models.SchemaFieldDef,
) (*models.CredentialConfig, error) {
	mappingJSON, err := json.Marshal(claimsMapping)
	if err != nil {
		return nil, fmt.Errorf("marshal claims_mapping: %w", err)
	}
	if category == "" {
		category = "identity"
	}
	if schemaFields == nil {
		schemaFields = []models.SchemaFieldDef{}
	}
	schemaJSON, err := json.Marshal(schemaFields)
	if err != nil {
		return nil, fmt.Errorf("marshal schema_fields: %w", err)
	}

	cfg := &models.CredentialConfig{}
	var rawSchema []byte
	err = r.pool.QueryRow(ctx, `
		INSERT INTO credential_configs
		    (org_id, vct, display_name, description, claims_mapping, ttl_seconds, category, schema_fields)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, org_id, vct, display_name, description, claims_mapping, ttl_seconds, is_active, category, schema_fields, pre_issuance_webhook_url, require_vp, presentation_definition_vpr, deferred_issuance, source_idp_type, credential_format, selective_disclosure, chain_source_vct, chain_claims_mapping, chain_offer_ttl_mins, require_key_attestation, delegated_by, delegation_jwt, created_at, updated_at
	`, orgID, vct, displayName, description, mappingJSON, ttlSeconds, category, schemaJSON).Scan(
		&cfg.ID, &cfg.OrgID, &cfg.VCT, &cfg.DisplayName, &cfg.Description,
		&cfg.ClaimsMapping, &cfg.TTLSeconds, &cfg.IsActive, &cfg.Category, &rawSchema,
		&cfg.PreIssuanceWebhookURL,
		&cfg.RequireVP, &cfg.PresentationDefinitionVPR,
		&cfg.DeferredIssuance, &cfg.SourceIdpType, &cfg.CredentialFormat, &cfg.SelectiveDisclosure,
		&cfg.ChainSourceVCT, &cfg.ChainClaimsMapping, &cfg.ChainOfferTTLMins,
		&cfg.RequireKeyAttestation,
		&cfg.DelegatedBy, &cfg.DelegationJWT,
		&cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rawSchema, &cfg.SchemaFields)
	return cfg, nil
}

func (r *OID4WRepository) ListCredentialConfigs(ctx context.Context, orgID uuid.UUID) ([]models.CredentialConfig, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, vct, display_name, description, claims_mapping, ttl_seconds, is_active, category, schema_fields, pre_issuance_webhook_url, require_vp, presentation_definition_vpr, deferred_issuance, source_idp_type, credential_format, selective_disclosure, chain_source_vct, chain_claims_mapping, chain_offer_ttl_mins, require_key_attestation, delegated_by, delegation_jwt, created_at, updated_at
		FROM credential_configs
		WHERE org_id = $1
		ORDER BY display_name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.CredentialConfig
	for rows.Next() {
		var cfg models.CredentialConfig
		var rawSchema []byte
		if err := rows.Scan(
			&cfg.ID, &cfg.OrgID, &cfg.VCT, &cfg.DisplayName, &cfg.Description,
			&cfg.ClaimsMapping, &cfg.TTLSeconds, &cfg.IsActive, &cfg.Category, &rawSchema,
			&cfg.PreIssuanceWebhookURL,
			&cfg.RequireVP, &cfg.PresentationDefinitionVPR,
			&cfg.DeferredIssuance, &cfg.SourceIdpType, &cfg.CredentialFormat, &cfg.SelectiveDisclosure,
			&cfg.ChainSourceVCT, &cfg.ChainClaimsMapping, &cfg.ChainOfferTTLMins,
			&cfg.RequireKeyAttestation,
			&cfg.DelegatedBy, &cfg.DelegationJWT,
			&cfg.CreatedAt, &cfg.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rawSchema, &cfg.SchemaFields)
		out = append(out, cfg)
	}
	return out, rows.Err()
}

// GetCredentialConfigsBySourceIdp returns all active credential configs linked to a
// specific identity provider type (e.g. "franceconnect", "spid").
func (r *OID4WRepository) GetCredentialConfigsBySourceIdp(ctx context.Context, orgID uuid.UUID, idpType string) ([]models.CredentialConfig, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, vct, display_name, description, claims_mapping, ttl_seconds, is_active, category, schema_fields, pre_issuance_webhook_url, require_vp, presentation_definition_vpr, deferred_issuance, source_idp_type, credential_format, selective_disclosure, chain_source_vct, chain_claims_mapping, chain_offer_ttl_mins, require_key_attestation, delegated_by, delegation_jwt, created_at, updated_at
		FROM credential_configs
		WHERE org_id = $1 AND source_idp_type = $2 AND is_active = TRUE
		ORDER BY display_name
	`, orgID, idpType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.CredentialConfig
	for rows.Next() {
		var cfg models.CredentialConfig
		var rawSchema []byte
		if err := rows.Scan(
			&cfg.ID, &cfg.OrgID, &cfg.VCT, &cfg.DisplayName, &cfg.Description,
			&cfg.ClaimsMapping, &cfg.TTLSeconds, &cfg.IsActive, &cfg.Category, &rawSchema,
			&cfg.PreIssuanceWebhookURL,
			&cfg.RequireVP, &cfg.PresentationDefinitionVPR,
			&cfg.DeferredIssuance, &cfg.SourceIdpType, &cfg.CredentialFormat, &cfg.SelectiveDisclosure,
			&cfg.ChainSourceVCT, &cfg.ChainClaimsMapping, &cfg.ChainOfferTTLMins,
			&cfg.RequireKeyAttestation,
			&cfg.DelegatedBy, &cfg.DelegationJWT,
			&cfg.CreatedAt, &cfg.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rawSchema, &cfg.SchemaFields)
		out = append(out, cfg)
	}
	return out, rows.Err()
}

// GetCredentialConfigsByChainSourceVCT returns all active credential configs that
// are chained to the given source VCT. Called by OID4VPHandler.Response() after
// a successful credential presentation to auto-generate derived credential offers.
func (r *OID4WRepository) GetCredentialConfigsByChainSourceVCT(ctx context.Context, orgID uuid.UUID, sourceVCT string) ([]models.CredentialConfig, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, vct, display_name, description, claims_mapping, ttl_seconds, is_active, category, schema_fields, pre_issuance_webhook_url, require_vp, presentation_definition_vpr, deferred_issuance, source_idp_type, credential_format, selective_disclosure, chain_source_vct, chain_claims_mapping, chain_offer_ttl_mins, require_key_attestation, delegated_by, delegation_jwt, created_at, updated_at
		FROM credential_configs
		WHERE org_id = $1 AND chain_source_vct = $2 AND is_active = TRUE
		ORDER BY display_name
	`, orgID, sourceVCT)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.CredentialConfig
	for rows.Next() {
		var cfg models.CredentialConfig
		var rawSchema []byte
		if err := rows.Scan(
			&cfg.ID, &cfg.OrgID, &cfg.VCT, &cfg.DisplayName, &cfg.Description,
			&cfg.ClaimsMapping, &cfg.TTLSeconds, &cfg.IsActive, &cfg.Category, &rawSchema,
			&cfg.PreIssuanceWebhookURL,
			&cfg.RequireVP, &cfg.PresentationDefinitionVPR,
			&cfg.DeferredIssuance, &cfg.SourceIdpType, &cfg.CredentialFormat, &cfg.SelectiveDisclosure,
			&cfg.ChainSourceVCT, &cfg.ChainClaimsMapping, &cfg.ChainOfferTTLMins,
			&cfg.RequireKeyAttestation,
			&cfg.DelegatedBy, &cfg.DelegationJWT,
			&cfg.CreatedAt, &cfg.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rawSchema, &cfg.SchemaFields)
		out = append(out, cfg)
	}
	return out, rows.Err()
}

func (r *OID4WRepository) GetCredentialConfigByVCT(ctx context.Context, orgID uuid.UUID, vct string) (*models.CredentialConfig, error) {
	cfg := &models.CredentialConfig{}
	var rawSchema []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, vct, display_name, description, claims_mapping, ttl_seconds, is_active, category, schema_fields, pre_issuance_webhook_url, pre_issuance_webhook_secret, require_vp, presentation_definition_vpr, deferred_issuance, source_idp_type, credential_format, selective_disclosure, chain_source_vct, chain_claims_mapping, chain_offer_ttl_mins, require_key_attestation, delegated_by, delegation_jwt, created_at, updated_at
		FROM credential_configs
		WHERE org_id = $1 AND vct = $2 AND is_active = TRUE
	`, orgID, vct).Scan(
		&cfg.ID, &cfg.OrgID, &cfg.VCT, &cfg.DisplayName, &cfg.Description,
		&cfg.ClaimsMapping, &cfg.TTLSeconds, &cfg.IsActive, &cfg.Category, &rawSchema,
		&cfg.PreIssuanceWebhookURL, &cfg.PreIssuanceWebhookSecret,
		&cfg.RequireVP, &cfg.PresentationDefinitionVPR,
		&cfg.DeferredIssuance, &cfg.SourceIdpType, &cfg.CredentialFormat, &cfg.SelectiveDisclosure,
		&cfg.ChainSourceVCT, &cfg.ChainClaimsMapping, &cfg.ChainOfferTTLMins,
		&cfg.RequireKeyAttestation,
		&cfg.DelegatedBy, &cfg.DelegationJWT,
		&cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rawSchema, &cfg.SchemaFields)
	return cfg, nil
}

// GetCredentialConfigByVCTAnyOrg fetches an active credential config by its VCT
// across all orgs. The VCT is a globally unique HTTPS URL, so it identifies a
// single config without an org scope — used by the root-level SD-JWT VC Type
// Metadata endpoint (GET /vct/...), which carries no org in its path.
func (r *OID4WRepository) GetCredentialConfigByVCTAnyOrg(ctx context.Context, vct string) (*models.CredentialConfig, error) {
	cfg := &models.CredentialConfig{}
	var rawSchema []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, vct, display_name, description, claims_mapping, ttl_seconds, is_active, category, schema_fields, pre_issuance_webhook_url, pre_issuance_webhook_secret, require_vp, presentation_definition_vpr, deferred_issuance, source_idp_type, credential_format, selective_disclosure, chain_source_vct, chain_claims_mapping, chain_offer_ttl_mins, require_key_attestation, delegated_by, delegation_jwt, created_at, updated_at
		FROM credential_configs
		WHERE vct = $1 AND is_active = TRUE
		LIMIT 1
	`, vct).Scan(
		&cfg.ID, &cfg.OrgID, &cfg.VCT, &cfg.DisplayName, &cfg.Description,
		&cfg.ClaimsMapping, &cfg.TTLSeconds, &cfg.IsActive, &cfg.Category, &rawSchema,
		&cfg.PreIssuanceWebhookURL, &cfg.PreIssuanceWebhookSecret,
		&cfg.RequireVP, &cfg.PresentationDefinitionVPR,
		&cfg.DeferredIssuance, &cfg.SourceIdpType, &cfg.CredentialFormat, &cfg.SelectiveDisclosure,
		&cfg.ChainSourceVCT, &cfg.ChainClaimsMapping, &cfg.ChainOfferTTLMins,
		&cfg.RequireKeyAttestation,
		&cfg.DelegatedBy, &cfg.DelegationJWT,
		&cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rawSchema, &cfg.SchemaFields)
	return cfg, nil
}

// GetCredentialConfigByID fetches a credential config by its primary key.
// Unlike GetCredentialConfigByVCT this method does not filter by is_active so it
// can be used by admin operations on inactive configs too.
func (r *OID4WRepository) GetCredentialConfigByID(ctx context.Context, id, orgID uuid.UUID) (*models.CredentialConfig, error) {
	cfg := &models.CredentialConfig{}
	var rawSchema []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, vct, display_name, description, claims_mapping, ttl_seconds, is_active, category, schema_fields, pre_issuance_webhook_url, pre_issuance_webhook_secret, require_vp, presentation_definition_vpr, deferred_issuance, source_idp_type, credential_format, selective_disclosure, chain_source_vct, chain_claims_mapping, chain_offer_ttl_mins, require_key_attestation, delegated_by, delegation_jwt, created_at, updated_at
		FROM credential_configs
		WHERE id = $1 AND org_id = $2
	`, id, orgID).Scan(
		&cfg.ID, &cfg.OrgID, &cfg.VCT, &cfg.DisplayName, &cfg.Description,
		&cfg.ClaimsMapping, &cfg.TTLSeconds, &cfg.IsActive, &cfg.Category, &rawSchema,
		&cfg.PreIssuanceWebhookURL, &cfg.PreIssuanceWebhookSecret,
		&cfg.RequireVP, &cfg.PresentationDefinitionVPR,
		&cfg.DeferredIssuance, &cfg.SourceIdpType, &cfg.CredentialFormat, &cfg.SelectiveDisclosure,
		&cfg.ChainSourceVCT, &cfg.ChainClaimsMapping, &cfg.ChainOfferTTLMins,
		&cfg.RequireKeyAttestation,
		&cfg.DelegatedBy, &cfg.DelegationJWT,
		&cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rawSchema, &cfg.SchemaFields)
	return cfg, nil
}

// UpsertVPRequirement sets or clears the Verifiable Presentation requirement for a
// credential config. When requireVP is true the credential endpoint will return
// "presentation_required" unless the wallet includes a valid vp_token.
// presentationDef may be nil to use the default identity presentation definition.
func (r *OID4WRepository) UpsertVPRequirement(
	ctx context.Context,
	configID, orgID uuid.UUID,
	requireVP bool,
	presentationDef map[string]interface{},
) error {
	var pdJSON []byte
	if presentationDef != nil {
		b, err := json.Marshal(presentationDef)
		if err != nil {
			return fmt.Errorf("marshal presentation_definition_vpr: %w", err)
		}
		pdJSON = b
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_configs
		SET require_vp = $1,
		    presentation_definition_vpr = $2,
		    updated_at = NOW()
		WHERE id = $3 AND org_id = $4
	`, requireVP, pdJSON, configID, orgID)
	return err
}

// LinkOfferVPSession stores the VP session ID on the offer so the credential
// endpoint can later verify the right session is being closed.
func (r *OID4WRepository) LinkOfferVPSession(ctx context.Context, offerID uuid.UUID, sessionID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_offers SET vp_session_id = $1 WHERE id = $2
	`, sessionID, offerID)
	return err
}

// UpsertPreIssuanceWebhook sets or clears the pre-issuance webhook for a credential config.
// Pass nil url to disable the hook (also clears the secret).
func (r *OID4WRepository) UpsertPreIssuanceWebhook(ctx context.Context, configID, orgID uuid.UUID, webhookURL, secret *string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_configs
		SET pre_issuance_webhook_url    = $1,
		    pre_issuance_webhook_secret = $2,
		    updated_at                  = NOW()
		WHERE id = $3 AND org_id = $4
	`, webhookURL, secret, configID, orgID)
	return err
}

// SetClaimsMapping replaces the claims_mapping for a credential config.
// Pass nil or an empty map to clear all mappings.
func (r *OID4WRepository) SetClaimsMapping(ctx context.Context, configID, orgID uuid.UUID, mapping map[string]interface{}) error {
	raw, err := json.Marshal(mapping)
	if err != nil {
		return fmt.Errorf("marshal claims_mapping: %w", err)
	}
	_, err = r.pool.Exec(ctx, `
		UPDATE credential_configs
		SET claims_mapping = $1,
		    updated_at     = NOW()
		WHERE id = $2 AND org_id = $3
	`, raw, configID, orgID)
	return err
}

// SetSourceIdpType links or unlinks a credential config to an identity provider type.
// Pass nil to clear the link.
func (r *OID4WRepository) SetSourceIdpType(ctx context.Context, configID, orgID uuid.UUID, idpType *string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_configs
		SET source_idp_type = $1,
		    updated_at      = NOW()
		WHERE id = $2 AND org_id = $3
	`, idpType, configID, orgID)
	return err
}

func (r *OID4WRepository) SetCredentialFormat(ctx context.Context, configID, orgID uuid.UUID, format string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_configs
		SET credential_format = $1,
		    updated_at        = NOW()
		WHERE id = $2 AND org_id = $3
	`, format, configID, orgID)
	return err
}

// SetSelectiveDisclosure enables or disables per-claim selective disclosure for a
// credential config.  When enabled (default for new configs) every mapped claim
// becomes an independent SD-JWT disclosure; the holder wallet can present a single
// claim (e.g. age_over_18) without revealing the others.
// Clavex also auto-derives age_over_18 and age_in_years from birth_date when SD is on.
func (r *OID4WRepository) SetSelectiveDisclosure(ctx context.Context, configID, orgID uuid.UUID, enabled bool) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_configs
		SET selective_disclosure = $1,
		    updated_at           = NOW()
		WHERE id = $2 AND org_id = $3
	`, enabled, configID, orgID)
	return err
}

// SetRequireKeyAttestation enables or disables key_attestations_required in
// OID4VCI issuer metadata for a credential config.
// When disabled (default) standard wallets (e.g. EUDI reference wallet) can
// complete the pre-authorized code flow without a wallet key attestation.
func (r *OID4WRepository) SetRequireKeyAttestation(ctx context.Context, configID, orgID uuid.UUID, enabled bool) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_configs
		SET require_key_attestation = $1,
		    updated_at              = NOW()
		WHERE id = $2 AND org_id = $3
	`, enabled, configID, orgID)
	return err
}

// SetDelegation sets or clears the delegated issuance configuration for a
// credential config (ARF EUDIW §6.3.4).
// Pass delegatedBy="" and delegationJWT="" to clear the delegation.
func (r *OID4WRepository) SetDelegation(
	ctx context.Context,
	configID, orgID uuid.UUID,
	delegatedBy string,
	delegationJWT string,
) error {
	var dbBy, dbJWT interface{}
	if delegatedBy != "" {
		dbBy = delegatedBy
	}
	if delegationJWT != "" {
		dbJWT = delegationJWT
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_configs
		SET delegated_by    = $1,
		    delegation_jwt  = $2,
		    updated_at      = NOW()
		WHERE id = $3 AND org_id = $4
	`, dbBy, dbJWT, configID, orgID)
	return err
}

func (r *OID4WRepository) DeleteCredentialConfig(ctx context.Context, id, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		DELETE FROM credential_configs WHERE id = $1 AND org_id = $2
	`, id, orgID)
	return err
}

// ── Credential Offers ─────────────────────────────────────────────────────────

func (r *OID4WRepository) CreateCredentialOffer(
	ctx context.Context,
	orgID uuid.UUID,
	userID *uuid.UUID,
	vct, preAuthCode string,
	txCodeHash *string,
	payload map[string]interface{},
	expiresAt time.Time,
) (*models.CredentialOffer, error) {
	var payloadJSON []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		payloadJSON = b
	}
	o := &models.CredentialOffer{}
	var rawPayload []byte
	err := r.pool.QueryRow(ctx, `
		INSERT INTO credential_offers
		    (org_id, user_id, vct, pre_auth_code, tx_code_hash, payload, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, org_id, user_id, vct, pre_auth_code, tx_code_hash, access_token_hash, status, payload, expires_at, created_at
	`, orgID, userID, vct, preAuthCode, txCodeHash, payloadJSON, expiresAt).Scan(
		&o.ID, &o.OrgID, &o.UserID, &o.VCT, &o.PreAuthCode, &o.TxCodeHash,
		&o.AccessTokenHash, &o.Status, &rawPayload, &o.ExpiresAt, &o.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(rawPayload) > 0 {
		_ = json.Unmarshal(rawPayload, &o.Payload)
	}
	return o, nil
}

func (r *OID4WRepository) GetOfferByID(ctx context.Context, id uuid.UUID) (*models.CredentialOffer, error) {
	o := &models.CredentialOffer{}
	var rawPayload []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, vct, pre_auth_code, tx_code_hash, access_token_hash, status, payload, vp_session_id, expires_at, created_at
		FROM credential_offers
		WHERE id = $1
	`, id).Scan(
		&o.ID, &o.OrgID, &o.UserID, &o.VCT, &o.PreAuthCode, &o.TxCodeHash,
		&o.AccessTokenHash, &o.Status, &rawPayload, &o.VPSessionID, &o.ExpiresAt, &o.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(rawPayload) > 0 {
		_ = json.Unmarshal(rawPayload, &o.Payload)
	}
	return o, nil
}

func (r *OID4WRepository) GetOfferByPreAuthCode(ctx context.Context, code string) (*models.CredentialOffer, error) {
	o := &models.CredentialOffer{}
	var rawPayload []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, vct, pre_auth_code, tx_code_hash, access_token_hash, status, payload, vp_session_id, expires_at, created_at
		FROM credential_offers
		WHERE pre_auth_code = $1
	`, code).Scan(
		&o.ID, &o.OrgID, &o.UserID, &o.VCT, &o.PreAuthCode, &o.TxCodeHash,
		&o.AccessTokenHash, &o.Status, &rawPayload, &o.VPSessionID, &o.ExpiresAt, &o.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(rawPayload) > 0 {
		_ = json.Unmarshal(rawPayload, &o.Payload)
	}
	return o, nil
}

func (r *OID4WRepository) GetOfferByAccessToken(ctx context.Context, tokenHash string) (*models.CredentialOffer, error) {
	o := &models.CredentialOffer{}
	var rawPayload []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, vct, pre_auth_code, tx_code_hash, access_token_hash, status, payload, vp_session_id, expires_at, created_at, c_nonce, c_nonce_expires_at
		FROM credential_offers
		WHERE access_token_hash = $1
	`, tokenHash).Scan(
		&o.ID, &o.OrgID, &o.UserID, &o.VCT, &o.PreAuthCode, &o.TxCodeHash,
		&o.AccessTokenHash, &o.Status, &rawPayload, &o.VPSessionID, &o.ExpiresAt, &o.CreatedAt,
		&o.CNonce, &o.CNonceExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	if len(rawPayload) > 0 {
		_ = json.Unmarshal(rawPayload, &o.Payload)
	}
	return o, nil
}

func (r *OID4WRepository) SetOfferAccessToken(ctx context.Context, offerID uuid.UUID, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_offers SET access_token_hash = $1 WHERE id = $2
	`, tokenHash, offerID)
	return err
}

// SetCNonce stores a fresh c_nonce for the offer (OID4VCI Final §8).
// The nonce expires at nonceExpiresAt; the wallet must include it in the proof JWT.
func (r *OID4WRepository) SetCNonce(ctx context.Context, offerID uuid.UUID, cNonce string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_offers SET c_nonce = $1, c_nonce_expires_at = $2 WHERE id = $3
	`, cNonce, expiresAt, offerID)
	return err
}

// GetOfferByCNonce returns the offer whose current c_nonce matches.
// Used during Credential endpoint proof validation.
func (r *OID4WRepository) GetOfferByCNonce(ctx context.Context, cNonce string) (*models.CredentialOffer, error) {
	o := &models.CredentialOffer{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, vct, pre_auth_code, tx_code_hash, access_token_hash, status, payload, expires_at, created_at
		FROM credential_offers
		WHERE c_nonce = $1 AND c_nonce_expires_at > NOW()
	`, cNonce).Scan(
		&o.ID, &o.OrgID, &o.UserID, &o.VCT, &o.PreAuthCode, &o.TxCodeHash,
		&o.AccessTokenHash, &o.Status, &o.Payload, &o.ExpiresAt, &o.CreatedAt,
	)
	return o, err
}

func (r *OID4WRepository) MarkOfferUsed(ctx context.Context, offerID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_offers SET status = 'used' WHERE id = $1
	`, offerID)
	return err
}

// ListOffers returns the most recent offers for an org (pending + used + expired),
// ordered by created_at desc. Used by the admin Wallet UI.
func (r *OID4WRepository) ListOffers(ctx context.Context, orgID uuid.UUID, limit int) ([]models.CredentialOffer, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, user_id, vct, status, expires_at, created_at
		FROM credential_offers
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var offers []models.CredentialOffer
	for rows.Next() {
		var o models.CredentialOffer
		if err := rows.Scan(&o.ID, &o.OrgID, &o.UserID, &o.VCT, &o.Status, &o.ExpiresAt, &o.CreatedAt); err != nil {
			return nil, err
		}
		offers = append(offers, o)
	}
	return offers, rows.Err()
}

// ── Issued Credentials ────────────────────────────────────────────────────────

func (r *OID4WRepository) RecordIssuedCredential(
	ctx context.Context,
	orgID uuid.UUID,
	userID *uuid.UUID,
	vct, sdJWTHash string,
	expiresAt *time.Time,
) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO issued_credentials (org_id, user_id, vct, sd_jwt_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, orgID, userID, vct, sdJWTHash, expiresAt)
	return err
}

// ListMyCredentials returns issued credentials for a specific user within an org.
// Used by the web wallet to show the current user's credential history.
func (r *OID4WRepository) ListMyCredentials(ctx context.Context, orgID, userID uuid.UUID) ([]models.IssuedCredential, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, user_id, vct, sd_jwt_hash, issued_at, expires_at,
		       is_revoked, revoked_at, revocation_reason, status_list_id, status_index
		FROM issued_credentials
		WHERE org_id = $1 AND user_id = $2
		ORDER BY issued_at DESC
		LIMIT 100
	`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.IssuedCredential
	for rows.Next() {
		var ic models.IssuedCredential
		if err := rows.Scan(
			&ic.ID, &ic.OrgID, &ic.UserID, &ic.VCT, &ic.SDJWTHash,
			&ic.IssuedAt, &ic.ExpiresAt,
			&ic.IsRevoked, &ic.RevokedAt, &ic.RevocationReason,
			&ic.StatusListID, &ic.StatusIndex,
		); err != nil {
			return nil, err
		}
		out = append(out, ic)
	}
	return out, rows.Err()
}

func (r *OID4WRepository) ListIssuedCredentials(ctx context.Context, orgID uuid.UUID, limit int) ([]models.IssuedCredential, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, user_id, vct, sd_jwt_hash, issued_at, expires_at,
		       is_revoked, revoked_at, revocation_reason, status_list_id, status_index
		FROM issued_credentials
		WHERE org_id = $1
		ORDER BY issued_at DESC
		LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.IssuedCredential
	for rows.Next() {
		var ic models.IssuedCredential
		if err := rows.Scan(
			&ic.ID, &ic.OrgID, &ic.UserID, &ic.VCT, &ic.SDJWTHash,
			&ic.IssuedAt, &ic.ExpiresAt,
			&ic.IsRevoked, &ic.RevokedAt, &ic.RevocationReason,
			&ic.StatusListID, &ic.StatusIndex,
		); err != nil {
			return nil, err
		}
		out = append(out, ic)
	}
	return out, rows.Err()
}

// ── Presentation Sessions ─────────────────────────────────────────────────────

func (r *OID4WRepository) CreatePresentationSession(
	ctx context.Context,
	orgID uuid.UUID,
	requestID string,
	presentationDef map[string]interface{},
	dcqlQuery map[string]interface{},
	responseURI string,
	redirectURI *string,
	state *string,
	nonce string,
	expiresAt time.Time,
	// cibaAuthReqID links this session to a CIBA request for combined SCA flows.
	// Pass nil for standalone VP sessions.
	cibaAuthReqID *string,
	// clientID is the OID4VP client_id used in the authorization request
	// (e.g. "redirect_uri:<responseURI>" or "x509_san_dns:<hostname>").
	// Stored so the response handler can verify KB-JWT aud without re-deriving
	// the scheme from config.
	clientID string,
) (*models.PresentationSession, error) {
	var defJSON, dcqlJSON []byte
	var err error
	if presentationDef != nil {
		defJSON, err = json.Marshal(presentationDef)
		if err != nil {
			return nil, fmt.Errorf("marshal presentation_definition: %w", err)
		}
	}
	if dcqlQuery != nil {
		dcqlJSON, err = json.Marshal(dcqlQuery)
		if err != nil {
			return nil, fmt.Errorf("marshal dcql_query: %w", err)
		}
	}

	s := &models.PresentationSession{}
	var dcqlRaw []byte
	err = r.pool.QueryRow(ctx, `
		INSERT INTO presentation_sessions
		    (org_id, request_id, presentation_definition, dcql_query, response_uri, redirect_uri, state, nonce, expires_at, ciba_auth_req_id, client_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, org_id, request_id, presentation_definition, dcql_query, response_uri, redirect_uri, state, nonce, status, vp_claims, ciba_auth_req_id, client_id, created_at, expires_at
	`, orgID, requestID, defJSON, dcqlJSON, responseURI, redirectURI, state, nonce, expiresAt, cibaAuthReqID, clientID).Scan(
		&s.ID, &s.OrgID, &s.RequestID, &s.PresentationDefinition, &dcqlRaw,
		&s.ResponseURI, &s.RedirectURI, &s.State, &s.Nonce,
		&s.Status, &s.VPClaims, &s.CIBAAuthReqID, &s.ClientID, &s.CreatedAt, &s.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	if len(dcqlRaw) > 0 {
		_ = json.Unmarshal(dcqlRaw, &s.DCQLQuery)
	}
	return s, nil
}

func (r *OID4WRepository) GetPresentationSession(ctx context.Context, requestID string) (*models.PresentationSession, error) {
	s := &models.PresentationSession{}
	var dcqlRaw []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, request_id, presentation_definition, dcql_query, response_uri, redirect_uri, state, nonce, status, vp_claims, ciba_auth_req_id, COALESCE(client_id,''), created_at, expires_at
		FROM presentation_sessions
		WHERE request_id = $1
	`, requestID).Scan(
		&s.ID, &s.OrgID, &s.RequestID, &s.PresentationDefinition, &dcqlRaw,
		&s.ResponseURI, &s.RedirectURI, &s.State, &s.Nonce,
		&s.Status, &s.VPClaims, &s.CIBAAuthReqID, &s.ClientID, &s.CreatedAt, &s.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	if len(dcqlRaw) > 0 {
		_ = json.Unmarshal(dcqlRaw, &s.DCQLQuery)
	}
	return s, nil
}

func (r *OID4WRepository) CompletePresentationSession(ctx context.Context, requestID string, vpClaims map[string]interface{}) error {
	claimsJSON, err := json.Marshal(vpClaims)
	if err != nil {
		return fmt.Errorf("marshal vp_claims: %w", err)
	}
	_, err = r.pool.Exec(ctx, `
		UPDATE presentation_sessions
		SET status = 'verified', vp_claims = $1
		WHERE request_id = $2
	`, claimsJSON, requestID)
	return err
}

func (r *OID4WRepository) FailPresentationSession(ctx context.Context, requestID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE presentation_sessions SET status = 'failed' WHERE request_id = $1
	`, requestID)
	return err
}

// ListPresentationSessions returns the most recent OID4VP presentation sessions
// for an org, ordered newest first.  limit=0 defaults to 50.
func (r *OID4WRepository) ListPresentationSessions(ctx context.Context, orgID uuid.UUID, limit int) ([]models.PresentationSession, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, request_id, presentation_definition, dcql_query,
		       response_uri, redirect_uri, state, nonce,
		       status, vp_claims, created_at, expires_at
		FROM presentation_sessions
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.PresentationSession
	for rows.Next() {
		var s models.PresentationSession
		var defRaw, dcqlRaw, claimsRaw []byte
		if err := rows.Scan(
			&s.ID, &s.OrgID, &s.RequestID, &defRaw, &dcqlRaw,
			&s.ResponseURI, &s.RedirectURI, &s.State, &s.Nonce,
			&s.Status, &claimsRaw, &s.CreatedAt, &s.ExpiresAt,
		); err != nil {
			return nil, err
		}
		if len(defRaw) > 0 {
			_ = json.Unmarshal(defRaw, &s.PresentationDefinition)
		}
		if len(dcqlRaw) > 0 {
			_ = json.Unmarshal(dcqlRaw, &s.DCQLQuery)
		}
		if len(claimsRaw) > 0 {
			_ = json.Unmarshal(claimsRaw, &s.VPClaims)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ── GDPR Processing Records ───────────────────────────────────────────────────

func (r *OID4WRepository) ListGDPRRecords(ctx context.Context, orgID uuid.UUID) ([]models.GDPRProcessingRecord, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, activity_name, purpose, legal_basis, data_categories,
		       data_subjects, retention_period, recipients, processors, is_active, created_at, updated_at
		FROM gdpr_processing_records
		WHERE org_id = $1
		ORDER BY activity_name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.GDPRProcessingRecord
	for rows.Next() {
		var rec models.GDPRProcessingRecord
		var dataCatsJSON []byte
		var recipientsJSON, processorsJSON []byte
		if err := rows.Scan(
			&rec.ID, &rec.OrgID, &rec.ActivityName, &rec.Purpose, &rec.LegalBasis,
			&dataCatsJSON, &rec.DataSubjects, &rec.RetentionPeriod,
			&recipientsJSON, &processorsJSON,
			&rec.IsActive, &rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(dataCatsJSON, &rec.DataCategories)
		_ = json.Unmarshal(recipientsJSON, &rec.Recipients)
		_ = json.Unmarshal(processorsJSON, &rec.Processors)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (r *OID4WRepository) CreateGDPRRecord(
	ctx context.Context,
	orgID uuid.UUID,
	activityName, purpose, legalBasis string,
	dataCategories []string,
	dataSubjects, retentionPeriod string,
	recipients, processors interface{},
) (*models.GDPRProcessingRecord, error) {
	dataCatsJSON, _ := json.Marshal(dataCategories)
	recipientsJSON, _ := json.Marshal(recipients)
	processorsJSON, _ := json.Marshal(processors)

	rec := &models.GDPRProcessingRecord{}
	var dataCatsRaw, recipientsRaw, processorsRaw []byte
	err := r.pool.QueryRow(ctx, `
		INSERT INTO gdpr_processing_records
		    (org_id, activity_name, purpose, legal_basis, data_categories, data_subjects, retention_period, recipients, processors)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, org_id, activity_name, purpose, legal_basis, data_categories, data_subjects, retention_period, recipients, processors, is_active, created_at, updated_at
	`, orgID, activityName, purpose, legalBasis, dataCatsJSON, dataSubjects, retentionPeriod, recipientsJSON, processorsJSON).Scan(
		&rec.ID, &rec.OrgID, &rec.ActivityName, &rec.Purpose, &rec.LegalBasis,
		&dataCatsRaw, &rec.DataSubjects, &rec.RetentionPeriod,
		&recipientsRaw, &processorsRaw,
		&rec.IsActive, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(dataCatsRaw, &rec.DataCategories)
	_ = json.Unmarshal(recipientsRaw, &rec.Recipients)
	_ = json.Unmarshal(processorsRaw, &rec.Processors)
	return rec, nil
}

func (r *OID4WRepository) UpdateGDPRRecord(
	ctx context.Context,
	id, orgID uuid.UUID,
	activityName, purpose, legalBasis string,
	dataCategories []string,
	dataSubjects, retentionPeriod string,
	recipients, processors interface{},
) (*models.GDPRProcessingRecord, error) {
	dataCatsJSON, _ := json.Marshal(dataCategories)
	recipientsJSON, _ := json.Marshal(recipients)
	processorsJSON, _ := json.Marshal(processors)

	rec := &models.GDPRProcessingRecord{}
	var dataCatsRaw, recipientsRaw, processorsRaw []byte
	err := r.pool.QueryRow(ctx, `
		UPDATE gdpr_processing_records SET
		    activity_name = $1, purpose = $2, legal_basis = $3, data_categories = $4,
		    data_subjects = $5, retention_period = $6, recipients = $7, processors = $8,
		    updated_at = NOW()
		WHERE id = $9 AND org_id = $10
		RETURNING id, org_id, activity_name, purpose, legal_basis, data_categories, data_subjects, retention_period, recipients, processors, is_active, created_at, updated_at
	`, activityName, purpose, legalBasis, dataCatsJSON, dataSubjects, retentionPeriod, recipientsJSON, processorsJSON, id, orgID).Scan(
		&rec.ID, &rec.OrgID, &rec.ActivityName, &rec.Purpose, &rec.LegalBasis,
		&dataCatsRaw, &rec.DataSubjects, &rec.RetentionPeriod,
		&recipientsRaw, &processorsRaw,
		&rec.IsActive, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(dataCatsRaw, &rec.DataCategories)
	_ = json.Unmarshal(recipientsRaw, &rec.Recipients)
	_ = json.Unmarshal(processorsRaw, &rec.Processors)
	return rec, nil
}

func (r *OID4WRepository) DeleteGDPRRecord(ctx context.Context, id, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM gdpr_processing_records WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ── Compliance queries ────────────────────────────────────────────────────────

// OrgDataSummary aggregates counts used in GDPR and NIS2 reports.
type OrgDataSummary struct {
	TotalUsers              int64     `json:"total_users"`
	ActiveUsers             int64     `json:"active_users"`
	MFAEnabledUsers         int64     `json:"mfa_enabled_users"`
	TotalClients            int64     `json:"total_clients"`
	IssuedCredentialsTotal  int64     `json:"issued_credentials_total"`
	ProcessingRecordsActive int64     `json:"processing_records_active"`
	ReportGeneratedAt       time.Time `json:"report_generated_at"`
}

func (r *OID4WRepository) GetOrgDataSummary(ctx context.Context, orgID uuid.UUID) (*OrgDataSummary, error) {
	s := &OrgDataSummary{ReportGeneratedAt: time.Now()}
	err := r.pool.QueryRow(ctx, `
		SELECT
		    COUNT(*)                                    AS total_users,
		    COUNT(*) FILTER (WHERE is_active)           AS active_users,
		    COUNT(*) FILTER (WHERE mfa_required)        AS mfa_enabled_users
		FROM users WHERE org_id = $1
	`, orgID).Scan(&s.TotalUsers, &s.ActiveUsers, &s.MFAEnabledUsers)
	if err != nil {
		return nil, err
	}

	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM clients WHERE org_id = $1`, orgID).Scan(&s.TotalClients)
	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM issued_credentials WHERE org_id = $1`, orgID).Scan(&s.IssuedCredentialsTotal)
	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM gdpr_processing_records WHERE org_id = $1 AND is_active`, orgID).Scan(&s.ProcessingRecordsActive)

	return s, nil
}

// AuditEventSummary holds aggregated security event counts for NIS2 evidence.
type AuditEventSummary struct {
	Period        struct{ From, To time.Time } `json:"period"`
	TotalEvents   int64                        `json:"total_events"`
	ByType        map[string]int64             `json:"by_type"`
	FailedLogins  int64                        `json:"failed_logins"`
	SuccessLogins int64                        `json:"successful_logins"`
	MFAChallenges int64                        `json:"mfa_challenges"`
	AdminActions  int64                        `json:"admin_actions"`
}

func (r *OID4WRepository) GetAuditEventSummary(ctx context.Context, orgID uuid.UUID, from, to time.Time) (*AuditEventSummary, error) {
	s := &AuditEventSummary{}
	s.Period.From = from
	s.Period.To = to
	s.ByType = make(map[string]int64)

	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(event_type, action) AS ev, COUNT(*) AS cnt
		FROM audit.audit_logs
		WHERE org_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY ev
		ORDER BY cnt DESC
	`, orgID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var evType string
		var cnt int64
		if err := rows.Scan(&evType, &cnt); err != nil {
			return nil, err
		}
		s.ByType[evType] = cnt
		s.TotalEvents += cnt
		switch evType {
		case "auth.login.failure":
			s.FailedLogins = cnt
		case "auth.login.success", "user.login":
			s.SuccessLogins += cnt
		case "auth.mfa.challenge", "mfa.challenge":
			s.MFAChallenges = cnt
		}
	}
	// Count admin actions (non-auth events).
	for t, cnt := range s.ByType {
		if len(t) > 5 && t[:5] != "auth." && t[:5] != "user." {
			s.AdminActions += cnt
		}
	}

	return s, rows.Err()
}

// UserDataExport contains all personal data held for a user — used for DSAR responses.
type UserDataExport struct {
	User              interface{}   `json:"user"`
	IssuedCredentials []interface{} `json:"issued_credentials"`
	RecentAuditEvents []interface{} `json:"recent_audit_events"`
	GeneratedAt       time.Time     `json:"generated_at"`
}

func (r *OID4WRepository) GetUserDataExport(ctx context.Context, userID, orgID uuid.UUID) (*UserDataExport, error) {
	export := &UserDataExport{GeneratedAt: time.Now()}

	// Fetch user record.
	var userData map[string]interface{}
	rows, _ := r.pool.Query(ctx, `
		SELECT id, org_id, email, first_name, last_name, is_active, is_email_verified,
		       mfa_required, required_actions, metadata, created_at, updated_at, last_login_at
		FROM users WHERE id = $1 AND org_id = $2
	`, userID, orgID)
	if rows != nil {
		defer rows.Close()
		if rows.Next() {
			vals, _ := rows.Values()
			fields := []string{"id", "org_id", "email", "first_name", "last_name", "is_active",
				"is_email_verified", "mfa_required", "required_actions", "metadata",
				"created_at", "updated_at", "last_login_at"}
			userData = make(map[string]interface{}, len(fields))
			for i, f := range fields {
				if i < len(vals) {
					userData[f] = vals[i]
				}
			}
		}
	}
	export.User = userData

	// Fetch issued credentials for this user.
	credRows, err := r.pool.Query(ctx, `
		SELECT id, vct, sd_jwt_hash, issued_at, expires_at
		FROM issued_credentials WHERE user_id = $1 AND org_id = $2
		ORDER BY issued_at DESC LIMIT 100
	`, userID, orgID)
	if err == nil {
		defer credRows.Close()
		for credRows.Next() {
			vals, _ := credRows.Values()
			export.IssuedCredentials = append(export.IssuedCredentials, vals)
		}
	}

	// Fetch recent audit events for this user.
	auditRows, err := r.pool.Query(ctx, `
		SELECT COALESCE(event_type, action), created_at, metadata
		FROM audit.audit_logs
		WHERE org_id = $1 AND user_id = $2
		ORDER BY created_at DESC LIMIT 200
	`, orgID, userID)
	if err == nil {
		defer auditRows.Close()
		for auditRows.Next() {
			vals, _ := auditRows.Values()
			export.RecentAuditEvents = append(export.RecentAuditEvents, vals)
		}
	}

	return export, nil
}

// ── Credential Status Lists ───────────────────────────────────────────────────

// CredentialStatusList is the DB row for a status list.
type CredentialStatusList struct {
	ID        uuid.UUID `db:"id"         json:"id"`
	OrgID     uuid.UUID `db:"org_id"     json:"org_id"`
	ListIndex int       `db:"list_index" json:"list_index"`
	Encoded   string    `db:"encoded"    json:"encoded"` // zlib+base64url bitstring
	NextSlot  int       `db:"next_slot"  json:"next_slot"`
}

// GetOrCreateStatusList returns the active status list for an org (the one
// with the highest list_index that still has free slots).  If none exists,
// or all slots are exhausted, it creates a new empty list.
func (r *OID4WRepository) GetOrCreateStatusList(ctx context.Context, orgID uuid.UUID) (*CredentialStatusList, error) {
	sl := &CredentialStatusList{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, list_index, encoded, next_slot
		FROM credential_status_lists
		WHERE org_id = $1 AND next_slot < 65536
		ORDER BY list_index DESC
		LIMIT 1
	`, orgID).Scan(&sl.ID, &sl.OrgID, &sl.ListIndex, &sl.Encoded, &sl.NextSlot)

	if errors.Is(err, pgx.ErrNoRows) {
		// Determine next list_index for this org.
		var maxIdx *int
		_ = r.pool.QueryRow(ctx, `
			SELECT MAX(list_index) FROM credential_status_lists WHERE org_id = $1
		`, orgID).Scan(&maxIdx)

		nextIdx := 0
		if maxIdx != nil {
			nextIdx = *maxIdx + 1
		}

		// New empty status list — all bits zero.
		emptyEncoded, encErr := newEmptyEncodedList()
		if encErr != nil {
			return nil, fmt.Errorf("create status list: %w", encErr)
		}

		err2 := r.pool.QueryRow(ctx, `
			INSERT INTO credential_status_lists (org_id, list_index, encoded, next_slot)
			VALUES ($1, $2, $3, 0)
			RETURNING id, org_id, list_index, encoded, next_slot
		`, orgID, nextIdx, emptyEncoded).Scan(&sl.ID, &sl.OrgID, &sl.ListIndex, &sl.Encoded, &sl.NextSlot)
		if err2 != nil {
			return nil, fmt.Errorf("create status list row: %w", err2)
		}
		return sl, nil
	}
	return sl, err
}

// AllocateStatusIndex atomically claims the next free slot in a status list.
// Returns the index that was allocated and the updated next_slot.
func (r *OID4WRepository) AllocateStatusIndex(ctx context.Context, listID uuid.UUID) (int, error) {
	var allocated int
	err := r.pool.QueryRow(ctx, `
		UPDATE credential_status_lists
		SET next_slot = next_slot + 1, updated_at = NOW()
		WHERE id = $1 AND next_slot < 65536
		RETURNING next_slot - 1
	`, listID).Scan(&allocated)
	if err != nil {
		return 0, fmt.Errorf("allocate status index: %w", err)
	}
	return allocated, nil
}

// GetStatusList fetches a status list by ID.
func (r *OID4WRepository) GetStatusList(ctx context.Context, id uuid.UUID) (*CredentialStatusList, error) {
	sl := &CredentialStatusList{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, list_index, encoded, next_slot
		FROM credential_status_lists WHERE id = $1
	`, id).Scan(&sl.ID, &sl.OrgID, &sl.ListIndex, &sl.Encoded, &sl.NextSlot)
	return sl, err
}

// UpdateStatusListEncoded replaces the encoded bitstring (e.g. after a revocation).
func (r *OID4WRepository) UpdateStatusListEncoded(ctx context.Context, id uuid.UUID, encoded string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE credential_status_lists SET encoded = $1, updated_at = NOW() WHERE id = $2
	`, encoded, id)
	return err
}

// RevokeIssuedCredential marks a credential as revoked and flips its bit in
// the status list.  Both writes happen inside a single transaction.
func (r *OID4WRepository) RevokeIssuedCredential(ctx context.Context, credID uuid.UUID, reason string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Lock and read the credential + its status list pointer.
	var statusListID *uuid.UUID
	var statusIndex *int
	if e := tx.QueryRow(ctx, `
		SELECT status_list_id, status_index
		FROM issued_credentials WHERE id = $1 AND NOT is_revoked
		FOR UPDATE
	`, credID).Scan(&statusListID, &statusIndex); e != nil {
		return fmt.Errorf("revoke: credential not found or already revoked: %w", e)
	}

	// Mark the DB row as revoked.
	if _, e := tx.Exec(ctx, `
		UPDATE issued_credentials
		SET is_revoked = TRUE, revoked_at = NOW(), revocation_reason = $2
		WHERE id = $1
	`, credID, reason); e != nil {
		return fmt.Errorf("revoke: update credential row: %w", e)
	}

	// Flip the bit in the status list, if one was assigned.
	if statusListID != nil && statusIndex != nil {
		var encoded string
		if e := tx.QueryRow(ctx, `
			SELECT encoded FROM credential_status_lists WHERE id = $1 FOR UPDATE
		`, *statusListID).Scan(&encoded); e != nil {
			return fmt.Errorf("revoke: load status list: %w", e)
		}

		sl, decErr := decodeStatusListRaw(encoded)
		if decErr != nil {
			return fmt.Errorf("revoke: decode status list: %w", decErr)
		}
		if e := sl.Set(*statusIndex, 1 /* StatusRevoked */); e != nil {
			return fmt.Errorf("revoke: set status bit: %w", e)
		}
		newEncoded, encErr := sl.Encode()
		if encErr != nil {
			return fmt.Errorf("revoke: encode status list: %w", encErr)
		}

		if _, e := tx.Exec(ctx, `
			UPDATE credential_status_lists SET encoded = $1, updated_at = NOW() WHERE id = $2
		`, newEncoded, *statusListID); e != nil {
			return fmt.Errorf("revoke: update status list: %w", e)
		}
	}

	return tx.Commit(ctx)
}

// ── internal helpers ──────────────────────────────────────────────────────────

// statusBitList is a minimal, local bitstring helper to avoid an import cycle
// with the oid4w package (oid4w → oidc → repository).
type statusBitList struct{ bits []byte }

func newEmptyEncodedList() (string, error) {
	sl := &statusBitList{bits: make([]byte, 65536/8)}
	return encodeStatusBits(sl.bits)
}

func decodeStatusListRaw(encoded string) (*statusBitList, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("status list: base64: %w", err)
	}
	r, err := zlib.NewReader(strings.NewReader(string(compressed)))
	if err != nil {
		return nil, fmt.Errorf("status list: zlib: %w", err)
	}
	defer r.Close()
	bits, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return &statusBitList{bits: bits}, nil
}

func encodeStatusBits(bits []byte) (string, error) {
	var buf strings.Builder
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(bits); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(buf.String())), nil
}

func (sl *statusBitList) Set(index int, val byte) error {
	if index < 0 || index >= len(sl.bits)*8 {
		return fmt.Errorf("status list: index %d out of range", index)
	}
	bytePos := index / 8
	bitPos := uint(index % 8)
	if val == 1 {
		sl.bits[bytePos] |= 1 << bitPos
	} else {
		sl.bits[bytePos] &^= 1 << bitPos
	}
	return nil
}

func (sl *statusBitList) Encode() (string, error) { return encodeStatusBits(sl.bits) }

// RestoreIssuedCredential clears the revocation flag and restores the status bit to valid.
func (r *OID4WRepository) RestoreIssuedCredential(ctx context.Context, credID uuid.UUID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var statusListID *uuid.UUID
	var statusIndex *int
	if e := tx.QueryRow(ctx, `
		SELECT status_list_id, status_index
		FROM issued_credentials WHERE id = $1 AND is_revoked
		FOR UPDATE
	`, credID).Scan(&statusListID, &statusIndex); e != nil {
		return fmt.Errorf("restore: credential not found or not revoked: %w", e)
	}

	if _, e := tx.Exec(ctx, `
		UPDATE issued_credentials
		SET is_revoked = FALSE, revoked_at = NULL, revocation_reason = NULL
		WHERE id = $1
	`, credID); e != nil {
		return fmt.Errorf("restore: update credential row: %w", e)
	}

	if statusListID != nil && statusIndex != nil {
		var encoded string
		if e := tx.QueryRow(ctx, `
			SELECT encoded FROM credential_status_lists WHERE id = $1 FOR UPDATE
		`, *statusListID).Scan(&encoded); e != nil {
			return fmt.Errorf("restore: load status list: %w", e)
		}
		sl, decErr := decodeStatusListRaw(encoded)
		if decErr != nil {
			return fmt.Errorf("restore: decode: %w", decErr)
		}
		if e := sl.Set(*statusIndex, 0 /* StatusValid */); e != nil {
			return fmt.Errorf("restore: clear status bit: %w", e)
		}
		newEncoded, encErr := sl.Encode()
		if encErr != nil {
			return fmt.Errorf("restore: encode: %w", encErr)
		}
		if _, e := tx.Exec(ctx, `
			UPDATE credential_status_lists SET encoded = $1, updated_at = NOW() WHERE id = $2
		`, newEncoded, *statusListID); e != nil {
			return fmt.Errorf("restore: update status list: %w", e)
		}
	}
	return tx.Commit(ctx)
}

// statusListBuf type stub removed — we use statusBitList directly.

// ── Deferred Credentials (OID4VCI Final §11) ──────────────────────────────────

// CreateDeferredCredentialParams holds the fields for inserting a deferred_credential row.
type CreateDeferredCredentialParams struct {
	OrgID                     uuid.UUID
	TransactionID             string
	OfferID                   uuid.UUID
	CredentialConfigurationID string
	ProofKeyID                string
	ClaimsPayload             map[string]interface{}
	ExpiresAt                 time.Time
}

// CreateDeferredCredential inserts a pending deferred issuance record and returns it.
func (r *OID4WRepository) CreateDeferredCredential(ctx context.Context, p CreateDeferredCredentialParams) (*models.DeferredCredential, error) {
	dc := &models.DeferredCredential{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO deferred_credentials
			(org_id, transaction_id, offer_id, credential_configuration_id, proof_key_id, claims_payload, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, org_id, transaction_id, offer_id, credential_configuration_id,
		          proof_key_id, claims_payload, status,
		          credential_jwt, error_code, error_description,
		          created_at, expires_at, completed_at
	`, p.OrgID, p.TransactionID, p.OfferID, p.CredentialConfigurationID,
		p.ProofKeyID, p.ClaimsPayload, p.ExpiresAt,
	).Scan(
		&dc.ID, &dc.OrgID, &dc.TransactionID, &dc.OfferID, &dc.CredentialConfigurationID,
		&dc.ProofKeyID, &dc.ClaimsPayload, &dc.Status,
		&dc.CredentialJWT, &dc.ErrorCode, &dc.ErrorDescription,
		&dc.CreatedAt, &dc.ExpiresAt, &dc.CompletedAt,
	)
	return dc, err
}

// GetDeferredCredential fetches a deferred_credential by its transaction_id.
func (r *OID4WRepository) GetDeferredCredential(ctx context.Context, transactionID string) (*models.DeferredCredential, error) {
	dc := &models.DeferredCredential{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, transaction_id, offer_id, credential_configuration_id,
		       proof_key_id, claims_payload, status,
		       credential_jwt, error_code, error_description,
		       created_at, expires_at, completed_at
		FROM deferred_credentials
		WHERE transaction_id = $1
	`, transactionID).Scan(
		&dc.ID, &dc.OrgID, &dc.TransactionID, &dc.OfferID, &dc.CredentialConfigurationID,
		&dc.ProofKeyID, &dc.ClaimsPayload, &dc.Status,
		&dc.CredentialJWT, &dc.ErrorCode, &dc.ErrorDescription,
		&dc.CreatedAt, &dc.ExpiresAt, &dc.CompletedAt,
	)
	return dc, err
}

// CompleteDeferredCredential stores the issued credential JWT and marks the record completed.
func (r *OID4WRepository) CompleteDeferredCredential(ctx context.Context, transactionID, credentialJWT string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE deferred_credentials
		SET status = 'completed', credential_jwt = $2, completed_at = NOW()
		WHERE transaction_id = $1 AND status = 'pending'
	`, transactionID, credentialJWT)
	return err
}

// FailDeferredCredential marks a pending record as failed with an RFC 6750-style error.
func (r *OID4WRepository) FailDeferredCredential(ctx context.Context, transactionID, errCode, errDesc string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE deferred_credentials
		SET status = 'failed', error_code = $2, error_description = $3, completed_at = NOW()
		WHERE transaction_id = $1 AND status = 'pending'
	`, transactionID, errCode, errDesc)
	return err
}

// ListDeferredCredentials returns all deferred records for an organisation, newest first.
func (r *OID4WRepository) ListDeferredCredentials(ctx context.Context, orgID uuid.UUID) ([]*models.DeferredCredential, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, transaction_id, offer_id, credential_configuration_id,
		       proof_key_id, claims_payload, status,
		       credential_jwt, error_code, error_description,
		       created_at, expires_at, completed_at
		FROM deferred_credentials
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.DeferredCredential
	for rows.Next() {
		dc := &models.DeferredCredential{}
		if err := rows.Scan(
			&dc.ID, &dc.OrgID, &dc.TransactionID, &dc.OfferID, &dc.CredentialConfigurationID,
			&dc.ProofKeyID, &dc.ClaimsPayload, &dc.Status,
			&dc.CredentialJWT, &dc.ErrorCode, &dc.ErrorDescription,
			&dc.CreatedAt, &dc.ExpiresAt, &dc.CompletedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, dc)
	}
	return out, rows.Err()
}

// ── OID4VCI Credential Notifications (§7) ────────────────────────────────────

// RecordCredentialNotification persists a wallet notification event received at
// POST /:org_slug/oid4vci/notification (OID4VCI Final §7).
//
// issuedCredentialID may be nil when the credential cannot be correlated to a
// known issued_credentials row (e.g. the hash is not recorded, or the row was
// pruned for GDPR reasons).
func (r *OID4WRepository) RecordCredentialNotification(
	ctx context.Context,
	orgID uuid.UUID,
	notificationID, event string,
	eventDescription *string,
	issuedCredentialID *uuid.UUID,
	rawPayload []byte,
) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oid4vci_credential_notifications
		    (org_id, notification_id, event, event_description, issued_credential_id, raw_payload)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, orgID, notificationID, event, eventDescription, issuedCredentialID, rawPayload)
	return err
}

// GetIssuedCredentialByHash looks up an issued_credentials row by sd_jwt_hash.
// Returns nil, nil when no row matches (not an error).
// GetIssuedCredentialByID fetches a single issued credential by its primary key.
func (r *OID4WRepository) GetIssuedCredentialByID(ctx context.Context, credID uuid.UUID) (*models.IssuedCredential, error) {
	ic := &models.IssuedCredential{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, vct, sd_jwt_hash, issued_at, expires_at,
		       is_revoked, revoked_at, revocation_reason, status_list_id, status_index
		FROM issued_credentials
		WHERE id = $1
	`, credID).Scan(
		&ic.ID, &ic.OrgID, &ic.UserID, &ic.VCT, &ic.SDJWTHash,
		&ic.IssuedAt, &ic.ExpiresAt,
		&ic.IsRevoked, &ic.RevokedAt, &ic.RevocationReason,
		&ic.StatusListID, &ic.StatusIndex,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return ic, err
}

func (r *OID4WRepository) GetIssuedCredentialByHash(ctx context.Context, orgID uuid.UUID, sdJWTHash string) (*models.IssuedCredential, error) {
	ic := &models.IssuedCredential{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, vct, sd_jwt_hash, issued_at, expires_at,
		       is_revoked, revoked_at, revocation_reason, status_list_id, status_index
		FROM issued_credentials
		WHERE org_id = $1 AND sd_jwt_hash = $2
		LIMIT 1
	`, orgID, sdJWTHash).Scan(
		&ic.ID, &ic.OrgID, &ic.UserID, &ic.VCT, &ic.SDJWTHash,
		&ic.IssuedAt, &ic.ExpiresAt,
		&ic.IsRevoked, &ic.RevokedAt, &ic.RevocationReason,
		&ic.StatusListID, &ic.StatusIndex,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return ic, err
}

// ── Cross-installation Revocation Network ─────────────────────────────────────

// RevokeByVCTAndUser revokes all non-revoked credentials of a given VCT for the
// user identified by sub (matched against sd_jwt_hash prefix or, if unavailable,
// by user_id where the user's external_sub matches).  Used by the federated
// revocation inbound handler to apply a partner's propagated revocation locally.
func (r *OID4WRepository) RevokeByVCTAndUser(ctx context.Context, orgID uuid.UUID, vct, userSub, reason string) error {
	// Find all active credentials for this org+vct whose linked user has this sub.
	// Users are identified by their ID which is stored as a UUID; federated subs
	// may arrive as UUID strings.  Try direct UUID match first, then email sub.
	rows, err := r.pool.Query(ctx, `
		SELECT ic.id, ic.status_list_id, ic.status_index
		FROM issued_credentials ic
		JOIN users u ON u.id = ic.user_id
		WHERE ic.org_id = $1
		  AND ic.vct = $2
		  AND NOT ic.is_revoked
		  AND (u.id::text = $3 OR u.email = $3)
		LIMIT 50
	`, orgID, vct, userSub)
	if err != nil {
		return err
	}
	defer rows.Close()

	type row struct {
		credID       uuid.UUID
		statusListID *uuid.UUID
		statusIndex  *int
	}
	var targets []row
	for rows.Next() {
		var t row
		if err := rows.Scan(&t.credID, &t.statusListID, &t.statusIndex); err != nil {
			return err
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, t := range targets {
		if err := r.RevokeIssuedCredential(ctx, t.credID, reason); err != nil {
			return err
		}
	}
	return nil
}

// ListActiveFederatedInstallations returns all active federated partners for an org.
func (r *OID4WRepository) ListActiveFederatedInstallations(ctx context.Context, orgID uuid.UUID) ([]*models.FederatedInstallation, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, entity_id, display_name, jwks_uri,
		       inbound_token_hash, outbound_token, ssf_endpoint, propagate_on,
		       is_active, created_at, updated_at
		FROM federated_installations
		WHERE org_id = $1 AND is_active
		ORDER BY entity_id
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.FederatedInstallation
	for rows.Next() {
		fi := &models.FederatedInstallation{}
		if err := rows.Scan(
			&fi.ID, &fi.OrgID, &fi.EntityID, &fi.DisplayName, &fi.JWKSUri,
			&fi.InboundTokenHash, &fi.OutboundToken, &fi.SSFEndpoint, &fi.PropagateOn,
			&fi.IsActive, &fi.CreatedAt, &fi.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, fi)
	}
	return out, rows.Err()
}

// GetFederatedInstallationByTokenHash looks up a federated partner by the
// SHA-256 hex digest of its inbound bearer token.
func (r *OID4WRepository) GetFederatedInstallationByTokenHash(ctx context.Context, tokenHash string) (*models.FederatedInstallation, error) {
	fi := &models.FederatedInstallation{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, entity_id, display_name, jwks_uri,
		       inbound_token_hash, outbound_token, ssf_endpoint, propagate_on,
		       is_active, created_at, updated_at
		FROM federated_installations
		WHERE inbound_token_hash = $1 AND is_active
		LIMIT 1
	`, tokenHash).Scan(
		&fi.ID, &fi.OrgID, &fi.EntityID, &fi.DisplayName, &fi.JWKSUri,
		&fi.InboundTokenHash, &fi.OutboundToken, &fi.SSFEndpoint, &fi.PropagateOn,
		&fi.IsActive, &fi.CreatedAt, &fi.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return fi, err
}

// ── Adaptive TTL ──────────────────────────────────────────────────────────────

// RecordPresentation bumps last_presented_at and presentation_count for the
// credential identified by its status-list slot.  Called by the status-list
// endpoint so that every verifier check is a signal of active usage.
func (r *OID4WRepository) RecordPresentation(ctx context.Context, statusListID uuid.UUID, statusIndex int) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE issued_credentials
		SET last_presented_at = NOW(),
		    presentation_count = presentation_count + 1
		WHERE status_list_id = $1 AND status_index = $2 AND NOT is_revoked
	`, statusListID, statusIndex)
	return err
}

// AdaptiveRenewalCandidate is a row returned by ListCredentialsForRenewal.
type AdaptiveRenewalCandidate struct {
	CredID        uuid.UUID
	OrgID         uuid.UUID
	VCT           string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	TTLSeconds    int
	MaxTTLSeconds int
	MinTTLSeconds int
}

// ListCredentialsForRenewal returns issued credentials where:
//   - The credential config has adaptive_ttl = true
//   - The credential is not revoked
//   - renewal_threshold fraction of the TTL has elapsed (time to renew)
//   - The credential has been presented at least once OR the user logged in
//     within min_ttl_seconds (active user signal)
//   - The credential has not yet exceeded max_ttl_seconds since issuance
func (r *OID4WRepository) ListCredentialsForRenewal(ctx context.Context) ([]AdaptiveRenewalCandidate, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT ic.id, ic.org_id, ic.vct, ic.issued_at, ic.expires_at,
		       cc.ttl_seconds, cc.max_ttl_seconds, cc.min_ttl_seconds
		FROM issued_credentials ic
		JOIN credential_configs cc ON cc.org_id = ic.org_id AND cc.vct = ic.vct
		LEFT JOIN users u ON u.id = ic.user_id
		WHERE cc.adaptive_ttl
		  AND NOT ic.is_revoked
		  AND ic.expires_at IS NOT NULL
		  -- Renewal threshold: elapsed fraction >= renewal_threshold
		  AND EXTRACT(EPOCH FROM (ic.expires_at - NOW()))
		        < (1.0 - cc.renewal_threshold) * cc.ttl_seconds
		  -- Active signal: presented recently OR user logged in within min_ttl
		  AND (
		        ic.last_presented_at > NOW() - (cc.min_ttl_seconds || ' seconds')::INTERVAL
		     OR u.last_login_at > NOW() - (cc.min_ttl_seconds || ' seconds')::INTERVAL
		  )
		  -- Hard ceiling: cannot renew beyond max_ttl from original issuance
		  AND ic.issued_at + (cc.max_ttl_seconds || ' seconds')::INTERVAL > NOW() + (cc.min_ttl_seconds || ' seconds')::INTERVAL
		ORDER BY ic.expires_at ASC
		LIMIT 500
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AdaptiveRenewalCandidate
	for rows.Next() {
		var c AdaptiveRenewalCandidate
		if err := rows.Scan(&c.CredID, &c.OrgID, &c.VCT, &c.IssuedAt, &c.ExpiresAt,
			&c.TTLSeconds, &c.MaxTTLSeconds, &c.MinTTLSeconds); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RenewCredential extends ExpiresAt to now + newTTL, capped at the max_ttl
// ceiling from the original issuance date.  Updates adaptive_renewed_at for audit.
func (r *OID4WRepository) RenewCredential(ctx context.Context, credID uuid.UUID, newExpiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE issued_credentials
		SET expires_at = $2, adaptive_renewed_at = NOW()
		WHERE id = $1 AND NOT is_revoked
	`, credID, newExpiresAt)
	return err
}

// ListInactiveCredentials returns issued credentials where:
//   - The credential config has adaptive_ttl = true
//   - The credential is not revoked
//   - The credential has NEVER been presented (presentation_count = 0)
//   - The user has not logged in for >= inactivity_revoke_days
func (r *OID4WRepository) ListInactiveCredentials(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT ic.id
		FROM issued_credentials ic
		JOIN credential_configs cc ON cc.org_id = ic.org_id AND cc.vct = ic.vct
		LEFT JOIN users u ON u.id = ic.user_id
		WHERE cc.adaptive_ttl
		  AND NOT ic.is_revoked
		  AND ic.presentation_count = 0
		  AND (
		        u.last_login_at IS NULL
		     OR u.last_login_at < NOW() - (cc.inactivity_revoke_days || ' days')::INTERVAL
		  )
		ORDER BY ic.issued_at ASC
		LIMIT 500
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

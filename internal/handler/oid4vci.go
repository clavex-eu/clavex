package handler

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/clavex-eu/clavex/internal/federation"
	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/sms"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// OID4VCIHandler handles OpenID for Verifiable Credential Issuance endpoints.
//
//	Public tenant endpoints (no admin JWT):
//	  GET  /:org_slug/.well-known/openid-credential-issuer
//	  POST /:org_slug/oid4vci/token
//	  POST /:org_slug/oid4vci/credential
//
//	Admin endpoints (JWT-authenticated, org-scoped):
//	  GET    /api/v1/organizations/:org_id/oid4vci/configs
//	  POST   /api/v1/organizations/:org_id/oid4vci/configs
//	  DELETE /api/v1/organizations/:org_id/oid4vci/configs/:config_id
//	  POST   /api/v1/organizations/:org_id/oid4vci/offers
//	  POST   /api/v1/organizations/:org_id/oid4vci/offers/:offer_id/send
//	  GET    /api/v1/organizations/:org_id/oid4vci/issued
type OID4VCIHandler struct {
	oidcHandler          *OIDCHandler
	repo                 *repository.OID4WRepository
	orgs                 *repository.OrgRepository
	users                *repository.UserRepository
	keys                 oidc.Signer
	metadataSigner       oid4w.MetadataSigner
	metadataSigningErr   error
	credentialSigner     *oid4w.CertificateCredentialSigner
	credentialSigningErr error
	cfg                  baseURLProvider
	smsRepo              *repository.SMSSettingsRepository
	smtp                 *repository.SMTPRepository
	rdb                  redis.UniversalClient
	mdocIssuers          *repository.MdocIssuerRepository
	statusDispatcher     *oid4w.CredStatusDispatcher
	ssfDisp              *ssf.Dispatcher
	revnet               *federation.RevNetDispatcher
}

type baseURLProvider interface {
	BaseURL() string
}

func NewOID4VCIHandler(pool *pgxpool.Pool, keys oidc.Signer, cfg baseURLProvider) *OID4VCIHandler {
	return &OID4VCIHandler{
		repo:        repository.NewOID4WRepository(pool),
		orgs:        repository.NewOrgRepository(pool),
		users:       repository.NewUserRepository(pool),
		keys:        keys,
		cfg:         cfg,
		smsRepo:     repository.NewSMSSettingsRepository(pool),
		smtp:        repository.NewSMTPRepository(pool),
		mdocIssuers: repository.NewMdocIssuerRepository(pool),
	}
}

// WithMetadataSigningFiles enables the optional certificate-backed metadata
// signer. Invalid configured material fails closed, including JSON requests.
func (h *OID4VCIHandler) WithMetadataSigningFiles(certFile, keyFile string) *OID4VCIHandler {
	if certFile != "" || keyFile != "" {
		h.metadataSigner, h.metadataSigningErr = oid4w.LoadCertificateMetadataSigner(certFile, keyFile)
		if h.metadataSigningErr != nil {
			log.Error().Err(h.metadataSigningErr).Msg("oid4vci: configured metadata signer is unavailable")
		}
	}
	return h
}

// WithCredentialSigningFiles only changes SD-JWT credential signing. OAuth
// tokens, metadata and mdoc Document Signers retain their own independent keys.
func (h *OID4VCIHandler) WithCredentialSigningFiles(certFile, keyFile string) *OID4VCIHandler {
	if certFile != "" || keyFile != "" {
		h.credentialSigner, h.credentialSigningErr = oid4w.LoadCertificateCredentialSigner(certFile, keyFile)
		if h.credentialSigningErr != nil {
			log.Error().Err(h.credentialSigningErr).Msg("oid4vci: configured credential signer is unavailable")
		}
	}
	return h
}

// CredentialSigningPublicKey is used only to register this installation's
// dedicated credential key with its local verifier. It exposes no private data.
func (h *OID4VCIHandler) CredentialSigningPublicKey() crypto.PublicKey {
	if h.credentialSigner == nil || h.credentialSigningErr != nil {
		return nil
	}
	return h.credentialSigner.CryptoSigner().Public()
}

func (h *OID4VCIHandler) CredentialSigningKeyValidity() (time.Time, time.Time) {
	if h.credentialSigner == nil || h.credentialSigningErr != nil {
		return time.Time{}, time.Time{}
	}
	return h.credentialSigner.CertificateValidity()
}

// WithRedis sets the Redis client used for the nonce endpoint.
func (h *OID4VCIHandler) WithRedis(rdb redis.UniversalClient) *OID4VCIHandler {
	h.rdb = rdb
	return h
}

// WithStatusDispatcher attaches the credential-status SSE dispatcher.
func (h *OID4VCIHandler) WithStatusDispatcher(d *oid4w.CredStatusDispatcher) *OID4VCIHandler {
	h.statusDispatcher = d
	return h
}

// WithSSFDispatcher attaches an SSF dispatcher to fire CAEP credential-change
// events to local SSF streams on revocation.
func (h *OID4VCIHandler) WithSSFDispatcher(d *ssf.Dispatcher) *OID4VCIHandler {
	h.ssfDisp = d
	return h
}

// WithRevocationNetwork attaches the cross-installation revocation dispatcher.
// When set, revocations are propagated to federated partner installations.
func (h *OID4VCIHandler) WithRevocationNetwork(d *federation.RevNetDispatcher) *OID4VCIHandler {
	h.revnet = d
	return h
}

// ── Public tenant endpoints ───────────────────────────────────────────────────

// IssuerMetadata handles GET /:org_slug/.well-known/openid-credential-issuer
//
// OID4VCI Final §12.2: serve signed metadata as application/jwt, or plain
// application/json when explicitly requested. The Final JWT is the entire
// response; it is not embedded in a signed_metadata JSON member.
func (h *OID4VCIHandler) IssuerMetadata(c echo.Context) error {
	if h.metadataSigningErr != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "issuer metadata signing is misconfigured")
	}
	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}

	configs, err := h.repo.ListCredentialConfigs(c.Request().Context(), org.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	conformanceMode := org.ConformanceMode || c.QueryParam("conformance") == "1"
	meta := oid4w.BuildIssuerMetadata(h.cfg.BaseURL(), org.Slug, configs, conformanceMode)
	if h.credentialSigningErr != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "credential signing is misconfigured")
	}
	if h.credentialSigner != nil {
		if _, _, err := h.credentialSigner.MetadataCertificateChain(meta.CredentialIssuer); err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "credential signing certificate is unavailable or invalid for this issuer")
		}
		for _, credential := range meta.CredentialConfigurationsSupported {
			if credential.Format == "dc+sd-jwt" {
				credential.CredentialSigningAlgValuesSupported = []string{string(h.credentialSigner.Algorithm())}
			}
		}
	}

	_, attesterKeys, trustErr := credentialAttesterKeys(org)
	if trustErr != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "credential attestation trust is misconfigured")
	}
	for _, credential := range meta.CredentialConfigurationsSupported {
		for _, proofType := range credential.ProofTypesSupported {
			if proofType.KeyAttestationsRequired != nil {
				if len(attesterKeys) == 0 {
					return echo.NewHTTPError(http.StatusServiceUnavailable, "credential attestation trust is not configured")
				}
				proofType.KeyAttestationsRequired.KeyAttestationJWKS.Keys = attesterKeys
			}
		}
	}
	if h.keys != nil {
		if rawJWK, jwkErr := jwk.FromRaw(h.keys.CryptoSigner().Public()); jwkErr == nil {
			_ = rawJWK.Set(jwk.KeyIDKey, h.keys.KID())
			// Populate credential_request_encryption.jwks with the issuer's public key.
			// VCICheckCredentialRequestEncryptionSupported requires the key to have an
			// explicit alg field naming an asymmetric JWE key-encryption algorithm
			// (getAlgorithm() == null → check returns false regardless of key type).
			// We use a separate JWK copy so setting alg here doesn't bleed into the
			// key_attestation_jwks entry where alg is irrelevant.
			if meta.CredentialRequestEncryption != nil && meta.CredentialRequestEncryption.JWKS != nil {
				if encJWK, encErr := jwk.FromRaw(h.keys.CryptoSigner().Public()); encErr == nil {
					_ = encJWK.Set(jwk.KeyIDKey, h.keys.KID())
					// Pick a JWE key-encryption alg compatible with the key type.
					switch h.keys.Algorithm() {
					case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
						_ = encJWK.Set(jwk.AlgorithmKey, jwa.RSA_OAEP_256)
					default:
						_ = encJWK.Set(jwk.AlgorithmKey, jwa.ECDH_ES)
					}
					meta.CredentialRequestEncryption.JWKS.Keys = []interface{}{encJWK}
				}
			}
		}
	}

	// Preserve the existing content-negotiation profile. Requiring wallets ask
	// for application/jwt; unsigned JSON remains available to other clients.
	accept := c.Request().Header.Get("Accept")
	prefersPlainJSON := strings.Contains(accept, "application/json") &&
		!strings.Contains(accept, "application/jwt")
	signer := h.metadataSigner
	if signer == nil {
		signer = h.keys
	}
	// Validate the configured certificate even when returning the JSON view.
	if certified, ok := signer.(*oid4w.CertificateMetadataSigner); ok {
		if _, _, err := certified.MetadataCertificateChain(meta.CredentialIssuer); err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "issuer metadata certificate is unavailable or invalid for this issuer")
		}
	}
	c.Response().Header().Add("Vary", "Accept")
	if signer != nil && !prefersPlainJSON {
		signed, signErr := oid4w.SignIssuerMetadata(meta, signer)
		if signErr == nil {
			c.Response().Header().Set("Content-Type", "application/jwt")
			return c.String(http.StatusOK, signed)
		}
		return echo.NewHTTPError(http.StatusServiceUnavailable, "issuer metadata signing failed")
	}

	return c.JSON(http.StatusOK, meta)
}

// CredentialIssuerCA serves the self-signed CA certificate whose key is
// deterministically derived from secret issuer RSA signing material. Verifiers and
// conformance suites configure this certificate as the "Credential Trust Anchor"
// (HAIP-6.1 / EnsureCredentialTrustAnchorConfigured). The CA's public key is
// stable for the lifetime of the issuer RSA key; only the signature bytes on
// the CA cert itself may vary across server restarts (ECDSA randomness), but
// the public key — which is what verifiers actually use — is always the same.
func (h *OID4VCIHandler) CredentialIssuerCA(c echo.Context) error {
	if h.credentialSigningErr != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "credential signing is misconfigured")
	}
	if h.credentialSigner != nil {
		if _, _, err := h.credentialSigner.MetadataCertificateChain(h.cfg.BaseURL() + "/" + c.Param("org_slug")); err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "credential signing certificate is unavailable")
		}
		return c.Blob(http.StatusOK, "application/x-pem-file", h.credentialSigner.RootCertificatePEM())
	}
	if h.keys == nil {
		return echo.NewHTTPError(http.StatusNotFound, "no signing key configured")
	}
	priv := h.keys.PrivateKey()
	if priv == nil {
		return echo.NewHTTPError(http.StatusNotFound, "key backend does not expose private key material")
	}
	pemBytes, err := oid4w.BuildIssuerCACertPEM(priv)
	if err != nil {
		return echo.ErrInternalServerError
	}
	c.Response().Header().Set("Cache-Control", "public, max-age=86400")
	return c.Blob(http.StatusOK, "application/x-pem-file", pemBytes)
}

// VCTTypeMetadata serves the SD-JWT VC Type Metadata document for a credential
// type at its `vct` URL (draft-ietf-oauth-sd-jwt-vc §6). The route is root-level
// and carries no org slug — the VCT (a globally unique HTTPS URL) identifies the
// credential config. The OIDF conformance suite fetches this
// (VCIFetchSdJwtVcTypeMetadata) to resolve the issued credential's type.
//
// The VCT is reconstructed from the issuer base URL and the request path, so it
// matches exactly the `vct` value stored on the config and published in the
// issuer metadata.
func (h *OID4VCIHandler) VCTTypeMetadata(c echo.Context) error {
	vct := strings.TrimRight(h.cfg.BaseURL(), "/") + c.Request().URL.Path
	cfg, err := h.repo.GetCredentialConfigByVCTAnyOrg(c.Request().Context(), vct)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "unknown credential type")
		}
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, oid4w.BuildTypeMetadata(*cfg))
}

const vciNonceRedisPrefix = "vci_nonce:"
const vciNonceTTL = 5 * time.Minute

// Nonce handles POST /:org_slug/oid4vci/nonce — OID4VCI Final Section 7.
//
// The endpoint issues a fresh c_nonce that the wallet MUST include in the
// key proof JWT sent to the credential endpoint. It requires no authentication
// but is scoped to the org slug so that nonces can only be used at the
// corresponding credential endpoint.
//
// OID4VCI 1.0 Final nonce response: {"c_nonce": "<value>"}.
// Nonce expiry is enforced by the server-side store.
func (h *OID4VCIHandler) Nonce(c echo.Context) error {
	if _, err := h.resolveOrg(c); err != nil {
		return err
	}
	orgSlug := c.Param("org_slug")

	nonce, err := h.issueCredentialNonce(c.Request().Context(), orgSlug)
	if err != nil {
		return writeCredentialProofError(c, err)
	}

	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, map[string]any{"c_nonce": nonce})
}

// Token handles POST /:org_slug/oid4vci/token
// Accepts pre-authorized_code grant type and returns an OID4VCI access token.
func (h *OID4VCIHandler) Token(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}
	grantType := c.FormValue("grant_type")
	const preAuthGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	if grantType == "authorization_code" {
		return h.authorizationCodeWalletGrant(c, org)
	}
	if grantType == "refresh_token" {
		return h.refreshWalletGrant(c, org)
	}
	if grantType != preAuthGrant {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": "only pre-authorized_code is supported",
		})
	}

	preAuthCode := c.FormValue("pre-authorized_code")
	if preAuthCode == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "pre-authorized_code is required",
		})
	}

	ctx := c.Request().Context()
	offer, err := h.repo.GetOfferByPreAuthCode(ctx, preAuthCode)
	if err != nil || offer.OrgID != org.ID {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "pre-authorized_code not found or expired",
		})
	}

	if offer.Status != "pending" || offer.AccessTokenHash != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "pre-authorized_code already used",
		})
	}

	if time.Now().After(offer.ExpiresAt) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "pre-authorized_code expired",
		})
	}

	// Check optional tx_code (user PIN).
	if offer.TxCodeHash != nil {
		txCode := c.FormValue("tx_code")
		if txCode == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_grant",
				"error_description": "tx_code required for this offer",
			})
		}
		// Brute-force protection (OID4VCI §6.1): the tx_code is a short PIN, so cap
		// wrong attempts and invalidate the offer once the cap is reached.
		const maxTxCodeAttempts = 5
		txKey := "vci:txcode:" + offer.ID.String()
		if hashTxCode(txCode) != *offer.TxCodeHash {
			if h.rdb != nil {
				attempts, _ := h.rdb.Incr(ctx, txKey).Result()
				if attempts == 1 {
					_ = h.rdb.Expire(ctx, txKey, time.Until(offer.ExpiresAt)).Err()
				}
				if attempts >= maxTxCodeAttempts {
					if err := h.repo.MarkOfferUsed(ctx, offer.ID); err != nil {
						return echo.ErrInternalServerError
					} // burn the offer
					_ = h.rdb.Del(ctx, txKey).Err()
				}
			}
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_grant",
				"error_description": "invalid tx_code",
			})
		}
		if h.rdb != nil {
			_ = h.rdb.Del(ctx, txKey).Err() // reset on success
		}
	}

	// Token-response nonce is retained for legacy clients, but uses the same
	// issuer-scoped challenge store as the Final Nonce Endpoint.
	cNonce, err := h.issueCredentialNonce(ctx, org.Slug)
	if err != nil {
		return writeCredentialProofError(c, err)
	}
	return h.startWalletGrant(c, org, offer, cNonce)
}

// credentialRequest is the body for POST /:org_slug/oid4vci/credential (OID4VCI Final §8).
type credentialRequest struct {
	// CredentialConfigurationID selects the credential type (replaces Draft-13 "format"+type).
	CredentialConfigurationID string `json:"credential_configuration_id"`
	CredentialIdentifier      string `json:"credential_identifier,omitempty"`
	// Proof is the legacy singular holder proof, retained for compatibility.
	Proof *credentialProof `json:"proof,omitempty"`
	// Proofs is the OID4VCI Final §8 multi-proof object: {"jwt": ["<jwt1>", …]}.
	// Either Proof or Proofs may be present; both forms are accepted.
	Proofs *credentialProofs `json:"proofs,omitempty"`
	// VPToken is the Verifiable Presentation token submitted by the wallet when the
	// issuer previously responded with "presentation_required". Format: SD-JWT.
	VPToken *string `json:"vp_token,omitempty"`
	// PresentationSubmission maps InputDescriptors to the submitted VPToken.
	PresentationSubmission *oid4w.PresentationSubmission `json:"presentation_submission,omitempty"`
	// VPRequestSession is the session ID returned with the "presentation_required"
	// error. The wallet must echo it back in the retry request.
	VPRequestSession *string `json:"vp_request_session,omitempty"`
	// CredentialResponseEncryption, when present, requests that the credential
	// response be returned as a JWE (OID4VCI Final §8.3).
	CredentialResponseEncryption *credentialResponseEncryptionReq `json:"credential_response_encryption,omitempty"`
}

// credentialResponseEncryptionReq is the wallet's JWE encryption parameters
// sent in the credential request body (OID4VCI Final §8.3).
type credentialResponseEncryptionReq struct {
	// JWK is the wallet's public key for key agreement (EC or RSA).
	JWK json.RawMessage `json:"jwk"`
	// Alg is the JWE key-agreement algorithm, e.g. "ECDH-ES".
	Alg string `json:"alg"`
	// Enc is the JWE content-encryption algorithm, e.g. "A256GCM".
	Enc string `json:"enc"`
}

// credentialProof is the legacy singular proof object.
type credentialProof struct {
	ProofType string `json:"proof_type"` // must be "jwt"
	JWT       string `json:"jwt"`
}

// credentialProofs is the OID4VCI Final §8 plural proofs object.
type credentialProofs struct {
	JWT []string `json:"jwt"`
}

// Credential handles POST /:org_slug/oid4vci/credential
// Requires a Bearer token obtained via the Token endpoint, then issues an SD-JWT-VC.
// Implements OID4VCI Final §8.
func (h *OID4VCIHandler) Credential(c echo.Context) error {
	rawToken := extractBearerToken(c)
	if rawToken == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid_token",
		})
	}

	ctx := c.Request().Context()
	tokenHash := hashToken(rawToken)
	offer, err := h.repo.GetOfferByAccessToken(ctx, tokenHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return echo.ErrServiceUnavailable
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// A known wallet token cannot fall through to ordinary JWT authorization
		// after its family was revoked/closed or its database lifetime elapsed.
		_, _, _, registeredErr := h.repo.WalletGrantForToken(ctx, tokenHash, "access")
		if registeredErr == nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		}
		if !errors.Is(registeredErr, pgx.ErrNoRows) {
			return echo.ErrServiceUnavailable
		}
	}
	if err != nil {
		// Pre-auth offer not found — try JWT access token (authorization_code /
		// wallet-initiated OID4VCI flow via the OIDC token endpoint).
		return h.credentialFromAuthCode(c, ctx, rawToken)
	}

	if err := h.validateWalletResource(c, rawToken); err != nil {
		return err
	}

	if offer.Status == "used" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "credential already issued for this offer",
		})
	}

	if time.Now().After(offer.ExpiresAt) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "offer expired",
		})
	}

	// ── Parse and validate credential request (OID4VCI Final §8) ──────────────
	var req credentialRequest
	if c.Request().ContentLength != 0 {
		if err := h.bindCredentialRequest(c, &req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "invalid request body",
			})
		}
	}

	if req.CredentialIdentifier != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unknown_credential_identifier"})
	}
	if !offerConfigurationMatches(req.CredentialConfigurationID, offer.VCT) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unknown_credential_configuration"})
	}
	// Resolve org and user.
	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}
	if offer.OrgID != org.ID {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}

	cfg, err := h.repo.GetCredentialConfigByVCT(ctx, org.ID, offer.VCT)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "unknown_credential_configuration",
			"error_description": "credential type not configured for this organisation",
		})
	}

	proofs, proofErr := validateCredentialProofs(&req, fmt.Sprintf("%s/%s", h.cfg.BaseURL(), org.Slug), cfg.CredentialFormat, time.Now())
	if proofErr != nil {
		return writeCredentialProofError(c, proofErr)
	}
	if err := validateCredentialAttestations(org, cfg, &req, proofs, time.Now(), ctx); err != nil {
		return writeCredentialProofError(c, err)
	}
	if cfg.DeferredIssuance && len(proofs) != 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_credential_request", "error_description": "deferred issuance currently supports one holder proof"})
	}

	var user *models.User
	if offer.UserID != nil {
		user, err = h.users.GetForOrg(ctx, *offer.UserID, offer.OrgID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !user.IsActive) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_request_denied", "error_description": "subject is not eligible in this organisation"})
		}
		if err != nil {
			return echo.ErrInternalServerError
		}
	} else {
		// No user bound to offer — issue a minimal org-level credential.
		user = &models.User{ID: uuid.Nil, OrgID: org.ID}
	}

	// ── Verifiable Presentation Request (VPR) check ──────────────────────────
	// If this credential type requires a VP and the wallet didn't include one,
	// create a presentation session and ask the wallet to present first.
	var completedVPR string
	var completedVPRResult *oid4w.VerificationResult
	if cfg.RequireVP {
		if req.VPToken == nil {
			// No VP supplied — issue a VPR and wait for the wallet to retry.
			requestID, _ := generateRequestID()
			vprNonce, _ := generateNonce()
			responseURI := fmt.Sprintf("%s/%s/oid4vci/credential", h.cfg.BaseURL(), org.Slug)
			pdMap := cfg.PresentationDefinitionVPR
			if pdMap == nil {
				// Default: require any SD-JWT-VC with a sub claim.
				pdMap = defaultIdentityPD(cfg.VCT)
			}
			session, err := h.repo.CreatePresentationSession(
				ctx, org.ID, requestID, pdMap, nil, responseURI, nil, nil, vprNonce,
				time.Now().Add(10*time.Minute),
				nil, // cibaAuthReqID — not a CIBA-linked session
				"redirect_uri:"+responseURI,
			)
			if err != nil {
				return echo.ErrInternalServerError
			}
			_ = h.repo.LinkOfferVPSession(ctx, offer.ID, session.RequestID)
			return c.JSON(http.StatusBadRequest, map[string]any{
				"error":                   "presentation_required",
				"error_description":       "A verifiable presentation is required to issue this credential",
				"presentation_definition": pdMap,
				"vp_request_nonce":        vprNonce,
				"vp_request_session":      session.RequestID,
			})
		}

		// VP supplied — verify it against the stored session.
		if req.VPRequestSession == nil || *req.VPRequestSession == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "vp_request_session is required when vp_token is provided",
			})
		}
		session, err := h.repo.GetPresentationSession(ctx, *req.VPRequestSession)
		if err != nil || session == nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "vp_request_session not found or expired",
			})
		}
		if session.Status != "pending" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "vp_request_session already consumed",
			})
		}
		if time.Now().After(session.ExpiresAt) {
			_ = h.repo.FailPresentationSession(ctx, session.RequestID)
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "vp_request_session expired",
			})
		}
		// Verify that this session was created for THIS offer.
		if offer.VPSessionID == nil || *offer.VPSessionID != session.RequestID {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "vp_request_session does not match this credential offer",
			})
		}
		pd := unmarshalPresentationDef(session.PresentationDefinition)
		// KB-JWT aud = the credential endpoint (response_uri) the wallet targeted.
		vprAud := fmt.Sprintf("%s/%s/oid4vci/credential", h.cfg.BaseURL(), org.Slug)
		vpResult, vpErr := oid4w.VerifyPresentation(*req.VPToken, pd, session.Nonce, vprAud, nil, h.keys.PublicKey())
		if vpErr != nil {
			_ = h.repo.FailPresentationSession(ctx, session.RequestID)
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_presentation",
				"error_description": vpErr.Error(),
			})
		}
		completedVPR = session.RequestID
		completedVPRResult = vpResult
	}

	h, tx, txErr := h.beginCredentialIssuance(ctx, offer, tokenHash)
	if txErr != nil {
		return writeIssuanceError(c, txErr)
	}
	defer tx.Rollback(ctx)
	if completedVPR != "" {
		if err := checkWalletStatus(ctx, h.repo, org.ID, h.cfg.BaseURL()+"/"+org.Slug, org.Settings, completedVPRResult, true); err != nil {
			return walletStatusError(c, err)
		}
		if err := h.repo.CompletePresentationSession(ctx, completedVPR, nil); err != nil {
			return echo.ErrInternalServerError
		}
	}

	if err := h.attachWalletGrantParents(ctx, org, offer, proofs); err != nil {
		return writeCredentialProofError(c, err)
	}
	if err := h.consumeCredentialProofs(ctx, org.Slug, proofs); err != nil {
		return writeCredentialProofError(c, err)
	}

	// ── Deferred issuance (OID4VCI Final §11) ────────────────────────────────
	// When the credential config has deferred_issuance=true the wallet receives
	// a transaction_id instead of the credential. An admin approves later via
	// POST /oid4vci/deferred/:txn_id/approve.
	if cfg.DeferredIssuance {
		grant, grantErr := h.repo.LockWalletGrant(ctx, offer.ID, org.ID)
		if grantErr != nil {
			return writeIssuanceError(c, grantErr)
		}
		deadline := time.Now().Add(walletGrantLifetime)
		if grant != nil {
			if !grant.DeferredAllowed {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_request_denied"})
			}
			deadline = grant.ExpiresAt
		}
		txnID, _ := generateTransactionID()
		holderJWK, keyErr := marshalCredentialHolderKey(proofs[0].Key)
		if keyErr != nil {
			return writeCredentialProofError(c, keyErr)
		}
		_, crErr := h.repo.CreateDeferredCredential(ctx, repository.CreateDeferredCredentialParams{
			OrgID:                     org.ID,
			TransactionID:             txnID,
			OfferID:                   offer.ID,
			CredentialConfigurationID: offer.VCT,
			HolderJWK:                 holderJWK,
			StatusParents:             marshalStatusParents(proofs[0].StatusParents),
			ClaimsPayload:             offer.Payload,
			ExpiresAt:                 deadline,
		})
		if crErr != nil {
			return echo.ErrInternalServerError
		}
		if err := h.repo.MarkOfferUsed(ctx, offer.ID); err != nil {
			return echo.ErrInternalServerError
		}
		// OID4VCI Final §8.3: deferred response uses top-level transaction_id.
		// c_nonce is no longer returned in the credential response per Final spec;
		// wallets obtain a fresh nonce via POST /:org_slug/oid4vci/nonce.
		return finishCredentialResponseStatus(c, tx, map[string]any{"transaction_id": txnID, "interval": deferredPollInterval}, req.CredentialResponseEncryption, http.StatusAccepted)
	}

	// Each returned credential is bound to the key whose possession was verified.
	credentials := make([]map[string]any, 0, len(proofs))
	for _, proof := range proofs {
		sdJWT, denyReason, err := h.runWebhookAndSign(ctx, org, cfg, user, offer.UserID, offer.Payload, proof.Key)
		if denyReason != "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_denied", "error_description": denyReason})
		}
		if err != nil {
			return echo.ErrInternalServerError
		}
		if err := h.recordWalletCredential(ctx, org.ID, offer.UserID, offer.VCT, sdJWT, cfg.CredentialFormat, proof.StatusParents); err != nil {
			return echo.ErrInternalServerError
		}
		credObj := map[string]any{"credential": sdJWT}
		if cfg.CredentialFormat == "mso_mdoc" {
			credObj["format"] = "mso_mdoc"
		}
		credentials = append(credentials, credObj)
	}
	if err := h.repo.MarkOfferUsed(ctx, offer.ID); err != nil {
		return echo.ErrInternalServerError
	}
	// c_nonce is no longer part of the success response in Final; wallets use
	// POST /nonce to obtain a fresh nonce before subsequent credential requests.
	responseBody := map[string]any{
		"credentials": credentials,
	}
	return finishCredentialResponse(c, tx, responseBody, req.CredentialResponseEncryption)
}

// batchCredentialRequest is the body for POST /:org_slug/oid4vci/batch-credential (OID4VCI Final §8).
type batchCredentialRequest struct {
	CredentialRequests []credentialRequest `json:"credential_requests"`
}

// batchCredentialItem is one entry in the credential_responses array.
type batchCredentialItem struct {
	Credential    *string `json:"credential,omitempty"`
	TransactionID *string `json:"transaction_id,omitempty"`
	Error         *string `json:"error,omitempty"`
	ErrorDesc     *string `json:"error_description,omitempty"`
}

// BatchCredential handles POST /:org_slug/oid4vci/batch-credential (OID4VCI Final §8.3.1).
// Accepts an array of credential_requests and responds with an array of results in one call.
func (h *OID4VCIHandler) BatchCredential(c echo.Context) error {
	rawToken := extractBearerToken(c)
	if rawToken == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}

	ctx := c.Request().Context()
	tokenHash := hashToken(rawToken)
	offer, err := h.repo.GetOfferByAccessToken(ctx, tokenHash)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}
	if err := h.validateWalletResource(c, rawToken); err != nil {
		return err
	}

	if offer.Status == "used" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "error_description": "credential already issued for this offer",
		})
	}
	if time.Now().After(offer.ExpiresAt) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "error_description": "offer expired",
		})
	}

	var req batchCredentialRequest
	if err := c.Bind(&req); err != nil || len(req.CredentialRequests) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "error_description": "credential_requests array is required",
		})
	}
	if len(req.CredentialRequests) > 100 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "error_description": "too many credential_requests (max 100)",
		})
	}

	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}
	cfg, err := h.repo.GetCredentialConfigByVCT(ctx, org.ID, offer.VCT)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "unknown_credential_configuration", "error_description": "credential type not configured",
		})
	}

	if cfg.DeferredIssuance {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_credential_request", "error_description": "use the credential endpoint for deferred issuance"})
	}

	if cfg.RequireVP {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_credential_request", "error_description": "use the credential endpoint for presentation-required issuance"})
	}
	var user *models.User
	if offer.UserID != nil {
		user, err = h.users.GetForOrg(ctx, *offer.UserID, offer.OrgID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !user.IsActive) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_request_denied", "error_description": "subject is not eligible in this organisation"})
		}
		if err != nil {
			return echo.ErrInternalServerError
		}
	} else {
		user = &models.User{ID: uuid.Nil, OrgID: org.ID}
	}

	if offer.OrgID != org.ID {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}
	batchProofs := make([]verifiedCredentialProof, 0, len(req.CredentialRequests))
	for _, cr := range req.CredentialRequests {
		if cr.CredentialConfigurationID != "" && cr.CredentialConfigurationID != offer.VCT && cr.CredentialConfigurationID != oid4w.CredentialConfigID(offer.VCT) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "unknown_credential_configuration"})
		}
		proofs, err := validateCredentialProofs(&cr, fmt.Sprintf("%s/%s", h.cfg.BaseURL(), org.Slug), cfg.CredentialFormat, time.Now())
		if err != nil {
			return writeCredentialProofError(c, err)
		}
		if err := validateCredentialAttestations(org, cfg, &cr, proofs, time.Now(), ctx); err != nil {
			return writeCredentialProofError(c, err)
		}
		if len(proofs) != 1 {
			return writeCredentialProofError(c, invalidCredentialProof("legacy batch items require one holder proof each"))
		}
		batchProofs = append(batchProofs, proofs[0])
	}
	h, tx, txErr := h.beginCredentialIssuance(ctx, offer, tokenHash)
	if txErr != nil {
		return writeIssuanceError(c, txErr)
	}
	defer tx.Rollback(ctx)
	if err := h.attachWalletGrantParents(ctx, org, offer, batchProofs); err != nil {
		return writeCredentialProofError(c, err)
	}
	if err := h.consumeCredentialProofs(ctx, org.Slug, batchProofs); err != nil {
		return writeCredentialProofError(c, err)
	}

	responses := make([]batchCredentialItem, 0, len(batchProofs))
	for _, proof := range batchProofs {
		if cfg.DeferredIssuance {
			txnID, err := generateTransactionID()
			if err != nil {
				return echo.ErrInternalServerError
			}
			holder, err := marshalCredentialHolderKey(proof.Key)
			if err != nil {
				return writeCredentialProofError(c, err)
			}
			if _, err := h.repo.CreateDeferredCredential(ctx, repository.CreateDeferredCredentialParams{OrgID: org.ID, TransactionID: txnID, OfferID: offer.ID, CredentialConfigurationID: offer.VCT, HolderJWK: holder, StatusParents: marshalStatusParents(proof.StatusParents), ClaimsPayload: offer.Payload, ExpiresAt: time.Now().Add(7 * 24 * time.Hour)}); err != nil {
				return echo.ErrInternalServerError
			}
			responses = append(responses, batchCredentialItem{TransactionID: &txnID})
		} else {
			credential, reason, err := h.runWebhookAndSign(ctx, org, cfg, user, offer.UserID, offer.Payload, proof.Key)
			if reason != "" {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_denied", "error_description": reason})
			}
			if err != nil {
				return echo.ErrInternalServerError
			}
			if err := h.recordWalletCredential(ctx, org.ID, offer.UserID, offer.VCT, credential, cfg.CredentialFormat, proof.StatusParents); err != nil {
				return echo.ErrInternalServerError
			}
			responses = append(responses, batchCredentialItem{Credential: &credential})
		}
	}
	if err := h.repo.MarkOfferUsed(ctx, offer.ID); err != nil {
		return echo.ErrInternalServerError
	}
	nonce, err := h.issueCredentialNonce(ctx, org.Slug)
	if err != nil {
		return writeCredentialProofError(c, err)
	}
	return finishCredentialResponse(c, tx, map[string]any{"credential_responses": responses, "c_nonce": nonce, "c_nonce_expires_in": 300}, nil)

}

// deferredCredentialRequest is the body for POST /:org_slug/oid4vci/deferred-credential.
type deferredCredentialRequest struct {
	TransactionID                string                           `json:"transaction_id"`
	CredentialResponseEncryption *credentialResponseEncryptionReq `json:"credential_response_encryption,omitempty"`
}

// DeferredCredential handles POST /:org_slug/oid4vci/deferred-credential (OID4VCI Final §11).
// The wallet polls this endpoint with the transaction_id received from the credential endpoint.
func (h *OID4VCIHandler) DeferredCredential(c echo.Context) error {
	return h.retrieveDeferredCredential(c)
}

// ── Notification endpoint (OID4VCI Final §7) ─────────────────────────────────

// notificationRequest is the body of POST /:org_slug/oid4vci/notification.
// OID4VCI Final §7.1.
type notificationRequest struct {
	// NotificationID is the opaque identifier originally issued by the issuer
	// alongside the credential. The wallet echoes it back here.
	NotificationID string `json:"notification_id"`
	// Event is the lifecycle event type (OID4VCI Final §7.2).
	// Valid values: "credential_accepted", "credential_deleted", "credential_failure".
	Event string `json:"event"`
	// EventDescription is an optional human-readable description of the event,
	// present only for "credential_failure".
	EventDescription *string `json:"event_description,omitempty"`
	// CredentialID is the opaque identifier of the credential as returned in
	// the credential response alongside the notification_id (optional,
	// implementation-specific extension used for hash-based correlation).
	CredentialID *string `json:"credential_id,omitempty"`
}

// validNotificationEvents is the set of event values defined in OID4VCI Final §7.2.
var validNotificationEvents = map[string]bool{
	"credential_accepted": true,
	"credential_deleted":  true,
	"credential_failure":  true,
}

// Notification handles POST /:org_slug/oid4vci/notification (OID4VCI Final §7).
//
// The wallet calls this endpoint after a post-issuance lifecycle event.
// Authentication uses the same Bearer token issued by the token endpoint
// (OID4VCI Final §7.1: "the Notification Request MUST be authenticated using
// the access token").
//
// On success the issuer returns HTTP 204 No Content (OID4VCI Final §7.3).
// If the access token is invalid the issuer returns 401 with error=invalid_token.
//
// Side effects:
//   - The event is persisted to oid4vci_credential_notifications for audit/analytics.
//   - For "credential_deleted" and "credential_failure" events the corresponding
//     issued_credentials row is revoked automatically (best-effort; failures are
//     logged but do not affect the HTTP response to the wallet).
func (h *OID4VCIHandler) Notification(c echo.Context) error {
	rawToken := extractBearerToken(c)
	if rawToken == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error":             "invalid_token",
			"error_description": "missing access token",
		})
	}

	ctx := c.Request().Context()
	tokenHash := hashToken(rawToken)
	offer, err := h.repo.GetOfferByAccessToken(ctx, tokenHash)
	if err != nil {
		// Also accept JWT access tokens issued by the OIDC token endpoint
		// (authorization_code flow) — resolve org from URL and accept any valid JWT.
		offer = nil
	}

	// Resolve org from URL slug.
	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}

	// When using a pre-auth access token the offer's org must match the URL slug.
	if offer != nil && offer.OrgID != org.ID {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid_token",
		})
	}

	// Read and cap body size (OID4VCI Final §7.1 does not constrain payload size
	// but 64 KiB is more than sufficient).
	body, err := io.ReadAll(io.LimitReader(c.Request().Body, 64<<10))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
	}

	var req notificationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "request body must be valid JSON",
		})
	}

	// OID4VCI Final §7.1: notification_id and event are REQUIRED.
	if req.NotificationID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_notification_id",
			"error_description": "notification_id is required",
		})
	}
	if !validNotificationEvents[req.Event] {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "event must be credential_accepted, credential_deleted, or credential_failure",
		})
	}

	// Try to correlate the notification to an issued_credentials row via the
	// credential_id (interpreted as sd_jwt_hash when present).
	var issuedCredID *uuid.UUID
	if req.CredentialID != nil && *req.CredentialID != "" {
		if ic, lookupErr := h.repo.GetIssuedCredentialByHash(ctx, org.ID, *req.CredentialID); lookupErr == nil && ic != nil {
			issuedCredID = &ic.ID
		}
	}

	// Persist the notification for audit/analytics (best-effort; do not fail
	// the wallet request on storage errors).
	_ = h.repo.RecordCredentialNotification(
		ctx,
		org.ID,
		req.NotificationID,
		req.Event,
		req.EventDescription,
		issuedCredID,
		body,
	)

	// Auto-revoke on credential_deleted or credential_failure when the
	// credential can be correlated.
	if issuedCredID != nil &&
		(req.Event == "credential_deleted" || req.Event == "credential_failure") {
		reason := "wallet_" + req.Event
		if revokeErr := h.repo.RevokeIssuedCredential(ctx, *issuedCredID, reason); revokeErr != nil {
			log.Warn().
				Err(revokeErr).
				Str("issued_credential_id", issuedCredID.String()).
				Str("event", req.Event).
				Msg("oid4vci: auto-revocation on notification failed")
		} else {
			log.Info().
				Str("issued_credential_id", issuedCredID.String()).
				Str("org_id", org.ID.String()).
				Str("event", req.Event).
				Msg("oid4vci: credential auto-revoked on wallet notification")
			if h.statusDispatcher != nil {
				h.statusDispatcher.Publish(*issuedCredID, "revoked")
			}
		}
	}

	// OID4VCI Final §7.3: success response is 204 No Content.
	return c.NoContent(http.StatusNoContent)
}

// ── Admin deferred credential endpoints ──────────────────────────────────────

// ListDeferredCredentials handles GET /api/v1/organizations/:org_id/oid4vci/deferred
func (h *OID4VCIHandler) ListDeferredCredentials(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	items, err := h.repo.ListDeferredCredentials(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if items == nil {
		items = []*models.DeferredCredential{}
	}
	return c.JSON(http.StatusOK, items)
}

// ApproveDeferredCredential handles POST /api/v1/organizations/:org_id/oid4vci/deferred/:txn_id/approve
// Signs the pending credential and marks the deferred record as completed.
func (h *OID4VCIHandler) ApproveDeferredCredential(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	txnID := c.Param("txn_id")
	if txnID == "" {
		return echo.ErrBadRequest
	}

	ctx := c.Request().Context()
	dc, err := h.repo.GetDeferredCredential(ctx, txnID)
	if err != nil || dc.OrgID != orgID {
		return echo.ErrNotFound
	}
	if dc.Status != "pending" {
		return echo.NewHTTPError(http.StatusConflict, "deferred credential is not pending")
	}
	if time.Now().After(dc.ExpiresAt) {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "deferred credential has expired")
	}

	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	cfg, err := h.repo.GetCredentialConfigByVCT(ctx, orgID, dc.CredentialConfigurationID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "credential config not found")
	}

	holderKey, keyErr := deferredCredentialHolderKey(dc.HolderJWK)
	if keyErr != nil {
		return echo.NewHTTPError(http.StatusConflict, keyErr.Error())
	}

	// Resolve the user from the original offer (if bound).
	user := &models.User{ID: uuid.Nil, OrgID: orgID}
	var boundUserID *uuid.UUID
	origOffer, offerErr := h.repo.GetOfferByID(ctx, dc.OfferID)
	if offerErr != nil || origOffer.OrgID != orgID {
		return echo.NewHTTPError(http.StatusConflict, "original issuance authorization is unavailable")
	}
	if origOffer.UserID != nil {
		u, err := h.users.GetForOrg(ctx, *origOffer.UserID, orgID)
		if err != nil || !u.IsActive {
			return echo.NewHTTPError(http.StatusConflict, "original subject is no longer eligible")
		}
		user = u
		boundUserID = origOffer.UserID
	}

	h, tx, txErr := h.beginCredentialIssuance(ctx, nil, "")
	if txErr != nil {
		return writeIssuanceError(c, txErr)
	}
	defer tx.Rollback(ctx)
	grant, grantErr := h.repo.LockWalletGrant(ctx, origOffer.ID, orgID)
	if grantErr != nil {
		return echo.ErrServiceUnavailable
	}
	currentOffer, eligErr := h.repo.LockWalletOffer(ctx, origOffer.ID, orgID)
	if eligErr != nil {
		return echo.ErrServiceUnavailable
	}
	if grant != nil {
		if !grant.DeferredAllowed || grant.ClosedAt != nil {
			return echo.NewHTTPError(http.StatusConflict, "issuance authorization is closed")
		}
		if err := h.repo.CheckWalletEligibility(ctx, grant, currentOffer); err != nil {
			return echo.NewHTTPError(http.StatusConflict, "issuance authorization is no longer eligible")
		}
	} else if err := h.repo.LockWalletEligibility(ctx, orgID, currentOffer.UserID, "", cfg.ID, currentOffer.VCT); err != nil {
		return echo.NewHTTPError(http.StatusConflict, "issuance authorization is no longer eligible")
	}

	if err := h.repo.LockDeferredIssuance(ctx, txnID, orgID); err != nil {
		return writeIssuanceError(c, err)
	}

	parents, parentErr := oid4w.ParseStatusParents(dc.StatusParents)
	if parentErr != nil {
		return echo.ErrServiceUnavailable
	}
	settings, policyErr := h.repo.LockWalletStatusPolicy(ctx, orgID)
	if policyErr != nil {
		return echo.ErrServiceUnavailable
	}
	if err := oid4w.CheckStatusParents(ctx, orgID.String(), settings, dc.StatusParents); err != nil {
		if errors.Is(err, oid4w.ErrRevoked) || errors.Is(err, oid4w.ErrSuspended) {
			return echo.NewHTTPError(http.StatusConflict, "parent attestation is not active")
		}
		return echo.ErrServiceUnavailable
	}
	// Use the public key authenticated and persisted at initial request time.
	sdJWT, denyReason, signErr := h.runWebhookAndSign(ctx, org, cfg, user, boundUserID, dc.ClaimsPayload, holderKey)
	if denyReason != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "credential_denied", "error_description": denyReason,
		})
	}
	if signErr != nil {
		return echo.ErrInternalServerError
	}

	if err := h.repo.CompleteDeferredCredential(ctx, txnID, sdJWT); err != nil {
		return echo.ErrInternalServerError
	}
	if err := h.recordWalletCredential(ctx, orgID, boundUserID, cfg.VCT, sdJWT, cfg.CredentialFormat, parents); err != nil {
		return echo.ErrInternalServerError
	}
	return finishCredentialResponse(c, tx, map[string]any{"transaction_id": txnID, "status": "completed"}, nil)
}

// credentialFromAuthCode handles the credential endpoint for the
// authorization_code (wallet-initiated) flow, where the bearer token is a
// regular JWT access token issued by the OIDC token endpoint rather than the
// opaque pre-authorized_code VCI token.
//
// OID4VCI Final §8 / Appendix A: the credential endpoint MUST accept both token
// types; when an opaque offer token is not found the server falls back to JWT
// verification.
func (h *OID4VCIHandler) credentialFromAuthCode(c echo.Context, ctx context.Context, rawToken string) error {
	orgSlug := c.Param("org_slug")
	issuer := fmt.Sprintf("%s/%s", h.cfg.BaseURL(), orgSlug)

	// Verify the JWT access token issued by our OIDC token endpoint (PS256).
	tok, err := jwt.Parse([]byte(rawToken),
		jwt.WithKey(jwa.PS256, h.keys.PublicKey()),
		jwt.WithIssuer(issuer),
		jwt.WithValidate(true),
	)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error":             "invalid_token",
			"error_description": "invalid or expired access token",
		})
	}

	if _, walletGrant := tok.Get("clavex_wallet_grant"); walletGrant {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}
	if !credentialAccessTokenValid(tok, c.Request(), time.Now()) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "invalid credential access token lifetime or sender binding"})
	}

	// Extract user UUID from sub claim.
	userID, err := uuid.Parse(tok.Subject())
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid_token",
		})
	}

	// DPoP validation (RFC 9449 §7.2): if the access token carries cnf.jkt the
	// caller MUST present a valid DPoP proof that binds to the same key.
	if boundJKT, hasDPoP := oidc.JKTFromCNF(tok); hasDPoP {
		// RFC 9449 §7.1: "the server MUST ensure that exactly one DPoP proof
		// is included in the request." Reject when multiple DPoP headers appear.
		if dpopVals := c.Request().Header.Values("DPoP"); len(dpopVals) > 1 {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_dpop_proof",
				"error_description": "exactly one DPoP header is allowed (RFC 9449 §7.1)",
			})
		}
		proofHeader := c.Request().Header.Get("DPoP")
		if proofHeader == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "dpop proof required for dpop-bound access token",
			})
		}
		htu := htuFromRequest(c, h.cfg.BaseURL())
		dpopKey, dpopErr := oidc.ParseDPoPProof(proofHeader, c.Request().Method, htu)
		if dpopErr != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "invalid dpop proof: " + dpopErr.Error(),
			})
		}
		if dpopKey == nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "dpop proof missing",
			})
		}
		if dpopKey.JKT != boundJKT {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "dpop proof key does not match token binding",
			})
		}
		// ath = base64url(SHA-256(ASCII(access_token))) — REQUIRED at resource
		// servers (RFC 9449 §7.1); reject proofs that omit it entirely.
		if dpopKey.ATH == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error":             "invalid_dpop_proof",
				"error_description": "ath claim is required in DPoP proof at the resource server (RFC 9449 §7.1)",
			})
		}
		h256 := sha256.Sum256([]byte(rawToken))
		expectedATH := base64.RawURLEncoding.EncodeToString(h256[:])
		if dpopKey.ATH != expectedATH {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "dpop ath claim does not match access token hash",
			})
		}
		// Anti-replay JTI check (best-effort — skip if Redis unavailable).
		if h.rdb != nil {
			if replayErr := oidc.CheckJTI(ctx, dpopKey.JTI, h.rdb); replayErr != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error":             "invalid_token",
					"error_description": "dpop proof replay detected",
				})
			}
		}
	}

	// Parse the credential request body (plain JSON or JWE-encrypted).
	var req credentialRequest
	if c.Request().ContentLength != 0 {
		if err := h.bindCredentialRequest(c, &req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "invalid request body",
			})
		}
	}

	// Resolve the org.
	org, orgErr := h.resolveOrg(c)
	if orgErr != nil {
		return orgErr
	}

	// Determine credential configuration from the request.
	configID := req.CredentialConfigurationID
	if configID == "" {
		// OID4VCI Final §8.3.1: use unknown_credential_identifier when no
		// credential identifier is present in the request.
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "unknown_credential_identifier",
			"error_description": "credential_configuration_id is required",
		})
	}

	// Find the matching credential config (credential_configuration_id is the
	// last path segment of the VCT URI per our BuildIssuerMetadata convention).
	allConfigs, err := h.repo.ListCredentialConfigs(ctx, org.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	var cfg *models.CredentialConfig
	for i := range allConfigs {
		if oid4w.CredentialConfigID(allConfigs[i].VCT) == configID {
			cfg = &allConfigs[i]
			break
		}
	}
	if cfg == nil || !cfg.IsActive {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "unknown_credential_configuration",
			"error_description": "credential type not configured for this organisation",
		})
	}

	if cfg.RequireVP || cfg.DeferredIssuance {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_credential_request", "error_description": "this credential requires an offer-based workflow"})
	}
	if req.CredentialIdentifier != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unknown_credential_identifier"})
	}
	if !credentialConfigurationAuthorized(tok, configID, issuer) {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "insufficient_scope", "error_description": "access token does not authorize this credential configuration"})
	}

	proofs, proofErr := validateCredentialProofs(&req, issuer, cfg.CredentialFormat, time.Now())
	if proofErr != nil {
		return writeCredentialProofError(c, proofErr)
	}
	if err := validateCredentialAttestations(org, cfg, &req, proofs, time.Now(), ctx); err != nil {
		return writeCredentialProofError(c, err)
	}

	// Look up the subject user.
	user, err := h.users.GetByID(ctx, userID)
	if err != nil || !user.IsActive || user.OrgID != org.ID {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid_token",
		})
	}

	h, tx, txErr := h.beginCredentialIssuance(ctx, nil, "")
	if txErr != nil {
		return writeIssuanceError(c, txErr)
	}
	defer tx.Rollback(ctx)
	if err := h.consumeCredentialProofs(ctx, org.Slug, proofs); err != nil {
		return writeCredentialProofError(c, err)
	}
	credentials := make([]map[string]any, 0, len(proofs))
	for _, proof := range proofs {
		credential, reason, err := h.runWebhookAndSign(ctx, org, cfg, user, &userID, nil, proof.Key)
		if reason != "" {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "credential_denied", "error_description": reason})
		}
		if err != nil {
			return echo.ErrInternalServerError
		}
		if err := h.recordWalletCredential(ctx, org.ID, &userID, cfg.VCT, credential, cfg.CredentialFormat, proof.StatusParents); err != nil {
			return echo.ErrInternalServerError
		}
		item := map[string]any{"credential": credential}
		if cfg.CredentialFormat == "mso_mdoc" {
			item["format"] = "mso_mdoc"
		}
		credentials = append(credentials, item)
	}
	return finishCredentialResponse(c, tx, map[string]any{"credentials": credentials}, req.CredentialResponseEncryption)
}

// encryptCredentialResponse wraps a plaintext credential response JSON in a JWE
// compact serialisation using the wallet's provided public key and algorithms.
// OID4VCI Final §8.3: when credential_response_encryption is present in the
// credential request the issuer MUST encrypt the response.
func encryptCredentialResponse(plaintext []byte, encReq *credentialResponseEncryptionReq) (string, error) {
	if encReq == nil {
		return "", fmt.Errorf("encryptCredentialResponse: nil encReq")
	}

	// Parse the wallet's ephemeral public key from the JWK field.
	walletKey, err := jwk.ParseKey(encReq.JWK)
	if err != nil {
		return "", fmt.Errorf("parse wallet JWK: %w", err)
	}

	// OID4VCI 1.0 Final §8.3: the key-encryption algorithm comes from the
	// JWK's own "alg" parameter, not a separate top-level "alg" field in
	// credential_response_encryption (conformance suite follows this).
	// Fall back to encReq.Alg when present for backward compat.
	algStr := encReq.Alg
	if algStr == "" {
		var rawJWK map[string]interface{}
		if jsonErr := json.Unmarshal(encReq.JWK, &rawJWK); jsonErr == nil {
			if a, ok := rawJWK["alg"].(string); ok {
				algStr = a
			}
		}
	}
	if algStr == "" {
		return "", fmt.Errorf("cannot determine JWE key-encryption algorithm: " +
			"neither credential_response_encryption.alg nor JWK alg parameter present")
	}

	// Encrypt using the algorithms requested by the wallet.
	ciphertext, err := jwe.Encrypt(plaintext,
		jwe.WithKey(jwa.KeyEncryptionAlgorithm(algStr), walletKey),
		jwe.WithContentEncryption(jwa.ContentEncryptionAlgorithm(encReq.Enc)),
	)
	if err != nil {
		return "", fmt.Errorf("jwe encrypt: %w", err)
	}
	return string(ciphertext), nil
}

// bindCredentialRequest parses the credential request body into req.
//
// When the wallet sends an encrypted request (Content-Type: application/jwt,
// OID4VCI Final §8 / credential_request_encryption), the body is a JWE compact
// serialisation.  It is decrypted with the issuer's private key before JSON
// unmarshalling.  Plain JSON requests are handled with echo's normal Bind.
func (h *OID4VCIHandler) bindCredentialRequest(c echo.Context, req any) error {
	ct := c.Request().Header.Get(echo.HeaderContentType)
	if !strings.HasPrefix(ct, "application/jwt") {
		return c.Bind(req)
	}

	// Encrypted credential request.
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return fmt.Errorf("read encrypted request body: %w", err)
	}
	if h.keys == nil {
		return fmt.Errorf("no issuer key configured for request decryption")
	}
	// Use PrivateKey() directly — *rsa.PrivateKey satisfies crypto.Decrypter,
	// which is what jwe.Decrypt requires for RSA-OAEP-256.  CryptoSigner()
	// returns crypto.Signer which may or may not be accepted by the library
	// depending on how the jwx type-switch is ordered.
	privKey := h.keys.PrivateKey()
	if privKey == nil {
		return fmt.Errorf("issuer private key is not available for request decryption (KMS/Vault backend?)")
	}
	plain, decErr := jwe.Decrypt(body, jwe.WithKey(jwa.RSA_OAEP_256, privKey))
	if decErr != nil {
		return fmt.Errorf("decrypt credential request: %w", decErr)
	}
	return json.Unmarshal(plain, req)
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

// ListConfigs handles GET /api/v1/organizations/:org_id/oid4vci/configs
func (h *OID4VCIHandler) ListConfigs(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	configs, err := h.repo.ListCredentialConfigs(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if configs == nil {
		configs = []models.CredentialConfig{}
	}
	return c.JSON(http.StatusOK, configs)
}

type createConfigRequest struct {
	VCT           string                  `json:"vct"            validate:"required,url"`
	DisplayName   string                  `json:"display_name"   validate:"required"`
	Description   *string                 `json:"description"`
	ClaimsMapping map[string]interface{}  `json:"claims_mapping"`
	TTLSeconds    int                     `json:"ttl_seconds"`
	Category      string                  `json:"category"`      // identity | training | qualification | badge
	SchemaFields  []models.SchemaFieldDef `json:"schema_fields"` // field descriptors for the admin UI
}

// CreateConfig handles POST /api/v1/organizations/:org_id/oid4vci/configs
func (h *OID4VCIHandler) CreateConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createConfigRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 86400
	}
	cfg, err := h.repo.CreateCredentialConfig(
		c.Request().Context(), orgID, req.VCT, req.DisplayName,
		req.Description, req.ClaimsMapping, req.TTLSeconds,
		req.Category, req.SchemaFields,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "credential config already exists for this vct")
	}
	return c.JSON(http.StatusCreated, cfg)
}

// DeleteConfig handles DELETE /api/v1/organizations/:org_id/oid4vci/configs/:config_id
func (h *OID4VCIHandler) DeleteConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	configID, err := uuidParam(c, "config_id")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteCredentialConfig(c.Request().Context(), configID, orgID); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// patchConfigRequest is the body for PATCH /oid4vci/configs/:config_id.
type patchConfigRequest struct {
	// WebhookURL is the HTTPS endpoint to call before issuing this credential type.
	// Set to empty string or null to disable the hook.
	WebhookURL *string `json:"pre_issuance_webhook_url"`
	// WebhookSecret is the HMAC-SHA256 signing secret.
	// Set to empty string or null to clear.
	WebhookSecret *string `json:"pre_issuance_webhook_secret"`
	// RequireVP controls whether the wallet must present a VP before issuance.
	// Omit the field (null) to leave the current value unchanged.
	RequireVP *bool `json:"require_vp"`
	// PresentationDefinitionVPR is the Presentation Exchange v2 definition to use
	// when RequireVP is true. Omit or null to use the default identity PD.
	PresentationDefinitionVPR map[string]interface{} `json:"presentation_definition_vpr"`
	// SourceIdpType links the credential config to an identity provider type so that
	// credentials are automatically offered after login and use verified IdP claims.
	// Known values: "franceconnect" | "spid" | "cie" | "itsme" | "bundid" | "digid" | "clave"
	// Send empty string or null to clear the link.
	SourceIdpType *string `json:"source_idp_type"`
	// SelectiveDisclosure enables per-claim SD-JWT selective disclosure.
	// When true (default) every mapped claim is a separate disclosure; the wallet can
	// present a single claim (e.g. age_over_18) to a verifier without exposing others.
	// Omit the field (null) to leave the current value unchanged.
	SelectiveDisclosure *bool `json:"selective_disclosure"`
	// RequireKeyAttestation controls whether key_attestations_required is
	// advertised in OID4VCI issuer metadata for this credential type.
	// When false (default) standard wallets (e.g. EUDI reference wallet) work.
	// Set to true only for HAIP conformance testing or high-security issuance.
	// Omit the field (null) to leave the current value unchanged.
	RequireKeyAttestation *bool `json:"require_key_attestation"`
	// ClaimsMapping replaces the credential config's claims_mapping when non-nil.
	// Each entry maps a credential field name to a source path (e.g. "given_name" →
	// "metadata.spid_name"). Pass an empty object {} to clear all mappings.
	// Omit the field (null/absent) to leave the current mapping unchanged.
	ClaimsMapping map[string]interface{} `json:"claims_mapping"`
}

// PatchConfig handles PATCH /api/v1/organizations/:org_id/oid4vci/configs/:config_id
// Sets or clears the pre-issuance webhook for a credential configuration.
func (h *OID4VCIHandler) PatchConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	configID, err := uuidParam(c, "config_id")
	if err != nil {
		return err
	}

	var req patchConfigRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}

	// Normalise: treat empty string as nil (no hook).
	webhookURL := req.WebhookURL
	if webhookURL != nil && *webhookURL == "" {
		webhookURL = nil
	}
	secret := req.WebhookSecret
	if secret != nil && *secret == "" {
		secret = nil
	}

	if err := h.repo.UpsertPreIssuanceWebhook(c.Request().Context(), configID, orgID, webhookURL, secret); err != nil {
		return echo.ErrInternalServerError
	}

	// Update VPR setting if provided.
	if req.RequireVP != nil {
		if err := h.repo.UpsertVPRequirement(c.Request().Context(), configID, orgID, *req.RequireVP, req.PresentationDefinitionVPR); err != nil {
			return echo.ErrInternalServerError
		}
	}

	// Update source_idp_type if the field was supplied (even as empty string → clear).
	if req.SourceIdpType != nil {
		idpType := req.SourceIdpType
		if *idpType == "" {
			idpType = nil
		}
		if err := h.repo.SetSourceIdpType(c.Request().Context(), configID, orgID, idpType); err != nil {
			return echo.ErrInternalServerError
		}
	}

	// Update selective_disclosure flag if supplied.
	if req.SelectiveDisclosure != nil {
		if err := h.repo.SetSelectiveDisclosure(c.Request().Context(), configID, orgID, *req.SelectiveDisclosure); err != nil {
			return echo.ErrInternalServerError
		}
	}

	// Update require_key_attestation flag if supplied.
	if req.RequireKeyAttestation != nil {
		if err := h.repo.SetRequireKeyAttestation(c.Request().Context(), configID, orgID, *req.RequireKeyAttestation); err != nil {
			return echo.ErrInternalServerError
		}
	}

	// Replace claims_mapping when the field is explicitly present in the request body.
	// An empty object {} clears all mappings; absence (null) leaves them unchanged.
	if req.ClaimsMapping != nil {
		if err := h.repo.SetClaimsMapping(c.Request().Context(), configID, orgID, req.ClaimsMapping); err != nil {
			return echo.ErrInternalServerError
		}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"config_id":                configID,
		"pre_issuance_webhook_url": webhookURL,
		"pre_issuance_webhook_set": webhookURL != nil,
		"require_vp":               req.RequireVP,
		"source_idp_type":          req.SourceIdpType,
		"selective_disclosure":     req.SelectiveDisclosure,
		"require_key_attestation":  req.RequireKeyAttestation,
	})
}

// setDelegationRequest is the body for PUT /oid4vci/configs/:config_id/delegation.
type setDelegationRequest struct {
	// DelegatedBy is the entity ID URL of the issuer that delegated this sub-issuer.
	// Send empty string to clear the delegation.
	DelegatedBy string `json:"delegated_by"`
	// DelegationJWT is the compact JWS delegation grant signed by the delegating issuer.
	// The JWT is validated structurally (iss, sub, vct, exp) before being stored.
	// Send empty string to clear.
	DelegationJWT string `json:"delegation_jwt"`
}

// SetDelegation handles PUT /api/v1/organizations/:org_id/oid4vci/configs/:config_id/delegation.
// Configures or removes the ARF EUDIW §6.3.4 delegation grant for a credential config.
// When set, every SD-JWT-VC issued for this config embeds a "del" claim containing the
// delegating issuer entity ID and the delegation proof JWS so wallets can verify the chain.
func (h *OID4VCIHandler) SetDelegation(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	configID, err := uuidParam(c, "config_id")
	if err != nil {
		return err
	}

	var req setDelegationRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}

	// Validate the delegation JWT structurally before storing it.
	if req.DelegationJWT != "" {
		grant, parseErr := oid4w.ParseDelegationJWT(req.DelegationJWT)
		if parseErr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid delegation_jwt: "+parseErr.Error())
		}
		// The VCT in the grant must match the credential config's VCT.
		cfg, cfgErr := h.repo.GetCredentialConfigByID(c.Request().Context(), configID, orgID)
		if cfgErr != nil {
			return echo.ErrNotFound
		}
		if grant.VCT != cfg.VCT {
			return echo.NewHTTPError(http.StatusBadRequest,
				"delegation_jwt vct does not match credential config vct")
		}
		// DelegatedBy must match the grant issuer.
		if req.DelegatedBy != "" && req.DelegatedBy != grant.Issuer {
			return echo.NewHTTPError(http.StatusBadRequest,
				"delegated_by does not match delegation_jwt iss claim")
		}
		if req.DelegatedBy == "" {
			req.DelegatedBy = grant.Issuer
		}
	}

	if err := h.repo.SetDelegation(c.Request().Context(), configID, orgID, req.DelegatedBy, req.DelegationJWT); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, map[string]any{
		"config_id":      configID,
		"delegated_by":   req.DelegatedBy,
		"delegation_set": req.DelegationJWT != "",
	})
}

// issueDelegationGrantRequest is the body for POST /oid4vci/configs/:config_id/delegation/issue.
type issueDelegationGrantRequest struct {
	// SubIssuerURL is the entity ID / issuer URL of the sub-issuer being delegated to.
	SubIssuerURL string `json:"sub_issuer_url" validate:"required,url"`
	// TTLDays is the lifetime of the grant in days. Defaults to 365.
	TTLDays int `json:"ttl_days"`
}

// IssueDelegationGrant handles POST /api/v1/organizations/:org_id/oid4vci/configs/:config_id/delegation/issue.
// The delegating issuer (e.g. the central university) calls this to generate a signed
// delegation grant JWS that can be given to the sub-issuer (a faculty Clavex) and
// then configured via PUT /delegation.
func (h *OID4VCIHandler) IssueDelegationGrant(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	configID, err := uuidParam(c, "config_id")
	if err != nil {
		return err
	}

	var req issueDelegationGrantRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.TTLDays <= 0 {
		req.TTLDays = 365
	}

	ctx := c.Request().Context()

	cfg, err := h.repo.GetCredentialConfigByID(ctx, configID, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	delegatingIssuer := fmt.Sprintf("%s/%s", h.cfg.BaseURL(), org.Slug)
	ttl := time.Duration(req.TTLDays) * 24 * time.Hour

	grantJWT, err := oid4w.BuildDelegationJWT(delegatingIssuer, req.SubIssuerURL, cfg.VCT, ttl, h.keys)
	if err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"delegation_jwt":    grantJWT,
		"delegating_issuer": delegatingIssuer,
		"sub_issuer_url":    req.SubIssuerURL,
		"vct":               cfg.VCT,
		"expires_in_days":   req.TTLDays,
	})
}

type createOfferRequest struct {
	UserID  *string `json:"user_id"`
	VCT     string  `json:"vct"     validate:"required"`
	TxCode  *string `json:"tx_code"` // optional user transaction code
	TTLMins int     `json:"ttl_minutes"`
	// Payload carries credential-specific claims for Clavex Verified types.
	// When provided the credential is issued from this data rather than the
	// bound user's profile attributes.
	Payload map[string]interface{} `json:"payload"`
}

// CreateOffer handles POST /api/v1/organizations/:org_id/oid4vci/offers
// Creates a credential offer (deep link) the admin can give to the user's wallet.
func (h *OID4VCIHandler) CreateOffer(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createOfferRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	ctx := c.Request().Context()

	// Validate the VCT is configured.
	_, err = h.repo.GetCredentialConfigByVCT(ctx, orgID, req.VCT)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "vct not configured for this organisation")
	}

	var userID *uuid.UUID
	if req.UserID != nil && *req.UserID != "" {
		uid, err := uuid.Parse(*req.UserID)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
		}
		u, userErr := h.users.GetForOrg(ctx, uid, orgID)
		if userErr != nil || !u.IsActive {
			return echo.NewHTTPError(http.StatusBadRequest, "user is not active in this organisation")
		}
		userID = &uid
	}

	ttl := time.Duration(req.TTLMins) * time.Minute
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	preAuthCode, err := generateSecureCode()
	if err != nil {
		return echo.ErrInternalServerError
	}

	var txCodeHash *string
	if req.TxCode != nil && *req.TxCode != "" {
		h := hashTxCode(*req.TxCode)
		txCodeHash = &h
	}

	offer, err := h.repo.CreateCredentialOffer(
		ctx, orgID, userID, req.VCT, preAuthCode, txCodeHash, req.Payload, time.Now().Add(ttl),
	)
	if err != nil {
		return echo.ErrInternalServerError
	}

	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Build the credential offer object per OID4VCI §4.1.
	preAuthGrant := map[string]any{
		"pre-authorized_code": offer.PreAuthCode,
	}
	if txCodeHash != nil {
		preAuthGrant["tx_code"] = map[string]any{
			"input_mode":  "numeric",
			"description": "Enter the transaction code provided by your administrator",
		}
	}
	offerObj := map[string]any{
		"credential_issuer":            fmt.Sprintf("%s/%s", h.cfg.BaseURL(), org.Slug),
		"credential_configuration_ids": []string{oid4w.CredentialConfigID(req.VCT)},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": preAuthGrant,
		},
	}

	offerURI := buildOfferDeepLink(h.cfg.BaseURL(), org.Slug, offer.ID)

	return c.JSON(http.StatusCreated, map[string]any{
		"offer_id":             offer.ID,
		"credential_offer":     offerObj,
		"credential_offer_uri": offerURI,
		"expires_at":           offer.ExpiresAt,
	})
}

// SendOffer delivers the openid-credential-offer:// deep-link to the recipient
// via SMS or email so they can open their eIDAS/digital-identity wallet by
// tapping the link on their phone (no QR scan required).
//
// POST /api/v1/organizations/:org_id/oid4vci/offers/:offer_id/send
//
// Request body:
//
//	{
//	  "channel": "sms" | "email",           // delivery channel (required)
//	  "to":      "+39333…" | "user@example.com"  // recipient override (optional)
//	                                         // defaults to the user linked to the offer
//	}
//
// On success returns 200 with {"channel","to","offer_id","sent_at"}.
// Returns 400 when channel is missing or "to" is absent and no user is linked.
// Returns 422 when the offer is expired or not pending.
// Returns 503 when the org's SMS/SMTP gateway is not configured.
func (h *OID4VCIHandler) SendOffer(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	offerID, err := uuidParam(c, "offer_id")
	if err != nil {
		return err
	}

	var req struct {
		Channel string `json:"channel" validate:"required,oneof=sms email"`
		To      string `json:"to"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	ctx := c.Request().Context()

	// Load and validate the offer.
	offer, err := h.repo.GetOfferByID(ctx, offerID)
	if err != nil || offer.OrgID != orgID {
		return echo.NewHTTPError(http.StatusNotFound, "offer not found")
	}
	if offer.Status != "pending" {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "offer is no longer pending")
	}
	if offer.ExpiresAt.Before(time.Now()) {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "offer has expired")
	}

	// Load org for issuer slug.
	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Resolve recipient address.
	to := strings.TrimSpace(req.To)
	if to == "" {
		if offer.UserID == nil {
			return echo.NewHTTPError(http.StatusBadRequest,
				"'to' is required when no user is linked to the offer")
		}
		user, err := h.users.GetForOrg(ctx, *offer.UserID, offer.OrgID)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "linked user not found")
		}
		if req.Channel == "sms" {
			// Phone may be in user metadata (common pattern for eIDAS citizen registrations).
			if phone, ok := user.Metadata["phone"].(string); ok && phone != "" {
				to = phone
			} else {
				return echo.NewHTTPError(http.StatusBadRequest,
					"linked user has no phone number; provide 'to' explicitly")
			}
		} else {
			to = user.Email
		}
	}

	offerURI := buildOfferDeepLink(h.cfg.BaseURL(), org.Slug, offer.ID)

	// Deliver via the requested channel.
	switch req.Channel {
	case "sms":
		provider, err := sms.ForOrg(ctx, h.smsRepo, orgID)
		if err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable,
				"SMS gateway not configured for this organisation")
		}
		body := "Your digital credential is ready. Tap the link to open your wallet:\n" + offerURI
		if err := provider.Send(ctx, to, body); err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable,
				"SMS delivery failed: "+err.Error())
		}

	case "email":
		m, err := mailer.ForOrg(ctx, h.smtp, orgID)
		if err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable,
				"Email gateway not configured for this organisation")
		}
		subject := "Your digital credential is ready — " + org.Name
		htmlBody := buildOfferEmailHTML(org.Name, offerURI, offer.ExpiresAt)
		if err := m.Send(to, subject, htmlBody); err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable,
				"Email delivery failed: "+err.Error())
		}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"offer_id": offer.ID,
		"channel":  req.Channel,
		"to":       to,
		"sent_at":  time.Now().UTC(),
	})
}

// buildOfferEmailHTML returns a minimal responsive HTML email body for
// the credential offer deep-link. The call-to-action button opens the
// openid-credential-offer:// URI in the recipient's wallet app.
func buildOfferEmailHTML(orgName, offerURI string, expiresAt time.Time) string {
	expiry := expiresAt.UTC().Format("2 January 2006 at 15:04 UTC")
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Your digital credential is ready</title>
</head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:32px 16px;">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:8px;overflow:hidden;max-width:560px;width:100%;">
        <!-- Header -->
        <tr><td style="background:#1a56db;padding:24px 32px;">
          <p style="margin:0;color:#ffffff;font-size:20px;font-weight:bold;">` + orgName + `</p>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:32px;">
          <h1 style="margin:0 0 16px;font-size:22px;color:#111827;">
            Your digital credential is ready
          </h1>
          <p style="margin:0 0 24px;font-size:15px;color:#374151;line-height:1.6;">
            Tap the button below on your smartphone to open your digital wallet
            and receive your credential. If the button does not open your wallet,
            copy the link and paste it into your wallet app.
          </p>
          <!-- CTA button -->
          <table role="presentation" cellpadding="0" cellspacing="0">
            <tr><td style="border-radius:6px;background:#1a56db;">
              <a href="` + offerURI + `"
                 style="display:inline-block;padding:14px 28px;color:#ffffff;
                        font-size:15px;font-weight:bold;text-decoration:none;border-radius:6px;">
                Open wallet &amp; receive credential
              </a>
            </td></tr>
          </table>
          <p style="margin:24px 0 0;font-size:13px;color:#6b7280;">
            This offer expires on <strong>` + expiry + `</strong>.
            Do not share this link with anyone.
          </p>
        </td></tr>
        <!-- Footer -->
        <tr><td style="padding:16px 32px;border-top:1px solid #e5e7eb;">
          <p style="margin:0;font-size:12px;color:#9ca3af;">
            Sent by ` + orgName + ` via Clavex Identity Platform.
            If you did not request this credential, please ignore this message.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`
}

// ListIssued handles GET /api/v1/organizations/:org_id/oid4vci/issued
func (h *OID4VCIHandler) ListIssued(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	issued, err := h.repo.ListIssuedCredentials(c.Request().Context(), orgID, 100)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if issued == nil {
		issued = []models.IssuedCredential{}
	}
	return c.JSON(http.StatusOK, issued)
}

// OfferJSON serves the Credential Offer Object at
//
//	GET /:org_slug/oid4vci/offers/:offer_id
//
// This public endpoint is used as the credential_offer_uri value inside the
// openid-credential-offer:// deep-link QR code.  The wallet fetches the JSON
// from this URL instead of reading it inline from the QR code (OID4VCI §4.1).
// Using by-reference delivery keeps QR codes small (~90 chars vs ~500) and
// avoids URL-encoding edge-cases with strict URI parsers.
func (h *OID4VCIHandler) OfferJSON(c echo.Context) error {
	ctx := c.Request().Context()

	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}

	offerID, err := uuid.Parse(c.Param("offer_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid offer_id")
	}

	offer, err := h.repo.GetOfferByID(ctx, offerID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "offer not found")
	}
	if offer.OrgID != org.ID {
		return echo.NewHTTPError(http.StatusNotFound, "offer not found")
	}
	if offer.ExpiresAt.Before(time.Now()) {
		return echo.NewHTTPError(http.StatusGone, "offer expired")
	}

	publicGrant := map[string]any{
		"pre-authorized_code": offer.PreAuthCode,
	}
	if offer.TxCodeHash != nil {
		publicGrant["tx_code"] = map[string]any{
			"input_mode": "numeric",
		}
	}
	offerObj := map[string]any{
		"credential_issuer":            fmt.Sprintf("%s/%s", h.cfg.BaseURL(), org.Slug),
		"credential_configuration_ids": []string{oid4w.CredentialConfigID(offer.VCT)},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": publicGrant,
		},
	}

	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Access-Control-Allow-Origin", "*")
	return c.JSON(http.StatusOK, offerObj)
}

func (h *OID4VCIHandler) ListOffers(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	offers, err := h.repo.ListOffers(c.Request().Context(), orgID, 100)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if offers == nil {
		offers = []models.CredentialOffer{}
	}
	return c.JSON(http.StatusOK, offers)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// buildOfferDeepLink returns the openid-credential-offer:// URI using the
// by-reference form (credential_offer_uri) so that wallets fetch the offer
// JSON over HTTPS.  This keeps QR codes small and avoids URL-encoding issues.
func buildOfferDeepLink(baseURL, orgSlug string, offerID uuid.UUID) string {
	credentialOfferURL := fmt.Sprintf("%s/%s/oid4vci/offers/%s", baseURL, orgSlug, offerID)
	return "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(credentialOfferURL)
}

func (h *OID4VCIHandler) resolveOrg(c echo.Context) (*models.Organization, error) {
	slug := c.Param("org_slug")
	if slug == "" {
		return nil, echo.ErrBadRequest
	}
	org, err := h.orgs.GetBySlug(c.Request().Context(), slug)
	if err != nil {
		return nil, echo.ErrNotFound
	}
	return org, nil
}

func generateOpaqueToken() (raw, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = hashToken(raw)
	return raw, hash
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

func hashTxCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return fmt.Sprintf("%x", h)
}

func generateSecureCode() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateNonce() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func extractBearerToken(c echo.Context) string {
	auth := c.Request().Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	// RFC 9110 §11.1: authentication scheme names are case-insensitive.
	// Accept "Bearer", "bearer", "BEARER", etc. and "DPoP", "dpop", "dpOp", etc.
	// Split at the first space to isolate the scheme without allocating a lowered copy
	// of the full (potentially large) token value.
	if idx := strings.IndexByte(auth, ' '); idx > 0 {
		scheme := strings.ToLower(auth[:idx])
		token := auth[idx+1:]
		if scheme == "bearer" || scheme == "dpop" {
			return token
		}
	}
	return ""
}

// htuFromRequest builds the DPoP htu (scheme://host/path) for the current request.
// Uses baseURL (e.g. "https://id.clavex.eu") to extract the scheme+host,
// with X-Forwarded-Proto / X-Forwarded-Host as fallbacks for reverse-proxy deployments.
func htuFromRequest(c echo.Context, baseURL string) string {
	path := c.Request().URL.Path
	if baseURL != "" {
		if u, err := url.Parse(strings.TrimRight(baseURL, "/")); err == nil {
			return u.Scheme + "://" + u.Host + path
		}
	}
	r := c.Request()
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
		scheme = fwdProto
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host + path
}

// runWebhookAndSign calls the pre-issuance webhook (if configured) and signs an SD-JWT-VC.
// Returns (sdJWT, "", nil) on success, ("", denyReason, nil) when the webhook denies issuance.
// holderKey is the wallet's public key from the proof JWT "jwk" header; nil is accepted (no cnf.jwk).
func (h *OID4VCIHandler) runWebhookAndSign(
	ctx context.Context,
	org *models.Organization,
	cfg *models.CredentialConfig,
	user *models.User,
	userID *uuid.UUID,
	payload map[string]interface{},
	holderKey jwk.Key,
) (sdJWT string, denyReason string, err error) {
	activePayload := payload
	if cfg.PreIssuanceWebhookURL != nil && *cfg.PreIssuanceWebhookURL != "" {
		hookReq := oid4w.PreIssuanceRequest{
			Event:   "credential.pre_issuance",
			VCT:     cfg.VCT,
			OrgID:   org.ID.String(),
			Payload: payload,
		}
		if userID != nil {
			uid := userID.String()
			hookReq.UserID = &uid
		}
		secret := ""
		if cfg.PreIssuanceWebhookSecret != nil {
			secret = *cfg.PreIssuanceWebhookSecret
		}
		merged, allowed, reason, hookErr := oid4w.CallPreIssuanceHook(
			ctx, *cfg.PreIssuanceWebhookURL, secret, hookReq,
		)
		if hookErr != nil || !allowed {
			r := reason
			if r == "" {
				r = "denied by pre-issuance hook"
			}
			return "", r, nil
		}
		activePayload = merged
	}
	sdJWT, err = h.signCredential(ctx, org, cfg, user, activePayload, holderKey)
	return sdJWT, "", err
}

// signCredential issues a credential in the format specified by cfg.CredentialFormat.
// For "vc+sd-jwt" (default) it returns an SD-JWT-VC compact serialisation.
// For "mso_mdoc" it returns a base64url-encoded CBOR IssuerSigned.
// holderKey is the wallet's EC public key from the OID4VCI proof JWT "jwk" header.
func (h *OID4VCIHandler) signCredential(
	ctx context.Context,
	org *models.Organization,
	cfg *models.CredentialConfig,
	user *models.User,
	payload map[string]interface{},
	holderKey jwk.Key,
) (string, error) {
	if cfg.CredentialFormat != "mso_mdoc" {
		if h.credentialSigningErr != nil {
			return "", fmt.Errorf("credential signing certificate is misconfigured")
		}
		if h.credentialSigner != nil {
			if _, _, err := h.credentialSigner.MetadataCertificateChain(h.cfg.BaseURL() + "/" + org.Slug); err != nil {
				return "", fmt.Errorf("credential signing certificate: %w", err)
			}
		}
	}
	list, index, err := h.repo.AllocateCredentialStatus(ctx, org.ID)
	if err != nil {
		return "", err
	}
	status := oid4w.BuildStatusClaim(h.cfg.BaseURL()+"/"+org.Slug+"/oid4vci/status-list/"+list.String(), index)
	if cfg.CredentialFormat == "mso_mdoc" {
		return h.issueMdocCredential(ctx, org, cfg, user, payload, holderKey, status)
	}
	// Default: SD-JWT-VC.
	userSub := org.ID.String()
	if user != nil && user.ID != uuid.Nil {
		userSub = user.ID.String()
	}
	var sdJWT string
	credentialKeys := h.keys
	if h.credentialSigner != nil {
		credentialKeys = h.credentialSigner
	}
	if len(payload) > 0 {
		sdJWT, _, err = oid4w.IssueVerifiedCredential(payload, userSub, org, cfg, credentialKeys, h.cfg.BaseURL(), holderKey, status)
	} else if isAgeOnlyConfig(cfg) {
		// Anonymous age credential: only derived age claims, pseudonymous sub.
		// Birth date is used for computation but never included in the credential
		// (GDPR Art.5(1)(c) data minimization — the strongest possible form).
		sdJWT, _, err = oid4w.IssueAgeCredential(user, org, cfg, credentialKeys, h.cfg.BaseURL(), holderKey, status)
	} else {
		sdJWT, _, err = oid4w.IssueIdentityCredential(user, org, cfg, credentialKeys, h.cfg.BaseURL(), holderKey, status)
	}
	return sdJWT, err
}

// isAgeOnlyConfig returns true when every output claim in the credential config's
// claims_mapping is a derived age value (age_over_18 or age_in_years).
// Such configs are routed to IssueAgeCredential for GDPR-minimal anonymous issuance.
func isAgeOnlyConfig(cfg *models.CredentialConfig) bool {
	if len(cfg.ClaimsMapping) == 0 {
		return false
	}
	for k := range cfg.ClaimsMapping {
		if k != "age_over_18" && k != "age_in_years" {
			return false
		}
	}
	return true
}

func generateTransactionID() (string, error) {
	return generateSecureCode()
}

// issueMdocCredential builds an ISO 18013-5 mdoc IssuerSigned for the given
// credential config and user. The mdoc is base64url-encoded and returned as
// the OID4VCI "credential" string.
//
// The wallet's public key (from the proof JWT) is bound into the MSO DeviceKeyInfo
// so the holder can prove key possession during proximity presentation.
func (h *OID4VCIHandler) issueMdocCredential(
	ctx context.Context,
	org *models.Organization,
	cfg *models.CredentialConfig,
	user *models.User,
	payload map[string]interface{},
	holderKey jwk.Key,
	status oid4w.StatusClaim,
) (string, error) {
	// Determine docType from VCT (for mso_mdoc, VCT == docType per OID4VCI §E.2).
	docType := cfg.VCT
	namespace := mdocNamespaceForDocType(docType)

	// Load the org's active DS key for this docType.
	issuerRec, err := h.mdocIssuers.GetActiveByDocType(ctx, org.ID, docType)
	if err != nil {
		return "", fmt.Errorf("mdoc: load DS issuer: %w", err)
	}
	if issuerRec == nil {
		return "", fmt.Errorf("mdoc: no active DS issuer configured for docType %q — upload a DS key via POST /mdoc/issuers", docType)
	}

	dsKey, err := repository.ParseDSKey(issuerRec)
	if err != nil {
		return "", fmt.Errorf("mdoc: parse DS key: %w", err)
	}
	dsCertDER, err := repository.ParseDSCert(issuerRec)
	if err != nil {
		return "", fmt.Errorf("mdoc: parse DS cert: %w", err)
	}

	// Build attribute map: use explicit payload if provided, otherwise derive
	// from user profile via ClaimsMapping.
	attrs := buildMdocAttributes(cfg, user, payload)

	// Extract holder's ECDSA public key from the JWK proof for key binding.
	var devicePub *ecdsa.PublicKey
	if holderKey != nil {
		var raw interface{}
		if err := holderKey.Raw(&raw); err == nil {
			if ecKey, ok := raw.(*ecdsa.PublicKey); ok {
				devicePub = ecKey
			}
		}
	}

	statusCBOR, err := cbor.Marshal(map[string]interface{}{"idx": status.StatusList.IDX, "uri": status.StatusList.URI})
	if err != nil {
		return "", err
	}
	issuerSignedCBOR, err := mdoc.IssueMdoc(mdoc.IssuanceParams{
		DocType:         docType,
		StatusList:      statusCBOR,
		Namespace:       namespace,
		Attributes:      attrs,
		DSKey:           dsKey,
		DSCertDER:       dsCertDER,
		DevicePublicKey: devicePub,
		ValidityHours:   issuerRec.ValidityHours,
	})
	if err != nil {
		return "", fmt.Errorf("mdoc: IssueMdoc: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(issuerSignedCBOR), nil
}

// buildMdocAttributes constructs the attribute map for an mdoc from the credential
// config ClaimsMapping and user profile. Payload overrides take precedence.
func buildMdocAttributes(cfg *models.CredentialConfig, user *models.User, payload map[string]interface{}) map[string]interface{} {
	var out map[string]interface{}
	switch {
	case len(payload) > 0:
		out = payload
	case cfg.ClaimsMapping == nil || user == nil:
		out = map[string]interface{}{}
	default:
		// Apply ClaimsMapping: each entry is "mdoc_element_id" → "user_field_path"
		userAttrs := oid4w.UserAttributes(user)
		out = make(map[string]interface{}, len(cfg.ClaimsMapping))
		for mdocKey, srcField := range cfg.ClaimsMapping {
			if srcStr, ok := srcField.(string); ok {
				if val, found := userAttrs[srcStr]; found {
					out[mdocKey] = val
				}
			}
		}
	}
	// The mDL docType has mandatory data elements (ISO 18013-5 §7.2.1) beyond the
	// configured claims; fill any that are missing with ISO-typed defaults.
	if cfg.VCT == mdoc.DocTypeMdl {
		mdoc.FillMdlMandatory(out)
	}
	return out
}

// mdocNamespaceForDocType maps a docType to its primary attribute namespace.
func mdocNamespaceForDocType(docType string) string {
	switch docType {
	case mdoc.DocTypeMdl:
		return mdoc.NSMdl
	case mdoc.DocTypeEuPid:
		return mdoc.NSEuPid
	default:
		// For custom doctypes, namespace = docType (common convention).
		return docType
	}
}

// baseURLFromConfig satisfies baseURLProvider using config.Config.
type baseURLFromConfig struct{ url string }

func (b *baseURLFromConfig) BaseURL() string { return b.url }

// staticBaseURL creates a baseURLProvider from a plain string (used in server wiring).
func StaticBaseURL(url string) baseURLProvider {
	return &baseURLFromConfig{url: url}
}

// defaultIdentityPD returns a minimal Presentation Exchange v2 definition that
// requests any SD-JWT-VC with a "sub" claim. Used when the admin hasn't set a
// custom presentation_definition_vpr on the credential config.
func defaultIdentityPD(vct string) map[string]any {
	return map[string]any{
		"id":      "vpr-identity-" + vct,
		"name":    "Identity verification",
		"purpose": "Verify holder identity before credential issuance",
		"input_descriptors": []any{
			map[string]any{
				"id":   "holder-identity",
				"name": "Holder identity credential",
				"format": map[string]any{
					"vc+sd-jwt": map[string]any{},
				},
				"constraints": map[string]any{
					"fields": []any{
						map[string]any{
							"path": []any{"$.sub"},
						},
					},
				},
			},
		},
	}
}

// ── Status List endpoints ─────────────────────────────────────────────────────

// StatusUpdates handles GET /:org_slug/oid4vci/status-updates
//
// Server-Sent Events stream. Wallets subscribe by presenting their issued
// SD-JWT as a Bearer token; the server resolves the credential by its hash and
// pushes a JSON event whenever the credential's status bit changes instead of
// waiting for the wallet to poll the status-list JWT.
//
// Auth: Authorization: Bearer <sd-jwt>
//
//	The server computes SHA-256(<sd-jwt>) as hex (matching the sd_jwt_hash
//	column) and resolves the issued_credential row.  Only the credential
//	holder — who possesses the raw SD-JWT — can authenticate this endpoint.
//
// Wire format: text/event-stream
//
//	data: {"credential_id":"<uuid>","status":"revoked","occurred_at":"…"}\n\n
//
// Keepalive: ": heartbeat\n\n" comment every 30 seconds.
func (h *OID4VCIHandler) StatusUpdates(c echo.Context) error {
	if h.statusDispatcher == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "status-updates not available")
	}

	rawToken := extractBearerToken(c)
	if rawToken == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}

	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}

	// Authenticate by looking up the credential whose sd_jwt_hash matches.
	tokenHash := oid4w.HashToken(rawToken)
	cred, err := h.repo.GetIssuedCredentialByHash(c.Request().Context(), org.ID, tokenHash)
	if err != nil || cred == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}

	// Subscribe before writing the HTTP response so no event is missed.
	ch, cancel := h.statusDispatcher.Subscribe([]uuid.UUID{cred.ID})
	defer cancel()

	c.Response().Header().Set("Content-Type", "text/event-stream")
	c.Response().Header().Set("Cache-Control", "no-cache")
	c.Response().Header().Set("Connection", "keep-alive")
	c.Response().Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering
	c.Response().WriteHeader(http.StatusOK)
	c.Response().Flush()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	ctx := c.Request().Context()
	w := c.Response()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-heartbeat.C:
			if _, writeErr := fmt.Fprint(w, ": heartbeat\n\n"); writeErr != nil {
				return nil // client disconnected
			}
			w.Flush()

		case evt, ok := <-ch:
			if !ok {
				return nil // dispatcher shut down
			}
			data, marshalErr := json.Marshal(evt)
			if marshalErr != nil {
				continue
			}
			if _, writeErr := fmt.Fprintf(w, "data: %s\n\n", data); writeErr != nil {
				return nil // client disconnected
			}
			w.Flush()
		}
	}
}

// StatusList handles GET /:org_slug/oid4vci/status-list/:list_id
// It serves the status list as a signed statuslist+jwt.
//
// The JWT is signed with the issuer's current RS256 signing key and carries:
//   - iss: issuer base URL
//   - sub: list UUID
//   - status_list.bits = 1 (1 bit per credential)
//   - status_list.lst  = zlib+base64url bitstring
func (h *OID4VCIHandler) StatusList(c echo.Context) error {
	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(c.Param("list_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	list, err := h.repo.GetStatusList(c.Request().Context(), id)
	if err != nil || list.OrgID != org.ID {
		return echo.ErrNotFound
	}
	decoded, err := oid4w.DecodeStatusListWithBits(list.Encoded, list.Bits)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	issuer := h.cfg.BaseURL() + "/" + org.Slug
	token, err := oid4w.IssueStatusListJWT(oid4w.StatusListJWTParams{Issuer: issuer, ListID: id, StatusList: decoded, TTL: 5 * time.Minute, Signer: h.keys.CryptoSigner(), Algorithm: h.keys.Algorithm(), KID: h.keys.KID()})
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	c.Response().Header().Set("Cache-Control", "public, max-age=60")
	return c.Blob(200, "application/statuslist+jwt", []byte(token))
}

// RevokeCredential handles POST /api/v1/organizations/:org_id/oid4vci/issued/:cred_id/revoke
func (h *OID4VCIHandler) RevokeCredential(c echo.Context) error {
	credIDStr := c.Param("cred_id")
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid cred_id"})
	}

	var body struct {
		Reason  string `json:"reason"`
		UserSub string `json:"user_sub"` // optional: used for federated propagation
	}
	_ = json.NewDecoder(c.Request().Body).Decode(&body)

	ctx := c.Request().Context()

	// Fetch the credential record before revoking so we can propagate.
	cred, err := h.repo.GetIssuedCredentialByID(ctx, credID)
	if err != nil || cred == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "credential not found"})
	}

	orgID, parseErr := uuidParam(c, "org_id")
	if parseErr != nil {
		return parseErr
	}
	if cred.OrgID != orgID {
		return echo.ErrNotFound
	}

	if err := h.repo.RevokeIssuedCredential(ctx, credID, body.Reason); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Notify local SSE subscribers (wallets polling for status changes).
	if h.statusDispatcher != nil {
		h.statusDispatcher.Publish(credID, "revoked")
	}

	// Fire CAEP credential-change SET to local SSF streams.
	if h.ssfDisp != nil {
		userSub := body.UserSub
		if userSub == "" && cred.UserID != nil {
			userSub = cred.UserID.String()
		}
		orgIDStr := cred.OrgID.String()
		go h.ssfDisp.Dispatch(cred.OrgID, orgIDStr, userSub, ssf.EventCredentialChange, map[string]interface{}{
			"change_type": "revoked",
			"vct":         cred.VCT,
			"reason":      body.Reason,
		})
	}

	// Propagate to federated partner installations (cross-installation revocation network).
	if h.revnet != nil {
		userSub := body.UserSub
		if userSub == "" && cred.UserID != nil {
			userSub = cred.UserID.String()
		}
		h.revnet.Propagate(cred.OrgID, cred, userSub, body.Reason)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "revoked"})
}

// SuspendCredential makes a tracked credential temporarily unusable.
func (h *OID4VCIHandler) SuspendCredential(c echo.Context) error {
	org, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "cred_id")
	if err != nil {
		return err
	}
	record, err := h.repo.GetIssuedCredentialByID(c.Request().Context(), id)
	if err != nil || record == nil || record.OrgID != org {
		return echo.ErrNotFound
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil && err != io.EOF {
		return echo.ErrBadRequest
	}
	if err := h.repo.SuspendIssuedCredential(c.Request().Context(), id, body.Reason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "credential_state_conflict"})
		}
		return echo.ErrServiceUnavailable
	}
	if h.statusDispatcher != nil {
		h.statusDispatcher.Publish(id, "suspended")
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "suspended"})
}

// RestoreCredential handles POST /api/v1/organizations/:org_id/oid4vci/issued/:cred_id/restore
func (h *OID4VCIHandler) RestoreCredential(c echo.Context) error {
	credIDStr := c.Param("cred_id")
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid cred_id"})
	}
	orgID, parseErr := uuidParam(c, "org_id")
	if parseErr != nil {
		return parseErr
	}
	record, lookupErr := h.repo.GetIssuedCredentialByID(c.Request().Context(), credID)
	if lookupErr != nil || record == nil || record.OrgID != orgID {
		return echo.ErrNotFound
	}

	if err := h.repo.RestoreIssuedCredential(c.Request().Context(), credID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "credential_state_conflict", "error_description": "only suspended credentials can be restored; revocation is terminal"})
		}
		return echo.ErrServiceUnavailable
	}
	if h.statusDispatcher != nil {
		h.statusDispatcher.Publish(credID, "restored")
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "restored"})
}

// OfferQR generates a scannable QR code for a credential offer.
// GET /:org_slug/oid4vci/offers/:offer_id/qr
//
// Returns a PNG image containing the openid-credential-offer:// deep-link URI.
// The wallet app scans the QR to start the pre-authorized code flow.
//
// Query params:
//
//	size — QR image dimension in pixels (default 256, max 1024)
func (h *OID4VCIHandler) OfferQR(c echo.Context) error {
	ctx := c.Request().Context()

	offerID, err := uuid.Parse(c.Param("offer_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid offer_id")
	}

	// Resolve the org and offer.
	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}
	offer, err := h.repo.GetOfferByID(ctx, offerID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "offer not found")
	}
	if offer.OrgID != org.ID {
		return echo.NewHTTPError(http.StatusNotFound, "offer not found")
	}
	if offer.ExpiresAt.Before(time.Now()) {
		return echo.NewHTTPError(http.StatusGone, "offer expired")
	}

	offerURI := buildOfferDeepLink(h.cfg.BaseURL(), org.Slug, offer.ID)

	// Determine image size.
	size := 256
	if s := c.QueryParam("size"); s != "" {
		var n int
		if _, scanErr := fmt.Sscanf(s, "%d", &n); scanErr == nil && n > 0 && n <= 1024 {
			size = n
		}
	}

	// Generate QR code.
	code, err := qr.Encode(offerURI, qr.M, qr.Auto)
	if err != nil {
		return echo.ErrInternalServerError
	}
	scaled, err := barcode.Scale(code, size, size)
	if err != nil {
		return echo.ErrInternalServerError
	}

	c.Response().Header().Set("Content-Type", "image/png")
	c.Response().Header().Set("Cache-Control", "no-store")
	return png.Encode(c.Response().Writer, scaled)
}

// OfferQRByOrgID serves the same QR as OfferQR but resolves the org via the
// :org_id UUID param (used by the admin API group at /api/v1/organizations/:org_id).
func (h *OID4VCIHandler) OfferQRByOrgID(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	offerID, err := uuid.Parse(c.Param("offer_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid offer_id")
	}

	offer, err := h.repo.GetOfferByID(ctx, offerID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "offer not found")
	}
	if offer.OrgID != orgID {
		return echo.NewHTTPError(http.StatusNotFound, "offer not found")
	}
	if offer.ExpiresAt.Before(time.Now()) {
		return echo.NewHTTPError(http.StatusGone, "offer expired")
	}

	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "org not found")
	}

	offerURI := buildOfferDeepLink(h.cfg.BaseURL(), org.Slug, offer.ID)

	size := 256
	if s := c.QueryParam("size"); s != "" {
		var n int
		if _, scanErr := fmt.Sscanf(s, "%d", &n); scanErr == nil && n > 0 && n <= 1024 {
			size = n
		}
	}

	code, err := qr.Encode(offerURI, qr.M, qr.Auto)
	if err != nil {
		return echo.ErrInternalServerError
	}
	scaled, err := barcode.Scale(code, size, size)
	if err != nil {
		return echo.ErrInternalServerError
	}

	c.Response().Header().Set("Content-Type", "image/png")
	c.Response().Header().Set("Cache-Control", "no-store")
	return png.Encode(c.Response().Writer, scaled)
}

func marshalStatusParents(parents []oid4w.StatusParent) json.RawMessage {
	if len(parents) == 0 {
		return json.RawMessage(`[]`)
	}
	raw, _ := json.Marshal(parents)
	return raw
}

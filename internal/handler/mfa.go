package handler

import (
	"context"
	"encoding/json"
	"errors"
	"image/png"
	"net/http"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/clavex-eu/clavex/internal/attestation"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/go-webauthn/webauthn/protocol"
	walib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
)

const webAuthnChallengeTTL = 5 * time.Minute

// ── Package-level TOTP helpers (shared with account portal) ──────────────────

type totpGenerateOpts struct {
	Issuer      string
	AccountName string
}

type totpKey struct {
	secret string
	url    string
}

func totpGenerate(opts totpGenerateOpts) (totpKey, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      opts.Issuer,
		AccountName: opts.AccountName,
	})
	if err != nil {
		return totpKey{}, err
	}
	return totpKey{secret: key.Secret(), url: key.URL()}, nil
}

func totpValidate(code, secret string) bool {
	return totp.Validate(code, secret)
}

// serveTOTPQRPNG encodes otpauthURI as a 300×300 PNG QR code and writes it to c.
func serveTOTPQRPNG(c echo.Context, otpauthURI string) error {
	qrCode, err := qr.Encode(otpauthURI, qr.M, qr.Auto)
	if err != nil {
		return echo.ErrInternalServerError
	}
	scaled, err := barcode.Scale(qrCode, 300, 300)
	if err != nil {
		return echo.ErrInternalServerError
	}
	c.Response().Header().Set("Content-Type", "image/png")
	c.Response().Header().Set("Cache-Control", "no-store")
	return png.Encode(c.Response().Writer, scaled)
}

// MFAHandler manages MFA credential enrollment and removal.
type MFAHandler struct {
	repo        *repository.MFARepository
	userRepo    *repository.UserRepository
	orgRepo     *repository.OrgRepository
	attestRepo  *repository.WebAuthnPolicyRepository
	mdsRepo     *repository.MDSRepository
	store       *session.Store
	webAuthn    *walib.WebAuthn // nil when not configured
	rdb         redis.UniversalClient
	totpIssuer  string
}

func NewMFAHandler(cfg *config.Config, pool *pgxpool.Pool, rdb redis.UniversalClient, store *session.Store) *MFAHandler {
	issuer := cfg.Auth.TOTPIssuer
	if issuer == "" {
		issuer = "Clavex"
	}
	h := &MFAHandler{
		repo:        repository.NewMFARepository(pool),
		userRepo:    repository.NewUserRepository(pool),
		orgRepo:     repository.NewOrgRepository(pool),
		attestRepo:  repository.NewWebAuthnPolicyRepository(pool),
		mdsRepo:     repository.NewMDSRepository(pool),
		store:       store,
		rdb:         rdb,
		totpIssuer:  issuer,
	}
	if cfg.Auth.WebAuthnRPID != "" {
		wa, err := walib.New(&walib.Config{
			RPDisplayName: cfg.Auth.WebAuthnRPName,
			RPID:          cfg.Auth.WebAuthnRPID,
			RPOrigins:     cfg.Auth.WebAuthnRPOrigins,
		})
		if err == nil {
			h.webAuthn = wa
		}
	}
	return h
}

// WebAuthn returns the underlying WebAuthn instance (may be nil).
func (h *MFAHandler) WebAuthn() *walib.WebAuthn { return h.webAuthn }

// enforceAttestationPolicy checks the attestation policy for the given org + credential,
// including MDS3 certification-level / revocation checks when the policy requires it.
// It also checks any scoped policies that apply to the user's groups and roles.
func (h *MFAHandler) enforceAttestationPolicy(ctx context.Context, orgID, userID uuid.UUID, credential *walib.Credential) error {
	// Helper to resolve MDS entry for a credential.
	resolveEntry := func(pol *attestation.Policy) attestation.MDSEntry {
		if !pol.RequireMDSCertification && pol.MinCertificationLevel == "" && !pol.ExcludeRevokedAuthenticators {
			return nil
		}
		aaguid, _, _ := attestation.ExtractMetadata(credential)
		dbEntry, err := h.mdsRepo.GetByAAGUID(ctx, aaguid)
		if err != nil || dbEntry == nil {
			return nil
		}
		level := ""
		if dbEntry.CertificationLevel != nil {
			level = *dbEntry.CertificationLevel
		}
		return &attestation.MDSEntryData{
			CertLevel:     level,
			StatusStrings: dbEntry.StatusReports,
		}
	}

	// Org-level base policy.
	policy, err := h.attestRepo.Get(ctx, orgID)
	if err != nil {
		return err
	}
	if policy != nil && policy.Enabled {
		if err := policy.EnforceWithMDS(credential, resolveEntry(policy)); err != nil {
			return err
		}
	}

	// Scoped policies (group / role).
	scoped, err := h.attestRepo.GetScopedForUser(ctx, orgID, userID)
	if err != nil {
		return err
	}
	for _, sp := range scoped {
		if sp == nil || !sp.Enabled {
			continue
		}
		if err := sp.EnforceWithMDS(credential, resolveEntry(sp)); err != nil {
			return err
		}
	}
	return nil
}

// List returns all MFA credentials for the authenticated user (no sensitive data).
func (h *MFAHandler) List(c echo.Context) error {
	userID, err := userIDFromClaims(c)
	if err != nil {
		return err
	}
	creds, err := h.repo.ListByUser(c.Request().Context(), userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if creds == nil {
		creds = make([]*models.MFACredential, 0)
	}
	return c.JSON(http.StatusOK, creds)
}

// Delete removes an MFA credential by ID — admin-only, no policy restriction.
// Scoped to the path's :user_id and :org_id so an admin cannot delete a
// credential belonging to another user or tenant by its (global) credential id.
func (h *MFAHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	credID, err := uuidParam(c, "cred_id")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteForUserInOrg(c.Request().Context(), credID, userID, orgID); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// SelfServiceDelete removes a user's own MFA credential.
// Blocks deletion if tenant or user policy requires MFA and no other credential would remain.
func (h *MFAHandler) SelfServiceDelete(c echo.Context) error {
	credID, err := uuidParam(c, "cred_id")
	if err != nil {
		return err
	}
	userID, err := userIDFromClaims(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrNotFound
	}
	org, err := h.orgRepo.GetByID(ctx, user.OrgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	if org.MFARequired || user.MFARequired {
		count, err := h.repo.CountConfirmedByUser(ctx, userID)
		if err != nil {
			return echo.ErrInternalServerError
		}
		if count <= 1 {
			return echo.NewHTTPError(http.StatusForbidden,
				"two-factor authentication is required; you cannot remove your last credential")
		}
	}

	// Scope the delete to the caller's own credential: credID must belong to the
	// authenticated user (and that user to their org). Without this a user could
	// delete another user's MFA credential by passing its id.
	if err := h.repo.DeleteForUserInOrg(ctx, credID, userID, user.OrgID); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// ── TOTP ─────────────────────────────────────────────────────────────────────

type enrollTOTPResponse struct {
	CredentialID string `json:"credential_id"`
	OTPAuthURI   string `json:"otpauth_uri"` // for QR code generation
	Secret       string `json:"secret"`      // for manual entry
}

// EnrollTOTP generates a new TOTP secret and stores it as pending (unconfirmed).
// Any previous unconfirmed TOTP for this user is replaced.
// POST /api/v1/me/mfa/totp/enroll
func (h *MFAHandler) EnrollTOTP(c echo.Context) error {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	ctx := c.Request().Context()

	// Clean up any leftover pending TOTP before issuing a fresh one.
	_ = h.repo.DeletePendingTOTP(ctx, userID)

	key, err := totpGenerate(totpGenerateOpts{
		Issuer:      h.totpIssuer,
		AccountName: claims.Email,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}

	cred, err := h.repo.CreateTOTP(ctx, userID, "Authenticator App", map[string]interface{}{
		"secret":      key.secret,
		"otpauth_uri": key.url,
		"confirmed":   false,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, enrollTOTPResponse{
		CredentialID: cred.ID.String(),
		OTPAuthURI:   key.url,
		Secret:       key.secret,
	})
}

// GetTOTPQR renders the otpauth URI for a pending (unconfirmed) TOTP credential as a
// 300×300 PNG QR code. The credential must belong to the authenticated user and must not
// yet be confirmed — after confirmation the secret is no longer served for security reasons.
//
// GET /api/v1/me/mfa/totp/:cred_id/qr
func (h *MFAHandler) GetTOTPQR(c echo.Context) error {
	credID, err := uuidParam(c, "cred_id")
	if err != nil {
		return err
	}
	userID, err := userIDFromClaims(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	full, err := h.repo.GetWithData(ctx, credID)
	if err != nil || full.UserID != userID || full.Type != "totp" {
		return echo.ErrNotFound
	}
	if confirmed, _ := full.Data["confirmed"].(bool); confirmed {
		return echo.NewHTTPError(http.StatusGone, "QR no longer available after confirmation")
	}
	otpauthURI, _ := full.Data["otpauth_uri"].(string)
	if otpauthURI == "" {
		// Rebuild from secret if the URI was not persisted (older enrollments).
		secret, _ := full.Data["secret"].(string)
		if secret == "" {
			return echo.ErrInternalServerError
		}
		otpauthURI = "otpauth://totp/" + h.totpIssuer + "?secret=" + secret + "&issuer=" + h.totpIssuer
	}
	return serveTOTPQRPNG(c, otpauthURI)
}

type confirmTOTPRequest struct {
	CredentialID string `json:"credential_id" validate:"required,uuid"`
	Code         string `json:"code"          validate:"required,len=6"`
}

type confirmTOTPResponse struct {
	BackupCodes []string `json:"backup_codes"` // shown exactly once; empty if already issued
}

// ConfirmTOTP verifies the first TOTP code, activates the credential, and issues backup codes.
// POST /api/v1/me/mfa/totp/confirm
func (h *MFAHandler) ConfirmTOTP(c echo.Context) error {
	var req confirmTOTPRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	credID, err := uuid.Parse(req.CredentialID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid credential_id")
	}

	ctx := c.Request().Context()
	cred, err := h.repo.GetWithData(ctx, credID)
	if err != nil {
		return echo.ErrNotFound
	}

	// Guard: already confirmed
	if confirmed, _ := cred.Data["confirmed"].(bool); confirmed {
		return echo.NewHTTPError(http.StatusConflict, "credential already confirmed")
	}

	secret, _ := cred.Data["secret"].(string)
	if !totpValidate(req.Code, secret) {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "invalid TOTP code")
	}

	if err := h.repo.SetTOTPConfirmed(ctx, credID); err != nil {
		return echo.ErrInternalServerError
	}

	// Generate and store backup codes (10 × 8-char alphanumeric, shown once).
	plainCodes, err := h.repo.GenerateBackupCodes(ctx, cred.UserID)
	if err != nil {
		// Non-fatal: credential is confirmed; backup codes will not be shown this time.
		return c.JSON(http.StatusOK, confirmTOTPResponse{BackupCodes: nil})
	}
	return c.JSON(http.StatusOK, confirmTOTPResponse{BackupCodes: plainCodes})
}

// ── WebAuthn ──────────────────────────────────────────────────────────────────

// BeginWebAuthnRegistration starts the WebAuthn registration ceremony.
// POST /api/v1/me/mfa/webauthn/register/begin
func (h *MFAHandler) BeginWebAuthnRegistration(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	ctx := c.Request().Context()

	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrNotFound
	}

	// Build existing credentials for exclusion list.
	existing, err := h.repo.ListWebAuthnByUser(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	waUser := &webAuthnUser{
		id:          userID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}

	options, session, err := h.webAuthn.BeginRegistration(waUser)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "begin registration failed")
	}

	// Persist the challenge in Redis for FinishRegistration.
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return echo.ErrInternalServerError
	}
	redisKey := "mfa:wa:reg:" + userID.String()
	if err := h.rdb.Set(ctx, redisKey, sessionBytes, webAuthnChallengeTTL).Err(); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, options)
}

// FinishWebAuthnRegistration completes the WebAuthn registration ceremony.
// POST /api/v1/me/mfa/webauthn/register/finish
func (h *MFAHandler) FinishWebAuthnRegistration(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	ctx := c.Request().Context()

	// Load and delete challenge from Redis (single-use).
	redisKey := "mfa:wa:reg:" + userID.String()
	sessionBytes, err := h.rdb.GetDel(ctx, redisKey).Bytes()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "registration session not found or expired; call begin first")
	}
	var session walib.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return echo.ErrInternalServerError
	}

	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrNotFound
	}
	existing, err := h.repo.ListWebAuthnByUser(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	waUser := &webAuthnUser{
		id:          userID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}

	credential, err := h.webAuthn.FinishRegistration(waUser, session, c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "WebAuthn verification failed")
	}

	// Enforce attestation policy (including MDS3 certification checks).
	if user.OrgID != (uuid.UUID{}) {
		if polErr := h.enforceAttestationPolicy(ctx, user.OrgID, user.ID, credential); polErr != nil {
			var pv *attestation.PolicyViolation
			if errors.As(polErr, &pv) {
				return echo.NewHTTPError(http.StatusUnprocessableEntity, map[string]string{
					"error":  "attestation_policy_violation",
					"reason": pv.Reason,
				})
			}
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "attestation policy check failed")
		}
	}

	// Serialize the credential into JSONB-compatible form.
	credBytes, err := json.Marshal(credential)
	if err != nil {
		return echo.ErrInternalServerError
	}
	var credData map[string]interface{}
	if err := json.Unmarshal(credBytes, &credData); err != nil {
		return echo.ErrInternalServerError
	}
	aaguid, format, transports := attestation.ExtractMetadata(credential)
	credData["aaguid"] = aaguid
	credData["attestation_format"] = format
	credData["attestation_transports"] = transports
	credData["attestation_verified"] = format != "" && format != "none"

	name := c.QueryParam("name")
	if name == "" {
		name = "Security Key"
	}
	saved, err := h.repo.CreateWebAuthn(ctx, userID, name, credData)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, saved)
}

// ── Passkey (resident key / discoverable credential) ─────────────────────────
//
// These endpoints implement passkey-as-primary authentication:
//   POST /api/v1/me/mfa/passkey/register/begin   → residentKey=required registration
//   POST /api/v1/me/mfa/passkey/register/finish  → stores passkey credential
//   POST /:org_slug/passkey/login/begin           → conditional UI (autofill)
//   POST /:org_slug/passkey/login/finish          → resolves user by credential ID

// BeginPasskeyRegistration initiates a passkey registration ceremony.
// Forces residentKey=required so the credential syncs to iCloud Keychain /
// Google Password Manager.
// POST /api/v1/me/mfa/passkey/register/begin
func (h *MFAHandler) BeginPasskeyRegistration(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	ctx := c.Request().Context()
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrNotFound
	}
	existing, err := h.repo.ListWebAuthnByUser(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	waUser := &webAuthnUser{
		id:          userID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}
	options, session, err := h.webAuthn.BeginRegistration(waUser,
		walib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		walib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "begin passkey registration failed")
	}
	sessionBytes, _ := json.Marshal(session)
	if err := h.rdb.Set(ctx, "mfa:pk:reg:"+userID.String(), sessionBytes, webAuthnChallengeTTL).Err(); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, options)
}

// FinishPasskeyRegistration completes the passkey registration.
// POST /api/v1/me/mfa/passkey/register/finish
func (h *MFAHandler) FinishPasskeyRegistration(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	ctx := c.Request().Context()
	sessionBytes, err := h.rdb.GetDel(ctx, "mfa:pk:reg:"+userID.String()).Bytes()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "passkey registration session expired; call begin first")
	}
	var session walib.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return echo.ErrInternalServerError
	}
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrNotFound
	}
	existing, err := h.repo.ListWebAuthnByUser(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	waUser := &webAuthnUser{
		id:          userID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}
	credential, err := h.webAuthn.FinishRegistration(waUser, session, c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "passkey verification failed")
	}

	// Enforce attestation policy (including MDS3 certification checks).
	if user.OrgID != (uuid.UUID{}) {
		if polErr := h.enforceAttestationPolicy(ctx, user.OrgID, user.ID, credential); polErr != nil {
			var pv *attestation.PolicyViolation
			if errors.As(polErr, &pv) {
				return echo.NewHTTPError(http.StatusUnprocessableEntity, map[string]string{
					"error":  "attestation_policy_violation",
					"reason": pv.Reason,
				})
			}
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "attestation policy check failed")
		}
	}

	credBytes, _ := json.Marshal(credential)
	var credData map[string]interface{}
	_ = json.Unmarshal(credBytes, &credData)
	credData["is_passkey"] = true // tag to distinguish from security-key MFA
	aaguid, format, transports := attestation.ExtractMetadata(credential)
	credData["aaguid"] = aaguid
	credData["attestation_format"] = format
	credData["attestation_transports"] = transports
	credData["attestation_verified"] = format != "" && format != "none"

	name := c.QueryParam("name")
	if name == "" {
		name = "Passkey"
	}
	saved, err := h.repo.CreateWebAuthn(ctx, userID, name, credData)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, saved)
}

// BeginHybridPasskeyRegistration initiates a cross-device passkey registration
// ceremony using FIDO2 Hybrid Transport (CTAP 2.2 caBLE).
//
// Setting AuthenticatorAttachment=CrossPlatform signals to the browser that a
// roaming authenticator is required. On Chrome ≥108, Edge ≥108, and Safari ≥17
// this triggers the browser's native hybrid QR dialog: the desktop displays a
// QR code, the user scans it with their phone, and the passkey is created on
// the phone but bound to the desktop's WebAuthn challenge.
//
// POST /api/v1/me/mfa/passkey/register/begin-hybrid
func (h *MFAHandler) BeginHybridPasskeyRegistration(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	ctx := c.Request().Context()
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrNotFound
	}
	existing, err := h.repo.ListWebAuthnByUser(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	waUser := &webAuthnUser{
		id:          userID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}
	options, session, err := h.webAuthn.BeginRegistration(waUser,
		walib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		walib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			// CrossPlatform forces the browser's hybrid QR flow instead of
			// offering the local platform authenticator (Touch ID, Windows Hello).
			AuthenticatorAttachment: protocol.CrossPlatform,
			UserVerification:        protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "begin hybrid passkey registration failed")
	}
	sessionBytes, _ := json.Marshal(session)
	if err := h.rdb.Set(ctx, "mfa:pk:hybrid:"+userID.String(), sessionBytes, webAuthnChallengeTTL).Err(); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, options)
}

// FinishHybridPasskeyRegistration completes a cross-device passkey registration.
// POST /api/v1/me/mfa/passkey/register/finish-hybrid
func (h *MFAHandler) FinishHybridPasskeyRegistration(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	ctx := c.Request().Context()
	sessionBytes, err := h.rdb.GetDel(ctx, "mfa:pk:hybrid:"+userID.String()).Bytes()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "hybrid registration session expired; call begin-hybrid first")
	}
	var session walib.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return echo.ErrInternalServerError
	}
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrNotFound
	}
	existing, err := h.repo.ListWebAuthnByUser(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	waUser := &webAuthnUser{
		id:          userID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}
	credential, err := h.webAuthn.FinishRegistration(waUser, session, c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "hybrid passkey verification failed")
	}

	// Enforce attestation policy (including MDS3 certification checks).
	if user.OrgID != (uuid.UUID{}) {
		if polErr := h.enforceAttestationPolicy(ctx, user.OrgID, user.ID, credential); polErr != nil {
			var pv *attestation.PolicyViolation
			if errors.As(polErr, &pv) {
				return echo.NewHTTPError(http.StatusUnprocessableEntity, map[string]string{
					"error":  "attestation_policy_violation",
					"reason": pv.Reason,
				})
			}
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "attestation policy check failed")
		}
	}

	credBytes, _ := json.Marshal(credential)
	var credData map[string]interface{}
	_ = json.Unmarshal(credBytes, &credData)
	credData["is_passkey"] = true
	credData["source_transport"] = "hybrid" // records that this passkey was enrolled via cross-device QR
	aaguid, format, transports := attestation.ExtractMetadata(credential)
	credData["aaguid"] = aaguid
	credData["attestation_format"] = format
	credData["attestation_transports"] = transports
	credData["attestation_verified"] = format != "" && format != "none"

	name := c.QueryParam("name")
	if name == "" {
		name = "Phone Passkey"
	}
	saved, err := h.repo.CreateWebAuthn(ctx, userID, name, credData)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, saved)
}

// BeginPasskeyLogin starts a discoverable-credential authentication ceremony.
// No session required — the browser's conditional UI / autofill picker resolves
// the user automatically.
// POST /:org_slug/passkey/login/begin
func (h *MFAHandler) BeginPasskeyLogin(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}
	// mediation=conditional → browser autofill passkey; no user identifier needed.
	options, session, err := h.webAuthn.BeginDiscoverableMediatedLogin(protocol.MediationConditional)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "begin passkey login failed")
	}
	sessionBytes, _ := json.Marshal(session)
	if err := h.rdb.Set(c.Request().Context(), "pk:challenge:"+session.Challenge, sessionBytes, webAuthnChallengeTTL).Err(); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, options)
}

// FinishPasskeyLogin completes the passkey login. The user identity is resolved
// from the credential ID embedded in the authenticator response.
// POST /:org_slug/passkey/login/finish
//
// Request body: WebAuthn PublicKeyCredential JSON (from navigator.credentials.get).
// Query param:  login_session_id — the OIDC login session to bind the user to.
// Header:       X-Passkey-Challenge — the challenge returned by BeginPasskeyLogin.
//
// On success returns {"resume_url": "/<org_slug>/authorize/resume?login_session_id=..."}.
func (h *MFAHandler) FinishPasskeyLogin(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}
	ctx := c.Request().Context()

	// Clients send the challenge as a header so we can load the server-side session
	// without consuming the request body before the WebAuthn library does.
	challenge := c.Request().Header.Get("X-Passkey-Challenge")
	if challenge == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "X-Passkey-Challenge header required")
	}
	sessionBytes, err := h.rdb.GetDel(ctx, "pk:challenge:"+challenge).Bytes()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "passkey challenge not found or expired")
	}
	var session walib.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return echo.ErrInternalServerError
	}

	var resolvedUserID uuid.UUID
	var resolvedCredID uuid.UUID
	discoverHandler := func(rawID, userHandle []byte) (walib.User, error) {
		cred, err := h.repo.GetWebAuthnByCredentialID(ctx, rawID)
		if err != nil {
			return nil, echo.ErrUnauthorized
		}
		resolvedUserID = cred.UserID
		resolvedCredID = cred.ID
		user, err := h.userRepo.GetByID(ctx, cred.UserID)
		if err != nil {
			return nil, echo.ErrUnauthorized
		}
		allCreds, _ := h.repo.ListWebAuthnByUser(ctx, cred.UserID)
		return &webAuthnUser{
			id:          cred.UserID[:],
			name:        user.Email,
			displayName: user.GetFirstName() + " " + user.GetLastName(),
			credentials: credentialsFromModels(allCreds),
		}, nil
	}
	if _, err := h.webAuthn.FinishDiscoverableLogin(discoverHandler, session, c.Request()); err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "passkey verification failed")
	}

	// Stamp the used credential so the self-service device list shows "last used".
	if resolvedCredID != (uuid.UUID{}) {
		_ = h.repo.UpdateLastUsed(ctx, resolvedCredID)
	}

	// Bind the verified user to the OIDC login session so the authorize/resume
	// endpoint can issue an authorization code.
	loginSessID := c.QueryParam("login_session_id")
	if loginSessID != "" && h.store != nil {
		loginSess, err := h.store.GetLoginSession(ctx, loginSessID)
		if err == nil && loginSess != nil {
			loginSess.UserID = resolvedUserID.String()
			loginSess.MFAPending = false
			_ = h.store.SaveLoginSession(ctx, loginSess, 10*time.Minute)
			resumeURL := "/" + loginSess.OrgSlug + "/authorize/resume?login_session_id=" + loginSessID
			return c.JSON(http.StatusOK, map[string]string{
				"user_id":    resolvedUserID.String(),
				"resume_url": resumeURL,
			})
		}
	}

	// Fallback: no login session (e.g. API clients, testing).
	return c.JSON(http.StatusOK, map[string]string{"user_id": resolvedUserID.String()})
}

// ── WebAuthn user entity ──────────────────────────────────────────────────────

type webAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []walib.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                      { return u.id }
func (u *webAuthnUser) WebAuthnName() string                    { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string             { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []walib.Credential { return u.credentials }

// credentialsFromModels converts stored MFA records (WebAuthn type) back to
// webauthn.Credential by round-tripping through JSON.
func credentialsFromModels(creds []*models.MFACredential) []walib.Credential {
	out := make([]walib.Credential, 0, len(creds))
	for _, c := range creds {
		raw, err := json.Marshal(c.Data)
		if err != nil {
			continue
		}
		var wc walib.Credential
		if err := json.Unmarshal(raw, &wc); err != nil {
			continue
		}
		out = append(out, wc)
	}
	return out
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func userIDFromClaims(c echo.Context) (uuid.UUID, error) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return uuid.Nil, echo.ErrUnauthorized
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, echo.ErrUnauthorized
	}
	return id, nil
}

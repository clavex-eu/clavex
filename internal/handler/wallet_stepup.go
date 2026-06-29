package handler

import (
	"context"
	"crypto"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// walletStepUpRiskThreshold is the minimum risk score (0–100) that triggers a
// wallet step-up challenge during token introspection. Matches the login-alert
// default (60) so operators see consistent behaviour across both paths.
const walletStepUpRiskThreshold = 60

// walletStepUpIssuedAfterWindow is how recent the presented credential must be.
// Credentials issued before (now - window) are rejected to prevent credential replay.
const walletStepUpIssuedAfterWindow = 24 * time.Hour

// WalletStepUpHandler handles Continuous Adaptive Authentication wallet step-up
// challenges. When UEBA / risk scoring detects an anomaly during an active
// session (new country, Tor exit, impossible travel …), instead of revoking the
// session Clavex creates a "wallet step-up challenge": the user's IT-Wallet must
// present a fresh SPID or CIE SD-JWT credential to re-establish high assurance.
//
// Public endpoints (per-tenant):
//
//	GET  /:org_slug/wallet/stepup/:challenge_id           → OID4VP auth request
//	POST /:org_slug/wallet/stepup/:challenge_id/response  → wallet submits vp_token
//
// Admin / RS endpoint:
//
//	POST /api/v1/organizations/:org_id/users/:user_id/wallet-stepup → create challenge
//	GET  /api/v1/organizations/:org_id/wallet-stepup/:challenge_id  → poll status
type WalletStepUpHandler struct {
	pool     *pgxpool.Pool
	store    *session.Store
	keys     oidc.Signer
	cfg      baseURLProvider
	ssfDisp  *ssf.Dispatcher
	credRepo *repository.OID4WRepository
	orgRepo  *repository.OrgRepository
}

// NewWalletStepUpHandler constructs the handler with all required dependencies.
func NewWalletStepUpHandler(pool *pgxpool.Pool, store *session.Store, keys oidc.Signer, cfg baseURLProvider) *WalletStepUpHandler {
	return &WalletStepUpHandler{
		pool:     pool,
		store:    store,
		keys:     keys,
		cfg:      cfg,
		credRepo: repository.NewOID4WRepository(pool),
		orgRepo:  repository.NewOrgRepository(pool),
	}
}

// WithSSFDispatcher attaches an SSF dispatcher to fire CAEP assurance-level-change
// events when a challenge is created (risk detected) or completed (step-up passed).
func (h *WalletStepUpHandler) WithSSFDispatcher(d *ssf.Dispatcher) *WalletStepUpHandler {
	h.ssfDisp = d
	return h
}

// ── Admin / RS endpoints ──────────────────────────────────────────────────────

// CreateChallenge handles:
//
//	POST /api/v1/organizations/:org_id/users/:user_id/wallet-stepup
//
// A resource server or admin calls this to explicitly create a wallet step-up
// challenge for a specific user. Returns the challenge ID and the OID4VP wallet
// request URL that the RS can pass to the user's wallet app.
func (h *WalletStepUpHandler) CreateChallenge(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	userIDStr := c.Param("user_id")
	if _, err := uuid.Parse(userIDStr); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}

	org, err := h.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	challenge, err := h.buildChallenge(ctx, orgID, org.Slug, userIDStr, nil, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	}

	if err := h.store.SaveWalletStepUpChallenge(ctx, challenge); err != nil {
		return echo.ErrInternalServerError
	}

	if h.ssfDisp != nil {
		h.dispatchAssuranceLevelChange(orgID, org.Slug, userIDStr, "spid_l2", "none", challenge.ID, "wallet_stepup_required")
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"challenge_id":  challenge.ID,
		"request_url":   h.cfg.BaseURL() + "/" + org.Slug + "/wallet/stepup/" + challenge.ID,
		"expires_at":    challenge.ExpiresAt,
		"status":        challenge.Status,
	})
}

// GetChallengeStatus handles:
//
//	GET /api/v1/organizations/:org_id/wallet-stepup/:challenge_id
//
// Allows a resource server to poll whether the step-up challenge has been
// completed, failed, or is still pending.
func (h *WalletStepUpHandler) GetChallengeStatus(c echo.Context) error {
	ctx := c.Request().Context()
	challengeID := c.Param("challenge_id")
	if challengeID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "challenge_id required")
	}

	challenge, err := h.store.GetWalletStepUpChallenge(ctx, challengeID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "challenge not found or expired")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"challenge_id":  challenge.ID,
		"status":        challenge.Status,
		"user_id":       challenge.UserID,
		"created_at":    challenge.CreatedAt,
		"expires_at":    challenge.ExpiresAt,
		"completed_at":  challenge.CompletedAt,
		"risk_score":    challenge.RiskScore,
		"risk_reasons":  challenge.RiskReasons,
	})
}

// ── Public wallet endpoints ───────────────────────────────────────────────────

// GetRequest handles:
//
//	GET /:org_slug/wallet/stepup/:challenge_id
//
// The wallet fetches the OID4VP authorization request object from this endpoint
// (request_uri pattern, OID4VP §5.2). The response is a JSON authorization
// request with a DCQL query requiring the user's SPID or CIE credential.
func (h *WalletStepUpHandler) GetRequest(c echo.Context) error {
	ctx := c.Request().Context()
	challengeID := c.Param("challenge_id")

	challenge, err := h.store.GetWalletStepUpChallenge(ctx, challengeID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "challenge not found or expired")
	}
	if challenge.Status != "pending" {
		return c.JSON(http.StatusGone, map[string]string{"error": "challenge_expired_or_used"})
	}
	if time.Now().After(challenge.ExpiresAt) {
		return c.JSON(http.StatusGone, map[string]string{"error": "challenge_expired"})
	}

	orgSlug := c.Param("org_slug")
	baseURL := h.cfg.BaseURL()
	responseURI := baseURL + "/" + orgSlug + "/wallet/stepup/" + challengeID + "/response"

	authReq := oid4w.AuthorizationRequest{
		ResponseType:   "vp_token",
		ClientID:       baseURL + "/" + orgSlug,
		ResponseMode:   "direct_post",
		ResponseURI:    responseURI,
		Nonce:          challenge.Nonce,
		ClientMetadata: defaultClientMetadata,
		DCQLQuery:      buildStepUpDCQL(challenge.VCTs),
	}

	return c.JSON(http.StatusOK, authReq)
}

// SubmitResponse handles:
//
//	POST /:org_slug/wallet/stepup/:challenge_id/response
//
// The wallet POSTs the SD-JWT vp_token here. The handler verifies:
//  1. The credential signature is valid (issued by this Clavex instance).
//  2. The KB-JWT nonce matches the challenge nonce (prevents replay).
//  3. The credential iat is within the walletStepUpIssuedAfterWindow.
//  4. The credential sub matches the challenge user ID.
//
// On success: challenge is marked completed and an SSF assurance-level-change
// event is dispatched so all registered resource servers are notified.
func (h *WalletStepUpHandler) SubmitResponse(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	challengeID := c.Param("challenge_id")

	vpToken := c.FormValue("vp_token")
	if vpToken == "" {
		var body struct {
			VPToken string `json:"vp_token"`
		}
		if err := c.Bind(&body); err == nil {
			vpToken = body.VPToken
		}
	}
	if vpToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "vp_token is required",
		})
	}

	challenge, err := h.store.GetWalletStepUpChallenge(ctx, challengeID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "challenge not found or expired",
		})
	}
	if challenge.Status != "pending" || time.Now().After(challenge.ExpiresAt) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "challenge_expired_or_used",
		})
	}

	baseURL := h.cfg.BaseURL()
	responseURI := baseURL + "/" + orgSlug + "/wallet/stepup/" + challengeID + "/response"

	// Credentials in wallet step-up are always issued by this Clavex instance.
	// Use the local public key as the sole trusted issuer.
	issuerID := baseURL + "/" + orgSlug
	trustedIssuers := map[string]crypto.PublicKey{
		issuerID: h.keys.PublicKey(),
	}

	result, err := oid4w.VerifyDCQLPresentation(
		ctx,
		extractDCQLVPToken(vpToken),
		buildStepUpDCQL(challenge.VCTs),
		challenge.Nonce,
		responseURI,
		trustedIssuers,
		true, // step-up credentials are always Clavex-issued (issuer always trusted)
		h.keys.PublicKey(),
	)
	if err != nil {
		_ = h.store.FailWalletStepUpChallenge(ctx, challengeID)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "vp_token_invalid",
			"error_description": err.Error(),
		})
	}

	// Verify the credential was issued recently (replay prevention).
	if iat, ok := result.Claims["iat"].(float64); ok {
		issuedAt := time.Unix(int64(iat), 0)
		if issuedAt.Before(challenge.IssuedAfter) {
			_ = h.store.FailWalletStepUpChallenge(ctx, challengeID)
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "credential_too_old",
				"error_description": "presented credential was issued before the step-up window",
			})
		}
	}

	// Verify the credential subject matches the challenged user.
	if sub, ok := result.Claims["sub"].(string); ok && sub != "" {
		if sub != challenge.UserID {
			_ = h.store.FailWalletStepUpChallenge(ctx, challengeID)
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "credential_subject_mismatch",
				"error_description": "presented credential subject does not match the challenged user",
			})
		}
	}

	if err := h.store.CompleteWalletStepUpChallenge(ctx, challengeID); err != nil {
		return echo.ErrInternalServerError
	}

	// Notify all registered SSF receivers that the assurance level has been
	// re-established (CAEP assurance-level-change: current_level = spid_l2_wallet_bound).
	if h.ssfDisp != nil {
		orgID, _ := uuid.Parse(challenge.OrgID)
		h.dispatchAssuranceLevelChange(
			orgID, orgSlug,
			challenge.UserID,
			"none", "spid_l2_wallet_bound",
			challengeID, "wallet_stepup_completed",
		)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"status":       "completed",
		"challenge_id": challengeID,
	})
}

// ── Introspect integration ────────────────────────────────────────────────────

// CheckAndCreateStepUp is called from OIDCHandler.Introspect when the token is
// active. It computes the risk score for the token's subject and, when risk is
// high and the org has SPID/CIE credential configs, creates a pending step-up
// challenge and returns the enriched fields to include in the introspection response.
//
// Returns nil when no step-up is needed or when step-up cannot be evaluated
// (missing risk scorer, no SPID/CIE configs, etc.).
func (h *WalletStepUpHandler) CheckAndCreateStepUp(
	ctx context.Context,
	orgID uuid.UUID,
	orgSlug string,
	userIDStr string,
	riskScore int,
	riskReasons []string,
) map[string]any {
	// Look for an existing pending challenge (idempotent).
	existing, _ := h.store.GetPendingWalletStepUpChallenge(ctx, orgID.String(), userIDStr)
	if existing != nil {
		return map[string]any{
			"wallet_stepup_required":   true,
			"wallet_stepup_challenge_id": existing.ID,
			"wallet_stepup_url":        h.cfg.BaseURL() + "/" + orgSlug + "/wallet/stepup/" + existing.ID,
		}
	}

	challenge, err := h.buildChallenge(ctx, orgID, orgSlug, userIDStr, &riskScore, riskReasons)
	if err != nil {
		return nil
	}
	if err := h.store.SaveWalletStepUpChallenge(ctx, challenge); err != nil {
		return nil
	}

	if h.ssfDisp != nil {
		h.dispatchAssuranceLevelChange(orgID, orgSlug, userIDStr, "spid_l2", "none", challenge.ID, "wallet_stepup_required")
	}

	return map[string]any{
		"wallet_stepup_required":     true,
		"wallet_stepup_challenge_id": challenge.ID,
		"wallet_stepup_url":          h.cfg.BaseURL() + "/" + orgSlug + "/wallet/stepup/" + challenge.ID,
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// buildChallenge fetches the org's SPID/CIE credential VCTs and constructs a
// WalletStepUpChallenge. Returns an error when the org has no SPID/CIE configs.
func (h *WalletStepUpHandler) buildChallenge(
	ctx context.Context,
	orgID uuid.UUID,
	orgSlug string,
	userID string,
	riskScore *int,
	riskReasons []string,
) (*session.WalletStepUpChallenge, error) {
	spidCreds, _ := h.credRepo.GetCredentialConfigsBySourceIdp(ctx, orgID, "spid")
	cieCreds, _ := h.credRepo.GetCredentialConfigsBySourceIdp(ctx, orgID, "cie")

	vcts := make([]string, 0, len(spidCreds)+len(cieCreds))
	for _, cc := range spidCreds {
		vcts = append(vcts, cc.VCT)
	}
	for _, cc := range cieCreds {
		vcts = append(vcts, cc.VCT)
	}
	if len(vcts) == 0 {
		return nil, errorf("organization has no SPID/CIE credential configurations")
	}

	score := 0
	if riskScore != nil {
		score = *riskScore
	}

	now := time.Now()
	challenge := &session.WalletStepUpChallenge{
		ID:          uuid.NewString(),
		OrgID:       orgID.String(),
		UserID:      userID,
		OrgSlug:     orgSlug,
		Nonce:       uuid.NewString(),
		VCTs:        vcts,
		IssuedAfter: now.Add(-walletStepUpIssuedAfterWindow),
		Status:      "pending",
		CreatedAt:   now,
		ExpiresAt:   now.Add(15 * time.Minute),
		RiskScore:   score,
		RiskReasons: riskReasons,
	}
	return challenge, nil
}

// buildStepUpDCQL returns a minimal DCQL query (OID4VP 1.0 Final §6) that
// accepts any credential with one of the provided VCT values.
func buildStepUpDCQL(vcts []string) map[string]any {
	return map[string]any{
		"credentials": map[string]any{
			"stepup_identity": map[string]any{
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": vcts,
				},
			},
		},
	}
}

// dispatchAssuranceLevelChange fires a CAEP assurance-level-change SSF SET
// asynchronously so the handler is never blocked by SSF delivery.
func (h *WalletStepUpHandler) dispatchAssuranceLevelChange(
	orgID uuid.UUID,
	orgSlug string,
	sub string,
	previousLevel string,
	currentLevel string,
	challengeID string,
	reasonAdmin string,
) {
	body := map[string]any{
		"previous_level": previousLevel,
		"current_level":  currentLevel,
		"reason_admin":   reasonAdmin,
		"challenge_id":   challengeID,
	}
	if currentLevel == "none" {
		// Include the step-up URL so push receivers can redirect the wallet.
		body["wallet_stepup_url"] = h.cfg.BaseURL() + "/" + orgSlug + "/wallet/stepup/" + challengeID
	}
	go h.ssfDisp.Dispatch(orgID, orgSlug, sub, ssf.EventAssuranceLvlChange, body)
}

// errorf returns a formatted error without importing fmt.
func errorf(msg string) error {
	return echo.NewHTTPError(http.StatusUnprocessableEntity, msg)
}

// stepUpFields returns the wallet step-up enrichment fields for a known challenge ID.
// This is used by OIDCHandler to enrich introspect responses without repeating
// the URL construction logic outside of this package.
func (h *WalletStepUpHandler) stepUpFields(orgSlug, challengeID string) map[string]any {
	return map[string]any{
		"wallet_stepup_required":     true,
		"wallet_stepup_challenge_id": challengeID,
		"wallet_stepup_url":          h.cfg.BaseURL() + "/" + orgSlug + "/wallet/stepup/" + challengeID,
	}
}

package handler

// ElevateHandler implements the step-up MFA (Elevate) API.
//
// Pattern: a resource server calls POST /elevate with the user's access token
// and a reason; Clavex returns a challenge ID that the user completes on their
// device; the resource server polls GET /elevate/:id and receives an elevated
// short-lived JWT (acr=urn:clavex:step-up, TTL=5min) on completion.
//
// Endpoints (all scoped under /api/v1/organizations/:org_id):
//
//	POST   /elevate                                — create challenge
//	GET    /elevate/:challenge_id                  — poll status
//	POST   /elevate/:challenge_id/verify           — complete with TOTP or WebAuthn credential
//	POST   /elevate/:challenge_id/webauthn/begin   — WebAuthn assertion options

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/metrics"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/tracing"
	walib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
)

const (
	elevateTTL            = 10 * time.Minute
	elevatedTokenTTL      = 5 * time.Minute
	elevateWAChallengeKey = "elevate:wa:" // + challenge_id
)

// ElevateChallenge mirrors an elevate_challenges row.
type ElevateChallenge struct {
	ID             uuid.UUID  `json:"id"`
	OrgID          uuid.UUID  `json:"org_id"`
	UserID         uuid.UUID  `json:"user_id"`
	Reason         string     `json:"reason"`
	AllowedMethods []string   `json:"allowed_methods"`
	Status         string     `json:"status"`
	ElevatedToken  *string    `json:"elevated_token,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// ElevateHandler handles step-up MFA challenges.
type ElevateHandler struct {
	pool     *pgxpool.Pool
	rdb      redis.UniversalClient
	mfaRepo  *repository.MFARepository
	orgRepo  *repository.OrgRepository
	userRepo *repository.UserRepository
	keys     oidc.Signer
	cfg      *config.Config
	webAuthn *walib.WebAuthn
}

// NewElevateHandler creates the handler. wa may be nil if WebAuthn is not configured.
func NewElevateHandler(cfg *config.Config, pool *pgxpool.Pool, rdb redis.UniversalClient, keys oidc.Signer, wa *walib.WebAuthn) *ElevateHandler {
	return &ElevateHandler{
		pool:     pool,
		rdb:      rdb,
		mfaRepo:  repository.NewMFARepository(pool),
		orgRepo:  repository.NewOrgRepository(pool),
		userRepo: repository.NewUserRepository(pool),
		keys:     keys,
		cfg:      cfg,
		webAuthn: wa,
	}
}

// ── DB helpers ────────────────────────────────────────────────────────────────

func (h *ElevateHandler) insertChallenge(ctx context.Context, orgID, userID uuid.UUID, reason string, allowed []string, callerIP, callerAgent string) (*ElevateChallenge, error) {
	ch := &ElevateChallenge{}
	var callerIPVal, callerAgentVal interface{}
	if callerIP != "" {
		callerIPVal = callerIP
	}
	if callerAgent != "" {
		callerAgentVal = callerAgent
	}
	err := h.pool.QueryRow(ctx, `
		INSERT INTO elevate_challenges
		    (org_id, user_id, reason, allowed_methods, caller_ip, caller_agent)
		VALUES ($1, $2, $3, $4, $5::inet, $6)
		RETURNING id, org_id, user_id, reason, allowed_methods, status,
		          elevated_token, expires_at, created_at, completed_at`,
		orgID, userID, reason, allowed, callerIPVal, callerAgentVal,
	).Scan(
		&ch.ID, &ch.OrgID, &ch.UserID, &ch.Reason, &ch.AllowedMethods,
		&ch.Status, &ch.ElevatedToken, &ch.ExpiresAt, &ch.CreatedAt, &ch.CompletedAt,
	)
	return ch, err
}

func (h *ElevateHandler) loadChallenge(ctx context.Context, orgID, challengeID uuid.UUID) (*ElevateChallenge, error) {
	ch := &ElevateChallenge{}
	err := h.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, reason, allowed_methods, status,
		       elevated_token, expires_at, created_at, completed_at
		FROM elevate_challenges
		WHERE id = $1 AND org_id = $2`, challengeID, orgID,
	).Scan(
		&ch.ID, &ch.OrgID, &ch.UserID, &ch.Reason, &ch.AllowedMethods,
		&ch.Status, &ch.ElevatedToken, &ch.ExpiresAt, &ch.CreatedAt, &ch.CompletedAt,
	)
	return ch, err
}

func (h *ElevateHandler) markCompleted(ctx context.Context, challengeID uuid.UUID, elevatedToken string) error {
	_, err := h.pool.Exec(ctx, `
		UPDATE elevate_challenges
		SET status='completed', elevated_token=$2, completed_at=NOW()
		WHERE id=$1 AND status='pending'`, challengeID, elevatedToken)
	return err
}

func (h *ElevateHandler) gcExpired(ctx context.Context) {
	_, _ = h.pool.Exec(ctx, `
		UPDATE elevate_challenges SET status='expired'
		WHERE status='pending' AND expires_at < NOW()`)
}

// ── Token helper ──────────────────────────────────────────────────────────────

func (h *ElevateHandler) buildIssuer(c echo.Context, orgSlug string) string {
	scheme := "http"
	if h.cfg.HTTP.TLSCertFile != "" {
		scheme = "https"
	}
	host := c.Request().Header.Get("X-Forwarded-Host")
	if host == "" {
		host = c.Request().Host
	}
	if host == "" {
		host = h.cfg.HTTP.BaseDomain
	}
	return fmt.Sprintf("%s://%s/%s", scheme, host, orgSlug)
}

func (h *ElevateHandler) issueElevatedToken(issuer string, userID, orgID uuid.UUID, email, reason string) (string, error) {
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(userID.String()).
		Audience([]string{issuer}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(elevatedTokenTTL)).
		JwtID(uuid.NewString()).
		Claim("org_id", orgID.String()).
		Claim("email", email).
		Claim("acr", "urn:clavex:step-up").
		Claim("step_up_reason", reason).
		Claim("token_use", "elevated").
		Build()
	if err != nil {
		return "", err
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, h.keys.KID())
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, h.keys.CryptoSigner(), jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// ── Request/response types ────────────────────────────────────────────────────

type createElevateRequest struct {
	BearerToken    string   `json:"bearer_token"    validate:"required"`
	Reason         string   `json:"reason"          validate:"required,max=255"`
	AllowedMethods []string `json:"allowed_methods"` // ["totp","webauthn"] — empty = all
}

type verifyElevateRequest struct {
	Method     string          `json:"method"     validate:"required,oneof=totp webauthn"`
	Code       string          `json:"code"`       // TOTP
	Credential json.RawMessage `json:"credential"` // WebAuthn assertion
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// Create handles POST /api/v1/organizations/:org_id/elevate
func (h *ElevateHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createElevateRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	for _, m := range req.AllowedMethods {
		if m != "totp" && m != "webauthn" {
			return echo.NewHTTPError(http.StatusBadRequest,
				fmt.Sprintf("invalid method %q: must be totp or webauthn", m))
		}
	}

	ctx := c.Request().Context()
	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.elevate.create")
	defer span.End()
	span.SetAttributes(attribute.String("org_id", orgID.String()))
	org, err := h.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	issuer := h.buildIssuer(c, org.Slug)
	tc := &oidc.TokenConfig{Keys: h.keys, Issuer: issuer}
	tok, _, _, err := tc.VerifyAccessToken(req.BearerToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired access token")
	}

	userID, err := uuid.Parse(tok.Subject())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "token sub is not a valid user ID")
	}
	tokOrgID, _ := tok.Get("org_id")
	if fmt.Sprint(tokOrgID) != orgID.String() {
		return echo.NewHTTPError(http.StatusForbidden, "token org_id does not match")
	}

	creds, err := h.mfaRepo.ListByUser(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	available := elevateMethods(creds, req.AllowedMethods, h.webAuthn != nil)
	if len(available) == 0 {
		return echo.NewHTTPError(http.StatusUnprocessableEntity,
			"user has no enrolled MFA credentials matching the requested methods")
	}

	ch, err := h.insertChallenge(ctx, orgID, userID, req.Reason, req.AllowedMethods,
		c.RealIP(), c.Request().UserAgent())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, err.Error())
		return echo.ErrInternalServerError
	}

	metrics.ElevateChallengesTotal.WithLabelValues("created").Inc()
	return c.JSON(http.StatusCreated, map[string]any{
		"challenge_id":      ch.ID,
		"status":            ch.Status,
		"expires_at":        ch.ExpiresAt,
		"available_methods": available,
		"reason":            ch.Reason,
	})
}

// Get handles GET /api/v1/organizations/:org_id/elevate/:challenge_id
func (h *ElevateHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	challengeID, err := uuidParam(c, "challenge_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	h.gcExpired(ctx)

	ch, err := h.loadChallenge(ctx, orgID, challengeID)
	if err != nil {
		return echo.ErrNotFound
	}

	resp := map[string]any{
		"challenge_id": ch.ID,
		"status":       ch.Status,
		"reason":       ch.Reason,
		"expires_at":   ch.ExpiresAt,
		"created_at":   ch.CreatedAt,
	}
	if ch.CompletedAt != nil {
		resp["completed_at"] = ch.CompletedAt
	}
	if ch.Status == "completed" && ch.ElevatedToken != nil {
		resp["elevated_token"] = *ch.ElevatedToken
		resp["token_ttl_seconds"] = int(elevatedTokenTTL.Seconds())
	}
	return c.JSON(http.StatusOK, resp)
}

// Verify handles POST /api/v1/organizations/:org_id/elevate/:challenge_id/verify
func (h *ElevateHandler) Verify(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	challengeID, err := uuidParam(c, "challenge_id")
	if err != nil {
		return err
	}
	var req verifyElevateRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	ctx := c.Request().Context()
	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.elevate.verify")
	defer span.End()
	span.SetAttributes(
		attribute.String("org_id", orgID.String()),
		attribute.String("challenge_id", challengeID.String()),
	)
	h.gcExpired(ctx)

	ch, err := h.loadChallenge(ctx, orgID, challengeID)
	if err != nil {
		return echo.ErrNotFound
	}
	switch ch.Status {
	case "expired":
		return echo.NewHTTPError(http.StatusGone, "challenge expired")
	case "completed":
		return echo.NewHTTPError(http.StatusConflict, "challenge already completed")
	}
	if len(ch.AllowedMethods) > 0 && !elevateContains(ch.AllowedMethods, req.Method) {
		return echo.NewHTTPError(http.StatusBadRequest,
			fmt.Sprintf("method %q not allowed for this challenge", req.Method))
	}

	org, err := h.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	user, err := h.userRepo.GetByID(ctx, ch.UserID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	switch req.Method {
	case "totp":
		if err := h.verifyTOTP(ctx, ch.UserID, req.Code); err != nil {
			span.SetStatus(otelcodes.Error, "invalid TOTP code")
			metrics.ElevateChallengesTotal.WithLabelValues("failed").Inc()
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid TOTP code")
		}
	case "webauthn":
		if h.webAuthn == nil {
			span.SetStatus(otelcodes.Error, "WebAuthn not configured")
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "WebAuthn not configured")
		}
		if err := h.verifyWebAuthn(ctx, ch, c, req.Credential); err != nil {
			span.RecordError(err)
			span.SetStatus(otelcodes.Error, "WebAuthn verification failed")
			metrics.ElevateChallengesTotal.WithLabelValues("failed").Inc()
			return echo.NewHTTPError(http.StatusUnauthorized, "WebAuthn verification failed: "+err.Error())
		}
	}

	issuer := h.buildIssuer(c, org.Slug)
	elevatedToken, err := h.issueElevatedToken(issuer, ch.UserID, orgID, user.Email, ch.Reason)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if err := h.markCompleted(ctx, ch.ID, elevatedToken); err != nil {
		return echo.ErrInternalServerError
	}
	metrics.ElevateChallengesTotal.WithLabelValues("completed").Inc()

	return c.JSON(http.StatusOK, map[string]any{
		"challenge_id":      ch.ID,
		"status":            "completed",
		"elevated_token":    elevatedToken,
		"token_ttl_seconds": int(elevatedTokenTTL.Seconds()),
		"acr":               "urn:clavex:step-up",
	})
}

// BeginWebAuthn handles POST /api/v1/organizations/:org_id/elevate/:challenge_id/webauthn/begin
func (h *ElevateHandler) BeginWebAuthn(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "WebAuthn not configured")
	}
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	challengeID, err := uuidParam(c, "challenge_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	ch, err := h.loadChallenge(ctx, orgID, challengeID)
	if err != nil {
		return echo.ErrNotFound
	}
	if ch.Status != "pending" {
		return echo.NewHTTPError(http.StatusConflict, "challenge is not pending")
	}

	waCreds, err := h.mfaRepo.ListWebAuthnByUser(ctx, ch.UserID)
	if err != nil || len(waCreds) == 0 {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "no WebAuthn credentials enrolled")
	}
	waUser := &webAuthnUser{
		id:          ch.UserID[:],
		credentials: credentialsFromModels(waCreds),
	}

	opts, session, err := h.webAuthn.BeginLogin(waUser)
	if err != nil {
		return echo.ErrInternalServerError
	}
	sessionBytes, _ := json.Marshal(session)
	if err := h.rdb.Set(ctx, elevateWAChallengeKey+ch.ID.String(), sessionBytes, elevateTTL).Err(); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, opts)
}

// ── Internal verifiers ────────────────────────────────────────────────────────

func (h *ElevateHandler) verifyTOTP(ctx context.Context, userID uuid.UUID, code string) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("empty code")
	}
	creds, err := h.mfaRepo.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, cred := range creds {
		if cred.Type != "totp" {
			continue
		}
		full, err := h.mfaRepo.GetWithData(ctx, cred.ID)
		if err != nil {
			continue
		}
		confirmed, _ := full.Data["confirmed"].(bool)
		if !confirmed {
			continue
		}
		secret, _ := full.Data["secret"].(string)
		if secret == "" {
			continue
		}
		if totp.Validate(code, secret) {
			return nil
		}
	}
	return fmt.Errorf("totp: no matching credential")
}

func (h *ElevateHandler) verifyWebAuthn(ctx context.Context, ch *ElevateChallenge, c echo.Context, credJSON json.RawMessage) error {
	redisKey := elevateWAChallengeKey + ch.ID.String()
	sessionBytes, err := h.rdb.GetDel(ctx, redisKey).Bytes()
	if err != nil {
		return fmt.Errorf("webauthn session not found — call /webauthn/begin first")
	}
	var session walib.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return fmt.Errorf("webauthn session corrupt")
	}

	waCreds, err := h.mfaRepo.ListWebAuthnByUser(ctx, ch.UserID)
	if err != nil {
		return err
	}
	waUser := &webAuthnUser{
		id:          ch.UserID[:],
		credentials: credentialsFromModels(waCreds),
	}

	// Replace request body with the credential JSON for FinishLogin.
	c.Request().Body = io.NopCloser(strings.NewReader(string(credJSON)))
	_, err = h.webAuthn.FinishLogin(waUser, session, c.Request())
	return err
}

// ── Package-local helpers ─────────────────────────────────────────────────────

func elevateMethods(creds []*models.MFACredential, allowed []string, webAuthnEnabled bool) []string {
	has := map[string]bool{}
	for _, c := range creds {
		if c.Type == "totp" {
			has["totp"] = true
		}
		if c.Type == "webauthn" && webAuthnEnabled {
			has["webauthn"] = true
		}
	}
	if len(allowed) == 0 {
		out := make([]string, 0, len(has))
		for m := range has {
			out = append(out, m)
		}
		return out
	}
	var out []string
	for _, m := range allowed {
		if has[m] {
			out = append(out, m)
		}
	}
	return out
}

func elevateContains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

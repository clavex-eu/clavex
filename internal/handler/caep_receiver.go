package handler

// caep_receiver.go — SSF/CAEP inbound event receiver.
//
// Clavex acts as both an SSF *transmitter* (push/poll delivery to RS clients)
// and as an SSF *receiver* for signals coming from upstream providers like the
// SPID/CIE identity providers, national UEBA brokers, or fraud-detection feeds.
//
// When a CAEP event arrives that indicates a session anomaly — specifically
// assurance-level-change, session-revoked or token-claims-change — Clavex
// immediately creates (or re-uses) a WalletStepUp challenge for the affected
// user.  The next time the Resource Server calls /introspect it will receive
// the step-up fields and redirect the user to their IT-Wallet for silent
// re-authentication.  The session is NOT revoked so the UX is non-disruptive
// for legitimate users.
//
// Endpoint registered in server.go:
//
//	POST /:org_slug/ssf/events
//
// Spec references:
//   - RFC 8935 §4 (Push-Based SET Delivery) — request format
//   - RFC 8417 §2 (Security Event Token) — SET structure
//   - OpenID CAEP 1.0 §5 (assurance-level-change event)

import (
	"context"
	"net/http"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// CAEPReceiverHandler accepts inbound CAEP Security Event Tokens from upstream
// SSF transmitters (e.g. the SPID/CIE national identity provider or an
// external UEBA service) and reacts by triggering wallet step-up challenges.
type CAEPReceiverHandler struct {
	orgs         *repository.OrgRepository
	userRepo     *repository.UserRepository
	walletStepUp *WalletStepUpHandler
	ssfDisp      *ssf.Dispatcher
	// trusted maps a SET issuer to its JWKS URI; jwksCache fetches/caches the keys.
	// Inbound SETs are accepted only from an issuer in this map, with a valid
	// signature. Empty ⇒ the receiver rejects every SET (fail-closed).
	trusted   map[string]string
	jwksCache *jwk.Cache
}

// WithTrustedTransmitters configures the allow-list of SSF transmitters whose
// signed SETs the receiver accepts. Without it the receiver rejects all events.
func (h *CAEPReceiverHandler) WithTrustedTransmitters(ts []config.SSFTrustedTransmitter) *CAEPReceiverHandler {
	if len(ts) == 0 {
		return h
	}
	cache := jwk.NewCache(context.Background())
	m := make(map[string]string, len(ts))
	for _, t := range ts {
		if t.Issuer == "" || t.JWKSURI == "" {
			continue
		}
		m[t.Issuer] = t.JWKSURI
		_ = cache.Register(t.JWKSURI)
	}
	if len(m) == 0 {
		return h
	}
	h.trusted = m
	h.jwksCache = cache
	return h
}

// verifySET authenticates an inbound Security Event Token: it selects the trusted
// transmitter by the (unverified) issuer, then verifies the signature against that
// transmitter's JWKS plus exp/iat/iss. SETs from unknown issuers, unsigned SETs,
// or any SET when no transmitters are configured are rejected (fail-closed). The
// returned error is an *echo.HTTPError ready to return from the handler.
func (h *CAEPReceiverHandler) verifySET(ctx context.Context, rawJWT string) (jwt.Token, error) {
	unverified, perr := jwt.Parse([]byte(rawJWT), jwt.WithVerify(false), jwt.WithValidate(false))
	if perr != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid SET JWT")
	}
	jwksURI := ""
	if h.jwksCache != nil {
		jwksURI = h.trusted[unverified.Issuer()]
	}
	if jwksURI == "" {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "untrusted SET issuer")
	}
	keySet, kerr := h.jwksCache.Get(ctx, jwksURI)
	if kerr != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "cannot verify SET signature")
	}
	tok, parseErr := jwt.Parse(
		[]byte(rawJWT),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(unverified.Issuer()),
		jwt.WithAcceptableSkew(60*1000*1000*1000), // 60 s clock skew
	)
	if parseErr != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "SET signature verification failed")
	}
	return tok, nil
}

// NewCAEPReceiverHandler creates the handler.  walletStepUp may be nil if
// SPID/CIE credential configs are not configured for this deployment.
func NewCAEPReceiverHandler(
	orgs *repository.OrgRepository,
	userRepo *repository.UserRepository,
	walletStepUp *WalletStepUpHandler,
	ssfDisp *ssf.Dispatcher,
) *CAEPReceiverHandler {
	return &CAEPReceiverHandler{
		orgs:         orgs,
		userRepo:     userRepo,
		walletStepUp: walletStepUp,
		ssfDisp:      ssfDisp,
	}
}

// ReceiveEvent handles POST /:org_slug/ssf/events
//
// Accepts a push-delivered SET per RFC 8935 §4.
// The body must be a compact serialized JWT (Content-Type: application/secevent+jwt).
// The JWT is parsed without signature verification here — in a production
// deployment the transmitter's public key would be registered per-stream and
// verified.  The parsed claims drive the step-up logic.
//
// Supported CAEP event types:
//   - assurance-level-change  → create wallet step-up challenge
//   - session-revoked         → create wallet step-up challenge (re-auth required)
//   - token-claims-change     → create wallet step-up challenge (identity drift)
//
// Non-actionable event types (e.g. account-enabled) are acknowledged silently
// with 202 Accepted so the transmitter does not retry them.
func (h *CAEPReceiverHandler) ReceiveEvent(c echo.Context) error {
	ctx := c.Request().Context()

	// ── 1. Resolve org ────────────────────────────────────────────────────────
	org, err := h.orgs.GetBySlug(ctx, c.Param("org_slug"))
	if err != nil || org == nil {
		return echo.ErrNotFound
	}

	// ── 2. Parse SET (compact JWT) ────────────────────────────────────────────
	// RFC 8935 §4.1: Content-Type MUST be application/secevent+jwt.
	// We parse without verification here; the stream secret / sender public key
	// is validated by the stream-level HMAC check inside VerifyStreamSecret when
	// a stream configuration has been registered by the operator.
	ct := c.Request().Header.Get("Content-Type")
	if ct != "application/secevent+jwt" {
		return echo.NewHTTPError(http.StatusUnsupportedMediaType,
			"Content-Type must be application/secevent+jwt")
	}

	rawJWT, readErr := readBodyString(c)
	if readErr != nil || rawJWT == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "empty body")
	}

	// ── Authenticate the SET ──────────────────────────────────────────────────
	tok, authErr := h.verifySET(ctx, rawJWT)
	if authErr != nil {
		return authErr
	}

	// ── 3. Extract events map (RFC 8417 §2.2) ────────────────────────────────
	eventsRaw, ok := tok.Get("events")
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "SET missing 'events' claim")
	}
	events, ok := eventsRaw.(map[string]interface{})
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "SET 'events' claim is not an object")
	}

	// ── 4. Extract subject (RFC 8417 §2.4) ───────────────────────────────────
	// We support iss_sub (the most common) and email subject formats.
	subjectRaw, _ := tok.Get("sub_id")
	if subjectRaw == nil {
		subjectRaw, _ = tok.Get("sub")
	}

	userIDStr, resolveErr := h.resolveSubject(ctx, org.ID, subjectRaw)
	if resolveErr != nil || userIDStr == "" {
		// Unknown subject — acknowledge silently to avoid transmitter retry storms.
		return c.NoContent(http.StatusAccepted)
	}

	// ── 5. Act on event type ──────────────────────────────────────────────────
	stepUpTriggered := false
	for eventType, payloadRaw := range events {
		switch eventType {
		case ssf.EventAssuranceLvlChange,
			ssf.EventSessionRevoked,
			ssf.EventTokenClaimsChange:
			// These event types indicate a session anomaly that requires
			// re-authentication via a fresh wallet credential presentation.
			if h.walletStepUp == nil {
				continue
			}

			payload, _ := payloadRaw.(map[string]interface{})
			riskScore, riskReasons := extractRiskFromPayload(payload, eventType)

			fields := h.walletStepUp.CheckAndCreateStepUp(
				ctx,
				org.ID,
				org.Slug,
				userIDStr,
				riskScore,
				riskReasons,
			)
			if fields != nil {
				stepUpTriggered = true
			}

		case ssf.EventSessionsRevoked,
			ssf.EventAccountDisabled:
			// Hard revocation — for now we also trigger a step-up instead of
			// immediately revoking (graceful degradation). A full session revocation
			// path can be added in the sessions handler when needed.
			if h.walletStepUp == nil {
				continue
			}
			fields := h.walletStepUp.CheckAndCreateStepUp(
				ctx,
				org.ID,
				org.Slug,
				userIDStr,
				walletStepUpRiskThreshold, // treat hard revocation as maximum risk
				[]string{"caep:sessions_revoked"},
			)
			if fields != nil {
				stepUpTriggered = true
			}

		default:
			// Unknown / non-actionable event type — acknowledge silently.
		}
	}

	// ── 6. Acknowledge per RFC 8935 §4.4 ─────────────────────────────────────
	// 202 Accepted. The response is intentionally constant (no per-subject hint)
	// so it cannot be used as a user-enumeration / step-up oracle.
	_ = stepUpTriggered
	return c.JSON(http.StatusAccepted, map[string]any{"status": "accepted"})
}

// resolveSubject maps the SET sub_id / sub claim to a local Clavex user ID.
// Supports:
//   - iss_sub format: {"format":"iss_sub","iss":"...","sub":"<id>"}
//   - email format:   {"format":"email","email":"..."}
//   - plain string:   "<uuid>" (direct Clavex user ID)
func (h *CAEPReceiverHandler) resolveSubject(
	_ context.Context,
	_ uuid.UUID,
	subjectRaw interface{},
) (string, error) {
	switch s := subjectRaw.(type) {
	case string:
		// Try as a direct UUID user ID first.
		if _, err := uuid.Parse(s); err == nil {
			return s, nil
		}
		return "", nil

	case map[string]interface{}:
		format, _ := s["format"].(string)
		switch format {
		case "iss_sub":
			sub, _ := s["sub"].(string)
			if sub == "" {
				return "", nil
			}
			// If sub is already a UUID, return directly.
			if _, err := uuid.Parse(sub); err == nil {
				return sub, nil
			}
			return "", nil

		case "opaque":
			if id, ok := s["id"].(string); ok {
				if _, err := uuid.Parse(id); err == nil {
					return id, nil
				}
			}
		}
	}
	return "", nil
}

// extractRiskFromPayload derives a risk score and reason flags from the CAEP
// event payload.  Different event types carry different semantic payloads.
func extractRiskFromPayload(payload map[string]interface{}, eventType string) (int, []string) {
	reasons := []string{"caep:" + shortEventName(eventType)}

	// Many CAEP producers include a "reason_admin" or "initiating_entity" field.
	if ra, ok := payload["reason_admin"].(string); ok && ra != "" {
		reasons = append(reasons, "reason:"+ra)
	}

	// Map event type to a default risk score.
	switch eventType {
	case ssf.EventAssuranceLvlChange:
		// Explicit assurance-level-change: honour the previous vs current delta.
		prev, _ := payload["previous_level"].(string)
		cur, _ := payload["current_level"].(string)
		if prev != "" && cur != "" && prev != cur {
			reasons = append(reasons, "assurance:"+prev+"->"+cur)
		}
		return walletStepUpRiskThreshold, reasons

	case ssf.EventTokenClaimsChange:
		return walletStepUpRiskThreshold, reasons

	case ssf.EventSessionRevoked:
		return walletStepUpRiskThreshold + 10, reasons // slightly higher urgency

	default:
		return walletStepUpRiskThreshold, reasons
	}
}

// shortEventName returns the last path segment of a CAEP event URI.
// e.g. "https://schemas.openid.net/.../session-revoked" → "session-revoked".
func shortEventName(eventType string) string {
	for i := len(eventType) - 1; i >= 0; i-- {
		if eventType[i] == '/' {
			return eventType[i+1:]
		}
	}
	return eventType
}

// readBodyString reads the raw request body as a string.
func readBodyString(c echo.Context) (string, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 512)
	body := c.Request().Body
	if body == nil {
		return "", nil
	}
	defer body.Close()
	for {
		n, err := body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(buf), nil
}

// ── JWT parse option helpers ──────────────────────────────────────────────────

// jwaAlgorithmNone is used when parsing SETs without signature verification.
var _ = jwa.NoSignature

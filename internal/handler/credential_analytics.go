package handler

// credential_analytics.go — Privacy-Preserving Analytics for credential issuers.
//
// Public endpoints (unauthenticated, called by wallets and verifiers):
//
//   GET  /:org_slug/oid4vci/analytics/public-key
//        Returns the org's RSA analytics public key in JWK Set format.
//        Wallets use this to blind their token before requesting a signature.
//
//   POST /:org_slug/oid4vci/analytics/token
//        Blind-signing endpoint.  Body: {"blinded": "<hex m_blind>"}.
//        Returns {"signed": "<hex s_blind>"}.
//        The issuer signs without seeing the actual token value.
//
//   POST /:org_slug/oid4vci/analytics/report
//        Anonymous presentation report.
//        Body: {"token_msg":"<hex>","token_sig":"<hex>","vct":"...","purpose_hint":"...","country_hint":"..."}
//        Verifies the blind signature, marks the token spent, increments counters.
//
// Admin endpoint (JWT-authenticated, scoped to org):
//
//   GET  /api/v1/organizations/:org_id/oid4vci/analytics/summary
//        Returns aggregate presentation counts.  No PII; no individual records.

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/analytics"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog/log"
)

// CredentialAnalyticsHandler handles all three analytics endpoints.
type CredentialAnalyticsHandler struct {
	repo    *repository.CredentialAnalyticsRepository
	orgRepo *repository.OrgRepository
}

func NewCredentialAnalyticsHandler(pool *pgxpool.Pool) *CredentialAnalyticsHandler {
	return &CredentialAnalyticsHandler{
		repo:    repository.NewCredentialAnalyticsRepository(pool),
		orgRepo: repository.NewOrgRepository(pool),
	}
}

// ── Public key ────────────────────────────────────────────────────────────────

// PublicKey handles GET /:org_slug/oid4vci/analytics/public-key
//
// Returns the RSA-2048 analytics signing key as a JWKS so wallets can blind
// their token before calling the signing endpoint.  The key is auto-generated
// on first request.
func (h *CredentialAnalyticsHandler) PublicKey(c echo.Context) error {
	org, err := resolveOrgBySlug(c, h.orgRepo)
	if err != nil {
		return err
	}

	priv, err := h.repo.GetOrCreateKey(c.Request().Context(), org.ID) //nolint:govet
	if err != nil {
		log.Error().Err(err).Str("org_id", org.ID.String()).Msg("analytics: get key")
		return echo.ErrInternalServerError
	}

	pub := &priv.PublicKey
	keySet, err := rsaPublicToJWKS(pub, org.ID.String())
	if err != nil {
		return echo.ErrInternalServerError
	}

	c.Response().Header().Set("Cache-Control", "public, max-age=3600")
	return c.JSON(http.StatusOK, keySet)
}

// ── Token signing ─────────────────────────────────────────────────────────────

// IssueBlindToken handles POST /:org_slug/oid4vci/analytics/token
//
// The wallet submits a blinded token (m_blind = m * r^e mod n) and receives
// the blind signature (s_blind = m_blind^d mod n).  The issuer never sees m.
// Rate-limit: the endpoint is rate-limited at the web-server level; additionally
// the wallet must include the OID4VCI access_token to prove it holds a credential.
func (h *CredentialAnalyticsHandler) IssueBlindToken(c echo.Context) error {
	org, err := resolveOrgBySlug(c, h.orgRepo)
	if err != nil {
		return err
	}

	var req struct {
		Blinded string `json:"blinded"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Blinded) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "blinded is required")
	}

	priv, err := h.repo.GetOrCreateKey(c.Request().Context(), org.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	if err := analytics.ValidateBlinded(req.Blinded, &priv.PublicKey); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	signed, err := analytics.SignBlind(req.Blinded, priv)
	if err != nil {
		log.Error().Err(err).Str("org_id", org.ID.String()).Msg("analytics: sign blind token")
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, map[string]string{"signed": signed})
}

// ── Anonymous report ──────────────────────────────────────────────────────────

// Report handles POST /:org_slug/oid4vci/analytics/report
//
// The wallet (or a verifier on the wallet's behalf) submits an anonymous
// presentation report.  The handler:
//  1. Verifies the blind signature — proves a legitimate credential holder signed this.
//  2. Checks the token has not been spent (single-use).
//  3. Marks the token as spent.
//  4. Increments the aggregate counter — no user identity stored.
func (h *CredentialAnalyticsHandler) Report(c echo.Context) error {
	org, err := resolveOrgBySlug(c, h.orgRepo)
	if err != nil {
		return err
	}

	var req struct {
		TokenMsg    string `json:"token_msg"`    // hex-encoded random message m
		TokenSig    string `json:"token_sig"`    // hex-encoded unblinded signature s
		VCT         string `json:"vct"`          // credential type
		PurposeHint string `json:"purpose_hint"` // optional: "employment", "education", ...
		CountryHint string `json:"country_hint"` // optional: ISO 3166-1 alpha-2
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	req.TokenMsg = strings.TrimSpace(req.TokenMsg)
	req.TokenSig = strings.TrimSpace(req.TokenSig)
	req.VCT      = strings.TrimSpace(req.VCT)
	if req.TokenMsg == "" || req.TokenSig == "" || req.VCT == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "token_msg, token_sig, vct are required")
	}

	ctx := c.Request().Context()

	priv, err := h.repo.GetOrCreateKey(ctx, org.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// 1. Verify blind signature.
	if !analytics.Verify(req.TokenMsg, req.TokenSig, &priv.PublicKey) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid token signature")
	}

	// 2. Check and mark spent (double-spend prevention).
	tokenHash, err := analytics.TokenHash(req.TokenMsg)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid token_msg encoding")
	}
	spent, err := h.repo.IsTokenSpent(ctx, org.ID, tokenHash)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if spent {
		return echo.NewHTTPError(http.StatusConflict, "token already redeemed")
	}
	if err := h.repo.MarkTokenSpent(ctx, org.ID, tokenHash); err != nil {
		// Race condition: another request marked it spent concurrently — still a double-spend.
		return echo.NewHTTPError(http.StatusConflict, "token already redeemed")
	}

	// 3. Increment aggregate counter (no PII stored).
	day := time.Now().UTC().Truncate(24 * time.Hour)
	if err := h.repo.RecordEvent(ctx, org.ID, req.VCT, req.PurposeHint, req.CountryHint, day); err != nil {
		log.Error().Err(err).Str("org_id", org.ID.String()).Msg("analytics: record event")
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusAccepted, map[string]string{"status": "recorded"})
}

// ── Admin summary ─────────────────────────────────────────────────────────────

// Summary handles GET /api/v1/organizations/:org_id/oid4vci/analytics/summary
//
// Returns aggregate presentation counts for the last 90 days (configurable via
// query params from= and to= in RFC 3339 date format).
// No individual records, no user identifiers.
func (h *CredentialAnalyticsHandler) Summary(c echo.Context) error {
	orgIDStr := c.Param("org_id")
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	from := time.Now().UTC().AddDate(0, -3, 0) // 90 days ago
	to   := time.Now().UTC()

	if f := c.QueryParam("from"); f != "" {
		if t, err := time.Parse("2006-01-02", f); err == nil {
			from = t
		}
	}
	if t := c.QueryParam("to"); t != "" {
		if ts, err := time.Parse("2006-01-02", t); err == nil {
			to = ts
		}
	}

	ctx := c.Request().Context()

	rows, err := h.repo.GetSummary(ctx, orgID, from, to)
	if err != nil {
		return echo.ErrInternalServerError
	}

	totals, err := h.repo.GetTotals(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, map[string]any{
		"from":   from.Format("2006-01-02"),
		"to":     to.Format("2006-01-02"),
		"rows":   rows,
		"totals": totals,
		"privacy_notice": "All statistics are aggregate counts using RSA blind signatures. " +
			"No presentation can be linked to a specific credential holder.",
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// resolveOrgBySlug resolves an org from the :org_slug route param.
func resolveOrgBySlug(c echo.Context, orgRepo *repository.OrgRepository) (*models.Organization, error) {
	slug := c.Param("org_slug")
	if slug == "" {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "missing org_slug")
	}
	org, err := orgRepo.GetBySlug(c.Request().Context(), slug)
	if err != nil || org == nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "organisation not found")
	}
	return org, nil
}

// rsaPublicToJWKS serialises an RSA public key as a minimal JWKS JSON object.
func rsaPublicToJWKS(pub *rsa.PublicKey, kid string) (json.RawMessage, error) {
	k, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, err
	}
	_ = k.Set(jwk.KeyIDKey, kid)
	_ = k.Set(jwk.AlgorithmKey, jwa.RS256)
	_ = k.Set(jwk.KeyUsageKey, jwk.ForSignature)

	set := jwk.NewSet()
	_ = set.AddKey(k)

	return json.Marshal(set)
}

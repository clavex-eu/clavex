package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/passkey"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// PasskeyExchangeHandler handles FIDO Alliance CXF passkey portability.
// Endpoints:
//   GET  /api/v1/me/passkeys                — list user's passkeys
//   POST /api/v1/me/passkeys/export         — export CXF bundle (optionally encrypted)
//   POST /api/v1/me/passkeys/import         — import CXF bundle
//   DELETE /api/v1/me/passkeys/:cred_id     — revoke a passkey
type PasskeyExchangeHandler struct {
	repo     *repository.MFARepository
	userRepo *repository.UserRepository
	rpID     string
	rpName   string
}

func NewPasskeyExchangeHandler(repo *repository.MFARepository, userRepo *repository.UserRepository, rpID, rpName string) *PasskeyExchangeHandler {
	return &PasskeyExchangeHandler{repo: repo, userRepo: userRepo, rpID: rpID, rpName: rpName}
}

// ─── passkey response DTO ────────────────────────────────────────────

type passkeyResponse struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	CredID     string     `json:"credential_id"`
	AAGUID     string     `json:"aaguid,omitempty"`
	Transports []string   `json:"transports,omitempty"`
	SignCount   uint32     `json:"sign_count"`
	IsImported bool       `json:"is_imported"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func credToDTO(cr *repository.MFACredentialWithMeta) passkeyResponse {
	return passkeyResponse{
		ID:         cr.ID,
		Name:       cr.Name,
		CredID:     credentialIDFromData(cr.Data),
		AAGUID:     stringFromData(cr.Data, "aaguid"),
		Transports: transportsFromData(cr.Data),
		SignCount:   signCountFromData(cr.Data),
		IsImported: cr.IsImported,
		CreatedAt:  cr.CreatedAt,
		LastUsedAt: cr.LastUsedAt,
	}
}

// List returns the authenticated user's passkeys.
// GET /api/v1/me/passkeys
func (h *PasskeyExchangeHandler) List(c echo.Context) error {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	creds, err := h.repo.ListPasskeysByUserWithMeta(c.Request().Context(), userID)
	if err != nil {
		log.Error().Err(err).Str("user_id", userID.String()).Msg("passkey list")
		return echo.ErrInternalServerError
	}
	out := make([]passkeyResponse, 0, len(creds))
	for _, cr := range creds {
		out = append(out, credToDTO(cr))
	}
	return c.JSON(http.StatusOK, out)
}

// ─── Export ──────────────────────────────────────────────────────────

type exportRequest struct {
	// Password is optional. When provided the export is AES-256-GCM encrypted.
	Password string `json:"password"`
	// Title is an optional human-readable label for the bundle.
	Title string `json:"title"`
}

// Export serialises the user's passkeys as a FIDO Alliance CXF document
// and returns it for download.  If a password is supplied the document is
// AES-256-GCM encrypted (PBKDF2-SHA256, 600 000 iterations).
//
// POST /api/v1/me/passkeys/export
func (h *PasskeyExchangeHandler) Export(c echo.Context) error {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}

	var req exportRequest
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}

	ctx := c.Request().Context()
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	creds, err := h.repo.ListPasskeysByUserWithMeta(ctx, userID)
	if err != nil {
		log.Error().Err(err).Str("user_id", userID.String()).Msg("passkey export: list")
		return echo.ErrInternalServerError
	}

	title := req.Title
	if title == "" {
		title = fmt.Sprintf("%s — Clavex passkeys", user.Email)
	}
	issuer := issuerFromRequest(c, h.rpID)

	doc := passkey.NewDocument(title, issuer)
	for _, cr := range creds {
		doc.Credentials = append(doc.Credentials, buildCXFCredential(cr, user.Email, user.Email, h.rpID))
	}

	if req.Password != "" {
		bundle, err := passkey.Encrypt(doc, req.Password)
		if err != nil {
			log.Error().Err(err).Msg("passkey export: encrypt")
			return echo.ErrInternalServerError
		}
		c.Response().Header().Set("Content-Disposition", `attachment; filename="clavex-passkeys.cxf.json"`)
		return c.JSON(http.StatusOK, bundle)
	}

	c.Response().Header().Set("Content-Disposition", `attachment; filename="clavex-passkeys.cxf.json"`)
	return c.JSON(http.StatusOK, doc)
}

// ─── Import ──────────────────────────────────────────────────────────

type importRequest struct {
	// Password is required when the bundle is encrypted.
	Password string `json:"password"`
	// Bundle holds the raw CXF JSON (plain or encrypted).
	Bundle json.RawMessage `json:"bundle"`
}

type importResult struct {
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"` // duplicate credential_id
	Errors   []string `json:"errors,omitempty"`
}

// Import accepts a FIDO Alliance CXF bundle (plain or encrypted) and creates
// passkey records for the authenticated user.
//
// POST /api/v1/me/passkeys/import
func (h *PasskeyExchangeHandler) Import(c echo.Context) error {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}

	var req importRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if len(req.Bundle) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "bundle is required")
	}

	doc, err := parseCXFBundle(req.Bundle, req.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if doc.Type != "credential-exchange" {
		return echo.NewHTTPError(http.StatusBadRequest, "unsupported CXF document type")
	}

	// Validate the RP ID to prevent cross-site passkey hijacking:
	// only accept credentials whose rp_id matches our configured RP.
	ctx := c.Request().Context()
	result := &importResult{}
	for _, cxfCred := range doc.Credentials {
		if cxfCred.RPID != h.rpID {
			result.Errors = append(result.Errors,
				fmt.Sprintf("credential %s: rp_id mismatch (got %q, expected %q)",
					cxfCred.CredentialID, cxfCred.RPID, h.rpID))
			result.Skipped++
			continue
		}
		if cxfCred.CredentialID == "" || cxfCred.PublicKey == "" {
			result.Errors = append(result.Errors,
				fmt.Sprintf("credential %s: missing required fields", cxfCred.CredentialID))
			result.Skipped++
			continue
		}
		// Decode and re-encode to validate base64url.
		rawID, err := base64.RawURLEncoding.DecodeString(cxfCred.CredentialID)
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("credential %s: invalid credential_id encoding", cxfCred.CredentialID))
			result.Skipped++
			continue
		}
		// Skip if already registered.
		existing, _ := h.repo.GetWebAuthnByCredentialID(ctx, rawID)
		if existing != nil {
			result.Skipped++
			continue
		}

		credData := buildCredentialData(cxfCred)
		name := cxfCred.Name
		if name == "" {
			name = fmt.Sprintf("Imported passkey (%s)", abbreviate(cxfCred.CredentialID))
		}
		if _, err := h.repo.ImportWebAuthn(ctx, userID, name, credData); err != nil {
			log.Error().Err(err).Str("user_id", userID.String()).
				Str("cred_id", cxfCred.CredentialID).Msg("passkey import: insert")
			result.Errors = append(result.Errors,
				fmt.Sprintf("credential %s: %v", cxfCred.CredentialID, err))
			continue
		}
		result.Imported++
	}

	return c.JSON(http.StatusOK, result)
}

// Revoke deletes a specific passkey belonging to the authenticated user.
//
// DELETE /api/v1/me/passkeys/:cred_id
func (h *PasskeyExchangeHandler) Revoke(c echo.Context) error {
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return echo.ErrUnauthorized
	}
	credID, err := uuid.Parse(c.Param("cred_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid cred_id")
	}

	ctx := c.Request().Context()
	if err := h.repo.DeletePasskeyByIDAndUser(ctx, credID, userID); err != nil {
		log.Error().Err(err).Str("cred_id", credID.String()).Msg("passkey revoke")
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ─── helpers ─────────────────────────────────────────────────────────

func parseCXFBundle(raw json.RawMessage, password string) (*passkey.Document, error) {
	// Peek at the "type" field to decide how to parse.
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("invalid bundle JSON")
	}

	switch probe.Type {
	case "credential-exchange":
		var doc passkey.Document
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("invalid CXF document")
		}
		return &doc, nil

	case "credential-exchange-encrypted":
		if password == "" {
			return nil, fmt.Errorf("bundle is encrypted — password required")
		}
		var bundle passkey.EncryptedBundle
		if err := json.Unmarshal(raw, &bundle); err != nil {
			return nil, fmt.Errorf("invalid encrypted CXF bundle")
		}
		return passkey.Decrypt(&bundle, password)

	default:
		return nil, fmt.Errorf("unsupported bundle type %q", probe.Type)
	}
}

// buildCXFCredential maps a stored MFACredential (with meta) to a CXF credential entry.
func buildCXFCredential(cr *repository.MFACredentialWithMeta, userName, displayName, rpID string) passkey.Credential {
	cred := passkey.Credential{
		Type:            "webauthn.create",
		CredentialID:    credentialIDFromData(cr.Data),
		UserHandle:      cr.UserID.String(), // opaque, base64url not needed here
		UserName:        userName,
		UserDisplayName: displayName,
		RPID:            rpID,
		PublicKey:       publicKeyFromData(cr.Data),
		Algorithm:       algorithmFromData(cr.Data),
		AAGUID:          stringFromData(cr.Data, "aaguid"),
		Transports:      transportsFromData(cr.Data),
		SignCount:        signCountFromData(cr.Data),
		Name:            cr.Name,
		CreatedAt:       cr.CreatedAt,
		LastUsedAt:      cr.LastUsedAt,
		IsImported:      cr.IsImported,
	}
	return cred
}

// buildCredentialData reconstructs the JSONB data map from a CXF credential for import.
func buildCredentialData(cxfCred passkey.Credential) map[string]interface{} {
	data := map[string]interface{}{
		"id":                    cxfCred.CredentialID,
		"publicKey":             cxfCred.PublicKey,
		"signCount":             cxfCred.SignCount,
		"is_passkey":            true,
		"aaguid":                cxfCred.AAGUID,
		"attestation_format":    "none",
		"attestation_transports": cxfCred.Transports,
		"attestation_verified":  false, // imported credentials are not attested
	}
	if cxfCred.Algorithm != 0 {
		data["algorithm"] = cxfCred.Algorithm
	}
	return data
}

// Data accessors — the go-webauthn library serialises the credential as JSONB.
func credentialIDFromData(data map[string]interface{}) string {
	if v, ok := data["id"].(string); ok {
		return v
	}
	return ""
}

func publicKeyFromData(data map[string]interface{}) string {
	if v, ok := data["publicKey"].(string); ok {
		return v
	}
	return ""
}

func stringFromData(data map[string]interface{}, key string) string {
	if v, ok := data[key].(string); ok {
		return v
	}
	return ""
}

func transportsFromData(data map[string]interface{}) []string {
	raw, ok := data["attestation_transports"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, t := range v {
			if s, ok := t.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func signCountFromData(data map[string]interface{}) uint32 {
	switch v := data["signCount"].(type) {
	case float64:
		return uint32(v)
	case int:
		return uint32(v)
	case uint32:
		return v
	}
	return 0
}

func algorithmFromData(data map[string]interface{}) int {
	// go-webauthn stores algorithm as part of the public key CBOR;
	// we default to -7 (ES256) which is the most common passkey algorithm.
	if v, ok := data["algorithm"].(float64); ok {
		return int(v)
	}
	return -7
}

func issuerFromRequest(c echo.Context, rpID string) string {
	// Build a best-effort base URL from the request.
	scheme := "https"
	if c.Request().TLS == nil && strings.Contains(c.Request().Host, "localhost") {
		scheme = "http"
	}
	if rpID != "" {
		return scheme + "://" + rpID
	}
	return scheme + "://" + c.Request().Host
}

func abbreviate(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-4:]
}

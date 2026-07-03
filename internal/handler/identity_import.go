package handler

// identity_import.go — Identity Continuity: verified identity portability between
// Clavex installations.
//
// A user with an existing account on "Clavex A" (e.g. a university) registers on
// "Clavex B" (e.g. a municipality).  Instead of re-submitting identity documents,
// they present an SD-JWT-VC issued by A.  Clavex B:
//   1. Fetches A's JWKS from A's /.well-known/jwks.json (OpenID Provider endpoint).
//   2. Verifies the SD-JWT-VC signature and structural validity.
//   3. Extracts identity claims (given_name, family_name, date_of_birth, …).
//   4. Stores the claims in the user's metadata under "identity_import" and marks
//      identity_source_issuer / identity_imported_at on the user row.
//
// This is NOT SSO: the user has a distinct account on B.  The feature provides
// portability of already-verified profile data without repeating the identification
// procedure (GDPR Art.5(1)(e) storage limitation / Art.5(1)(c) data minimisation).
//
// Endpoint registered in server.go:
//
//	POST /api/v1/organizations/:org_id/users/:user_id/identity/import
//
// Authentication: admin Bearer JWT (standard RequireResourcePermission middleware).
//
// Request body:
//
//	{
//	  "vp_token":    "<SD-JWT-VC compact token issued by the remote Clavex>",
//	  "issuer_url":  "https://university.example/orgslug"
//	}
//
// Response 200:
//
//	{
//	  "user_id":      "...",
//	  "source_issuer": "https://university.example/orgslug",
//	  "imported_claims": { "given_name": "Alice", … }
//	}

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/safehttp"
)

// IdentityImportHandler handles identity portability between Clavex installations.
type IdentityImportHandler struct {
	users *repository.UserRepository
	hc    *http.Client
}

// NewIdentityImportHandler constructs the handler.
func NewIdentityImportHandler(users *repository.UserRepository) *IdentityImportHandler {
	return &IdentityImportHandler{
		users: users,
		hc:    safehttp.Client(10*time.Second, false), // SSRF guard: block private targets
	}
}

// WithHTTPClient overrides the outbound HTTP client (SSRF-relaxed opt-in).
func (h *IdentityImportHandler) WithHTTPClient(hc *http.Client) *IdentityImportHandler {
	if hc != nil {
		h.hc = hc
	}
	return h
}

// importIdentityRequest is the JSON body for POST …/identity/import.
type importIdentityRequest struct {
	// VPToken is the SD-JWT-VC compact token issued by the remote Clavex installation.
	VPToken string `json:"vp_token" validate:"required"`
	// IssuerURL is the base issuer URL of the remote Clavex installation.
	// Example: "https://university.example/university".
	// Used to fetch the remote JWKS for signature verification.
	IssuerURL string `json:"issuer_url" validate:"required,url"`
}

// identityClaimKeys lists the well-known identity claims we extract from the
// imported credential and store in the user's metadata.
var identityClaimKeys = []string{
	"given_name", "family_name", "birthdate", "date_of_birth",
	"gender", "phone_number", "email", "address", "nationality",
	"place_of_birth", "personal_number", "document_number",
	// eIDAS / IT-Wallet / EUDIW PID claims
	"tax_id", "fiscal_code", "resident_address",
}

// ImportIdentity handles POST /api/v1/organizations/:org_id/users/:user_id/identity/import.
func (h *IdentityImportHandler) ImportIdentity(c echo.Context) error {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}

	var req importIdentityRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	ctx := c.Request().Context()

	// ── Step 1: fetch the remote issuer's JWKS ────────────────────────────────
	remoteKey, err := h.fetchIssuerPublicKey(ctx, req.IssuerURL)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf(
			"cannot fetch remote issuer JWKS from %s: %s", req.IssuerURL, err.Error(),
		))
	}

	// ── Step 2: parse and verify the SD-JWT-VC ───────────────────────────────
	issuerJWT, disclosureRaws, _, parseErr := oid4w.ParseSDJWT(req.VPToken)
	if parseErr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid vp_token: "+parseErr.Error())
	}

	claims, verifyErr := oid4w.VerifyAndExtractClaims(issuerJWT, disclosureRaws, remoteKey)
	if verifyErr != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "vp_token signature verification failed: "+verifyErr.Error())
	}

	// ── Step 3: confirm the credential was issued by the stated issuer ────────
	iss, _ := claims["iss"].(string)
	expectedBase := strings.TrimRight(req.IssuerURL, "/")
	if !strings.HasPrefix(strings.TrimRight(iss, "/"), expectedBase) &&
		!strings.HasPrefix(expectedBase, strings.TrimRight(iss, "/")) {
		return echo.NewHTTPError(http.StatusUnauthorized,
			"vp_token iss claim does not match issuer_url")
	}

	// ── Step 4: check expiry ──────────────────────────────────────────────────
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return echo.NewHTTPError(http.StatusBadRequest, "vp_token has expired")
		}
	}

	// ── Step 5: extract identity claims ──────────────────────────────────────
	imported := make(map[string]interface{}, len(identityClaimKeys))
	for _, k := range identityClaimKeys {
		if v, ok := claims[k]; ok {
			imported[k] = v
		}
	}
	if len(imported) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest,
			"vp_token contains no recognisable identity claims")
	}

	// ── Step 6: persist ───────────────────────────────────────────────────────
	if err := h.users.RecordIdentityImport(ctx, userID, req.IssuerURL, imported); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"user_id":         userID,
		"source_issuer":   req.IssuerURL,
		"imported_claims": imported,
	})
}

// fetchIssuerPublicKey fetches the remote Clavex issuer's first RSA/EC public key
// from its JWKS endpoint (GET <issuerURL>/jwks.json or <issuerURL>/.well-known/jwks.json).
//
// In production the caller should verify the issuer's OpenID Federation entity
// configuration to fully establish trust (the federation trust chain is already
// available in Clavex via internal/federation).  For the initial implementation
// we fetch the JWKS directly — the caller is expected to only call this endpoint
// for known-trusted partner installations or after a manual trust establishment.
func (h *IdentityImportHandler) fetchIssuerPublicKey(ctx context.Context, issuerURL string) (crypto.PublicKey, error) {
	base := strings.TrimRight(issuerURL, "/")
	candidates := []string{
		base + "/jwks.json",
		base + "/.well-known/jwks.json",
	}

	for _, u := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := h.hc.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if readErr != nil {
			continue
		}

		set, parseErr := jwk.ParseString(string(body))
		if parseErr != nil || set.Len() == 0 {
			continue
		}

		// Return the first key that supports verification (RSA or EC).
		for i := 0; i < set.Len(); i++ {
			k, _ := set.Key(i)
			var rawKey interface{}
			if err := k.Raw(&rawKey); err != nil {
				continue
			}
			if pub, ok := rawKey.(crypto.PublicKey); ok {
				return pub, nil
			}
		}
	}
	return nil, fmt.Errorf("no usable public key found at issuer JWKS endpoint for %s", issuerURL)
}

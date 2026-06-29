package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/tracing"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
)

// ClaimsEnricher is an optional synchronous hook called just before token
// issuance.  Implementations should have a short timeout (≤ 500 ms) and must
// never block token issuance: callers log and discard any returned error.
// A nil ClaimsEnricher disables enrichment for a given grant.
type ClaimsEnricher func(ctx context.Context, clientID, scope string, uc *UserClaims) (map[string]any, error)

// TokenError is an OAuth2 token error (returned as JSON, not redirect).
type TokenError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *TokenError) Error() string { return e.Code + ": " + e.Description }

// CodeConsumer abstracts authorization code consumption for testability.
// It is implemented by *repository.AuthCodeRepository.
type CodeConsumer interface {
	Consume(ctx context.Context, codeHash string) (*repository.AuthCode, error)
	// SetRevocationData records the access token JTI and refresh token family_id
	// on the consumed code row for targeted revocation if the code is replayed
	// (RFC 6749 §4.1.2). Implementations that do not persist may be a no-op.
	SetRevocationData(ctx context.Context, codeHash, jti string, familyID uuid.UUID) error
}

// ExchangeCode implements the authorization_code grant.
// It validates the code, PKCE, and redirect_uri, then issues a full token set.
// idTokenAlg is the client's id_token_signed_response_alg (empty = server default PS256).
// enricher is optional; when non-nil it is called after mapper resolution to inject
// additional claims before the access token is signed.
func ExchangeCode(
	ctx context.Context,
	clientID, code, redirectURI, codeVerifier string,
	idTokenAlg string,
	tc *TokenConfig,
	codes CodeConsumer,
	tokens *repository.RefreshTokenRepository,
	users *repository.UserRepository,
	groupRepo *repository.GroupRepository,
	mapperRepo *repository.MapperRepository,
	dpop *DPoPKey,
	grantRepo *repository.RARGrantRepository, // may be nil; records RAR grants
	mtls *MTLSCert,
	enricher ClaimsEnricher, // may be nil
	flagsRepo *repository.FeatureFlagRepository, // may be nil; injects "flags" claim
	attestationJKT string, // OAuth2-ATCA §10.3: cnf.jwk thumbprint; empty if not attest_jwt_client_auth
) (*TokenSet, error) {
	ctx, span := tracing.Tracer("clavex/oidc").Start(ctx, "oidc.token.exchange_code")
	defer span.End()
	span.SetAttributes(
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.grant_type", "authorization_code"),
	)

	codeHash := hashString(code)
	ac, err := codes.Consume(ctx, codeHash)
	if err != nil {
		span.SetAttributes(attribute.Bool("oauth.code_valid", false))
		span.SetStatus(otelcodes.Error, "invalid_grant")
		return nil, &TokenError{Code: "invalid_grant", Description: "authorization code not found or already used"}
	}

	if ac.ClientID != clientID {
		return nil, &TokenError{Code: "invalid_grant", Description: "code was not issued to this client"}
	}
	if ac.RedirectURI != redirectURI {
		return nil, &TokenError{Code: "invalid_grant", Description: "redirect_uri mismatch"}
	}
	if time.Now().After(ac.ExpiresAt) {
		return nil, &TokenError{Code: "invalid_grant", Description: "authorization code expired"}
	}

	if err := VerifyPKCE(ac.PKCEChallenge, codeVerifier); err != nil {
		return nil, &TokenError{Code: "invalid_grant", Description: err.Error()}
	}

	// RFC 9449 §10: if dpop_jkt was committed at authorization time, the token
	// request MUST include a DPoP proof whose JWK thumbprint matches that value.
	// A mismatch or missing proof means the caller cannot prove key possession.
	if ac.DpopJKT != "" {
		if dpop == nil {
			return nil, &TokenError{Code: "invalid_dpop_proof",
				Description: "DPoP proof required: authorization was bound to dpop_jkt"}
		}
		if dpop.JKT != ac.DpopJKT {
			return nil, &TokenError{Code: "invalid_dpop_proof",
				Description: "DPoP proof key does not match the dpop_jkt committed at authorization time"}
		}
	}

	span.SetAttributes(
		attribute.Bool("oauth.code_valid", true),
		attribute.String("oauth.user_id", ac.UserID.String()),
		attribute.String("oauth.scope", ac.Scope),
	)

	user, err := users.GetByID(ctx, ac.UserID)
	if err != nil || !user.IsActive {
		return nil, &TokenError{Code: "invalid_grant", Description: "user not found or inactive"}
	}

	uc := UserClaimsFromModel(user)
	uc.AuthTime = ac.AuthTime
	uc.Acr = ac.Acr
	// RFC 9396: carry authorization_details from the auth code into the token.
	uc.AuthorizationDetails = ac.AuthorizationDetails
	// OIDC Core §5.5: carry claims parameter so BuildUserInfo returns requested claims.
	uc.ReqClaims = ac.ClaimsParam
	if groupRepo != nil {
		if gnames, err := groupRepo.GroupsForUser(ctx, ac.UserID); err == nil {
			uc.Groups = gnames
		}
	}
	// Load roles and apply protocol mappers for additional claims
	if roleNames, err := users.FlattenRoleNames(ctx, ac.UserID); err == nil {
		uc.Roles = roleNames
	}
	if mapperRepo != nil {
		uc.ExtraClaims = ResolveMapperExtraClaims(ctx, mapperRepo, clientID, uc, user.Metadata)
	}

	// Merge flow-engine claims (enrich_claims / set_claim steps) into ExtraClaims.
	// These take lower precedence than protocol mappers but higher than defaults.
	if len(ac.ExtraClaims) > 0 {
		if uc.ExtraClaims == nil {
			uc.ExtraClaims = make(map[string]any, len(ac.ExtraClaims))
		}
		for k, v := range ac.ExtraClaims {
			if _, already := uc.ExtraClaims[k]; !already {
				uc.ExtraClaims[k] = v
			}
		}
	}

	// OpenID Connect for Identity Assurance 1.0: include verified_claims in
	// the ID token when the claims request parameter requests it there.
	if ac.ClaimsParam != "" {
		var cp struct {
			IDToken map[string]json.RawMessage `json:"id_token"`
		}
		if json.Unmarshal([]byte(ac.ClaimsParam), &cp) == nil {
			if rawVC, ok := cp.IDToken["verified_claims"]; ok {
				// Build a minimal profile-claims map from what we have.
				profileClaims := map[string]any{}
				if uc.FirstName != "" {
					profileClaims["given_name"] = uc.FirstName
				}
				if uc.LastName != "" {
					profileClaims["family_name"] = uc.LastName
				}
				if vc := BuildVerifiedClaims(user.Metadata, profileClaims, rawVC); vc != nil {
					if uc.ExtraClaims == nil {
						uc.ExtraClaims = map[string]any{}
					}
					uc.ExtraClaims["verified_claims"] = vc
				}
			}
		}
	}

	// Synchronous claims-enrichment hook (Auth0 Actions-style).
	// Called after all mapper resolution so the enricher sees the final claim set.
	// Errors are non-fatal: log and continue.
	if enricher != nil {
		if extra, enrichErr := enricher(ctx, clientID, ac.Scope, &uc); enrichErr == nil {
			if uc.ExtraClaims == nil {
				uc.ExtraClaims = make(map[string]any, len(extra))
			}
			for k, v := range extra {
				uc.ExtraClaims[k] = v
			}
		}
	}

	// Feature flags: resolve per-user/per-role flag values and inject as "flags" claim.
	// Only injected when the org has at least one flag defined.
	if flagsRepo != nil {
		var roleIDs []uuid.UUID
		if roleModels, err := users.ListRolesByUser(ctx, ac.UserID); err == nil {
			roleIDs = make([]uuid.UUID, len(roleModels))
			for i, r := range roleModels {
				roleIDs[i] = r.ID
			}
		}
		if flags, err := flagsRepo.ResolveForUser(ctx, ac.OrgID, ac.UserID, roleIDs); err == nil && flags != nil {
			if uc.ExtraClaims == nil {
				uc.ExtraClaims = map[string]any{}
			}
			uc.ExtraClaims["flags"] = flags
		}
	}

	accessToken, accessJTI, err := tc.IssueAccessToken(clientID, ac.Scope, &uc, dpop, mtls)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, err.Error())
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	// OIDC Core §3.1.3.3: id_token is only issued when openid is in the granted
	// scope.  OID4VCI flows may use authorization_details without openid scope.
	var idToken string
	if strings.Contains(ac.Scope, "openid") {
		uc.AtHash = ComputeAtHash(accessToken)
		idToken, err = tc.IssueIDToken(clientID, ac.Nonce, uc, ResolveIDTokenAlg(idTokenAlg))
		if err != nil {
			return nil, fmt.Errorf("issue id token: %w", err)
		}
	}

	familyID := uuid.New()
	dpopJKT := ""
	if dpop != nil {
		dpopJKT = dpop.JKT
	}
	mtlsThumb := ""
	if mtls != nil {
		mtlsThumb = mtls.X5TS256
	}
	refreshToken, err := IssueRefreshToken(ctx, tokens, repository.CreateRefreshTokenParams{
		OrgID:          ac.OrgID,
		ClientID:       clientID,
		UserID:         &ac.UserID,
		FamilyID:       familyID,
		Scope:          ac.Scope,
		ExpiresAt:      time.Now().Add(tc.RefreshTokenTTL),
		DpopJKT:        dpopJKT,
		MTLSX5TS256:    mtlsThumb,
		AttestationJKT: attestationJKT,
	})
	if err != nil {
		return nil, fmt.Errorf("issue refresh token: %w", err)
	}

	// Store the access token JTI and refresh family_id on the auth code row so
	// that if the code is replayed, only the specific tokens from this exchange
	// can be revoked (RFC 6749 §4.1.2 — targeted revocation, not broad user+client).
	capturedCodeHash := ac.CodeHash
	capturedJTI := accessJTI
	capturedFamilyID := familyID
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = codes.SetRevocationData(bgCtx, capturedCodeHash, capturedJTI, capturedFamilyID)
	}()

	// RFC 9396: persist the grant record so the consent management dashboard can
	// display and allow revocation of authorization_details grants.
	if grantRepo != nil && len(ac.AuthorizationDetails) > 0 {
		go func() {
			_, _ = grantRepo.Upsert(context.Background(),
				ac.OrgID, ac.UserID, clientID, ac.Scope, ac.AuthorizationDetails)
		}()
	}

	tokenType := "Bearer"
	if dpop != nil {
		tokenType = "DPoP"
	}
	return &TokenSet{
		AccessToken:          accessToken,
		IDToken:              idToken,
		RefreshToken:         refreshToken,
		TokenType:            tokenType,
		ExpiresIn:            int(tc.AccessTokenTTL.Seconds()),
		Scope:                ac.Scope,
		AuthorizationDetails: ac.AuthorizationDetails,
	}, nil
}

// ExchangeRefreshToken implements the refresh_token grant with rotation and
// family-based revocation on token replay.
func ExchangeRefreshToken(
	ctx context.Context,
	clientID, rawRefreshToken string,
	tc *TokenConfig,
	tokens *repository.RefreshTokenRepository,
	users *repository.UserRepository,
	store *session.Store,
	mapperRepo *repository.MapperRepository,
	dpop *DPoPKey,
	mtls *MTLSCert,
	enricher ClaimsEnricher, // may be nil
	flagsRepo *repository.FeatureFlagRepository, // may be nil; injects "flags" claim
	attestationJKT string, // OAuth2-ATCA §10.3: cnf.jwk thumbprint from current request; empty if not attest_jwt_client_auth
) (*TokenSet, error) {
	ctx, span := tracing.Tracer("clavex/oidc").Start(ctx, "oidc.token.refresh")
	defer span.End()
	span.SetAttributes(
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.grant_type", "refresh_token"),
	)

	tokenHash := hashString(rawRefreshToken)
	rt, err := tokens.GetByHash(ctx, tokenHash)
	if err != nil {
		span.SetStatus(otelcodes.Error, "refresh token not found")
		return nil, &TokenError{Code: "invalid_grant", Description: "refresh token not found"}
	}

	// Detect replay: if this token is already revoked, handle based on whether it
	// was legitimately rotated.
	// RFC 9700 §2.2.1 / RFC 6819 §5.2.2.3: token theft detection via rotation.
	// If the revoked token has NO successor (ReplacedBy == nil), it was revoked for
	// an unknown reason — treat as possible theft and revoke the entire family.
	// If it HAS a successor (ReplacedBy != nil), it was consumed by normal rotation.
	// Per FAPI2.0 §5.3.1.1-9 ("lost refresh token recovery"): if the successor is
	// still valid (not yet used), the client likely lost the rotation response and
	// is replaying the request — treat the successor as the current token.
	// If the successor was already used/revoked, escalate to family revocation.
	if rt.RevokedAt != nil {
		span.SetAttributes(attribute.Bool("oauth.token_replay", true))
		if rt.ReplacedBy == nil {
			// No successor — suspicious; escalate to family revocation.
			span.SetStatus(otelcodes.Error, "token replay detected (no successor)")
			_ = tokens.RevokeFamilyByID(ctx, rt.FamilyID)
			return nil, &TokenError{Code: "invalid_grant", Description: "refresh token already used"}
		}
		// Token was rotated. Check if the successor is still valid.
		successor, serr := tokens.GetByID(ctx, *rt.ReplacedBy)
		if serr != nil || successor.RevokedAt != nil {
			// Successor already used or not found — definitive replay/theft.
			span.SetStatus(otelcodes.Error, "token replay detected (successor already used)")
			_ = tokens.RevokeFamilyByID(ctx, rt.FamilyID)
			return nil, &TokenError{Code: "invalid_grant", Description: "refresh token already used"}
		}
		// Successor is still valid: the client lost the rotation response.
		// Continue using the successor as the effective current token.
		rt = successor
	}

	if rt.ClientID != clientID {
		return nil, &TokenError{Code: "invalid_grant", Description: "token was not issued to this client"}
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, &TokenError{Code: "invalid_grant", Description: "refresh token expired"}
	}

	// OAuth2-ATCA §10.3: if the refresh token was bound to a client instance key
	// at issuance, the same key must be presented on every rotation request.
	if rt.AttestationJKT != "" {
		if attestationJKT == "" {
			return nil, &TokenError{Code: "invalid_client", Description: "client_attestation required: refresh token is bound to a client instance key"}
		}
		if attestationJKT != rt.AttestationJKT {
			return nil, &TokenError{Code: "invalid_client", Description: "client instance key mismatch: refresh token is bound to a different client instance key"}
		}
	}

	// RFC 9449 §6: if the token is DPoP-bound and NO DPoP proof at all was sent,
	// that is an error. But we do NOT require the SAME key as was used at exchange
	// time — RFC 9449 §6 says binding to a specific key is optional ("can"), and
	// FAPI2 conformance uses different DPoP keys across the auth and refresh phases.
	// The "sender-constrained" requirement (any valid DPoP proof must be present)
	// is already enforced upstream in the token endpoint handler.

	// Revoke old token before issuing new one
	if err := tokens.RevokeByID(ctx, rt.ID); err != nil {
		return nil, fmt.Errorf("revoke old refresh token: %w", err)
	}

	// Prepare new access token
	var uc *UserClaims
	if rt.UserID != nil {
		user, err := users.GetByID(ctx, *rt.UserID)
		if err != nil || !user.IsActive {
			return nil, &TokenError{Code: "invalid_grant", Description: "user not found or inactive"}
		}
		claims := UserClaimsFromModel(user)
		if roleNames, err := users.FlattenRoleNames(ctx, *rt.UserID); err == nil {
			claims.Roles = roleNames
		}
		if mapperRepo != nil {
			claims.ExtraClaims = ResolveMapperExtraClaims(ctx, mapperRepo, clientID, claims, user.Metadata)
		}
		uc = &claims
	}

	// Synchronous claims-enrichment hook on refresh.
	if enricher != nil && uc != nil {
		if extra, enrichErr := enricher(ctx, clientID, rt.Scope, uc); enrichErr == nil {
			if uc.ExtraClaims == nil {
				uc.ExtraClaims = make(map[string]any, len(extra))
			}
			for k, v := range extra {
				uc.ExtraClaims[k] = v
			}
		}
	}

	// Feature flags on refresh: re-resolve flags so any admin change is reflected.
	if flagsRepo != nil && uc != nil && rt.UserID != nil {
		var roleIDs []uuid.UUID
		if roleModels, err := users.ListRolesByUser(ctx, *rt.UserID); err == nil {
			roleIDs = make([]uuid.UUID, len(roleModels))
			for i, r := range roleModels {
				roleIDs[i] = r.ID
			}
		}
		if flags, err := flagsRepo.ResolveForUser(ctx, rt.OrgID, *rt.UserID, roleIDs); err == nil && flags != nil {
			if uc.ExtraClaims == nil {
				uc.ExtraClaims = map[string]any{}
			}
			uc.ExtraClaims["flags"] = flags
		}
	}

	// RFC 8705 §7.1 / FAPI 2.0 §5.3.1.1-6: verify mTLS sender-constraint.
	if err := verifyMTLSRefreshBinding(rt.MTLSX5TS256, mtls); err != nil {
		return nil, err
	}
	effectiveMTLS := mtls

	accessToken, _, err := tc.IssueAccessToken(clientID, rt.Scope, uc, dpop, effectiveMTLS)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	// Issue new refresh token in the same family
	newDpopJKT := ""
	if dpop != nil {
		newDpopJKT = dpop.JKT
	}
	// Propagate the cert binding: prefer a newly-presented cert; fall back to
	// whatever was stored on the incoming token.
	newMTLSX5TS256 := rt.MTLSX5TS256
	if mtls != nil {
		newMTLSX5TS256 = mtls.X5TS256
	}
	newRefreshToken, err := IssueRefreshToken(ctx, tokens, repository.CreateRefreshTokenParams{
		OrgID:          rt.OrgID,
		ClientID:       clientID,
		UserID:         rt.UserID,
		FamilyID:       rt.FamilyID, // same family
		Scope:          rt.Scope,
		ExpiresAt:      rt.ExpiresAt, // inherit original expiry (don't extend)
		ReplacesID:     &rt.ID,
		DpopJKT:        newDpopJKT,
		MTLSX5TS256:    newMTLSX5TS256,
		AttestationJKT: rt.AttestationJKT, // carry forward the bound key
	})
	if err != nil {
		return nil, fmt.Errorf("issue new refresh token: %w", err)
	}

	var idToken string
	if rt.UserID != nil && uc != nil {
		// Omit id_token in token refresh responses per OIDC Core §12
		_ = idToken
	}

	refreshTT := "Bearer"
	if dpop != nil {
		refreshTT = "DPoP"
	}
	return &TokenSet{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    refreshTT,
		ExpiresIn:    int(tc.AccessTokenTTL.Seconds()),
		Scope:        rt.Scope,
	}, nil
}

// ExchangeClientCredentials implements the client_credentials grant (M2M).
// No refresh token is issued.
func ExchangeClientCredentials(
	ctx context.Context,
	clientID, scope string,
	tc *TokenConfig,
	dpop *DPoPKey,
	mtls *MTLSCert,
) (*TokenSet, error) {
	_, span := tracing.Tracer("clavex/oidc").Start(ctx, "oidc.token.client_credentials")
	defer span.End()
	span.SetAttributes(
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.grant_type", "client_credentials"),
	)
	if scope == "" {
		scope = "api"
	}

	accessToken, _, err := tc.IssueAccessToken(clientID, scope, nil, dpop, mtls)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	ccTT := "Bearer"
	if dpop != nil {
		ccTT = "DPoP"
	}
	return &TokenSet{
		AccessToken: accessToken,
		TokenType:   ccTT,
		ExpiresIn:   int(tc.AccessTokenTTL.Seconds()),
		Scope:       scope,
	}, nil
}

// issueRefreshToken generates and stores a new opaque refresh token.
func IssueRefreshToken(
	ctx context.Context,
	repo *repository.RefreshTokenRepository,
	params repository.CreateRefreshTokenParams,
) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(raw)
	params.TokenHash = hashString(plain)

	if err := repo.Create(ctx, params); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return plain, nil
}

// UserClaimsFromModel maps a models.User to UserClaims.
// Imported via concrete type to avoid circular deps.
func UserClaimsFromModel(u interface {
	GetID() string
	GetOrgID() string
	GetEmail() string
	GetEmailVerified() bool
	GetFirstName() string
	GetLastName() string
}) UserClaims {
	return UserClaims{
		UserID:        u.GetID(),
		OrgID:         u.GetOrgID(),
		Email:         u.GetEmail(),
		EmailVerified: u.GetEmailVerified(),
		FirstName:     u.GetFirstName(),
		LastName:      u.GetLastName(),
	}
}

// resolveMapperExtraClaims queries protocol_mappers for the given client and
// builds a map of additional token claims from the user's data.
// Only mappers with add_to_access_token=true are included (access token focus).
// Errors are silently ignored so a misconfigured mapper never blocks login.
func ResolveMapperExtraClaims(
	ctx context.Context,
	repo *repository.MapperRepository,
	clientID string,
	uc UserClaims,
	metadata map[string]interface{},
) map[string]any {
	mappers, err := repo.ListByClient(ctx, clientID)
	if err != nil || len(mappers) == 0 {
		return nil
	}
	extra := make(map[string]any)
	for _, m := range mappers {
		if !m.AddToAccessToken {
			continue
		}
		switch m.MapperType {
		case "user_property":
			if m.AttributeName == nil {
				continue
			}
			switch *m.AttributeName {
			case "email":
				extra[m.ClaimName] = uc.Email
			case "first_name":
				extra[m.ClaimName] = uc.FirstName
			case "last_name":
				extra[m.ClaimName] = uc.LastName
			case "sub":
				extra[m.ClaimName] = uc.UserID
			}
		case "user_attribute":
			if m.AttributeName == nil {
				continue
			}
			if v, ok := metadata[*m.AttributeName]; ok {
				extra[m.ClaimName] = v
			}
		case "hardcoded":
			if m.ClaimValue != nil {
				extra[m.ClaimName] = *m.ClaimValue
			}
		case "role_list":
			extra[m.ClaimName] = uc.Roles
		case "group_membership":
			extra[m.ClaimName] = uc.Groups
		}
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
}

// ErrInvalidGrant is a sentinel for grant-level failures.
var ErrInvalidGrant = errors.New("invalid_grant")

// ── Token Exchange (RFC 8693) ─────────────────────────────────────────────────

// TokenExchangeResponse is the RFC 8693 response body (superset of TokenSet).
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"` // urn:ietf:params:oauth:token-type:access_token
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
}

// ExchangeToken implements RFC 8693 token exchange.
//
//	subject_token      — the caller's existing access token or refresh token
//	subject_token_type — urn:ietf:params:oauth:token-type:access_token | refresh_token
//	audience           — optional requested audience (client_id of target service)
//	scope              — optional requested scope (subset of original)
//	actorToken         — optional delegation/impersonation actor token (ignored for now)
//
// The implementation validates the subject_token, loads the user, and issues a
// fresh access token scoped to the requested audience. Refresh tokens are NOT
// issued for exchanged tokens (RFC 8693 §5).
// allowedAudiences restricts the value the caller may request via the
// audience/resource parameter (RFC 8693 §2.1); an audience equal to the calling
// clientID is always permitted. verifyTC verifies the subject access token and
// MUST use the issuer that minted it (for cross-org exchange this is the SOURCE
// org's issuer, which differs from the issuing tc).
func ExchangeToken(
	ctx context.Context,
	clientID string,
	subjectToken, subjectTokenType string,
	requestedAudience, requestedScope string,
	allowedAudiences []string,
	verifyTC *TokenConfig,
	tc *TokenConfig,
	tokens *repository.RefreshTokenRepository,
	users *repository.UserRepository,
	store *session.Store,
	mapperRepo *repository.MapperRepository,
) (*TokenExchangeResponse, error) {
	var uc *UserClaims
	var originalScope string

	switch subjectTokenType {
	case "urn:ietf:params:oauth:token-type:access_token", "":
		// Parse and validate the subject access token against the issuer that
		// minted it (verifyTC). For same-org exchange verifyTC == tc.
		tok, _, _, err := verifyTC.VerifyAccessToken(subjectToken)
		if err != nil {
			return nil, &TokenError{Code: "invalid_grant", Description: "subject_token is invalid or expired"}
		}
		userID := tok.Subject()
		scopeRaw, _ := tok.Get("scope")
		originalScope, _ = scopeRaw.(string)

		if userID != "" {
			userUUID, err := uuid.Parse(userID)
			if err != nil {
				return nil, &TokenError{Code: "invalid_grant", Description: "invalid sub claim in subject_token"}
			}
			user, err := users.GetByID(ctx, userUUID)
			if err != nil || !user.IsActive {
				return nil, &TokenError{Code: "invalid_grant", Description: "user not found or inactive"}
			}
			claims := UserClaimsFromModel(user)
			if roleNames, err := users.FlattenRoleNames(ctx, userUUID); err == nil {
				claims.Roles = roleNames
			}
			if mapperRepo != nil {
				claims.ExtraClaims = ResolveMapperExtraClaims(ctx, mapperRepo, clientID, claims, user.Metadata)
			}
			uc = &claims
		}

	case "urn:ietf:params:oauth:token-type:refresh_token":
		// Exchange a refresh token — look it up, validate, don't rotate.
		tokenHash := hashString(subjectToken)
		rt, err := tokens.GetByHash(ctx, tokenHash)
		if err != nil {
			return nil, &TokenError{Code: "invalid_grant", Description: "subject_token (refresh) not found"}
		}
		if rt.RevokedAt != nil || time.Now().After(rt.ExpiresAt) {
			return nil, &TokenError{Code: "invalid_grant", Description: "subject_token (refresh) is revoked or expired"}
		}
		originalScope = rt.Scope
		if rt.UserID != nil {
			user, err := users.GetByID(ctx, *rt.UserID)
			if err != nil || !user.IsActive {
				return nil, &TokenError{Code: "invalid_grant", Description: "user not found or inactive"}
			}
			claims := UserClaimsFromModel(user)
			if roleNames, err := users.FlattenRoleNames(ctx, *rt.UserID); err == nil {
				claims.Roles = roleNames
			}
			uc = &claims
		}

	default:
		return nil, &TokenError{Code: "invalid_request", Description: "unsupported subject_token_type"}
	}

	// Scope narrowing: requested_scope must be a subset of the original scope.
	effectiveScope := originalScope
	if requestedScope != "" {
		effectiveScope = narrowScope(originalScope, requestedScope)
		if effectiveScope == "" {
			return nil, &TokenError{Code: "invalid_scope", Description: "requested scope exceeds subject_token scope"}
		}
	}

	// Audience: use the requested audience as the token's aud claim, otherwise
	// fall back to the calling client_id (impersonation / delegation use-case).
	// RFC 8693 §2.1: a requested audience must be explicitly permitted for this
	// client (allowed_audiences) or equal the caller itself; otherwise reject
	// with invalid_target (§2.2.1) rather than minting a token for an arbitrary
	// resource server.
	targetAud := clientID
	if requestedAudience != "" {
		if !audiencePermitted(requestedAudience, clientID, allowedAudiences) {
			return nil, &TokenError{Code: "invalid_target", Description: "requested audience is not permitted for this client"}
		}
		targetAud = requestedAudience
	}

	accessToken, _, err := tc.IssueAccessToken(targetAud, effectiveScope, uc, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("issue exchanged access token: %w", err)
	}

	return &TokenExchangeResponse{
		AccessToken:     accessToken,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
		ExpiresIn:       int(tc.AccessTokenTTL.Seconds()),
		Scope:           effectiveScope,
	}, nil
}

// narrowScope returns the intersection of granted and requested scopes
// (space-separated). Returns "" if the request exceeds what was granted.
func narrowScope(granted, requested string) string {
	grantedSet := make(map[string]bool)
	for _, s := range splitScope(granted) {
		grantedSet[s] = true
	}
	var result []string
	for _, s := range splitScope(requested) {
		if !grantedSet[s] {
			return "" // requested scope not in granted set
		}
		result = append(result, s)
	}
	if len(result) == 0 {
		return granted // empty request → keep original
	}
	return joinScope(result)
}

func splitScope(s string) []string {
	var out []string
	for _, part := range strings.Fields(s) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func joinScope(parts []string) string {
	return strings.Join(parts, " ")
}

// verifyMTLSRefreshBinding enforces RFC 8705 §7.1: when a refresh token
// carries an mTLS thumbprint the client MUST re-present the matching
// certificate.  Forwarding the stored thumbprint without proof of possession
// is not sufficient.
//
//   - storedThumb == "" → token is not mTLS-bound; no check needed.
//   - mtls == nil       → cert absent; return invalid_client (401).
//   - thumbprint ≠      → wrong cert;  return invalid_grant  (400).
func verifyMTLSRefreshBinding(storedThumb string, mtls *MTLSCert) error {
	if storedThumb == "" {
		return nil
	}
	if mtls == nil {
		return &TokenError{
			Code:        "invalid_client",
			Description: "mTLS client certificate is required: refresh token is sender-constrained",
		}
	}
	if mtls.X5TS256 != storedThumb {
		return &TokenError{
			Code:        "invalid_grant",
			Description: "mTLS certificate thumbprint mismatch: refresh token was bound to a different certificate",
		}
	}
	return nil
}

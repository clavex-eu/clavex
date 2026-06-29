package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// IntrospectionResponse is the RFC 7662 §2.2 compliant response body.
type IntrospectionResponse struct {
	// REQUIRED
	Active bool `json:"active"`
	// RFC 7662 §2.2 standard claims
	JTI       string   `json:"jti,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Nbf       int64    `json:"nbf,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"` // human-readable identifier (email)
	// Extension claims
	OrgID string `json:"org_id,omitempty"`
}

// Introspect validates the token, checks the revocation list, and returns
// its metadata. Always returns a valid (possibly inactive) response — never
// an error — per RFC 7662 §2.2.
func Introspect(
	ctx context.Context,
	rawToken string,
	tc *TokenConfig,
	store *session.Store,
) IntrospectionResponse {
	inactive := IntrospectionResponse{Active: false}

	tok, jti, exp, err := tc.VerifyAccessToken(rawToken)
	if err != nil {
		return inactive
	}

	// Check revocation list
	if revoked, _ := store.IsRevoked(ctx, jti); revoked {
		return inactive
	}

	orgID, _ := tok.Get("org_id")
	email, _ := tok.Get("email")
	emailStr := fmt.Sprint(email)

	return IntrospectionResponse{
		Active: true,
		JTI:    jti,
		Sub:    tok.Subject(),
		Aud:    tok.Audience(),
		ClientID: func() string {
			if a := tok.Audience(); len(a) > 0 {
				return a[0]
			}
			return ""
		}(),
		Scope:     stringClaim(tok, "scope"),
		Iss:       tok.Issuer(),
		Exp:       exp.Unix(),
		Nbf:       tok.IssuedAt().Unix(), // nbf = iat (tokens valid from issuance)
		Iat:       tok.IssuedAt().Unix(),
		TokenType: "Bearer",
		Username:  emailStr,
		OrgID:     fmt.Sprint(orgID),
	}
}

// RevokeAccessToken adds the token's JTI to the Redis revocation list.
func RevokeAccessToken(
	ctx context.Context,
	rawToken string,
	tc *TokenConfig,
	store *session.Store,
) error {
	_, jti, exp, err := tc.VerifyAccessToken(rawToken)
	if err != nil {
		// Ignore invalid tokens — revocation endpoint should still return 200
		return nil
	}
	ttl := time.Until(exp)
	if ttl <= 0 {
		return nil // already expired
	}
	return store.RevokeToken(ctx, jti, ttl)
}

// RevokeRefreshTokenByValue revokes a refresh token by its plain value.
func RevokeRefreshTokenByValue(
	ctx context.Context,
	rawToken string,
	tokens *repository.RefreshTokenRepository,
) error {
	hash := hashString(rawToken)
	rt, err := tokens.GetByHash(ctx, hash)
	if err != nil {
		return nil // not found → treat as already revoked
	}
	return tokens.RevokeByID(ctx, rt.ID)
}

// BuildUserInfo fetches and returns user claims for the /userinfo endpoint.
// Claims are scope-gated per OIDC Core §5.4:
//   - "openid" (always): sub
//   - "email":   email, email_verified
//   - "profile": all 14 standard profile claims (null when not stored)
//   - always:   groups, roles (non-scope-gated, always included)
//
// The access token must already be validated by the caller.
func BuildUserInfo(
	ctx context.Context,
	tok jwt.Token,
	users *repository.UserRepository,
	groups *repository.GroupRepository,
) (map[string]any, error) {
	sub := tok.Subject()
	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, &TokenError{Code: "invalid_token", Description: "invalid sub claim"}
	}

	user, err := users.GetByID(ctx, userID)
	if err != nil || !user.IsActive {
		return nil, &TokenError{Code: "invalid_token", Description: "user not found"}
	}

	scope := stringClaim(tok, "scope")
	hasScope := func(s string) bool {
		for _, tok := range strings.Fields(scope) {
			if tok == s {
				return true
			}
		}
		return false
	}

	out := map[string]any{
		"sub": user.ID.String(),
	}

	// "email" scope — OIDC Core §5.1 table
	if hasScope("email") {
		out["email"] = user.Email
		out["email_verified"] = user.IsEmailVerified
	}

	// "profile" scope — all 14 standard claims per OIDC Core §5.1
	// Claims with no value are OMITTED (not null) per §5.1.
	// Extended fields (middle_name, nickname, etc.) are stored in user.Metadata
	// under their OIDC claim names, populated by the conformance seed.
	if hasScope("profile") {
		givenName := strPtrVal(user.FirstName)
		familyName := strPtrVal(user.LastName)
		name := strings.TrimSpace(givenName + " " + familyName)

		setIfNonEmpty(out, "name", name)
		setIfNonEmpty(out, "given_name", givenName)
		setIfNonEmpty(out, "family_name", familyName)
		setMetaClaim(out, user.Metadata, "middle_name")
		setMetaClaim(out, user.Metadata, "nickname")
		setMetaClaim(out, user.Metadata, "preferred_username")
		setMetaClaim(out, user.Metadata, "profile")
		if av := strPtrVal(user.AvatarURL); av != "" {
			out["picture"] = av
		} else {
			setMetaClaim(out, user.Metadata, "picture")
		}
		setMetaClaim(out, user.Metadata, "website")
		setMetaClaim(out, user.Metadata, "gender")
		setMetaClaim(out, user.Metadata, "birthdate")
		setMetaClaim(out, user.Metadata, "zoneinfo")
		setMetaClaim(out, user.Metadata, "locale")
		out["updated_at"] = user.UpdatedAt.Unix()
	}

	// Always include groups and roles — not scope-gated, used by downstream
	// applications (e.g. Grafana role_attribute_path) for access control.
	if groups != nil {
		if gnames, err := groups.GroupsForUser(ctx, userID); err == nil {
			if gnames == nil {
				gnames = []string{}
			}
			out["groups"] = gnames
		}
	}
	if roleNames, err := users.FlattenRoleNames(ctx, userID); err == nil {
		if roleNames == nil {
			roleNames = []string{}
		}
		out["roles"] = roleNames
	}

	// OIDC Core §5.5 claims parameter: return any explicitly requested userinfo
	// claims regardless of scope so essential claim requests are honoured.
	var reqUserInfoClaims map[string]json.RawMessage
	if rawClaims := stringClaim(tok, "req_claims"); rawClaims != "" {
		var cp struct {
			UserInfo map[string]json.RawMessage `json:"userinfo"`
		}
		if json.Unmarshal([]byte(rawClaims), &cp) == nil {
			reqUserInfoClaims = cp.UserInfo
			for claimName, rawVal := range cp.UserInfo {
				if claimName == "verified_claims" {
					// Handled below after profile claims are resolved.
					_ = rawVal
					continue
				}
				if _, already := out[claimName]; already {
					continue // already included via scope
				}
				switch claimName {
				case "name":
					gn := strPtrVal(user.FirstName)
					fn := strPtrVal(user.LastName)
					if n := strings.TrimSpace(gn + " " + fn); n != "" {
						out["name"] = n
					}
				case "given_name":
					if v := strPtrVal(user.FirstName); v != "" {
						out["given_name"] = v
					}
				case "family_name":
					if v := strPtrVal(user.LastName); v != "" {
						out["family_name"] = v
					}
				case "email":
					out["email"] = user.Email
				case "email_verified":
					out["email_verified"] = user.IsEmailVerified
				default:
					setMetaClaim(out, user.Metadata, claimName)
				}
			}
		}
	}

	// OpenID Connect for Identity Assurance 1.0 §5 — verified_claims.
	// Include when the claims parameter requests verified_claims in userinfo,
	// or when the scope contains "verified_claims" (OP-defined convenience scope).
	includeVerifiedClaims := hasScope("verified_claims")
	var rawVerifiedClaimsReq json.RawMessage
	if reqUserInfoClaims != nil {
		if raw, ok := reqUserInfoClaims["verified_claims"]; ok {
			includeVerifiedClaims = true
			rawVerifiedClaimsReq = raw
		}
	}
	if includeVerifiedClaims {
		if vc := BuildVerifiedClaims(user.Metadata, out, rawVerifiedClaimsReq); vc != nil {
			out["verified_claims"] = vc
		}
	}

	return out, nil
}

// setIfNonEmpty adds key→val to m only when val is a non-empty string.
func setIfNonEmpty(m map[string]any, key, val string) {
	if val != "" {
		m[key] = val
	}
}

// setMetaClaim copies a claim from user.Metadata into out if it is a non-empty string.
func setMetaClaim(out map[string]any, meta map[string]interface{}, key string) {
	if meta == nil {
		return
	}
	if v, ok := meta[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			out[key] = s
		}
	}
}

// stringClaim safely extracts a string claim from a JWT.
func stringClaim(tok jwt.Token, key string) string {
	v, ok := tok.Get(key)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// strPtrVal safely dereferences a *string; returns "" if nil.
func strPtrVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

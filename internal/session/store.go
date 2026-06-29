package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	prefixRevoked     = "clavex:revoked:"     // key = token jti, value = "1", TTL = token exp
	prefixLogin       = "clavex:login:"       // key = login_session_id, value = LoginSession JSON
	prefixSAMLLogin   = "clavex:saml:login:"  // key = saml_login_session_id, value = SAMLLoginSession JSON
	prefixPWReset     = "clavex:pwreset:"     // key = token, value = user_id (UUID string)
	prefixEmailVerify = "clavex:emailverify:" // key = token, value = user_id|login_session_id
	prefixAccount     = "clavex:account:"     // key = account_session_id, value = AccountSession JSON
	prefixSSO         = "clavex:sso:"         // key = sso_session_id, value = SSOSession JSON
	prefixUnlockToken = "clavex:unlock:"      // key = token, value = orgID|email, TTL = 15 min
	prefixOTPSendCD   = "clavex:otp:sendcd:"  // OTP resend min-interval key, TTL = otpSendCooldown
	prefixOTPSendHr   = "clavex:otp:sendhr:"  // OTP hourly send counter, TTL = 1h
)

const (
	otpSendCooldown  = 30 * time.Second // minimum gap between OTP sends to the same address
	otpSendHourlyCap = 5                // max OTP sends per address per hour
)

// OTPSendAllowed enforces resend throttling for OTP delivery: a minimum interval
// between sends plus an hourly cap, per (scope, org, identifier). scope is
// "email" or "phone". Returns (false, retryAfter) when a send must be refused —
// protecting against email bombing and SMS toll-fraud. The identifier is hashed
// so addresses are never stored in plaintext. Fail-open on Redis errors so an
// outage never blocks legitimate delivery.
func (s *Store) OTPSendAllowed(ctx context.Context, scope, orgID, identifier string) (bool, time.Duration) {
	idh := otpIdentHash(orgID, identifier)
	cdKey := prefixOTPSendCD + scope + ":" + orgID + ":" + idh

	ok, err := s.rdb.SetNX(ctx, cdKey, "1", otpSendCooldown).Result()
	if err != nil {
		return true, 0 // fail-open
	}
	if !ok {
		ttl, _ := s.rdb.TTL(ctx, cdKey).Result()
		if ttl <= 0 {
			ttl = otpSendCooldown
		}
		return false, ttl
	}

	hrKey := prefixOTPSendHr + scope + ":" + orgID + ":" + idh
	n, err := s.rdb.Incr(ctx, hrKey).Result()
	if err != nil {
		return true, 0 // fail-open
	}
	if n == 1 {
		_ = s.rdb.Expire(ctx, hrKey, time.Hour).Err()
	}
	if n > int64(otpSendHourlyCap) {
		ttl, _ := s.rdb.TTL(ctx, hrKey).Result()
		if ttl <= 0 {
			ttl = time.Hour
		}
		return false, ttl
	}
	return true, 0
}

// otpIdentHash derives a Redis-safe, non-reversible key from (orgID, identifier).
func otpIdentHash(orgID, identifier string) string {
	h := sha256.Sum256([]byte(orgID + ":" + strings.ToLower(strings.TrimSpace(identifier))))
	return hex.EncodeToString(h[:16])
}

// Store wraps Redis for OIDC session operations.
type Store struct {
	rdb redis.UniversalClient
}

// NewStore creates a session Store using the provided Redis client.
func NewStore(rdb redis.UniversalClient) *Store {
	return &Store{rdb: rdb}
}

// ── Token revocation list ─────────────────────────────────────────────────────

// RevokeToken adds a token's JTI to the revocation list.
// ttl should be set to the token's remaining lifetime so Redis auto-expires it.
func (s *Store) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	return s.rdb.Set(ctx, prefixRevoked+jti, "1", ttl).Err()
}

// IsRevoked returns true if the given JTI has been revoked.
func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	res, err := s.rdb.Exists(ctx, prefixRevoked+jti).Result()
	if err != nil {
		return false, err
	}
	return res > 0, nil
}

// ── Login sessions (transient state during the authorize flow) ────────────────

// LoginSession holds the in-flight state of an authorisation request.
// It lives in Redis for the duration of the login interaction (max ~10 min).
type LoginSession struct {
	ID            string `json:"id"`
	OrgSlug       string `json:"org_slug"`
	OrgID         string `json:"org_id"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
	State         string `json:"state"`
	Nonce         string `json:"nonce"`
	PKCEChallenge string `json:"pkce_challenge,omitempty"`
	PKCEMethod    string `json:"pkce_method,omitempty"`
	// ResponseMode: "query" (default) | "query.jwt" | "fragment.jwt" (JARM) | "form_post" | "fragment"
	ResponseMode string `json:"response_mode,omitempty"`
	// ResponseType: "code" (default) | "code id_token" (hybrid) | "code token" etc.
	ResponseType string `json:"response_type,omitempty"`
	// OIDC interactive parameters forwarded from the authorization request
	Prompt    string `json:"prompt,omitempty"`
	LoginHint string `json:"login_hint,omitempty"`
	MaxAge    int    `json:"max_age,omitempty"`
	// AuthTime is the Unix timestamp of successful user authentication.
	// Set in AuthorizeSubmit after password verification; carried through MFA/resume.
	AuthTime  int64     `json:"auth_time,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// MFA step: set after password verification when MFA is required.
	UserID     string `json:"user_id,omitempty"`
	MFAPending bool   `json:"mfa_pending,omitempty"`
	// ForceMFA is set by the policy engine to require MFA step-up even when
	// the org/user settings do not mandate it.
	ForceMFA bool `json:"force_mfa,omitempty"`
	// BreachWarningAcknowledged is set after the user has seen and dismissed
	// the breach warning interstitial (breached_password_action=warn).
	// On the next AuthorizeSubmit call the breach check is skipped.
	BreachWarningAcknowledged bool `json:"breach_warning_acknowledged,omitempty"`

	// AuthorizationDetails carries the parsed RFC 9396 RAR array.
	// Stored so it survives MFA step-up and can be emitted in the token.
	AuthorizationDetails []map[string]any `json:"authorization_details,omitempty"`
	// AcrValues is the space-separated list of requested ACR values from the
	// authorization request. Forwarded to the auth code so the ID token can
	// include the acr claim (OIDC Core §2).
	AcrValues string `json:"acr_values,omitempty"`
	// ClaimsParam is the raw JSON value of the OIDC claims request parameter
	// (OIDC Core §5.5). Forwarded to the auth code and ultimately to the
	// access token so that BuildUserInfo can return explicitly requested claims.
	ClaimsParam string `json:"claims_param,omitempty"`
	// EmailOTPPending is set after the user requests an email OTP code.
	// The auth flow is paused until the correct code is submitted.
	EmailOTPPending bool `json:"email_otp_pending,omitempty"`
	// EmailOTPAddress is the email address to which the OTP was sent.
	EmailOTPAddress string `json:"email_otp_address,omitempty"`
	// PhoneOTPPending is set after the user requests a phone (SMS) OTP code
	// as the primary login factor.  The auth flow is paused until the correct
	// code is submitted.
	PhoneOTPPending bool `json:"phone_otp_pending,omitempty"`
	// PhoneOTPPhone is the E.164 phone number to which the OTP was sent.
	PhoneOTPPhone string `json:"phone_otp_phone,omitempty"`
	// ExtraClaims holds additional claims injected by the login flow engine
	// (enrich_claims / set_claim steps). Forwarded into the authorization code
	// and ultimately merged into the id_token at token exchange.
	ExtraClaims map[string]any `json:"extra_claims,omitempty"`

	// RequiredSPIDLevel, when > 0, overrides the SP AuthnLevel during an
	// in-session SPID level upgrade triggered by check_verified.
	// Values mirror SPID levels: 1=L1, 2=L2, 3=L3.
	RequiredSPIDLevel int `json:"required_spid_level,omitempty"`
	// RequiredCIEUpgrade, when true, marks that an in-session CIE re-authentication
	// is in progress (triggered by check_verified with upgrade:"cie").
	// The CIE callback clears this flag after successful re-authentication.
	RequiredCIEUpgrade bool `json:"required_cie_upgrade,omitempty"`
	// LastCIEProviderID is the UUID of the CIE IdP used in the most recent
	// CIE authentication. Used by UpgradeSSO to auto-redirect to the same provider.
	LastCIEProviderID string `json:"last_cie_provider_id,omitempty"`
	// DpopJKT is the JWK SHA-256 Thumbprint committed by the client at
	// authorization time via the dpop_jkt parameter (RFC 9449 §10).
	// When non-empty the token endpoint MUST verify the DPoP proof uses this key.
	DpopJKT string `json:"dpop_jkt,omitempty"`
	// LastSPIDIdPEntityID is the SAML entity ID of the IdP used in the most
	// recent SPID authentication. Used by UpgradeSSO to auto-redirect to
	// the same IdP at the higher level without forcing the user to re-pick.
	LastSPIDIdPEntityID string `json:"last_spid_idp_entity_id,omitempty"`
	// SessionIsolation mirrors OIDCClient.SessionIsolation.  When true the
	// post-login SSO cookie uses a client-specific name so the session is not
	// shared with other clients in the same org.
	SessionIsolation bool `json:"session_isolation,omitempty"`
	// OID4VPPending is set when the login flow engine's oid4vp_challenge step
	// requires a verifiable credential presentation before the login can complete.
	// The auth flow is paused until the wallet presents a matching credential.
	OID4VPPending bool `json:"oid4vp_pending,omitempty"`
	// OID4VPRequestID is the ID of the linked OID4VP presentation session.
	// Used by the challenge page to poll for status and by the resume handler
	// to fetch the verified claims and merge them into extra_claims.
	OID4VPRequestID string `json:"oid4vp_request_id,omitempty"`
	// OID4VPMessage is the user-facing prompt configured in the oid4vp_challenge
	// step, shown on the challenge page above the QR code.
	OID4VPMessage string `json:"oid4vp_message,omitempty"`
}

func (s *Store) SaveLoginSession(ctx context.Context, sess *LoginSession, ttl time.Duration) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal login session: %w", err)
	}
	return s.rdb.Set(ctx, prefixLogin+sess.ID, b, ttl).Err()
}

// GetLoginSession retrieves and deserialises a LoginSession by ID.
// Returns nil, nil if the session does not exist or has expired.
func (s *Store) GetLoginSession(ctx context.Context, id string) (*LoginSession, error) {
	b, err := s.rdb.Get(ctx, prefixLogin+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sess LoginSession
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal login session: %w", err)
	}
	return &sess, nil
}

// DeleteLoginSession removes a login session (called after code is issued).
func (s *Store) DeleteLoginSession(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, prefixLogin+id).Err()
}

// ── SAML login sessions ───────────────────────────────────────────────────────

// SAMLLoginSession stores in-flight SAML authn state.
// The type is defined in internal/saml to avoid an import cycle;
// we operate on it via interface{} + JSON here.

// SaveSAMLLoginSession persists an arbitrary JSON-serialisable SAML session.
func (s *Store) SaveSAMLLoginSession(ctx context.Context, sess interface{ GetID() string }, ttl time.Duration) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal saml login session: %w", err)
	}
	return s.rdb.Set(ctx, prefixSAMLLogin+sess.GetID(), b, ttl).Err()
}

// GetSAMLLoginSession retrieves the raw JSON for a SAML login session.
// Returns (nil, nil) if not found.
func (s *Store) GetSAMLLoginSession(ctx context.Context, id string) ([]byte, error) {
	b, err := s.rdb.Get(ctx, prefixSAMLLogin+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return b, err
}

// DeleteSAMLLoginSession removes a SAML login session.
func (s *Store) DeleteSAMLLoginSession(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, prefixSAMLLogin+id).Err()
}

// ── Identity provider OAuth2 state ───────────────────────────────────────────

const prefixIDPState = "clavex:idp_state:"

// IDPState holds the in-flight state during an upstream IdP OAuth2 redirect.
type IDPState struct {
	ProviderID     string `json:"provider_id"`
	LoginSessionID string `json:"login_session_id"`
	OrgSlug        string `json:"org_slug"`
	// CIE PKCE / OIDC nonce fields (populated only for provider_type == "cie")
	CodeVerifier string `json:"code_verifier,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
}

// SaveIDPState stores an IDPState under the given state token for 10 minutes.
func (s *Store) SaveIDPState(ctx context.Context, stateToken string, data *IDPState) error {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal idp state: %w", err)
	}
	return s.rdb.Set(ctx, prefixIDPState+stateToken, b, 10*time.Minute).Err()
}

// GetIDPState retrieves the IDPState for a given state token, consuming it atomically.
// Returns nil, nil if not found or expired.
func (s *Store) GetIDPState(ctx context.Context, stateToken string) (*IDPState, error) {
	key := prefixIDPState + stateToken
	b, err := s.rdb.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var data IDPState
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("unmarshal idp state: %w", err)
	}
	return &data, nil
}

// ── SPID relay state ──────────────────────────────────────────────────────────

const prefixSPIDState = "clavex:spid_state:"

// SPIDState is stored during the SPID SSO flow to correlate AuthnRequest → SAMLResponse.
type SPIDState struct {
	RequestID      string `json:"request_id"`       // AuthnRequest ID (_<uuid>)
	LoginSessionID string `json:"login_session_id"` // OIDC authorize session to resume
	OrgSlug        string `json:"org_slug"`
	OrgID          string `json:"org_id"`
	IdPEntityID    string `json:"idp_entity_id"` // which SPID IdP was chosen
}

// SaveSPIDState stores a SPIDState for 10 minutes (enough for IdP round-trip).
func (s *Store) SaveSPIDState(ctx context.Context, relayState string, data *SPIDState) error {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal spid state: %w", err)
	}
	return s.rdb.Set(ctx, prefixSPIDState+relayState, b, 10*time.Minute).Err()
}

// GetSPIDState retrieves and deletes the SPIDState for the given relay-state token.
func (s *Store) GetSPIDState(ctx context.Context, relayState string) (*SPIDState, error) {
	key := prefixSPIDState + relayState
	b, err := s.rdb.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var data SPIDState
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("unmarshal spid state: %w", err)
	}
	return &data, nil
}

// ── BundID SAML SSO state ─────────────────────────────────────────────────────

const prefixBundIDSAMLState = "clavex:bundidsaml_state:"

// BundIDSAMLState is stored during the BundID SAML SSO flow to correlate
// AuthnRequest (relayState) → SAMLResponse callback.
type BundIDSAMLState struct {
	RequestID      string `json:"request_id"`       // AuthnRequest ID (_<uuid>)
	LoginSessionID string `json:"login_session_id"` // OIDC authorize session to resume
	OrgSlug        string `json:"org_slug"`
	OrgID          string `json:"org_id"`
}

// SaveBundIDSAMLState stores a BundIDSAMLState for 10 minutes.
func (s *Store) SaveBundIDSAMLState(ctx context.Context, relayState string, data *BundIDSAMLState) error {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal bundidsaml state: %w", err)
	}
	return s.rdb.Set(ctx, prefixBundIDSAMLState+relayState, b, 10*time.Minute).Err()
}

// GetBundIDSAMLState retrieves and deletes the BundIDSAMLState for the given relay-state.
func (s *Store) GetBundIDSAMLState(ctx context.Context, relayState string) (*BundIDSAMLState, error) {
	key := prefixBundIDSAMLState + relayState
	b, err := s.rdb.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var data BundIDSAMLState
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("unmarshal bundidsaml state: %w", err)
	}
	return &data, nil
}

// ── eIDAS SSO state ───────────────────────────────────────────────────────────

const prefixEidasState = "clavex:eidas_state:"

// EidasState is stored during the eIDAS SSO flow to correlate AuthnRequest → SAMLResponse.
type EidasState struct {
	LoginSessionID string `json:"login_session_id"` // OIDC authorize session to resume
	OrgSlug        string `json:"org_slug"`
	OrgID          string `json:"org_id"`
	// RequestID is the SAML AuthnRequest ID; the ACS enforces that the assertion's
	// InResponseTo matches it (binds the response to this request).
	RequestID      string `json:"request_id"`
}

// SaveEidasState stores an EidasState under the relay-state key for 10 minutes.
func (s *Store) SaveEidasState(ctx context.Context, relayState string, data *EidasState) error {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal eidas state: %w", err)
	}
	return s.rdb.Set(ctx, prefixEidasState+relayState, b, 10*time.Minute).Err()
}

// GetEidasState retrieves and atomically deletes the EidasState for relayState.
func (s *Store) GetEidasState(ctx context.Context, relayState string) (*EidasState, error) {
	key := prefixEidasState + relayState
	b, err := s.rdb.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var data EidasState
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("unmarshal eidas state: %w", err)
	}
	return &data, nil
}

// ── Password reset tokens ─────────────────────────────────────────────────────

// SavePWResetToken stores a password-reset token that maps to a user ID.
func (s *Store) SavePWResetToken(ctx context.Context, token, userID string) error {
	return s.rdb.Set(ctx, prefixPWReset+token, userID, time.Hour).Err()
}

// ConsumePWResetToken atomically retrieves and deletes a password-reset token.
// Returns "", nil if not found or expired.
func (s *Store) ConsumePWResetToken(ctx context.Context, token string) (userID string, err error) {
	v, err := s.rdb.GetDel(ctx, prefixPWReset+token).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return v, err
}

// ── Email verification tokens ─────────────────────────────────────────────────

// SaveEmailVerifyToken stores a token that maps to "userID|loginSessionID".
func (s *Store) SaveEmailVerifyToken(ctx context.Context, token, userID, loginSessionID string) error {
	return s.rdb.Set(ctx, prefixEmailVerify+token, userID+"|"+loginSessionID, 30*time.Minute).Err()
}

// ConsumeEmailVerifyToken atomically retrieves and deletes the verify token.
// Returns "", "", nil when not found.
func (s *Store) ConsumeEmailVerifyToken(ctx context.Context, token string) (userID, loginSessionID string, err error) {
	v, err := s.rdb.GetDel(ctx, prefixEmailVerify+token).Result()
	if errors.Is(err, redis.Nil) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(v, "|", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("malformed email verify token")
	}
	return parts[0], parts[1], nil
}

// ── Account portal sessions ───────────────────────────────────────────────────

// AccountSession is a short-lived session for the user self-service portal.
// It is stored in Redis and referenced by an HTTP-only cookie on the browser.
type AccountSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	OrgID     string    `json:"org_id"`
	OrgSlug   string    `json:"org_slug"`
	CreatedAt time.Time `json:"created_at"`
}

const AccountSessionTTL = time.Hour

// SaveAccountSession stores an AccountSession for 1 hour.
func (s *Store) SaveAccountSession(ctx context.Context, sess *AccountSession) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal account session: %w", err)
	}
	return s.rdb.Set(ctx, prefixAccount+sess.ID, b, AccountSessionTTL).Err()
}

// GetAccountSession retrieves an AccountSession by ID.
// Returns nil, nil if not found or expired.
func (s *Store) GetAccountSession(ctx context.Context, id string) (*AccountSession, error) {
	b, err := s.rdb.Get(ctx, prefixAccount+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sess AccountSession
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal account session: %w", err)
	}
	return &sess, nil
}

// DeleteAccountSession removes an account session (logout).
func (s *Store) DeleteAccountSession(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, prefixAccount+id).Err()
}

// ── SSO browser sessions (prompt=none support) ────────────────────────────────

// SSOSession is a long-lived browser session created after a successful
// interactive login.  It is referenced by an HTTP-only cookie and lets the
// server satisfy prompt=none authorization requests without re-prompting.
type SSOSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	OrgID     string    `json:"org_id"`
	OrgSlug   string    `json:"org_slug"`
	AuthTime  int64     `json:"auth_time"` // Unix timestamp of the original authentication
	CreatedAt time.Time `json:"created_at"`
	// ClientID is non-empty only for isolated sessions (client.SessionIsolation=true).
	// When set, the session must only be used for the matching client.
	ClientID string `json:"client_id,omitempty"`
}

const SSOSessionTTL = 12 * time.Hour

// SaveSSOSession stores an SSOSession for SSOSessionTTL.
func (s *Store) SaveSSOSession(ctx context.Context, sess *SSOSession) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal sso session: %w", err)
	}
	return s.rdb.Set(ctx, prefixSSO+sess.ID, b, SSOSessionTTL).Err()
}

// GetSSOSession retrieves an SSOSession by ID.
// Returns nil, nil if not found or expired.
func (s *Store) GetSSOSession(ctx context.Context, id string) (*SSOSession, error) {
	b, err := s.rdb.Get(ctx, prefixSSO+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sess SSOSession
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal sso session: %w", err)
	}
	return &sess, nil
}

// DeleteSSOSession removes an SSO session (logout).
func (s *Store) DeleteSSOSession(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, prefixSSO+id).Err()
}

// ── Account unlock magic-link tokens ─────────────────────────────────────────

const unlockTokenTTL = 15 * time.Minute

// SaveUnlockToken stores a one-time unlock token that maps to "orgID|email".
// TTL is 15 minutes; the token is deleted on first use via ConsumeUnlockToken.
func (s *Store) SaveUnlockToken(ctx context.Context, token, orgID, email string) error {
	return s.rdb.Set(ctx, prefixUnlockToken+token, orgID+"|"+email, unlockTokenTTL).Err()
}

// ConsumeUnlockToken atomically retrieves and deletes the token.
// Returns "", "", nil if the token is not found or has expired.
func (s *Store) ConsumeUnlockToken(ctx context.Context, token string) (orgID, email string, err error) {
	v, err := s.rdb.GetDel(ctx, prefixUnlockToken+token).Result()
	if errors.Is(err, redis.Nil) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(v, "|", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("malformed unlock token payload")
	}
	return parts[0], parts[1], nil
}

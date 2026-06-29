// Package ssf implements the OpenID Shared Signals Framework (SSF) transmitter.
//
// Specifications:
//   - SSF Framework:  https://openid.net/specs/openid-sharedsignals-framework-1_0.html
//   - Push delivery:  RFC 8935 (Push-Based Security Event Token Delivery Using HTTP)
//   - Poll delivery:  RFC 8936 (Poll-Based Security Event Token Delivery Using HTTP)
//   - SET format:     RFC 8417 (Security Event Token)
//   - CAEP events:    https://openid.net/specs/openid-caep-specification-1_0.html
//   - RISC events:    https://openid.net/specs/openid-risc-profile-specification-1_0.html
package ssf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ── Event type URIs ──────────────────────────────────────────────────────────

// CAEP event type URIs per openid-caep-specification-1_0.
const (
	EventSessionRevoked     = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventCredentialChange   = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventAssuranceLvlChange = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	EventTokenClaimsChange  = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
)

// RISC event type URIs per openid-risc-profile-specification-1_0.
const (
	EventAccountDisabled    = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EventAccountEnabled     = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	EventAccountPurged      = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	EventSessionsRevoked    = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
	EventCredentialCompro   = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
)

// AllSupportedEvents is the set of event types this transmitter can produce.
var AllSupportedEvents = []string{
	EventSessionRevoked,
	EventCredentialChange,
	EventAssuranceLvlChange,
	EventTokenClaimsChange,
	EventAccountDisabled,
	EventAccountEnabled,
	EventAccountPurged,
	EventSessionsRevoked,
	EventCredentialCompro,
}

// ── Subject identifier ───────────────────────────────────────────────────────

// SubjectIdentifier describes the end-user the SET is about.
// Format follows the Subject Identifier Types spec (opaque or email).
type SubjectIdentifier struct {
	// Format: "iss_sub" (most common) or "email".
	Format  string `json:"format"`
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub,omitempty"`
	Email   string `json:"email,omitempty"`
}

// IssSubject returns an iss_sub format subject identifier.
func IssSubject(issuer, sub string) SubjectIdentifier {
	return SubjectIdentifier{Format: "iss_sub", Issuer: issuer, Subject: sub}
}

// ── SET builder ─────────────────────────────────────────────────────────────

// SETConfig holds the signing keys needed to build SETs.
type SETConfig struct {
	Issuer     string      // OP issuer URL
	PrivateKey interface{} // RSA/EC private key
	KID        string      // key ID for the JWK
}

// EventClaims is the per-event payload embedded in the SET's "events" claim.
// RFC 8417 §2.2: the "events" member is a JSON object where the key is the
// event type URI and the value is a JSON object (may be empty {}).
type EventClaims map[string]interface{}

// BuildSET creates a signed SET (Security Event Token) JWT per RFC 8417.
//
// Parameters:
//   - cfg:       transmitter signing config
//   - audience:  the stream's client_id (RFC 8417 §2.2 "aud")
//   - subject:   who the event is about
//   - eventType: one of the Event* constants above
//   - eventBody: per-event claims (nil is treated as an empty object)
func BuildSET(
	cfg *SETConfig,
	audience string,
	subject SubjectIdentifier,
	eventType string,
	eventBody map[string]interface{},
) (string, string, error) {
	jti := uuid.NewString()
	now := time.Now()

	if eventBody == nil {
		eventBody = map[string]interface{}{}
	}

	// RFC 8417 §2.2: "events" is a JSON object; only one event per SET.
	events := map[string]interface{}{
		eventType: eventBody,
	}

	b := jwt.NewBuilder().
		JwtID(jti).
		Issuer(cfg.Issuer).
		Audience([]string{audience}).
		IssuedAt(now).
		Claim("events", events).
		Claim("sub_id", subject)

	// RFC 8417 §2.2: toe (time of event) — optional, set to now.
	b = b.Claim("toe", now.Unix())

	tok, err := b.Build()
	if err != nil {
		return "", "", fmt.Errorf("ssf: build SET: %w", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, cfg.KID)
	// RFC 8417 §2.1: typ header MUST be "secevent+jwt"
	_ = hdrs.Set("typ", "secevent+jwt")

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, cfg.PrivateKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", "", fmt.Errorf("ssf: sign SET: %w", err)
	}
	return string(signed), jti, nil
}

// ── Push delivery helpers ────────────────────────────────────────────────────

// SignPushPayload produces an HMAC-SHA256 signature over the SET JWT body,
// using the stream's push secret. Returned as "sha256=<hex>".
// Mirrors the webhook signature convention already used in Clavex.
func SignPushPayload(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// GenerateStreamSecret returns a cryptographically random 32-byte secret
// encoded as base64url, used as the HMAC signing key for push delivery.
func GenerateStreamSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashStreamSecret produces a SHA-256 hex hash of the secret for storage.
func HashStreamSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// ── Transmitter metadata ─────────────────────────────────────────────────────

// TransmitterMetadata is the SSF transmitter configuration document served at
// /.well-known/ssf-configuration per the SSF Framework spec §7.
type TransmitterMetadata struct {
	Issuer                      string   `json:"issuer"`
	JWKSUri                     string   `json:"jwks_uri"`
	DeliveryMethodsSupported    []string `json:"delivery_methods_supported"`
	ConfigurationEndpoint       string   `json:"configuration_endpoint"`
	StatusEndpoint              string   `json:"status_endpoint"`
	AddSubjectEndpoint          string   `json:"add_subject_endpoint"`
	RemoveSubjectEndpoint       string   `json:"remove_subject_endpoint"`
	VerificationEndpoint        string   `json:"verification_endpoint"`
	CriticalSubjectMembers      []string `json:"critical_subject_members,omitempty"`
	EventTypesSupported         []string `json:"event_types_supported"`
}

// BuildTransmitterMetadata constructs the transmitter metadata document
// for the given per-tenant issuer base URL.
func BuildTransmitterMetadata(base string) TransmitterMetadata {
	return TransmitterMetadata{
		Issuer:  base,
		JWKSUri: base + "/.well-known/jwks.json",
		DeliveryMethodsSupported: []string{
			"https://schemas.openid.net/secevent/risc/delivery-method/push",
			"https://schemas.openid.net/secevent/risc/delivery-method/poll",
		},
		ConfigurationEndpoint:  base + "/ssf/stream",
		StatusEndpoint:         base + "/ssf/stream/status",
		AddSubjectEndpoint:     base + "/ssf/subjects:add",
		RemoveSubjectEndpoint:  base + "/ssf/subjects:remove",
		VerificationEndpoint:   base + "/ssf/stream/verify",
		EventTypesSupported:    AllSupportedEvents,
	}
}
// ── CAEP event body constructors ─────────────────────────────────────────────
//
// These helpers produce the per-event claims object for each CAEP/RISC event
// type, per the openid-caep-specification-1_0 and openid-risc-profile-1_0 specs.
// Callers pass the result as the eventBody argument to BuildSET / Dispatcher.Dispatch.

// CredentialChangeBody returns the event body for a CAEP credential-change event.
//
// credentialType: "password" | "pin" | "x509" | "fido2-platform" | "fido2-roaming" | "otp"
// changeType:     "create" | "revoke" | "update"
//
// Spec: openid-caep-specification-1_0 §3.3
func CredentialChangeBody(credentialType, changeType string) map[string]interface{} {
	return map[string]interface{}{
		"credential_type": credentialType,
		"change_type":     changeType,
	}
}

// SessionRevokedBody returns the event body for a CAEP session-revoked event.
//
// reason: "logout" | "admin" | "idle_timeout" | "reauthentication" | "password_change" | "revoked"
//
// Spec: openid-caep-specification-1_0 §3.1
func SessionRevokedBody(reason string) map[string]interface{} {
	return map[string]interface{}{
		"reason_admin": map[string]interface{}{
			"en": reason,
		},
	}
}

// SessionsRevokedBody returns the event body for a RISC sessions-revoked event.
//
// Spec: openid-risc-profile-specification-1_0 §2.5
func SessionsRevokedBody(reason string) map[string]interface{} {
	return map[string]interface{}{
		"reason": reason,
	}
}

// AccountDisabledBody returns the event body for a RISC account-disabled event.
//
// reason: "hijacking" | "bulk-account" | "admin"
//
// Spec: openid-risc-profile-specification-1_0 §2.1
func AccountDisabledBody(reason string) map[string]interface{} {
	return map[string]interface{}{
		"reason": reason,
	}
}

// TokenRevokedBody returns the event body for a CAEP token-claims-change event
// signalling that an access token has been explicitly revoked.
//
// Per draft-ietf-oauth-caep (CAE): the RS receives this event and MUST
// immediately invalidate the named token from any local cache, rather than
// waiting for its natural expiry.
//
// jti is the JWT ID of the revoked access token (empty string is allowed when
// the token is opaque and the JTI is not available).
//
// Spec: openid-caep-specification-1_0 §3.4 (token-claims-change)
func TokenRevokedBody(jti string) map[string]interface{} {
	body := map[string]interface{}{
		"change_type": "revoke",
	}
	if jti != "" {
		body["token_jti"] = jti
	}
	return body
}
// ── Poll delivery response ───────────────────────────────────────────────────

// PollResponse is the JSON body returned by the poll endpoint (RFC 8936 §2.3).
type PollResponse struct {
	Sets         map[string]string `json:"sets"`          // jti → compact SET JWT
	MoreAvailable bool             `json:"moreAvailable"` // true when queue still has SETs
}

// PollRequest is the JSON body sent by the receiver to the poll endpoint.
type PollRequest struct {
	// Acknowledge previously received SETs by JTI.
	Ack         []string `json:"ack,omitempty"`
	// MaxEvents caps the number of new SETs returned (default: 100).
	MaxEvents   int      `json:"maxEvents,omitempty"`
	ReturnImmediately bool `json:"returnImmediately,omitempty"`
}

// SETRecord is a decoded SET used internally when reading from the DB.
type SETRecord struct {
	JTI       string
	StreamID  uuid.UUID
	Payload   string // compact JWT
	EventType string
}

// ── Stream configuration ─────────────────────────────────────────────────────

// StreamConfig is the JSON representation of an SSF stream, used both in the
// API request/response and as the basis for the model.
type StreamConfig struct {
	StreamID        string   `json:"stream_id,omitempty"`
	Iss             string   `json:"iss,omitempty"`
	Aud             []string `json:"aud,omitempty"`
	EventsRequested []string `json:"events_requested"`
	EventsDelivered []string `json:"events_delivered,omitempty"`
	Delivery        Delivery `json:"delivery"`
	Status          string   `json:"status,omitempty"`
	Description     string   `json:"description,omitempty"`
}

// Delivery specifies the delivery method for a stream.
type Delivery struct {
	// Method URI: push or poll delivery method URI.
	Method          string `json:"method"`
	// EndpointURL is the push receiver URL (required for push delivery).
	EndpointURL     string `json:"endpoint_url,omitempty"`
}

// PushMethodURI is the delivery method URI for push (RFC 8935).
const PushMethodURI = "https://schemas.openid.net/secevent/risc/delivery-method/push"

// PollMethodURI is the delivery method URI for poll (RFC 8936).
const PollMethodURI = "https://schemas.openid.net/secevent/risc/delivery-method/poll"

// VerificationEventType is the event type for verification SETs (RFC 8936 §2.4).
const VerificationEventType = "https://schemas.openid.net/secevent/risc/event-type/verification"

// BuildVerificationSET builds a SET for stream verification (RFC 8936 §2.4).
// The state value is echoed back so the receiver can confirm delivery.
func BuildVerificationSET(cfg *SETConfig, audience, state string) (string, string, error) {
	body := map[string]interface{}{}
	if state != "" {
		body["state"] = state
	}
	return BuildSET(cfg, audience, SubjectIdentifier{}, VerificationEventType, body)
}

// ParseSETPayload is a minimal parsed representation of a SET for internal use.
type ParsedSET struct {
	JTI       string
	EventType string
	Body      json.RawMessage
}

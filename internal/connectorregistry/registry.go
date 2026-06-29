// Package connectorregistry is the central catalog for all pluggable Clavex
// connectors: social / OAuth2 login providers, SMS gateways, and email delivery
// services.
//
// # Architecture
//
// Connectors register themselves in package init() functions.  Built-in
// connectors (Twilio, SendGrid, Google, …) are registered in the sub-files of
// this package.  Third-party connectors can be added by creating a Go package
// that calls Register* at init time and importing it with a blank import:
//
//	import _ "github.com/acme/clavex-infobip-sms"
//
// No binary plugins (plugin.Open), no CGo, no subprocesses — just Go's
// standard init-based registration pattern (same as database/sql drivers).
//
// # Catalog API
//
// The full catalog is exposed at:
//
//	GET /connector-catalog?category=social|sms|email
//
// # Adding a social provider
//
// To add "Okta" as a new built-in:
//
//	func init() {
//	    connectorregistry.RegisterSocial(&connectorregistry.SocialDef{
//	        ID: "okta", DisplayName: "Okta", Category: "enterprise",
//	        AuthorizationURL: "https://{domain}/oauth2/default/v1/authorize",
//	        ...
//	    })
//	}
package connectorregistry

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// ── Social / OAuth2 connector ─────────────────────────────────────────────────

// SocialDef is the full definition of a social / OAuth2 login connector in the
// catalog.  ISVs select a connector by ID; Clavex fills in all endpoint URLs
// so the admin only needs to supply the client credentials.
type SocialDef struct {
	// ID is the canonical provider_type value stored in the identity_providers
	// table (e.g. "google", "github", "slack").
	ID string `json:"id"`

	// DisplayName is the human-readable provider name shown in the admin UI.
	DisplayName string `json:"display_name"`

	// Category groups providers in the marketplace UI.
	// Values: "social" | "enterprise" | "government" | "custom"
	Category string `json:"category"`

	// LogoURL points to the provider's logo (SVG preferred, may be empty).
	LogoURL string `json:"logo_url,omitempty"`

	// Standard OAuth2 / OIDC endpoints.
	AuthorizationURL string  `json:"authorization_url"`
	TokenURL         string  `json:"token_url"`
	UserinfoURL      *string `json:"userinfo_url,omitempty"`
	Scopes           string  `json:"scopes"`

	// Default claim names used to populate the Clavex user profile.
	EmailClaim     string `json:"email_claim"`
	FirstNameClaim string `json:"first_name_claim"`
	LastNameClaim  string `json:"last_name_claim"`

	// ConfigSchema lists extra provider-specific fields required from the admin
	// (e.g. Apple Sign In needs team_id / key_id / private_key).
	// An empty slice means only client_id + client_secret are needed.
	ConfigSchema []ConfigField `json:"config_schema,omitempty"`

	// Notes surfaces provider-specific setup requirements in the admin UI.
	Notes string `json:"notes,omitempty"`
}

// ── SMS connector ─────────────────────────────────────────────────────────────

// SMSSender is the minimal interface for sending a single SMS message.
// It is structurally identical to sms.Provider; sms.Provider is defined as a
// type alias of this interface to eliminate any conversion overhead.
type SMSSender interface {
	Send(ctx context.Context, to, body string) error
}

// SMSFactory constructs an SMSSender from a provider-specific config map.
// Config keys are provider-defined (see SMSConnectorDef.ConfigSchema).
type SMSFactory func(config map[string]any) (SMSSender, error)

// SMSConnectorDef describes an SMS gateway connector in the catalog.
type SMSConnectorDef struct {
	ID           string        `json:"id"`
	DisplayName  string        `json:"display_name"`
	LogoURL      string        `json:"logo_url,omitempty"`
	ConfigSchema []ConfigField `json:"config_schema"`
}

// ── Email connector ───────────────────────────────────────────────────────────

// EmailSender is the minimal interface for transactional HTML email delivery.
type EmailSender interface {
	SendHTML(ctx context.Context, to, subject, htmlBody string) error
}

// EmailFactory constructs an EmailSender from a provider-specific config map.
type EmailFactory func(config map[string]any) (EmailSender, error)

// EmailConnectorDef describes an email delivery connector in the catalog.
type EmailConnectorDef struct {
	ID           string        `json:"id"`
	DisplayName  string        `json:"display_name"`
	LogoURL      string        `json:"logo_url,omitempty"`
	ConfigSchema []ConfigField `json:"config_schema"`
}

// ── ConfigField ───────────────────────────────────────────────────────────────

// ConfigField is a single input required to configure a connector.
// Used by the admin UI to render forms and validate inputs before storage.
type ConfigField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	// Type: "text" | "password" | "textarea" | "number" | "url"
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
	Description string `json:"description,omitempty"`
}

// ── Registries ────────────────────────────────────────────────────────────────

var (
	socialMu   sync.RWMutex
	socialDefs = map[string]*SocialDef{}

	smsMu        sync.RWMutex
	smsDefs      = map[string]*SMSConnectorDef{}
	smsFactories = map[string]SMSFactory{}

	emailMu        sync.RWMutex
	emailDefs      = map[string]*EmailConnectorDef{}
	emailFactories = map[string]EmailFactory{}
)

// ── Registration ──────────────────────────────────────────────────────────────

// RegisterSocial adds a social / OAuth2 connector to the catalog.
// Intended to be called from package init() functions; safe for concurrent use.
func RegisterSocial(def *SocialDef) {
	socialMu.Lock()
	defer socialMu.Unlock()
	socialDefs[def.ID] = def
}

// RegisterSMS adds an SMS gateway connector to the catalog.
func RegisterSMS(def *SMSConnectorDef, factory SMSFactory) {
	smsMu.Lock()
	defer smsMu.Unlock()
	smsDefs[def.ID] = def
	smsFactories[def.ID] = factory
}

// RegisterEmail adds an email delivery connector to the catalog.
func RegisterEmail(def *EmailConnectorDef, factory EmailFactory) {
	emailMu.Lock()
	defer emailMu.Unlock()
	emailDefs[def.ID] = def
	emailFactories[def.ID] = factory
}

// ── Queries ───────────────────────────────────────────────────────────────────

// ListSocial returns all registered social connectors sorted by ID.
func ListSocial() []*SocialDef {
	socialMu.RLock()
	defer socialMu.RUnlock()
	out := make([]*SocialDef, 0, len(socialDefs))
	for _, d := range socialDefs {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// GetSocial returns the SocialDef for a given provider type ID, or nil.
func GetSocial(id string) *SocialDef {
	socialMu.RLock()
	defer socialMu.RUnlock()
	return socialDefs[id]
}

// ListSMS returns all registered SMS connectors sorted by ID.
func ListSMS() []*SMSConnectorDef {
	smsMu.RLock()
	defer smsMu.RUnlock()
	out := make([]*SMSConnectorDef, 0, len(smsDefs))
	for _, d := range smsDefs {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// GetSMS returns the SMSConnectorDef for a given provider ID, or nil.
func GetSMS(id string) *SMSConnectorDef {
	smsMu.RLock()
	defer smsMu.RUnlock()
	return smsDefs[id]
}

// ListEmail returns all registered email connectors sorted by ID.
func ListEmail() []*EmailConnectorDef {
	emailMu.RLock()
	defer emailMu.RUnlock()
	out := make([]*EmailConnectorDef, 0, len(emailDefs))
	for _, d := range emailDefs {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IsSocialRegistered returns true if a provider_type is either "oidc" (fully
// custom) or a known registered social connector.
func IsSocialRegistered(id string) bool {
	if id == "oidc" {
		return true
	}
	socialMu.RLock()
	defer socialMu.RUnlock()
	_, ok := socialDefs[id]
	return ok
}

// ── Factories ─────────────────────────────────────────────────────────────────

// NewSMSProvider instantiates the registered SMS provider with the given config.
// Returns an error when the provider ID is unknown.
func NewSMSProvider(providerID string, config map[string]any) (SMSSender, error) {
	smsMu.RLock()
	f, ok := smsFactories[providerID]
	smsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("connectorregistry: unknown SMS provider %q (register it via RegisterSMS)", providerID)
	}
	return f(config)
}

// NewEmailProvider instantiates the registered email provider with the given config.
func NewEmailProvider(providerID string, config map[string]any) (EmailSender, error) {
	emailMu.RLock()
	f, ok := emailFactories[providerID]
	emailMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("connectorregistry: unknown email provider %q (register it via RegisterEmail)", providerID)
	}
	return f(config)
}

// Package connector provides a pluggable event-publishing interface for
// clavex auth lifecycle events (login, token issued, logout, …).
//
// Two built-in transports are provided:
//
//   - HTTPConnector — publishes to an external HTTP webhook (the same signed
//     JSON format as the existing webhook.Dispatcher).
//   - MQTTConnector — publishes to an MQTT topic (compatible with keel's
//     mqtt-gateway by default).
//
// Additional connectors can be registered at startup by calling Register.
package connector

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Event is a named auth lifecycle event.
type Event = string

const (
	EventUserLogin               Event = "user.login"
	EventUserLoginFailed         Event = "user.login.failed"
	EventUserIdentifierLockout   Event = "user.identifier.lockout" // adaptive lockout applied to an identifier
	EventUserLogout              Event = "user.logout"
	EventTokenIssued             Event = "token.issued"
	EventTokenRevoked            Event = "token.revoked"
	EventMFASuccess              Event = "mfa.success"
	EventMFAFailed               Event = "mfa.failed"
	EventPasswordReset           Event = "password.reset"
	EventEmailVerified           Event = "user.email.verified"
	EventUserCreated             Event = "user.created"
	EventUserUpdated             Event = "user.updated"
	EventUserDeleted             Event = "user.deleted"
)

// Payload is the JSON envelope sent on every event.
type Payload struct {
	ID         string          `json:"id"`
	Event      string          `json:"event"`
	OccurredAt time.Time       `json:"occurred_at"`
	OrgID      string          `json:"org_id"`
	Data       json.RawMessage `json:"data"`
}

// Connector publishes a single event payload.
type Connector interface {
	// Publish sends the payload asynchronously. Errors are logged; the caller
	// is never blocked.
	Publish(ctx context.Context, p *Payload)
	// Close releases any resources (MQTT connections, etc.).
	Close()
}

// ── Registry ─────────────────────────────────────────────────────────────────

var (
	mu         sync.RWMutex
	connectors []Connector
)

// Register adds a connector to the global registry.
// Call from main/server init before serving requests.
func Register(c Connector) {
	mu.Lock()
	defer mu.Unlock()
	connectors = append(connectors, c)
}

// Dispatch builds a Payload and publishes it on all registered connectors.
// Non-blocking: each connector runs in its own goroutine.
func Dispatch(orgID, event string, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		log.Error().Err(err).Str("event", event).Msg("connector: marshal data")
		return
	}
	p := &Payload{
		ID:         uuid.NewString(),
		Event:      event,
		OccurredAt: time.Now().UTC(),
		OrgID:      orgID,
		Data:       raw,
	}

	mu.RLock()
	list := make([]Connector, len(connectors))
	copy(list, connectors)
	mu.RUnlock()

	for _, c := range list {
		c := c
		go c.Publish(context.Background(), p)
	}
}

// CloseAll shuts down all registered connectors.
func CloseAll() {
	mu.Lock()
	defer mu.Unlock()
	for _, c := range connectors {
		c.Close()
	}
	connectors = nil
}

// ── HTTP Connector ────────────────────────────────────────────────────────────

// HTTPConfig configures an HTTP connector.
type HTTPConfig struct {
	// URL is the endpoint to POST events to.
	URL string
	// Secret is used to sign the body with HMAC-SHA256 (X-Clavex-Signature header).
	// Leave empty to skip signing.
	Secret string
	// Events is the allowlist of event types to forward. Empty = all events.
	Events []string
	// Timeout for each HTTP request (default 10s).
	Timeout time.Duration
}

// HTTPConnector POSTs signed JSON payloads to an external URL.
type HTTPConnector struct {
	cfg    HTTPConfig
	client *http.Client
	events map[string]bool
}

// NewHTTP creates an HTTPConnector. Satisfies the Connector interface.
func NewHTTP(cfg HTTPConfig) *HTTPConnector {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	evts := make(map[string]bool)
	for _, e := range cfg.Events {
		evts[e] = true
	}
	return &HTTPConnector{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}, events: evts}
}

func (h *HTTPConnector) Publish(ctx context.Context, p *Payload) {
	if len(h.events) > 0 && !h.events[p.Event] {
		return
	}
	body, err := json.Marshal(p)
	if err != nil {
		log.Error().Err(err).Msg("connector/http: marshal payload")
		return
	}
	sig := signBody(body, h.cfg.Secret)

	for attempt := 1; attempt <= 3; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if sig != "" {
			req.Header.Set("X-Clavex-Signature", "sha256="+sig)
		}
		resp, err := h.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return
			}
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
		}
	}
	log.Warn().Str("url", h.cfg.URL).Str("event", p.Event).Msg("connector/http: all delivery attempts failed")
}

func (h *HTTPConnector) Close() {}

func signBody(body []byte, secret string) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// wrapSigned wraps body in {"payload":<body>,"sig":"sha256=<hmac>"} when
// secret is non-empty. Returns body unchanged otherwise.
func wrapSigned(body []byte, secret string) []byte {
	sig := signBody(body, secret)
	if sig == "" {
		return body
	}
	type envelope struct {
		Payload json.RawMessage `json:"payload"`
		Sig     string          `json:"sig"`
	}
	wrapped, err := json.Marshal(envelope{Payload: body, Sig: "sha256=" + sig})
	if err != nil {
		return body
	}
	return wrapped
}

// ── MQTT Connector ────────────────────────────────────────────────────────────

// MQTTConfig configures an MQTT connector.
type MQTTConfig struct {
	// BrokerURL is the MQTT broker (e.g. "tcp://localhost:1883" or "ssl://...").
	BrokerURL string
	// ClientID used when connecting to the broker.
	ClientID string
	// Username / Password for broker auth (optional).
	Username string
	Password string
	// TopicPattern is a Go format string with one %s for the event name.
	// Default: "clavex/%s"
	TopicPattern string
	// QoS level (0, 1, or 2). Default: 1.
	QoS byte
	// Events is the allowlist of event types to forward. Empty = all events.
	Events []string
	// Secret enables payload signing: when non-empty each message is wrapped in a
	// {"payload":<event>,"sig":"sha256=<hmac>"} envelope so consumers can verify integrity.
	Secret string
}

// MQTTConnector publishes events to an MQTT broker.
// Compatible with keel's mqtt-gateway (mochi-mqtt server).
type MQTTConnector struct {
	cfg    MQTTConfig
	client mqtt.Client
	events map[string]bool
}

// NewMQTT dials the broker and returns an MQTTConnector.
// Returns an error if the initial connection fails.
func NewMQTT(cfg MQTTConfig) (*MQTTConnector, error) {
	if cfg.TopicPattern == "" {
		cfg.TopicPattern = "clavex/%s"
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "clavex-connector-" + uuid.NewString()[:8]
	}

	evts := make(map[string]bool)
	for _, e := range cfg.Events {
		evts[e] = true
	}

	opts := mqtt.NewClientOptions().
		AddBroker(cfg.BrokerURL).
		SetClientID(cfg.ClientID).
		SetUsername(cfg.Username).
		SetPassword(cfg.Password).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetOnConnectHandler(func(_ mqtt.Client) {
			log.Info().Str("broker", cfg.BrokerURL).Msg("connector/mqtt: connected")
		}).
		SetConnectionLostHandler(func(_ mqtt.Client, err error) {
			log.Warn().Err(err).Str("broker", cfg.BrokerURL).Msg("connector/mqtt: connection lost, reconnecting")
		})

	client := mqtt.NewClient(opts)
	if tok := client.Connect(); tok.WaitTimeout(10*time.Second) && tok.Error() != nil {
		return nil, fmt.Errorf("connector/mqtt: connect to %s: %w", cfg.BrokerURL, tok.Error())
	}

	return &MQTTConnector{cfg: cfg, client: client, events: evts}, nil
}

func (m *MQTTConnector) Publish(_ context.Context, p *Payload) {
	if len(m.events) > 0 && !m.events[p.Event] {
		return
	}
	body, err := json.Marshal(p)
	if err != nil {
		log.Error().Err(err).Msg("connector/mqtt: marshal payload")
		return
	}
	topic := fmt.Sprintf(m.cfg.TopicPattern, dotToSlash(p.Event))
	tok := m.client.Publish(topic, m.cfg.QoS, false, wrapSigned(body, m.cfg.Secret))
	if !tok.WaitTimeout(5 * time.Second) {
		log.Warn().Str("topic", topic).Msg("connector/mqtt: publish timeout")
	}
}

func (m *MQTTConnector) Close() {
	m.client.Disconnect(500)
}

func dotToSlash(s string) string {
	out := make([]byte, len(s))
	for i := range s {
		if s[i] == '.' {
			out[i] = '/'
		} else {
			out[i] = s[i]
		}
	}
	return string(out)
}

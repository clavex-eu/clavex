package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// ── Sink interface ────────────────────────────────────────────────────────────

// SinkConfig mirrors the audit_sinks row.
type SinkConfig struct {
	ID             uuid.UUID
	OrgID          uuid.UUID
	Name           string
	SinkType       string // "webhook" | "http" | "mqtt" | "kafka"
	Config         map[string]interface{}
	FilterActions  []string
	FilterStatuses []string
}

// Sink delivers a single CloudEvents event to an external endpoint.
type Sink interface {
	// Type returns the sink type string ("webhook", "http", "mqtt", "kafka").
	Type() string
	// Send delivers the event. Returns an error if the delivery failed.
	Send(ctx context.Context, e *Event) error
}

// SinkStatsUpdater is the repository method used to record delivery outcomes.
type SinkStatsUpdater interface {
	UpdateSinkStats(ctx context.Context, sinkID uuid.UUID, success bool, errMsg string) error
}

// ── 1. Webhook sink (HMAC-signed HTTP POST) ───────────────────────────────────

type webhookSink struct {
	url     string
	secret  string
	headers map[string]string
	hc      *http.Client
}

// NewWebhookSink creates an HMAC-SHA256 signed webhook sink.
// config keys: url (required), secret, headers (object).
func NewWebhookSink(config map[string]interface{}) (Sink, error) {
	u, _ := config["url"].(string)
	if u == "" {
		return nil, fmt.Errorf("webhook sink: url is required")
	}
	secret, _ := config["secret"].(string)
	headers := map[string]string{}
	if hm, ok := config["headers"].(map[string]interface{}); ok {
		for k, v := range hm {
			if sv, ok := v.(string); ok {
				headers[k] = sv
			}
		}
	}
	return &webhookSink{
		url:     u,
		secret:  secret,
		headers: headers,
		hc:      &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (s *webhookSink) Type() string { return "webhook" }

func (s *webhookSink) Send(ctx context.Context, e *Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("webhook sink marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/cloudevents+json")
	req.Header.Set("Ce-Specversion", e.SpecVersion)
	req.Header.Set("Ce-Id", e.ID)
	req.Header.Set("Ce-Source", e.Source)
	req.Header.Set("Ce-Type", e.Type)

	if s.secret != "" {
		mac := hmac.New(sha256.New, []byte(s.secret))
		mac.Write(body)
		req.Header.Set("X-Clavex-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook sink: non-2xx response %d", resp.StatusCode)
	}
	return nil
}

// ── 2. HTTP sink (generic HTTP POST/PUT, no signature) ────────────────────────

type httpSink struct {
	url     string
	method  string
	headers map[string]string
	hc      *http.Client
}

// NewHTTPSink creates a plain HTTP sink.
// config keys: url (required), method (default POST), headers, timeout_seconds.
func NewHTTPSink(config map[string]interface{}) (Sink, error) {
	u, _ := config["url"].(string)
	if u == "" {
		return nil, fmt.Errorf("http sink: url is required")
	}
	method := "POST"
	if m, ok := config["method"].(string); ok && m != "" {
		method = m
	}
	timeout := 10 * time.Second
	if ts, ok := config["timeout_seconds"].(float64); ok && ts > 0 {
		timeout = time.Duration(ts) * time.Second
	}
	headers := map[string]string{}
	if hm, ok := config["headers"].(map[string]interface{}); ok {
		for k, v := range hm {
			if sv, ok := v.(string); ok {
				headers[k] = sv
			}
		}
	}
	return &httpSink{
		url:     u,
		method:  method,
		headers: headers,
		hc:      &http.Client{Timeout: timeout},
	}, nil
}

func (s *httpSink) Type() string { return "http" }

func (s *httpSink) Send(ctx context.Context, e *Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("http sink marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, s.method, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/cloudevents+json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http sink: non-2xx response %d", resp.StatusCode)
	}
	return nil
}

// signedEnvelope wraps a message payload with an HMAC-SHA256 signature so
// consumers can optionally verify integrity. The sig field is computed over the
// exact bytes of the payload field — consumers must not re-serialise before
// verifying.
type signedEnvelope struct {
	Payload json.RawMessage `json:"payload"`
	Sig     string          `json:"sig"`
}

// wrapSigned serialises body inside a signedEnvelope. Returns body unchanged
// when secret is empty (backwards-compatible).
func wrapSigned(body []byte, secret string) []byte {
	if secret == "" {
		return body
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	wrapped, err := json.Marshal(signedEnvelope{Payload: body, Sig: sig})
	if err != nil {
		return body
	}
	return wrapped
}

// ── 3. MQTT sink ──────────────────────────────────────────────────────────────

type mqttSink struct {
	client mqtt.Client
	topic  string
	qos    byte
	secret string
}

// NewMQTTSink creates an MQTT sink.
// config keys: broker (required, e.g. "tcp://localhost:1883"), topic (required),
//
//	qos (0|1|2, default 1), client_id, username, password.
func NewMQTTSink(config map[string]interface{}) (Sink, error) {
	broker, _ := config["broker"].(string)
	if broker == "" {
		return nil, fmt.Errorf("mqtt sink: broker is required")
	}
	topic, _ := config["topic"].(string)
	if topic == "" {
		return nil, fmt.Errorf("mqtt sink: topic is required")
	}
	qos := byte(1)
	if q, ok := config["qos"].(float64); ok {
		qos = byte(q)
	}
	clientID := "clavex-audit-" + uuid.NewString()[:8]
	if cid, ok := config["client_id"].(string); ok && cid != "" {
		clientID = cid
	}

	opts := mqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID(clientID).
		SetAutoReconnect(true).
		SetConnectRetry(true)
	if u, ok := config["username"].(string); ok && u != "" {
		opts.SetUsername(u)
	}
	if p, ok := config["password"].(string); ok && p != "" {
		opts.SetPassword(p)
	}

	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, fmt.Errorf("mqtt sink connect: %w", token.Error())
	}
	secret, _ := config["secret"].(string)
	return &mqttSink{client: client, topic: topic, qos: qos, secret: secret}, nil
}

func (s *mqttSink) Type() string { return "mqtt" }

func (s *mqttSink) Send(ctx context.Context, e *Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("mqtt sink marshal: %w", err)
	}
	token := s.client.Publish(s.topic, s.qos, false, wrapSigned(body, s.secret))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-token.Done():
	}
	return token.Error()
}

// ── 4. Kafka sink ─────────────────────────────────────────────────────────────

// kafkaSink wraps a minimal async Kafka producer using net/http chunked encoding
// is NOT appropriate here — we use a direct TCP writer via the franz-go or
// sarama library. To keep the dependency footprint small we implement a
// stdlib-only "fire-and-forget via kafka REST proxy" fallback first, and
// expose an interface so native Kafka can be plugged in without changing callers.

type kafkaSink struct {
	// REST-proxy URL (e.g. https://rest-proxy.example.com/topics/clavex-audit)
	// We target Confluent REST Proxy v2 or Redpanda REST Proxy by default.
	// For native Kafka support, swap the implementation behind this interface.
	proxyURL string
	topic    string
	hc       *http.Client
	auth     string // "Basic ..." or "Bearer ..." — empty means no auth
	secret   string
}

// KafkaProducer is an optional interface for a native Kafka client.
// If injected via NewKafkaSinkNative, the REST proxy path is bypassed.
type KafkaProducer interface {
	Produce(topic string, key, value []byte) error
}

// kafkaNativeSink wraps an injected KafkaProducer.
type kafkaNativeSink struct {
	producer KafkaProducer
	topic    string
	secret   string
}

func (s *kafkaNativeSink) Type() string { return "kafka" }
func (s *kafkaNativeSink) Send(_ context.Context, e *Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("kafka sink marshal: %w", err)
	}
	return s.producer.Produce(s.topic, []byte(e.ID), wrapSigned(body, s.secret))
}

// NewKafkaSinkNative wraps a native KafkaProducer.
// Pass a non-empty secret to have each message wrapped in a signedEnvelope.
func NewKafkaSinkNative(producer KafkaProducer, topic, secret string) Sink {
	return &kafkaNativeSink{producer: producer, topic: topic, secret: secret}
}

// NewKafkaSink creates a Kafka sink that delivers via a REST proxy.
// config keys: proxy_url (required), topic (required), username, password.
func NewKafkaSink(config map[string]interface{}) (Sink, error) {
	proxyURL, _ := config["proxy_url"].(string)
	topic, _ := config["topic"].(string)
	if proxyURL == "" || topic == "" {
		return nil, fmt.Errorf("kafka sink: proxy_url and topic are required")
	}
	s := &kafkaSink{
		proxyURL: proxyURL,
		topic:    topic,
		hc:       &http.Client{Timeout: 10 * time.Second},
		secret:   stringOrEmpty(config["secret"]),
	}
	if u, ok := config["username"].(string); ok && u != "" {
		p, _ := config["password"].(string)
		s.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
	}
	return s, nil
}

func (s *kafkaSink) Type() string { return "kafka" }

// Send delivers the event as a Confluent REST Proxy v2 record.
// Payload format: {"records":[{"key":"<event-id>","value":<event-json>}]}
func (s *kafkaSink) Send(ctx context.Context, e *Event) error {
	evtJSON, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("kafka sink: marshal event: %w", err)
	}

	type record struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	body, err := json.Marshal(map[string]interface{}{
		"records": []record{{Key: e.ID, Value: wrapSigned(evtJSON, s.secret)}},
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/topics/%s", s.proxyURL, s.topic)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/vnd.kafka.json.v2+json")
	req.Header.Set("Accept", "application/vnd.kafka.v2+json")
	if s.auth != "" {
		req.Header.Set("Authorization", s.auth)
	}

	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("kafka rest proxy: non-2xx status %d", resp.StatusCode)
	}
	return nil
}

// ── Sink factory ──────────────────────────────────────────────────────────────

// BuildSink constructs the appropriate Sink implementation from a SinkConfig.
func BuildSink(cfg SinkConfig) (Sink, error) {
	switch cfg.SinkType {
	case "webhook":
		return NewWebhookSink(cfg.Config)
	case "http":
		return NewHTTPSink(cfg.Config)
	case "mqtt":
		return NewMQTTSink(cfg.Config)
	case "kafka":
		return NewKafkaSink(cfg.Config)
	case "splunk_hec":
		return NewSplunkHECSink(cfg.Config)
	case "sentinel":
		return NewSentinelSink(cfg.Config)
	case "elastic_ecs":
		return NewElasticECSSink(cfg.Config)
	default:
		return nil, fmt.Errorf("unknown sink type: %s", cfg.SinkType)
	}
}

// ── 5. Splunk HEC sink ────────────────────────────────────────────────────────

// splunkHECSink delivers events to a Splunk HTTP Event Collector endpoint.
//
// Config keys:
//
//	url         (required) — HEC endpoint, e.g. "https://splunk.example.com:8088/services/collector/event"
//	token       (required) — HEC token
//	index       (optional) — target Splunk index (default: empty = Splunk default)
//	source      (optional) — source field (default: "clavex:audit")
//	sourcetype  (optional) — sourcetype field (default: "clavex:audit:event")
//	host        (optional) — host field (default: "clavex")
type splunkHECSink struct {
	url        string
	token      string
	index      string
	source     string
	sourcetype string
	host       string
	hc         *http.Client
}

// NewSplunkHECSink creates a Splunk HEC sink.
func NewSplunkHECSink(config map[string]interface{}) (Sink, error) {
	u, _ := config["url"].(string)
	if u == "" {
		return nil, fmt.Errorf("splunk_hec sink: url is required")
	}
	tok, _ := config["token"].(string)
	if tok == "" {
		return nil, fmt.Errorf("splunk_hec sink: token is required")
	}
	src, _ := config["source"].(string)
	if src == "" {
		src = "clavex:audit"
	}
	st, _ := config["sourcetype"].(string)
	if st == "" {
		st = "clavex:audit:event"
	}
	h, _ := config["host"].(string)
	if h == "" {
		h = "clavex"
	}
	return &splunkHECSink{
		url:        u,
		token:      tok,
		index:      stringOrEmpty(config["index"]),
		source:     src,
		sourcetype: st,
		host:       h,
		hc:         &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (s *splunkHECSink) Type() string { return "splunk_hec" }

// Send wraps the CloudEvents event in the Splunk HEC JSON envelope and POSTs it.
// Format: https://docs.splunk.com/Documentation/Splunk/latest/Data/HECExamples
func (s *splunkHECSink) Send(ctx context.Context, e *Event) error {
	// Splunk expects "time" as Unix epoch with millisecond precision.
	ts := float64(e.Time.UnixMilli()) / 1000.0

	// The "event" payload is the CloudEvents data + envelope context fields so
	// Splunk users can search on action, actor_id, org_id, etc. directly.
	var data EventData
	_ = json.Unmarshal(e.Data, &data)

	event := map[string]interface{}{
		"specversion": e.SpecVersion,
		"id":          e.ID,
		"source":      e.Source,
		"type":        e.Type,
		"subject":     e.Subject,
		"org_id":      e.OrgID,
		"request_id":  e.RequestID,
		"session_id":  e.SessionID,
		"action":      data.Action,
		"status":      data.Status,
		"actor_id":    data.ActorID,
		"actor_email": data.ActorEmail,
		"resource_type": data.ResourceType,
		"resource_id": data.ResourceID,
		"ip_address":  data.IPAddress,
		"country_code": data.CountryCode,
		"metadata":    data.Metadata,
	}

	envelope := map[string]interface{}{
		"time":       ts,
		"host":       s.host,
		"source":     s.source,
		"sourcetype": s.sourcetype,
		"event":      event,
	}
	if s.index != "" {
		envelope["index"] = s.index
	}

	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("splunk_hec sink: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.token)

	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("splunk_hec sink: non-2xx response %d", resp.StatusCode)
	}
	return nil
}

// ── 6. Microsoft Sentinel sink (Log Analytics Data Collector API) ─────────────

// sentinelSink delivers events to a Microsoft Sentinel / Log Analytics workspace
// using the Data Collector API (HMAC-SHA256 signed requests).
//
// Config keys:
//
//	workspace_id  (required) — Log Analytics workspace ID
//	workspace_key (required) — primary or secondary shared key (base64-encoded)
//	log_type      (optional) — custom log table name (default: "ClavexAudit")
//	api_version   (optional) — API version (default: "2016-04-01")
type sentinelSink struct {
	workspaceID  string
	workspaceKey []byte // decoded base64 shared key
	logType      string
	apiVersion   string
	hc           *http.Client
}

// NewSentinelSink creates a Microsoft Sentinel / Log Analytics Data Collector sink.
func NewSentinelSink(config map[string]interface{}) (Sink, error) {
	wsID, _ := config["workspace_id"].(string)
	if wsID == "" {
		return nil, fmt.Errorf("sentinel sink: workspace_id is required")
	}
	wsKeyB64, _ := config["workspace_key"].(string)
	if wsKeyB64 == "" {
		return nil, fmt.Errorf("sentinel sink: workspace_key is required")
	}
	wsKey, err := base64.StdEncoding.DecodeString(wsKeyB64)
	if err != nil {
		return nil, fmt.Errorf("sentinel sink: workspace_key must be base64-encoded: %w", err)
	}
	lt, _ := config["log_type"].(string)
	if lt == "" {
		lt = "ClavexAudit"
	}
	av, _ := config["api_version"].(string)
	if av == "" {
		av = "2016-04-01"
	}
	return &sentinelSink{
		workspaceID:  wsID,
		workspaceKey: wsKey,
		logType:      lt,
		apiVersion:   av,
		hc:           &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (s *sentinelSink) Type() string { return "sentinel" }

// Send transforms the CloudEvents event into an ECS-compatible record and
// delivers it to the Log Analytics Data Collector API.
// API reference: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
func (s *sentinelSink) Send(ctx context.Context, e *Event) error {
	var data EventData
	_ = json.Unmarshal(e.Data, &data)

	// Build an ECS-flavoured record. Sentinel auto-appends "_CL" suffix to the
	// log type and "_s"/"_d" suffixes to field names for custom log tables.
	record := map[string]interface{}{
		"TimeGenerated":   e.Time.UTC().Format(time.RFC3339Nano),
		"EventId":         e.ID,
		"EventType":       e.Type,
		"EventSource":     e.Source,
		"OrgId":           e.OrgID,
		"Action":          data.Action,
		"Status":          data.Status,
		"ActorId":         stringVal(data.ActorID),
		"ActorEmail":      stringVal(data.ActorEmail),
		"ResourceType":    stringVal(data.ResourceType),
		"ResourceId":      stringVal(data.ResourceID),
		"IpAddress":       stringVal(data.IPAddress),
		"CountryCode":     stringVal(data.CountryCode),
		"SessionId":       e.SessionID,
		"RequestId":       e.RequestID,
		"Subject":         e.Subject,
	}

	body, err := json.Marshal([]interface{}{record})
	if err != nil {
		return fmt.Errorf("sentinel sink: marshal: %w", err)
	}

	// Build the HMAC-SHA256 authorization signature.
	dateStr := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	contentLen := len(body)
	sigStr := fmt.Sprintf("POST\n%d\napplication/json\nx-ms-date:%s\n/api/logs", contentLen, dateStr)
	mac := hmac.New(sha256.New, s.workspaceKey)
	mac.Write([]byte(sigStr))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	auth := fmt.Sprintf("SharedKey %s:%s", s.workspaceID, sig)

	url := fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=%s",
		s.workspaceID, s.apiVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	req.Header.Set("Log-Type", s.logType)
	req.Header.Set("x-ms-date", dateStr)
	req.Header.Set("time-generated-field", "TimeGenerated")

	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sentinel sink: non-2xx response %d", resp.StatusCode)
	}
	return nil
}

// ── 7. Elastic ECS sink ───────────────────────────────────────────────────────

// elasticECSSink delivers events to Elasticsearch using the Bulk API, mapping
// Clavex audit fields to Elastic Common Schema (ECS).
//
// Config keys:
//
//	url         (required) — Elasticsearch base URL, e.g. "https://elastic.example.com"
//	index       (required) — target index or data stream, e.g. "logs-clavex.audit-default"
//	api_key     (optional) — API key (recommended over username/password)
//	username    (optional) — HTTP Basic auth username
//	password    (optional) — HTTP Basic auth password
type elasticECSSink struct {
	url      string
	index    string
	apiKey   string
	username string
	password string
	hc       *http.Client
}

// NewElasticECSSink creates an Elasticsearch ECS sink.
func NewElasticECSSink(config map[string]interface{}) (Sink, error) {
	u, _ := config["url"].(string)
	if u == "" {
		return nil, fmt.Errorf("elastic_ecs sink: url is required")
	}
	idx, _ := config["index"].(string)
	if idx == "" {
		return nil, fmt.Errorf("elastic_ecs sink: index is required")
	}
	return &elasticECSSink{
		url:      u,
		index:    idx,
		apiKey:   stringOrEmpty(config["api_key"]),
		username: stringOrEmpty(config["username"]),
		password: stringOrEmpty(config["password"]),
		hc:       &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (s *elasticECSSink) Type() string { return "elastic_ecs" }

// Send delivers the event as a single-document Bulk API request in ECS format.
// ECS reference: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
func (s *elasticECSSink) Send(ctx context.Context, e *Event) error {
	var data EventData
	_ = json.Unmarshal(e.Data, &data)

	doc := map[string]interface{}{
		// ECS base
		"@timestamp": e.Time.UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]string{"version": "8.11"},
		"message":    data.Action,
		// ECS event
		"event": map[string]interface{}{
			"id":       e.ID,
			"kind":     "event",
			"category": []string{"authentication"},
			"type":     []string{"info"},
			"action":   data.Action,
			"outcome":  data.Status,
			"provider": "clavex",
			"dataset":  "clavex.audit",
		},
		// ECS user
		"user": map[string]interface{}{
			"id":    stringVal(data.ActorID),
			"email": stringVal(data.ActorEmail),
		},
		// ECS source (IP)
		"source": map[string]interface{}{
			"ip": stringVal(data.IPAddress),
			"geo": map[string]interface{}{
				"country_iso_code": stringVal(data.CountryCode),
			},
		},
		// ECS user_agent
		"user_agent": map[string]interface{}{
			"original": stringVal(data.UserAgent),
		},
		// Clavex extensions (mapped as labels for ECS compatibility)
		"labels": map[string]interface{}{
			"org_id":        e.OrgID,
			"session_id":    e.SessionID,
			"request_id":    e.RequestID,
			"resource_type": stringVal(data.ResourceType),
			"resource_id":   stringVal(data.ResourceID),
			"ce_source":     e.Source,
			"ce_type":       e.Type,
		},
	}
	if data.Metadata != nil {
		doc["clavex"] = map[string]interface{}{"metadata": data.Metadata}
	}

	// Elasticsearch Bulk API: action meta + newline + document + newline
	meta, err := json.Marshal(map[string]interface{}{
		"index": map[string]string{"_index": s.index},
	})
	if err != nil {
		return fmt.Errorf("elastic_ecs sink: marshal meta: %w", err)
	}
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("elastic_ecs sink: marshal doc: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(meta)
	buf.WriteByte('\n')
	buf.Write(docJSON)
	buf.WriteByte('\n')

	bulkURL := s.url + "/_bulk"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bulkURL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+s.apiKey)
	} else if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("elastic_ecs sink: non-2xx response %d", resp.StatusCode)
	}

	// Check for per-item errors in the bulk response.
	var bulkResp struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Error *struct {
				Reason string `json:"reason"`
			} `json:"error,omitempty"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err == nil && bulkResp.Errors {
		for _, item := range bulkResp.Items {
			for _, v := range item {
				if v.Error != nil {
					return fmt.Errorf("elastic_ecs sink: indexing error: %s", v.Error.Reason)
				}
			}
		}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func stringOrEmpty(v interface{}) string {
	s, _ := v.(string)
	return s
}

func stringVal(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ── matches helper ────────────────────────────────────────────────────────────

// Matches reports whether the event passes the sink's filter.
func (cfg SinkConfig) Matches(e *Event) bool {
	var data EventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return true // be permissive on parse errors
	}
	if len(cfg.FilterActions) > 0 {
		found := false
		for _, a := range cfg.FilterActions {
			if a == data.Action {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(cfg.FilterStatuses) > 0 {
		found := false
		for _, s := range cfg.FilterStatuses {
			if s == data.Status {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// noop logger to suppress paho noise in tests
var _ = log.Logger

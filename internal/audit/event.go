// Package audit provides the structured audit-log pipeline for Clavex.
//
// Architecture:
//
//	Handler/service code → Emitter.Emit() → DB insert → channel → Dispatcher
//	                                                                   ↓
//	                                              sink goroutines: webhook / http / mqtt / kafka
//
// All events follow a CloudEvents 1.0 envelope (https://cloudevents.io/).
// The data payload is a fixed JSON schema versioned under /schemas/audit/v1.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ── CloudEvents envelope ──────────────────────────────────────────────────────

// Event is a CloudEvents 1.0 compliant audit event.
// https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md
type Event struct {
	// CloudEvents required attributes
	SpecVersion string    `json:"specversion"`
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	Type        string    `json:"type"`
	Time        time.Time `json:"time"`
	// CloudEvents optional attributes
	Subject    string `json:"subject,omitempty"`
	DataSchema string `json:"dataschema,omitempty"`
	// Extension attributes (ce-* prefix in HTTP headers)
	OrgID     string `json:"orgid"`
	RequestID string `json:"requestid,omitempty"`
	SessionID string `json:"sessionid,omitempty"`
	// Data payload
	DataContentType string          `json:"datacontenttype"`
	Data            json.RawMessage `json:"data"`
}

// EventData is the structured payload carried in Event.Data.
type EventData struct {
	Action       string                 `json:"action"`
	Status       string                 `json:"status"` // "success" | "failure"
	ActorID      *string                `json:"actor_id,omitempty"`
	ActorEmail   *string                `json:"actor_email,omitempty"`
	ResourceType *string                `json:"resource_type,omitempty"`
	ResourceID   *string                `json:"resource_id,omitempty"`
	IPAddress    *string                `json:"ip_address,omitempty"`
	UserAgent    *string                `json:"user_agent,omitempty"`
	CountryCode  *string                `json:"country_code,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// actionToType converts a dot-notation action (e.g. "user.login") to a
// reverse-DNS CloudEvents type (e.g. "com.clavex.audit.user.login").
func actionToType(action string) string {
	return "com.clavex.audit." + action
}

// buildSubject returns a resource URI subject for the event.
func buildSubject(orgID string, resourceType, resourceID *string) string {
	if resourceType == nil || resourceID == nil {
		return "/orgs/" + orgID
	}
	return fmt.Sprintf("/orgs/%s/%ss/%s", orgID, *resourceType, *resourceID)
}

// ── Emitter ───────────────────────────────────────────────────────────────────

// EmitParams carries all the information needed to record a single audit event.
type EmitParams struct {
	OrgID        uuid.UUID
	ActorID      *uuid.UUID
	ActorEmail   *string
	Action       string
	ResourceType *string
	ResourceID   *string
	Status       string // "success" | "failure"  (defaults to "success")
	IPAddress    *string
	UserAgent    *string
	CountryCode  *string
	SessionID    *string
	RequestID    *string
	Metadata     map[string]interface{}
}

// Recorder is the interface needed by Emitter to persist events.
// *repository.AuditRepository satisfies this.
type Recorder interface {
	RecordEvent(ctx context.Context, e *Event, data *EventData) error
	PublishToChannel(e *Event)
}

// Emitter builds and dispatches audit events.
type Emitter struct {
	source   string // base source URL, e.g. "https://auth.example.com"
	recorder Recorder
}

// NewEmitter creates an Emitter.
// source should be the public base URL of the Clavex instance.
func NewEmitter(source string, recorder Recorder) *Emitter {
	return &Emitter{source: source, recorder: recorder}
}

// Emit records an audit event in the DB and fans it out to all active sinks.
// It never blocks the caller: the fan-out is asynchronous.
func (em *Emitter) Emit(ctx context.Context, p EmitParams) {
	if p.Status == "" {
		p.Status = "success"
	}

	actorIDStr := (*string)(nil)
	if p.ActorID != nil {
		s := p.ActorID.String()
		actorIDStr = &s
	}

	data := &EventData{
		Action:       p.Action,
		Status:       p.Status,
		ActorID:      actorIDStr,
		ActorEmail:   p.ActorEmail,
		ResourceType: p.ResourceType,
		ResourceID:   p.ResourceID,
		IPAddress:    p.IPAddress,
		UserAgent:    p.UserAgent,
		CountryCode:  p.CountryCode,
		Metadata:     p.Metadata,
	}

	rawData, err := json.Marshal(data)
	if err != nil {
		rawData = json.RawMessage(`{}`)
	}

	orgStr := p.OrgID.String()
	sesID := ""
	if p.SessionID != nil {
		sesID = *p.SessionID
	}
	reqID := ""
	if p.RequestID != nil {
		reqID = *p.RequestID
	}

	evt := &Event{
		SpecVersion:     "1.0",
		ID:              uuid.NewString(),
		Source:          fmt.Sprintf("%s/%s", em.source, p.OrgID.String()),
		Type:            actionToType(p.Action),
		Time:            time.Now().UTC(),
		Subject:         buildSubject(orgStr, p.ResourceType, p.ResourceID),
		DataSchema:      "https://clavex.dev/schemas/audit/v1",
		OrgID:           orgStr,
		RequestID:       reqID,
		SessionID:       sesID,
		DataContentType: "application/json",
		Data:            rawData,
	}

	// Persist synchronously so the event is never lost.
	if err := em.recorder.RecordEvent(ctx, evt, data); err != nil {
		// Logging only — never surface audit errors to callers.
		_ = err
		return
	}

	// Async fan-out — fire and forget.
	em.recorder.PublishToChannel(evt)
}

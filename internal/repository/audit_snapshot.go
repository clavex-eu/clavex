package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// EntitySnapshot is the result of replaying audit events for a single entity
// up to a given point in time.
//
// Because the audit log is an append-only CloudEvents stream (not a full CQRS
// event store), the reconstructed State is built by folding the metadata of
// mutation events in chronological order. Fields written by earlier events are
// overwritten by later ones, giving the best-known state at time T.
//
// The raw Events slice lets the caller inspect the complete audit trail,
// while ChangeLog surfaces only the mutations (created / updated / deleted)
// with before/after metadata when available.
type EntitySnapshot struct {
	OrgID          uuid.UUID              `json:"org_id"`
	EntityType     string                 `json:"entity_type"`
	EntityID       string                 `json:"entity_id"`
	ReconstructedAt time.Time             `json:"reconstructed_at"`
	FirstSeenAt    *time.Time             `json:"first_seen_at,omitempty"`
	LastModifiedAt *time.Time             `json:"last_modified_at,omitempty"`
	// State is the best-effort reconstruction of the entity's field values
	// at ReconstructedAt, derived by folding mutation metadata.
	State     map[string]interface{} `json:"state"`
	// ChangeLog contains only mutation events (created / updated / deleted),
	// ordered chronologically, so callers can show a field-level diff timeline.
	ChangeLog []ChangeEntry `json:"change_log"`
	// Events is the full ordered list of audit events for the entity up to
	// ReconstructedAt (includes access / view / login events).
	Events []*AuditEvent `json:"events"`
}

// ChangeEntry represents a single mutation in the entity's lifecycle.
type ChangeEntry struct {
	At          time.Time              `json:"at"`
	Action      string                 `json:"action"`
	Status      string                 `json:"status"`
	ActorID     *uuid.UUID             `json:"actor_id,omitempty"`
	ActorEmail  *string                `json:"actor_email,omitempty"`
	IPAddress   *string                `json:"ip_address,omitempty"`
	Before      map[string]interface{} `json:"before,omitempty"`
	After       map[string]interface{} `json:"after,omitempty"`
	ChangedFields map[string]interface{} `json:"changed_fields,omitempty"`
}

// isMutationAction reports whether an audit action represents a state change
// (as opposed to a read/access/login event).
func isMutationAction(action string) bool {
	for _, suffix := range []string{
		".created", ".updated", ".deleted", ".enabled", ".disabled",
		".invited", ".suspended", ".restored", ".reset", ".verified",
		".set", ".removed", ".added", ".blocked", ".unblocked",
	} {
		if len(action) > len(suffix) && action[len(action)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

// SnapshotEntity replays all audit events for the given entity up to at and
// returns a reconstructed snapshot of its state.
//
//   - entityType: value of resource_type in audit_logs (e.g. "user", "client")
//   - entityID:   value of resource_id  in audit_logs
//   - at:         upper bound (inclusive); if zero, defaults to now
func (r *AuditRepository) SnapshotEntity(
	ctx context.Context,
	orgID uuid.UUID,
	entityType, entityID string,
	at time.Time,
) (*EntitySnapshot, error) {
	if at.IsZero() {
		at = time.Now()
	}

	rows, err := r.pool.Query(ctx, `
		SELECT id, event_id, spec_version,
		       COALESCE(event_source,''), COALESCE(event_type,''), COALESCE(subject,''),
		       org_id, user_id, actor_email, action, resource_type, resource_id,
		       status, ip_address::text, user_agent, country_code, session_id, request_id,
		       metadata, created_at
		FROM audit.audit_logs
		WHERE org_id = $1
		  AND resource_id = $2
		  AND ($3 = '' OR resource_type = $3)
		  AND created_at <= $4
		ORDER BY id ASC`,
		orgID, entityID, entityType, at,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	snap := &EntitySnapshot{
		OrgID:           orgID,
		EntityType:      entityType,
		EntityID:        entityID,
		ReconstructedAt: at,
		State:           make(map[string]interface{}),
	}

	for rows.Next() {
		e := &AuditEvent{}
		var metaRaw []byte
		if err := rows.Scan(
			&e.ID, &e.EventID, &e.SpecVersion, &e.Source, &e.Type, &e.Subject,
			&e.OrgID, &e.ActorID, &e.ActorEmail, &e.Action, &e.ResourceType, &e.ResourceID,
			&e.Status, &e.IPAddress, &e.UserAgent, &e.CountryCode, &e.SessionID, &e.RequestID,
			&metaRaw, &e.Time,
		); err != nil {
			return nil, err
		}
		if len(metaRaw) > 0 {
			_ = json.Unmarshal(metaRaw, &e.Metadata)
		}
		snap.Events = append(snap.Events, e)

		// Track time bounds
		t := e.Time
		if snap.FirstSeenAt == nil {
			snap.FirstSeenAt = &t
		}
		snap.LastModifiedAt = &t

		// Only mutation events contribute to state reconstruction and ChangeLog
		if !isMutationAction(e.Action) {
			continue
		}

		entry := ChangeEntry{
			At:         e.Time,
			Action:     e.Action,
			Status:     e.Status,
			ActorID:    e.ActorID,
			ActorEmail: e.ActorEmail,
			IPAddress:  e.IPAddress,
		}

		if e.Metadata != nil {
			// Extract before/after if the emitter included them
			if b, ok := e.Metadata["before"]; ok {
				if bm, ok := b.(map[string]interface{}); ok {
					entry.Before = bm
				}
			}
			if a, ok := e.Metadata["after"]; ok {
				if am, ok := a.(map[string]interface{}); ok {
					entry.After = am
					// Fold "after" into accumulated state
					for k, v := range am {
						snap.State[k] = v
					}
				}
			}
			if cf, ok := e.Metadata["changed_fields"]; ok {
				if cfm, ok := cf.(map[string]interface{}); ok {
					entry.ChangedFields = cfm
					for k, v := range cfm {
						snap.State[k] = v
					}
				}
			}
			// If no explicit before/after, fold the whole metadata as state
			// (handles emitters that write flat metadata like {email: "..."})
			if entry.After == nil && entry.ChangedFields == nil {
				for k, v := range e.Metadata {
					if k != "before" && k != "after" && k != "changed_fields" {
						snap.State[k] = v
					}
				}
			}
		}

		snap.ChangeLog = append(snap.ChangeLog, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return snap, nil
}

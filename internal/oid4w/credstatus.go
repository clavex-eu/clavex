package oid4w

// CredStatusDispatcher fans credential lifecycle events to SSE subscribers.
//
// Each subscriber registers one or more credential UUIDs it wants to watch.
// When a credential is revoked or restored the server calls Publish(); every
// subscriber that registered that UUID receives a CredStatusEvent immediately,
// without any DB polling.
//
// The dispatcher is in-process only: for multi-pod deployments the caller
// should layer a Redis pub/sub adapter on top; for single-pod deployments
// the in-memory bus is sufficient and has zero external dependencies.

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// CredStatusEvent is the payload delivered to SSE subscribers.
// It is serialised as-is in the SSE `data:` line.
type CredStatusEvent struct {
	CredentialID string    `json:"credential_id"`
	Status       string    `json:"status"`      // "revoked" | "restored"
	OccurredAt   time.Time `json:"occurred_at"`
}

// CredStatusDispatcher manages live SSE subscriptions keyed by credential UUID.
// All methods are safe for concurrent use.
type CredStatusDispatcher struct {
	mu   sync.RWMutex
	subs map[uuid.UUID][]chan CredStatusEvent // credentialID → subscriber channels
}

// NewCredStatusDispatcher allocates a ready-to-use dispatcher.
func NewCredStatusDispatcher() *CredStatusDispatcher {
	return &CredStatusDispatcher{
		subs: make(map[uuid.UUID][]chan CredStatusEvent),
	}
}

// Subscribe registers interest in a set of credential IDs.
//
// Returns a receive-only channel on which CredStatusEvents are delivered and a
// cancel function the caller MUST invoke when the SSE connection closes.
// cancel() is idempotent and safe to call from a defer statement.
func (d *CredStatusDispatcher) Subscribe(credentialIDs []uuid.UUID) (<-chan CredStatusEvent, func()) {
	ch := make(chan CredStatusEvent, 16)
	var once sync.Once

	d.mu.Lock()
	for _, id := range credentialIDs {
		d.subs[id] = append(d.subs[id], ch)
	}
	d.mu.Unlock()

	cancel := func() {
		once.Do(func() {
			d.mu.Lock()
			for _, id := range credentialIDs {
				list := d.subs[id]
				for i, c := range list {
					if c == ch {
						d.subs[id] = append(list[:i], list[i+1:]...)
						break
					}
				}
				if len(d.subs[id]) == 0 {
					delete(d.subs, id)
				}
			}
			d.mu.Unlock()
			close(ch)
		})
	}
	return ch, cancel
}

// Publish delivers a status-change event to all subscribers watching credentialID.
// Non-blocking: slow consumers are silently skipped (the wallet will fall back
// to polling the status-list JWT on its next check interval).
func (d *CredStatusDispatcher) Publish(credentialID uuid.UUID, status string) {
	evt := CredStatusEvent{
		CredentialID: credentialID.String(),
		Status:       status,
		OccurredAt:   time.Now().UTC(),
	}

	d.mu.RLock()
	list := d.subs[credentialID]
	// Copy under read-lock so sends do not hold the lock.
	snapshot := make([]chan CredStatusEvent, len(list))
	copy(snapshot, list)
	d.mu.RUnlock()

	for _, ch := range snapshot {
		select {
		case ch <- evt:
		default:
			// subscriber is too slow; skip rather than blocking
		}
	}
}

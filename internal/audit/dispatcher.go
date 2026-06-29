package audit

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// ── Fan-out dispatcher ────────────────────────────────────────────────────────

const (
	channelBuffer   = 2048
	workerCount     = 4
	deliveryTimeout = 15 * time.Second
	maxRetries      = 3
)

// SinkLoader returns the active sink configurations for a given org.
// Implementations should cache: this is called on every event.
type SinkLoader interface {
	ActiveSinksForOrg(ctx context.Context, orgID uuid.UUID) ([]SinkConfig, error)
}

// Dispatcher consumes events from a buffered channel and fans them out to all
// matching sinks. It is intentionally decoupled from the HTTP request path.
type Dispatcher struct {
	ch     chan *Event
	loader SinkLoader
	stats  SinkStatsUpdater
	wg     sync.WaitGroup
	once   sync.Once

	// live-stream subscriptions: per-org list of subscriber channels.
	subMu sync.RWMutex
	subs  map[string][]chan *Event // key: org UUID string
}

// NewDispatcher creates a Dispatcher.
// Call Start() to begin processing.
func NewDispatcher(loader SinkLoader, stats SinkStatsUpdater) *Dispatcher {
	return &Dispatcher{
		ch:     make(chan *Event, channelBuffer),
		loader: loader,
		stats:  stats,
		subs:   make(map[string][]chan *Event),
	}
}

// Subscribe registers a live-stream subscriber for a given org.
// Returns a read-only channel on which events are delivered and a cancel
// function the caller MUST invoke when the stream ends (client disconnect,
// timeout, etc.) to avoid goroutine / memory leaks.
func (d *Dispatcher) Subscribe(orgID string) (<-chan *Event, func()) {
	ch := make(chan *Event, 64) // small per-subscriber buffer

	d.subMu.Lock()
	d.subs[orgID] = append(d.subs[orgID], ch)
	d.subMu.Unlock()

	cancel := func() {
		d.subMu.Lock()
		list := d.subs[orgID]
		for i, c := range list {
			if c == ch {
				d.subs[orgID] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(d.subs[orgID]) == 0 {
			delete(d.subs, orgID)
		}
		d.subMu.Unlock()
		// Drain and close so the reader goroutine can exit cleanly.
		close(ch)
		for range ch {
		}
	}
	return ch, cancel
}

// notifySubscribers fans an event to all live subscribers for the event's org.
// Non-blocking: slow consumers are dropped.
func (d *Dispatcher) notifySubscribers(e *Event) {
	d.subMu.RLock()
	list := d.subs[e.OrgID]
	// Copy slice under read-lock so we don't hold the lock during sends.
	snapshot := make([]chan *Event, len(list))
	copy(snapshot, list)
	d.subMu.RUnlock()

	for _, ch := range snapshot {
		select {
		case ch <- e:
		default:
			// Subscriber is too slow; skip rather than blocking the dispatcher.
		}
	}
}

// Publish queues an event for fan-out. Never blocks: if the buffer is full the
// event is dropped and a warning is logged.
func (d *Dispatcher) Publish(e *Event) {
	select {
	case d.ch <- e:
	default:
		log.Warn().
			Str("event_id", e.ID).
			Str("event_type", e.Type).
			Msg("audit dispatcher: channel full, event dropped")
	}
}

// Start launches workerCount goroutines. Call Stop() on shutdown.
func (d *Dispatcher) Start(ctx context.Context) {
	d.once.Do(func() {
		for i := 0; i < workerCount; i++ {
			d.wg.Add(1)
			go d.worker(ctx)
		}
	})
}

// Stop drains the channel and waits for all in-flight deliveries to complete.
// It is safe to call multiple times.
func (d *Dispatcher) Stop() {
	close(d.ch)
	d.wg.Wait()
}

func (d *Dispatcher) worker(ctx context.Context) {
	defer d.wg.Done()
	for e := range d.ch {
		d.fanOut(ctx, e)
	}
}

func (d *Dispatcher) fanOut(ctx context.Context, e *Event) {
	// Notify live SSE subscribers first (non-blocking).
	d.notifySubscribers(e)

	orgID, err := uuid.Parse(e.OrgID)
	if err != nil {
		return
	}

	loadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	sinkCfgs, err := d.loader.ActiveSinksForOrg(loadCtx, orgID)
	cancel()
	if err != nil {
		log.Error().Err(err).Str("org_id", e.OrgID).Msg("audit dispatcher: failed to load sinks")
		return
	}

	var wg sync.WaitGroup
	for _, cfg := range sinkCfgs {
		if !cfg.Matches(e) {
			continue
		}
		wg.Add(1)
		go func(cfg SinkConfig) {
			defer wg.Done()
			d.deliverWithRetry(ctx, cfg, e)
		}(cfg)
	}
	wg.Wait()
}

func (d *Dispatcher) deliverWithRetry(ctx context.Context, cfg SinkConfig, e *Event) {
	sink, err := BuildSink(cfg)
	if err != nil {
		log.Error().Err(err).
			Str("sink_id", cfg.ID.String()).
			Str("sink_type", cfg.SinkType).
			Msg("audit dispatcher: failed to build sink")
		d.recordStats(ctx, cfg.ID, false, err.Error())
		return
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		dCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
		lastErr = sink.Send(dCtx, e)
		cancel()

		if lastErr == nil {
			d.recordStats(ctx, cfg.ID, true, "")
			return
		}

		log.Warn().
			Err(lastErr).
			Int("attempt", attempt).
			Str("sink_id", cfg.ID.String()).
			Str("event_id", e.ID).
			Msg("audit dispatcher: delivery attempt failed")

		if attempt < maxRetries {
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				d.recordStats(ctx, cfg.ID, false, "context cancelled")
				return
			}
		}
	}

	d.recordStats(ctx, cfg.ID, false, lastErr.Error())
}

func (d *Dispatcher) recordStats(ctx context.Context, sinkID uuid.UUID, ok bool, msg string) {
	if d.stats == nil {
		return
	}
	statsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := d.stats.UpdateSinkStats(statsCtx, sinkID, ok, msg); err != nil {
		log.Error().Err(err).Str("sink_id", sinkID.String()).Msg("audit dispatcher: failed to update sink stats")
	}
}

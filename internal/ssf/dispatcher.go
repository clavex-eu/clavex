package ssf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// pushHTTPClient is the SSRF-safe client used for outbound SET push delivery.
// SetPushHTTPClient lets the operator opt into private targets at startup.
var pushHTTPClient = safehttp.Client(10*time.Second, false)

// SetPushHTTPClient overrides the client used for SSF push delivery.
func SetPushHTTPClient(c *http.Client) {
	if c != nil {
		pushHTTPClient = c
	}
}

// Dispatcher sends SSF SETs to all enabled streams for an organisation.
// For push streams it delivers immediately (best-effort, background goroutine).
// For poll streams it enqueues the SET for later retrieval by the receiver.
type Dispatcher struct {
	repo   StreamQueuer
	setcfg SetConfigProvider
	rdb    redis.UniversalClient // optional — for push delivery logging
}

// DeliveryRecord is stored in Redis per stream to track the last push attempt.
type DeliveryRecord struct {
	Timestamp time.Time `json:"ts"`
	OK        bool      `json:"ok"`
	EventType string    `json:"event_type"`
	Error     string    `json:"error,omitempty"`
}

const deliveryKeyTTL = 30 * 24 * time.Hour // keep last-delivery record for 30 days

func deliveryRedisKey(streamID uuid.UUID) string {
	return fmt.Sprintf("ssf:delivery:%s:last", streamID)
}

// StreamQueuer is the repository interface the dispatcher needs.
type StreamQueuer interface {
	ListPushEnabled(ctx context.Context, orgID uuid.UUID) ([]*models.SSFStream, error)
	ListPollEnabled(ctx context.Context, orgID uuid.UUID) ([]*models.SSFStream, error)
	EnqueueSET(ctx context.Context, streamID uuid.UUID, jti, compact, eventType string) error
}

// SetConfigProvider returns a SETConfig for a given org slug (issuer URL).
type SetConfigProvider interface {
	ConfigForOrg(orgSlug string) *SETConfig
}

// StaticConfig is a SetConfigProvider that always returns the same config.
// Suitable for single-key setups.
type StaticConfig struct {
	Cfg *SETConfig
}

func (s *StaticConfig) ConfigForOrg(_ string) *SETConfig { return s.Cfg }

// DynamicConfig is a SetConfigProvider that derives the issuer from the org slug.
type DynamicConfig struct {
	base *SETConfig
	// IssuerFn returns the issuer URL for a given org slug.
	IssuerFn func(orgSlug string) string
}

// ConfigForOrg returns a SETConfig with the issuer set for the given org slug.
func (d *DynamicConfig) ConfigForOrg(orgSlug string) *SETConfig {
	cfg := *d.base
	cfg.Issuer = d.IssuerFn(orgSlug)
	return &cfg
}

// NewDispatcher creates a new SSF dispatcher.
func NewDispatcher(repo StreamQueuer, cfg *SETConfig) *Dispatcher {
	return &Dispatcher{repo: repo, setcfg: &StaticConfig{Cfg: cfg}}
}

// NewDynamicDispatcher creates an SSF dispatcher where the issuer URL
// is derived per-org from the provided function.
func NewDynamicDispatcher(repo StreamQueuer, baseKey *SETConfig, issuerFn func(string) string) *Dispatcher {
	return &Dispatcher{
		repo: repo,
		setcfg: &DynamicConfig{
			base:     baseKey,
			IssuerFn: issuerFn,
		},
	}
}

// WithRedis attaches a Redis client so the dispatcher records last push delivery
// status per stream at key ssf:delivery:<stream_id>:last (TTL 30 days).
// This enables the admin API to surface push endpoint health without a DB query.
func (d *Dispatcher) WithRedis(rdb redis.UniversalClient) *Dispatcher {
	d.rdb = rdb
	return d
}

// LastDelivery returns the most recent push delivery record for a stream,
// or nil if no delivery has been attempted yet.
func (d *Dispatcher) LastDelivery(ctx context.Context, streamID uuid.UUID) *DeliveryRecord {
	if d.rdb == nil {
		return nil
	}
	b, err := d.rdb.Get(ctx, deliveryRedisKey(streamID)).Bytes()
	if err != nil {
		return nil
	}
	var rec DeliveryRecord
	if json.Unmarshal(b, &rec) != nil {
		return nil
	}
	return &rec
}

// Dispatch fires an SSF event asynchronously for a given orgID.
// userSub is the user's sub claim in the issuer's token space.
// It is safe to call from any goroutine; delivery happens in the background.
func (d *Dispatcher) Dispatch(orgID uuid.UUID, orgSlug, userSub, eventType string, eventBody map[string]interface{}) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d.dispatch(ctx, orgID, orgSlug, userSub, eventType, eventBody)
	}()
}

func (d *Dispatcher) dispatch(ctx context.Context, orgID uuid.UUID, orgSlug, userSub, eventType string, eventBody map[string]interface{}) {
	cfg := d.setcfg.ConfigForOrg(orgSlug)
	subject := IssSubject(cfg.Issuer, userSub)

	streams, err := d.repo.ListPushEnabled(ctx, orgID)
	if err != nil {
		log.Error().Err(err).Str("event", eventType).Msg("ssf: list push streams")
	}
	for _, s := range streams {
		if !streamWantsEvent(s, eventType) {
			continue
		}
		compact, _, err := BuildSET(cfg, s.ClientID, subject, eventType, eventBody)
		if err != nil {
			log.Error().Err(err).Str("stream_id", s.ID.String()).Msg("ssf: build SET for push")
			continue
		}
		deliveryErr := deliverPush(ctx, s, compact)
		if deliveryErr != nil {
			log.Warn().Err(deliveryErr).Str("stream_id", s.ID.String()).Msg("ssf: push delivery failed")
		}
		d.recordDelivery(ctx, s.ID, eventType, deliveryErr)
	}

	pollStreams, err := d.repo.ListPollEnabled(ctx, orgID)
	if err != nil {
		log.Error().Err(err).Str("event", eventType).Msg("ssf: list poll streams")
	}
	for _, s := range pollStreams {
		if !streamWantsEvent(s, eventType) {
			continue
		}
		compact, jti, err := BuildSET(cfg, s.ClientID, subject, eventType, eventBody)
		if err != nil {
			log.Error().Err(err).Str("stream_id", s.ID.String()).Msg("ssf: build SET for poll")
			continue
		}
		if err := d.repo.EnqueueSET(ctx, s.ID, jti, compact, eventType); err != nil {
			log.Error().Err(err).Str("stream_id", s.ID.String()).Msg("ssf: enqueue SET")
		}
	}
}

func streamWantsEvent(s *models.SSFStream, eventType string) bool {
	for _, e := range s.EventsRequested {
		if e == eventType {
			return true
		}
	}
	return false
}

// recordDelivery persists the last push delivery result in Redis (best-effort).
func (d *Dispatcher) recordDelivery(ctx context.Context, streamID uuid.UUID, eventType string, err error) {
	if d.rdb == nil {
		return
	}
	rec := DeliveryRecord{
		Timestamp: time.Now(),
		OK:        err == nil,
		EventType: eventType,
	}
	if err != nil {
		rec.Error = err.Error()
	}
	b, merr := json.Marshal(rec)
	if merr != nil {
		return
	}
	// Best-effort: ignore Redis errors.
	d.rdb.SetEx(ctx, deliveryRedisKey(streamID), b, deliveryKeyTTL)
}

func deliverPush(ctx context.Context, s *models.SSFStream, compact string) error {
	if s.PushEndpoint == nil || *s.PushEndpoint == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *s.PushEndpoint, bytes.NewBufferString(compact))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	resp, err := pushHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return http.ErrNotSupported
	}
	return nil
}

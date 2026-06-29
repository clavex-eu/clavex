package scim

import (
	"context"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/clavex-eu/clavex/internal/webhook"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	// DefaultAnomalyThreshold is the number of deprovisionings that triggers
	// an alert when crossed within the observation window.
	DefaultAnomalyThreshold = 50

	// DefaultAnomalyWindowSeconds is the observation window in seconds (5 min).
	DefaultAnomalyWindowSeconds = 300
)

// SSFAnomalyDispatcher is the subset of *ssf.Dispatcher needed by AnomalyDetector.
type SSFAnomalyDispatcher interface {
	Dispatch(orgID uuid.UUID, orgSlug, userSub, eventType string, eventBody map[string]interface{})
}

// WebhookAnomalyDispatcher is the subset of *webhook.Dispatcher needed by AnomalyDetector.
type WebhookAnomalyDispatcher interface {
	Dispatch(orgID uuid.UUID, event string, data any)
}

// AnomalyDetector counts SCIM deprovisionings per org using a Redis sliding
// window. When the count exceeds the configured threshold within the window it
// fires a RISC account-disabled SSF SET and a configurable webhook — giving
// SOC/SIEM integrations an NIS2-aligned early-warning signal for bulk
// deprovisioning attacks or runaway automation.
type AnomalyDetector struct {
	rdb        redis.UniversalClient
	ssfDisp    SSFAnomalyDispatcher
	hookDisp   WebhookAnomalyDispatcher
	issuerFunc func(orgSlug string) string
}

// NewAnomalyDetector creates an AnomalyDetector. ssfDisp and hookDisp may be
// nil; the detector degrades gracefully when either is absent.
func NewAnomalyDetector(
	rdb redis.UniversalClient,
	ssfDisp SSFAnomalyDispatcher,
	hookDisp WebhookAnomalyDispatcher,
	issuerFunc func(orgSlug string) string,
) *AnomalyDetector {
	return &AnomalyDetector{
		rdb:        rdb,
		ssfDisp:    ssfDisp,
		hookDisp:   hookDisp,
		issuerFunc: issuerFunc,
	}
}

// Record counts one deprovision event for the org and fires alerts when the
// threshold is exceeded. It is designed to be called synchronously inside the
// SCIM request handler (fast: two Redis pipelines).
func (a *AnomalyDetector) Record(ctx context.Context, org *models.Organization) {
	threshold, window := a.thresholds(org)

	windowKey := fmt.Sprintf("scim:anomaly:window:%s", org.ID)
	alertKey := fmt.Sprintf("scim:anomaly:alerted:%s", org.ID)
	now := time.Now()

	// ── Sliding-window counter ────────────────────────────────────────────────
	pipe := a.rdb.Pipeline()
	pipe.ZAdd(ctx, windowKey, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: now.UnixNano(), // unique enough within one goroutine context
	})
	cutoff := float64(now.Add(-window).UnixNano())
	pipe.ZRemRangeByScore(ctx, windowKey, "-inf", fmt.Sprintf("%f", cutoff))
	countCmd := pipe.ZCard(ctx, windowKey)
	pipe.Expire(ctx, windowKey, window+time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		log.Warn().Err(err).Str("org_id", org.ID.String()).
			Msg("scim anomaly: redis pipeline error")
		return
	}

	count := countCmd.Val()
	if count < int64(threshold) {
		return // not anomalous yet
	}

	// ── De-duplicate: fire at most once per window ────────────────────────────
	// SET NX returns true only when the key did NOT exist (first alert).
	set, err := a.rdb.SetNX(ctx, alertKey, 1, window).Result()
	if err != nil || !set {
		return // already alerted in this window
	}

	log.Warn().
		Str("org_id", org.ID.String()).
		Str("org_slug", org.Slug).
		Int64("count", count).
		Int("threshold", threshold).
		Dur("window", window).
		Msg("scim anomaly: bulk deprovisioning threshold exceeded — dispatching SSF+webhook alert")

	a.dispatch(org, count, threshold, window)
}

// dispatch fires the SSF SET and webhook asynchronously so it does not block
// the inbound SCIM response.
func (a *AnomalyDetector) dispatch(org *models.Organization, count int64, threshold int, window time.Duration) {
	orgID := org.ID
	orgSlug := org.Slug

	if a.ssfDisp != nil {
		issuer := ""
		if a.issuerFunc != nil {
			issuer = a.issuerFunc(orgSlug)
		}
		// RISC account-disabled: closest standardised signal for mass disabling.
		// userSub is the org sentinel — not a specific end-user subject.
		body := map[string]interface{}{
			"reason":            "bulk_deprovisioning_anomaly",
			"deprovisioned":     count,
			"threshold":         threshold,
			"window_seconds":    int(window.Seconds()),
			"initiating_entity": "policy",
			"reason_admin": map[string]string{
				"en": fmt.Sprintf("NIS2 alert: %d deprovisionings in %s detected by Clavex SCIM anomaly detector", count, window),
			},
			"issuer": issuer,
		}
		a.ssfDisp.Dispatch(orgID, orgSlug,
			fmt.Sprintf("org:%s", orgID), // org-level subject
			ssf.EventAccountDisabled, body)
	}

	if a.hookDisp != nil {
		data := map[string]any{
			"org_id":         orgID,
			"deprovisioned":  count,
			"threshold":      threshold,
			"window_seconds": int(window.Seconds()),
			"alert":          "bulk_deprovisioning_anomaly",
		}
		a.hookDisp.Dispatch(orgID, webhook.EventSCIMDeprovisioningAnomaly, data)
	}
}

// thresholds extracts per-org overrides from org.Settings, falling back to
// package-level defaults. Stored as:
//
//	org.settings["scim_anomaly_threshold"]        int   (default 50)
//	org.settings["scim_anomaly_window_seconds"]   int   (default 300)
func (a *AnomalyDetector) thresholds(org *models.Organization) (int, time.Duration) {
	threshold := DefaultAnomalyThreshold
	windowSec := DefaultAnomalyWindowSeconds

	if org.Settings != nil {
		if v, ok := org.Settings["scim_anomaly_threshold"]; ok {
			switch n := v.(type) {
			case float64:
				if n > 0 {
					threshold = int(n)
				}
			case int:
				if n > 0 {
					threshold = n
				}
			}
		}
		if v, ok := org.Settings["scim_anomaly_window_seconds"]; ok {
			switch n := v.(type) {
			case float64:
				if n > 0 {
					windowSec = int(n)
				}
			case int:
				if n > 0 {
					windowSec = n
				}
			}
		}
	}

	return threshold, time.Duration(windowSec) * time.Second
}

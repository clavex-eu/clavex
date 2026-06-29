// Package metrics defines all Prometheus metrics exported by Clavex.
//
// All metrics use a "clavex_" prefix and are registered on a dedicated
// non-default registry so the process-level Go runtime metrics are excluded
// by default — they can be added by callers who want them.
//
// Usage:
//
//	// In main / server setup:
//	http.Handle("/metrics", promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{}))
//
//	// In handlers:
//	metrics.LoginTotal.WithLabelValues(orgSlug, "success", "password").Inc()
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var reg = prometheus.NewRegistry()

// Registry returns the Clavex-scoped Prometheus registry.
// Register it with promhttp.HandlerFor to expose /metrics.
func Registry() *prometheus.Registry { return reg }

func mustRegister(c prometheus.Collector) {
	reg.MustRegister(c)
}

// ── Login counter ─────────────────────────────────────────────────────────────

// LoginTotal counts authentication attempts, labelled by org, outcome, and method.
//
//	org    — organisation slug (e.g. "acme-corp")
//	status — "success" | "failure" | "blocked"
//	method — "password" | "totp" | "idp" | "spid" | "cie" | "magic_link" | "device"
var LoginTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "clavex_logins_total",
		Help: "Total authentication attempts, by org, status, and method.",
	},
	[]string{"org", "status", "method"},
)

// ── Token counter ─────────────────────────────────────────────────────────────

// TokensIssuedTotal counts OAuth 2.0 tokens issued per org and grant type.
//
//	org        — organisation slug
//	grant_type — "authorization_code" | "refresh_token" | "client_credentials" |
//	             "urn:ietf:params:oauth:grant-type:token-exchange" |
//	             "urn:ietf:params:oauth:grant-type:device_code"
var TokensIssuedTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "clavex_tokens_issued_total",
		Help: "Total access tokens issued, by org and grant_type.",
	},
	[]string{"org", "grant_type"},
)

// ── Risk score histogram ──────────────────────────────────────────────────────

// RiskScoreHistogram records the distribution of computed identity risk scores (0-100)
// on successful logins, labelled by org.
//
// Buckets are chosen to separate low-risk (0-20), moderate (20-50),
// elevated (50-75), and high-risk (75-100) bands.
var RiskScoreHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "clavex_risk_score",
		Help:    "Distribution of identity risk scores (0–100) computed on successful logins.",
		Buckets: []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
	},
	[]string{"org"},
)

// ── Elevate challenge counter ─────────────────────────────────────────────────

// ElevateChallengesTotal counts step-up (Elevate) MFA challenges, labelled by outcome.
//
//	status — "created" | "completed" | "expired" | "failed"
var ElevateChallengesTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "clavex_elevate_challenges_total",
		Help: "Total Elevate (step-up MFA) challenges, by status.",
	},
	[]string{"status"},
)

// ── HTTP request duration ─────────────────────────────────────────────────────

// HTTPRequestDuration records latency for all HTTP endpoints.
// The handler label uses the Echo route pattern (e.g. "/:org_slug/token").
var HTTPRequestDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "clavex_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, by method, route, and status code.",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"method", "route", "code"},
)

func init() {
	mustRegister(LoginTotal)
	mustRegister(TokensIssuedTotal)
	mustRegister(RiskScoreHistogram)
	mustRegister(ElevateChallengesTotal)
	mustRegister(HTTPRequestDuration)
	// Include standard Go runtime and process metrics on the same registry.
	mustRegister(collectors.NewGoCollector())
	mustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

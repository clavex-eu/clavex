package metrics_test

import (
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// ── Registry ─────────────────────────────────────────────────────────────────

func TestRegistry_NotNil(t *testing.T) {
	if metrics.Registry() == nil {
		t.Fatal("Registry() returned nil")
	}
}

func TestRegistry_SameInstance(t *testing.T) {
	r1 := metrics.Registry()
	r2 := metrics.Registry()
	if r1 != r2 {
		t.Error("Registry() should return the same singleton instance")
	}
}

// ── Metrics are registered ────────────────────────────────────────────────────

func TestAllMetricsRegistered(t *testing.T) {
	// Prometheus Gather() only returns metrics with at least one observation.
	// Use Describe() instead, which lists all registered collectors
	// regardless of whether they have been observed.
	descCh := make(chan *prometheus.Desc, 128)
	metrics.Registry().Describe(descCh)
	close(descCh)

	names := make(map[string]bool)
	for desc := range descCh {
		// prometheus.Desc.String() format:
		//   Desc{fqName:"clavex_logins_total", help:"...", constLabels:{}, variableLabels:[...]}
		s := desc.String()
		const marker = `fqName: "`
		if i := strings.Index(s, marker); i >= 0 {
			rest := s[i+len(marker):]
			if j := strings.Index(rest, `"`); j >= 0 {
				names[rest[:j]] = true
			}
		}
	}

	required := []string{
		"clavex_logins_total",
		"clavex_tokens_issued_total",
		"clavex_risk_score",
		"clavex_elevate_challenges_total",
		"clavex_http_request_duration_seconds",
	}
	for _, name := range required {
		if !names[name] {
			t.Errorf("metric %q not found in registry (via Describe)", name)
		}
	}
}

func TestMetricNames_ClavexPrefix(t *testing.T) {
	mfs, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		name := mf.GetName()
		if !strings.HasPrefix(name, "clavex_") &&
			!strings.HasPrefix(name, "go_") &&
			!strings.HasPrefix(name, "process_") {
			t.Errorf("unexpected metric name without clavex_/go_/process_ prefix: %q", name)
		}
	}
}

// ── LoginTotal ────────────────────────────────────────────────────────────────

func TestLoginTotal_Increment(t *testing.T) {
	before := gatherCounterValue(t, "clavex_logins_total",
		map[string]string{"org": "test-org", "status": "success", "method": "password"})

	metrics.LoginTotal.WithLabelValues("test-org", "success", "password").Inc()

	after := gatherCounterValue(t, "clavex_logins_total",
		map[string]string{"org": "test-org", "status": "success", "method": "password"})

	if after-before != 1 {
		t.Errorf("counter should have incremented by 1, got delta %v", after-before)
	}
}

func TestLoginTotal_MultipleStatuses(t *testing.T) {
	metrics.LoginTotal.WithLabelValues("org-a", "success", "totp").Inc()
	metrics.LoginTotal.WithLabelValues("org-a", "failure", "totp").Inc()
	metrics.LoginTotal.WithLabelValues("org-a", "failure", "totp").Inc()

	success := gatherCounterValue(t, "clavex_logins_total",
		map[string]string{"org": "org-a", "status": "success", "method": "totp"})
	failure := gatherCounterValue(t, "clavex_logins_total",
		map[string]string{"org": "org-a", "status": "failure", "method": "totp"})

	if success < 1 {
		t.Errorf("success counter should be ≥ 1, got %v", success)
	}
	if failure < 2 {
		t.Errorf("failure counter should be ≥ 2, got %v", failure)
	}
}

// ── TokensIssuedTotal ─────────────────────────────────────────────────────────

func TestTokensIssuedTotal_Increment(t *testing.T) {
	before := gatherCounterValue(t, "clavex_tokens_issued_total",
		map[string]string{"org": "tok-org", "grant_type": "authorization_code"})

	metrics.TokensIssuedTotal.WithLabelValues("tok-org", "authorization_code").Inc()

	after := gatherCounterValue(t, "clavex_tokens_issued_total",
		map[string]string{"org": "tok-org", "grant_type": "authorization_code"})

	if after-before != 1 {
		t.Errorf("counter delta should be 1, got %v", after-before)
	}
}

// ── ElevateChallengesTotal ────────────────────────────────────────────────────

func TestElevateChallengesTotal_Statuses(t *testing.T) {
	for _, status := range []string{"created", "completed", "failed", "expired"} {
		metrics.ElevateChallengesTotal.WithLabelValues(status).Inc()
	}
	for _, status := range []string{"created", "completed", "failed", "expired"} {
		v := gatherCounterValue(t, "clavex_elevate_challenges_total",
			map[string]string{"status": status})
		if v < 1 {
			t.Errorf("elevate counter for status=%q should be ≥ 1, got %v", status, v)
		}
	}
}

// ── RiskScoreHistogram ────────────────────────────────────────────────────────

func TestRiskScoreHistogram_Observe(t *testing.T) {
	metrics.RiskScoreHistogram.WithLabelValues("risk-org").Observe(42)
	metrics.RiskScoreHistogram.WithLabelValues("risk-org").Observe(85)

	count := gatherHistogramCount(t, "clavex_risk_score",
		map[string]string{"org": "risk-org"})
	if count < 2 {
		t.Errorf("histogram count should be ≥ 2, got %d", count)
	}
}

// ── HTTPRequestDuration ───────────────────────────────────────────────────────

func TestHTTPRequestDuration_Observe(t *testing.T) {
	metrics.HTTPRequestDuration.WithLabelValues("GET", "/healthz", "200").Observe(0.005)
	metrics.HTTPRequestDuration.WithLabelValues("POST", "/:org_slug/token", "200").Observe(0.12)

	count := gatherHistogramCount(t, "clavex_http_request_duration_seconds",
		map[string]string{"method": "GET", "route": "/healthz", "code": "200"})
	if count < 1 {
		t.Errorf("histogram count should be ≥ 1, got %d", count)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// gatherCounterValue returns the current value of a counter metric with the given labels.
// Returns 0 if the metric/label combination is not yet observed.
func gatherCounterValue(t *testing.T, metricName string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m, labels) {
				if c := m.GetCounter(); c != nil {
					return c.GetValue()
				}
			}
		}
	}
	return 0
}

// gatherHistogramCount returns the sample count of a histogram metric with the given labels.
func gatherHistogramCount(t *testing.T, metricName string, labels map[string]string) uint64 {
	t.Helper()
	mfs, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m, labels) {
				if h := m.GetHistogram(); h != nil {
					return h.GetSampleCount()
				}
			}
		}
	}
	return 0
}

// labelsMatch returns true when all required labels appear in the metric's label pairs.
func labelsMatch(m *dto.Metric, required map[string]string) bool {
	have := make(map[string]string, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		have[lp.GetName()] = lp.GetValue()
	}
	for k, v := range required {
		if have[k] != v {
			return false
		}
	}
	return true
}

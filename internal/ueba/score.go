package ueba

import (
	"fmt"
	"math"

	"github.com/clavex-eu/clavex/internal/models"
)

// Result is the UEBA anomaly contribution for a single login event.
// Score (0–30) is additive and intended to be summed with the static risk
// signals from internal/risk.  Flags carry machine-readable signal labels
// using the "ueba:*" prefix for auditability.
type Result struct {
	Score int      // 0..30 additive contribution
	Flags []string // e.g. ["ueba:time_anomaly:p0.009:bin1(h03-05)", "ueba:session_velocity:recent_42:p0.001"]
}

// Score computes how anomalous event is relative to the user's baseline using a
// Naive Bayes model over six independent features.
//
// For each feature i the scorer computes:
//
//	p_i       = Laplace-smoothed P(observed value | user baseline)
//	surprise  = −log₂(p_i)                          [bits]
//	entropy   = H(baseline distribution for feature) [bits — expected surprise]
//	excess    = max(0, surprise − entropy)            [above-average anomaly]
//
// The weighted joint excess is normalised by the maximum possible weighted
// excess (all features simultaneously maximally novel) to yield a 0–30 score.
// A user with diverse history (high per-feature entropy) is inherently hard to
// surprise, which prevents false positives for travel-heavy or multi-device users.
//
// recentLoginCount is the number of OTHER successful logins recorded for this
// user in the 1-hour window immediately preceding event.CreatedAt.  The caller
// (risk/scorer.go) derives this from the already-loaded event slice without an
// extra DB round-trip.
//
// Feature weights (higher = stronger signal):
//
//	hour-of-day       1.0   — personal activity window is a strong signal
//	country           1.0   — rare-country is a strong signal
//	/24 subnet        0.6   — IP mobility is noisier (mobile, VPN, CGNAT)
//	UA family         0.7   — browser/tool shift is a moderate signal
//	auth method       0.8   — method shift is a reliable takeover indicator
//	session velocity  1.2   — login rate is the strongest credential-stuffing indicator
func Score(event *models.LoginEvent, baseline *Baseline, recentLoginCount int) *Result {
	r := &Result{}
	if baseline == nil || baseline.Count < minSamples {
		return r
	}

	const alpha = 0.5

	// featureExcess computes (excess surprise, maxExcess) for a single feature
	// value observed against a histogram/count-map bucket. k = number of buckets.
	featureExcess := func(count, total, k int, entropy float64) (float64, float64) {
		p := smoothedProb(count, total, k)
		surprise := -math.Log2(p)
		excess := surprise - entropy
		if excess < 0 {
			excess = 0
		}
		// Maximum possible excess: when a completely novel value is observed.
		pNovel := alpha / (float64(total) + float64(k)*alpha)
		maxExcess := -math.Log2(pNovel) - entropy
		if maxExcess < 0 {
			maxExcess = 0
		}
		return excess, maxExcess
	}

	type signal struct {
		weight    float64
		excess    float64
		maxExcess float64
		flag      string
	}
	signals := make([]signal, 0, 6)

	// ── 1. Hour-of-day (3-hour bins, 8 buckets) ───────────────────────────────
	{
		const w = 1.0
		bin := event.CreatedAt.UTC().Hour() / 3
		cnt := baseline.HourBinHist[bin]
		ex, mx := featureExcess(cnt, baseline.Count, 8, baseline.HourBinEntropy)
		var f string
		if ex > 0 {
			p := smoothedProb(cnt, baseline.Count, 8)
			f = fmt.Sprintf("ueba:time_anomaly:p%.3f:bin%d(h%02d-%02d)", p, bin, bin*3, bin*3+2)
		}
		signals = append(signals, signal{w, ex, mx, f})
	}

	// ── 2. Country ────────────────────────────────────────────────────────────
	if event.CountryCode != nil && *event.CountryCode != "" {
		const w = 1.0
		cc := *event.CountryCode
		k := len(baseline.CountryCount) + 1
		ex, mx := featureExcess(baseline.CountryCount[cc], baseline.Count, k, baseline.CountryEntropy)
		var f string
		if ex > 0 {
			p := smoothedProb(baseline.CountryCount[cc], baseline.Count, k)
			f = fmt.Sprintf("ueba:rare_country:%s:p%.3f", cc, p)
		}
		signals = append(signals, signal{w, ex, mx, f})
	}

	// ── 3. /24 subnet ─────────────────────────────────────────────────────────
	if event.IPAddress != nil && *event.IPAddress != "" {
		const w = 0.6
		sub := subnet24(*event.IPAddress)
		k := len(baseline.SubnetCount) + 1
		ex, mx := featureExcess(baseline.SubnetCount[sub], baseline.Count, k, baseline.SubnetEntropy)
		var f string
		if ex > 0 {
			p := smoothedProb(baseline.SubnetCount[sub], baseline.Count, k)
			f = fmt.Sprintf("ueba:new_subnet:%s.0/24:p%.3f", sub, p)
		}
		signals = append(signals, signal{w, ex, mx, f})
	}

	// ── 4. User-agent family ──────────────────────────────────────────────────
	{
		const w = 0.7
		ua := ""
		if event.UserAgent != nil {
			ua = *event.UserAgent
		}
		fam := uaFamily(ua)
		k := len(baseline.UAFamilyCount) + 1
		ex, mx := featureExcess(baseline.UAFamilyCount[fam], baseline.Count, k, baseline.UAEntropy)
		var f string
		if ex > 0 {
			p := smoothedProb(baseline.UAFamilyCount[fam], baseline.Count, k)
			f = fmt.Sprintf("ueba:ua_shift:%s:p%.3f", fam, p)
		}
		signals = append(signals, signal{w, ex, mx, f})
	}

	// ── 5. Auth method ────────────────────────────────────────────────────────
	{
		const w = 0.8
		k := len(baseline.AuthMethodCount) + 1
		ex, mx := featureExcess(baseline.AuthMethodCount[event.AuthMethod], baseline.Count, k, baseline.AuthMethEntropy)
		var f string
		if ex > 0 {
			p := smoothedProb(baseline.AuthMethodCount[event.AuthMethod], baseline.Count, k)
			f = fmt.Sprintf("ueba:auth_method_shift:%s:p%.3f", event.AuthMethod, p)
		}
		signals = append(signals, signal{w, ex, mx, f})
	}

	// ── 6. Session velocity (logins in preceding 1-hour window) ──────────────
	// Weight 1.2 — highest of all features: a high login rate is the strongest
	// indicator of automated credential-stuffing attacks.
	{
		const w = 1.2
		bin := velocityBin(recentLoginCount)
		ex, mx := featureExcess(baseline.VelocityBinHist[bin], baseline.Count, 5, baseline.VelocityEntropy)
		var f string
		if ex > 0 {
			p := smoothedProb(baseline.VelocityBinHist[bin], baseline.Count, 5)
			f = fmt.Sprintf("ueba:session_velocity:recent_%d:p%.3f", recentLoginCount, p)
		}
		signals = append(signals, signal{w, ex, mx, f})
	}

	// ── Normalise and score ───────────────────────────────────────────────────
	var joint, maxJoint float64
	for _, s := range signals {
		joint += s.weight * s.excess
		maxJoint += s.weight * s.maxExcess
	}

	if maxJoint > 0 {
		frac := joint / maxJoint
		if frac > 1 {
			frac = 1
		}
		r.Score = int(math.Round(frac * 30))
	}

	// Emit flags only for features that contributed non-zero excess.
	for _, s := range signals {
		if s.flag != "" {
			r.Flags = append(r.Flags, s.flag)
		}
	}

	return r
}

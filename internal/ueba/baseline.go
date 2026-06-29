// Package ueba provides User and Entity Behaviour Analytics (UEBA) for Clavex.
//
// Scoring uses a per-user Naive Bayes model.  For each feature, we compute the
// Laplace-smoothed log-probability of the observed value under the user's
// historical distribution, then measure how much that probability deviates from
// the distribution's Shannon entropy (the "expected" per-feature surprise).
//
// "Excess surprise" above entropy aggregated across features, weighted and
// normalised, yields a 0–30 anomaly score that is:
//   - personalised: a user with diverse history is hard to surprise;
//   - calibrated: the score saturates at 30 only when every feature is novel;
//   - zero-dependency: pure Go, no external ML library required.
//
// Features scored
//
//	hour-of-day       3-hour bins (8 bins) — personal activity window
//	country           ISO-3166             — travel / proxy anomaly
//	/24 subnet                             — IP mobility anomaly
//	UA family         coarse family        — tool / browser shift
//	auth method                            — credential-stuffing method shift
//	session velocity  logins/1 h           — automation / credential-stuffing rate
package ueba

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
)

const (
	// minSamples is the minimum number of successful baseline events required
	// before the UEBA scorer produces non-zero output.  Below this threshold
	// we lack statistical power and would generate too many false positives.
	minSamples = 10

	// maxBaselineSize caps how many successful events contribute to the model.
	// Older events beyond this window are ignored, keeping the model fresh.
	maxBaselineSize = 200
)

// Baseline is a compact per-user behavioural model derived from historical
// successful login events.  All fields are computed once via Build().
type Baseline struct {
	// Count is the number of successful events used to build this baseline.
	Count int

	// HourBinHist is an 8-element histogram of login counts per 3-hour UTC bin.
	// Bin i covers hours [3i, 3i+2] (i.e. bin 0 = 00:00–02:59, bin 3 = 09:00–11:59).
	// 3-hour bins reduce histogram sparsity vs. a 24-bucket histogram.
	HourBinHist [8]int

	// CountryCount maps ISO-3166 country codes to login counts.
	CountryCount map[string]int

	// SubnetCount maps IPv4 /24 prefixes to login counts.
	SubnetCount map[string]int

	// UAFamilyCount maps coarse user-agent family names to login counts.
	UAFamilyCount map[string]int

	// AuthMethodCount maps authentication method names to login counts.
	AuthMethodCount map[string]int

	// VelocityBinHist is a 5-bin histogram recording how many other successful
	// logins preceded each baseline event within a 1-hour window.
	// Bins: [0]=0 others, [1]=1, [2]=2–3, [3]=4–9, [4]=10+
	// High velocity (bins 3–4) is the strongest signal for credential stuffing.
	VelocityBinHist [5]int

	// Precomputed Shannon entropies (bits) for each feature distribution.
	// Stored here so Score() does not re-derive them on every call.
	HourBinEntropy  float64
	CountryEntropy  float64
	SubnetEntropy   float64
	UAEntropy       float64
	AuthMethEntropy float64
	VelocityEntropy float64
}

// Build derives a Baseline from historical login events (sorted newest-first).
// Only successful logins are used to model normal behaviour.
func Build(events []*models.LoginEvent) *Baseline {
	b := &Baseline{
		CountryCount:    make(map[string]int),
		SubnetCount:     make(map[string]int),
		UAFamilyCount:   make(map[string]int),
		AuthMethodCount: make(map[string]int),
	}

	// Two-pass: collect successful events first so the velocity loop can look
	// ahead in the sorted slice without a second full scan.
	successful := make([]*models.LoginEvent, 0, maxBaselineSize)
	for _, ev := range events {
		if ev.Status != "success" {
			continue
		}
		if len(successful) >= maxBaselineSize {
			break
		}
		successful = append(successful, ev)
	}
	b.Count = len(successful)

	// Ensure newest-first order so the velocity look-ahead below is correct.
	// The production caller (risk/scorer.go) already passes events newest-first,
	// but sorting here makes Build() safe for any input ordering.
	sort.Slice(successful, func(i, j int) bool {
		return successful[i].CreatedAt.After(successful[j].CreatedAt)
	})

	for i, ev := range successful {
		b.HourBinHist[ev.CreatedAt.UTC().Hour()/3]++
		if ev.CountryCode != nil && *ev.CountryCode != "" {
			b.CountryCount[*ev.CountryCode]++
		}
		if ev.IPAddress != nil && *ev.IPAddress != "" {
			b.SubnetCount[subnet24(*ev.IPAddress)]++
		}
		ua := ""
		if ev.UserAgent != nil {
			ua = *ev.UserAgent
		}
		b.UAFamilyCount[uaFamily(ua)]++
		b.AuthMethodCount[ev.AuthMethod]++

		// Velocity: count successful events that occurred in the 1 h before ev.
		// successful is sorted newest-first, so events at j > i are older.
		// We want events whose time is in [ev.CreatedAt−1h, ev.CreatedAt).
		preceding := 0
		for j := i + 1; j < len(successful); j++ {
			if ev.CreatedAt.Sub(successful[j].CreatedAt) <= time.Hour {
				preceding++
			} else {
				break // slice is sorted; remaining events are even older
			}
		}
		b.VelocityBinHist[velocityBin(preceding)]++
	}

	// Precompute per-feature entropies.
	b.HourBinEntropy = histEntropy(b.HourBinHist[:], b.Count)
	b.CountryEntropy = mapEntropy(b.CountryCount, b.Count)
	b.SubnetEntropy = mapEntropy(b.SubnetCount, b.Count)
	b.UAEntropy = mapEntropy(b.UAFamilyCount, b.Count)
	b.AuthMethEntropy = mapEntropy(b.AuthMethodCount, b.Count)
	b.VelocityEntropy = histEntropy(b.VelocityBinHist[:], b.Count)
	return b
}

// velocityBin maps a login count to one of 5 velocity bins.
// Bins: 0=none, 1=one, 2=2–3, 3=4–9, 4=10+
func velocityBin(count int) int {
	switch {
	case count == 0:
		return 0
	case count == 1:
		return 1
	case count <= 3:
		return 2
	case count <= 9:
		return 3
	default:
		return 4
	}
}

// histEntropy computes the Laplace-smoothed Shannon entropy (bits) of a
// histogram slice over total events.  Alpha = 0.5 (Jeffreys prior).
func histEntropy(hist []int, total int) float64 {
	const alpha = 0.5
	k := len(hist)
	denom := float64(total) + float64(k)*alpha
	var h float64
	for _, c := range hist {
		p := (float64(c) + alpha) / denom
		h -= p * math.Log2(p)
	}
	return h
}

// mapEntropy computes the Laplace-smoothed Shannon entropy (bits) of a count
// map.  An additional "novel" pseudo-bucket is always included so that unseen
// values have non-zero probability.
func mapEntropy(counts map[string]int, total int) float64 {
	const alpha = 0.5
	k := len(counts) + 1 // +1 for the novel-value pseudo-bucket
	denom := float64(total) + float64(k)*alpha
	var h float64
	for _, c := range counts {
		p := (float64(c) + alpha) / denom
		h -= p * math.Log2(p)
	}
	// Novel-value pseudo-bucket.
	p := alpha / denom
	h -= p * math.Log2(p)
	return h
}

// subnet24 extracts the /24 network prefix of an IPv4 address ("a.b.c").
// For IPv6 or unparseable strings the input is returned unchanged.
func subnet24(ip string) string {
	if parts := strings.SplitN(ip, ".", 4); len(parts) == 4 {
		return parts[0] + "." + parts[1] + "." + parts[2]
	}
	return ip
}

// uaFamily extracts a coarse browser/client family from a raw User-Agent string
// without any external dependency.  Order matters: Edge must be checked before
// Chrome because Edge UA strings contain both "Chrome" and "Edg".
func uaFamily(ua string) string {
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "edg/") || strings.Contains(l, "edge/"):
		return "Edge"
	case strings.Contains(l, "chrome") && strings.Contains(l, "safari"):
		return "Chrome"
	case strings.Contains(l, "firefox"):
		return "Firefox"
	case strings.Contains(l, "safari"):
		return "Safari"
	case strings.Contains(l, "opera") || strings.Contains(l, "opr/"):
		return "Opera"
	case strings.Contains(l, "okhttp"):
		return "OkHttp"
	case strings.Contains(l, "curl"):
		return "curl"
	case strings.Contains(l, "python"):
		return "Python"
	case strings.Contains(l, "go-http-client"):
		return "Go"
	case ua == "":
		return "none"
	default:
		return "other"
	}
}

// smoothedProb returns the Laplace-smoothed probability of observing count
// out of total events, given numBuckets equally-likely alternatives.
// Alpha = 0.5 (Jeffreys prior) prevents zero-probability surprises.
func smoothedProb(count, total, numBuckets int) float64 {
	const alpha = 0.5
	return (float64(count) + alpha) / (float64(total) + float64(numBuckets)*alpha)
}

// hourZScore returns how many standard deviations below the baseline mean the
// given UTC hour is.  Kept for backward compatibility and testing.
func hourZScore(hist [24]int, hour int) float64 {
	total := 0
	for _, c := range hist {
		total += c
	}
	if total == 0 {
		return 0
	}
	freq := make([]float64, 24)
	for i, c := range hist {
		freq[i] = float64(c) / float64(total)
	}
	const mean = 1.0 / 24.0
	var variance float64
	for _, f := range freq {
		d := f - mean
		variance += d * d
	}
	variance /= 24.0
	std := math.Sqrt(variance)
	if std < 1e-9 {
		return 0
	}
	return (freq[hour] - mean) / std
}

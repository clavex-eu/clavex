// Package policy implements a lightweight, config-driven auth-flow policy engine.
//
// # Concepts
//
// A Policy is an ordered list of Rules. The evaluator walks the rules in
// priority order (lowest number = first) and returns the outcome of the first
// rule whose Conditions all match.  If no rule matches the built-in default is
// "allow" (so an empty policy = unrestricted access).
//
// # Conditions
//
// Each condition is a boolean expression over a single signal field:
//
//   ip_cidr:        "10.0.0.0/8" or ["10.0.0.0/8","192.168.0.0/16"]
//   country:        "IT" or ["IT","DE","FR"]       (ISO 3166-1 alpha-2)
//   country_not:    "CN" or ["CN","RU"]            (complement)
//   client_id:      "my-client-id" or [...]
//   mfa_enrolled:   true | false
//   new_country:    true | false                   (country not in 90-day baseline)
//   day_of_week:    ["Mon","Tue",...]              (UTC)
//   hour_range:     {from: 0, to: 22}             (UTC, inclusive)
//   last_login_before: "720h"                      (Go duration; nil = never logged in)
//
// # Actions
//
//   allow          — proceed with the normal flow
//   deny           — reject the request (403)
//   require_mfa    — enforce MFA step-up regardless of org/user setting
//   step_up        — alias for require_mfa
//
// # Policy source
//
// Policies are stored in the identity.org_auth_policies table as JSONB and
// cached in-process.  Operators may also embed a global default in config YAML
// (under auth.default_policies) which is used as a fallback when an org has no
// DB rows.
//
// # Evaluation context (EvalInput)
//
// The OIDC handler builds an EvalInput from the live request and calls
// Engine.Evaluate before issuing the auth code.  The same EvalInput is used by
// the dry-run simulate endpoint — no side-effects.
package policy

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Action is the outcome of a matched rule.
type Action string

const (
	ActionAllow      Action = "allow"
	ActionDeny       Action = "deny"
	ActionRequireMFA Action = "require_mfa"
	ActionStepUp     Action = "step_up" // alias for require_mfa
)

// Outcome is returned by the evaluator.
type Outcome struct {
	Action    Action `json:"action"`
	RuleName  string `json:"rule_name,omitempty"`  // which rule fired
	Reason    string `json:"reason,omitempty"`     // human-readable explanation
	MFAForced bool   `json:"mfa_forced,omitempty"` // true when action is require_mfa / step_up
}

// IsDeny reports whether the outcome blocks the request.
func (o Outcome) IsDeny() bool { return o.Action == ActionDeny }

// IsMFARequired reports whether the outcome forces MFA step-up.
func (o Outcome) IsMFARequired() bool {
	return o.Action == ActionRequireMFA || o.Action == ActionStepUp
}

// HourRange is a UTC time window [From, To] (inclusive, 0-23).
type HourRange struct {
	From int `json:"from" yaml:"from"`
	To   int `json:"to"   yaml:"to"`
}

// Conditions holds all the optional conditions for a rule.
// A nil/zero-value field means "no constraint for this signal".
type Conditions struct {
	// IP CIDR allowlist — matches if the request IP is in any of these ranges.
	IPCIDRs []string `json:"ip_cidr,omitempty"   yaml:"ip_cidr,omitempty"`

	// Country allowlist / denylist (ISO 3166-1 alpha-2).
	Countries    []string `json:"country,omitempty"     yaml:"country,omitempty"`
	NotCountries []string `json:"country_not,omitempty" yaml:"country_not,omitempty"`

	// OIDC client_id filter.
	ClientIDs []string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// MFA enrollment state.
	MFAEnrolled *bool `json:"mfa_enrolled,omitempty" yaml:"mfa_enrolled,omitempty"`

	// True when the current country has never been seen in the user's 90-day baseline.
	NewCountry *bool `json:"new_country,omitempty" yaml:"new_country,omitempty"`

	// Restrict to specific UTC days of week.
	DaysOfWeek []string `json:"day_of_week,omitempty" yaml:"day_of_week,omitempty"` // "Mon","Tue",...

	// Restrict to a UTC hour range.
	HourRange *HourRange `json:"hour_range,omitempty" yaml:"hour_range,omitempty"`

	// Require more than this duration since last successful login
	// (expressed as a Go duration string, e.g. "720h").
	// An absent LastLoginAt (first login) is treated as "infinite duration" → matches.
	LastLoginBefore string `json:"last_login_before,omitempty" yaml:"last_login_before,omitempty"`
}

// Rule is a single named policy rule.
type Rule struct {
	// Name is a human-readable identifier used in audit logs and simulate responses.
	Name string `json:"name" yaml:"name"`
	// Priority controls evaluation order — lower numbers are checked first.
	// Rules with equal priority are evaluated in declaration order.
	Priority int `json:"priority" yaml:"priority"`
	// Conditions that must ALL match for this rule to fire.
	Conditions Conditions `json:"conditions" yaml:"conditions"`
	// Action to take when all conditions match.
	Action Action `json:"action" yaml:"action"`
	// Enabled allows rules to be disabled without deletion.
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// Policy is an ordered collection of rules for one org.
type Policy struct {
	// Rules in the policy (sorted by Priority ascending before evaluation).
	Rules []Rule `json:"rules" yaml:"rules"`
}

// EvalInput holds all the signals available during a single authorization
// request.  Fields that cannot be determined (e.g. country when geo-IP is
// disabled) are left as zero values — conditions depending on them will not
// match.
type EvalInput struct {
	// Request context
	IPAddress   string // raw IP string
	Country     string // ISO 3166-1 alpha-2 or ""
	UserAgent   string
	RequestTime time.Time // defaults to time.Now() if zero

	// Client
	ClientID string

	// User signals (populated after authentication; may be zero for dry-run)
	UserID      string
	MFAEnrolled bool
	NewCountry  bool // true if Country not in 90-day baseline
	LastLoginAt *time.Time
}

// ── Evaluator ─────────────────────────────────────────────────────────────────

// Evaluate walks the rules in priority order and returns the first matching
// outcome.  If no rule matches, returns Outcome{Action: ActionAllow}.
func Evaluate(p *Policy, in EvalInput) Outcome {
	if p == nil || len(p.Rules) == 0 {
		return Outcome{Action: ActionAllow, Reason: "no policy"}
	}

	// Sort rules by priority (stable insertion — preserve declaration order for ties).
	sorted := sortedRules(p.Rules)

	if in.RequestTime.IsZero() {
		in.RequestTime = time.Now().UTC()
	}

	for _, rule := range sorted {
		if !rule.Enabled {
			continue
		}
		if matchAll(rule.Conditions, in) {
			out := Outcome{
				Action:   rule.Action,
				RuleName: rule.Name,
				Reason:   fmt.Sprintf("rule %q matched", rule.Name),
			}
			if out.IsMFARequired() {
				out.MFAForced = true
			}
			return out
		}
	}
	return Outcome{Action: ActionAllow, Reason: "no rule matched"}
}

// matchAll returns true if every non-empty condition in c matches in.
func matchAll(c Conditions, in EvalInput) bool {
	// IP CIDR
	if len(c.IPCIDRs) > 0 {
		if !ipMatchesCIDRs(in.IPAddress, c.IPCIDRs) {
			return false
		}
	}

	// Country allowlist
	if len(c.Countries) > 0 {
		if !stringIn(in.Country, c.Countries) {
			return false
		}
	}

	// Country denylist
	if len(c.NotCountries) > 0 {
		if stringIn(in.Country, c.NotCountries) {
			return false
		}
	}

	// ClientID filter
	if len(c.ClientIDs) > 0 {
		if !stringIn(in.ClientID, c.ClientIDs) {
			return false
		}
	}

	// MFA enrolled
	if c.MFAEnrolled != nil {
		if in.MFAEnrolled != *c.MFAEnrolled {
			return false
		}
	}

	// New country
	if c.NewCountry != nil {
		if in.NewCountry != *c.NewCountry {
			return false
		}
	}

	// Day of week
	if len(c.DaysOfWeek) > 0 {
		day := in.RequestTime.UTC().Weekday().String()[:3] // "Mon", "Tue" …
		if !stringIn(day, c.DaysOfWeek) {
			return false
		}
	}

	// Hour range
	if c.HourRange != nil {
		h := in.RequestTime.UTC().Hour()
		if c.HourRange.From <= c.HourRange.To {
			if h < c.HourRange.From || h > c.HourRange.To {
				return false
			}
		} else {
			// Wrap-around range (e.g. 22 to 6)
			if h < c.HourRange.From && h > c.HourRange.To {
				return false
			}
		}
	}

	// Last login before
	if c.LastLoginBefore != "" {
		threshold, err := time.ParseDuration(c.LastLoginBefore)
		if err == nil {
			if in.LastLoginAt == nil {
				// Never logged in — treat as infinitely long ago → matches
			} else {
				elapsed := in.RequestTime.Sub(*in.LastLoginAt)
				if elapsed <= threshold {
					return false
				}
			}
		}
	}

	return true
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func ipMatchesCIDRs(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		// Accept bare IP addresses as /32 (or /128).
		if !strings.Contains(cidr, "/") {
			if net.ParseIP(cidr) != nil {
				cidr = cidr + "/32"
				if strings.Contains(cidr, ":") {
					cidr = strings.Replace(cidr, "/32", "/128", 1)
				}
			}
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func stringIn(v string, list []string) bool {
	vUpper := strings.ToUpper(v)
	for _, s := range list {
		if strings.ToUpper(s) == vUpper {
			return true
		}
	}
	return false
}

// SortedRules returns a copy of rules sorted by Priority ascending.
// Exported for the trace logic in the simulate handler.
// Stable so that equal-priority rules preserve their declaration order.
func SortedRules(rules []Rule) []Rule { return sortedRules(rules) }

// MatchAll reports whether all conditions in c match in.
// Exported for the trace logic in the simulate handler.
func MatchAll(c Conditions, in EvalInput) bool { return matchAll(c, in) }

// sortedRules returns a copy of rules sorted by Priority ascending.
// Stable so that equal-priority rules preserve their declaration order.
func sortedRules(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	// Insertion sort (list is typically tiny).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Priority < out[j-1].Priority; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

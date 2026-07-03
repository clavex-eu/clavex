// Package domainverify holds the shared custom-domain CNAME verification logic
// used by both the on-demand Verify endpoint and the background re-verify worker.
package domainverify

import (
	"context"
	"strings"
)

// Resolver looks up the canonical name a host points to. Satisfied by
// *net.Resolver; faked in tests.
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Matches reports whether a resolved CNAME points at the expected target. Both
// are compared case-insensitively without the trailing dot; a match on the
// exact target or a subdomain of it (e.g. a chained CNAME) counts.
func Matches(resolved, target string) bool {
	r := strings.ToLower(strings.TrimSuffix(resolved, "."))
	t := strings.ToLower(strings.TrimSuffix(target, "."))
	if t == "" || r == "" {
		return false
	}
	return r == t || strings.HasSuffix(r, "."+t)
}

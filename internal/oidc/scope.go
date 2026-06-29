package oidc

// FilterScope returns the intersection of the requested scopes and the client's
// registered (allowed) scopes, preserving the order of the requested scopes.
//
// Semantics (RFC 6749 §3.3 — silent downgrade):
//   - allowed empty            → requested returned unchanged (allow-all, backward compat)
//   - requested empty          → "" (nothing requested)
//   - otherwise                → space-joined intersection; scopes not in allowed are dropped
//
// Unlike narrowScope (used by token-exchange), an empty intersection against a
// non-empty allow-list is NOT an error: it simply yields "" (no scopes granted).
func FilterScope(requested string, allowed []string) string {
	if len(allowed) == 0 {
		return requested
	}
	allowSet := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		allowSet[s] = true
	}
	var result []string
	for _, s := range splitScope(requested) {
		if allowSet[s] {
			result = append(result, s)
		}
	}
	return joinScope(result)
}

// audiencePermitted reports whether a token-exchange request may set the given
// target audience (RFC 8693 §2.1): an empty request defaults to the caller, the
// caller's own client_id is always allowed, and any explicitly allow-listed
// audience is permitted. Everything else is rejected (invalid_target).
func audiencePermitted(requested, clientID string, allowed []string) bool {
	if requested == "" || requested == clientID {
		return true
	}
	for _, a := range allowed {
		if a == requested {
			return true
		}
	}
	return false
}

package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// ComputeSessionState computes the OIDC Session Management 1.0 §2 session_state
// value that is included in every authorization response and later used by the
// check_session_iframe to detect session changes.
//
// Format: base64url(sha256(clientID + " " + rpOrigin + " " + browserState + " " + salt)) + "." + salt
//
// Where:
//   - clientID     is the RP's OAuth2 client_id
//   - rpOrigin     is the RP's origin (scheme://host[:port]), derived from the redirect_uri
//   - browserState is the value stored in the OP browser-state cookie (clavex_bs)
//   - salt         is a fresh random value generated per response
//
// The same salt is embedded in the returned value (after ".") so the check_session_iframe
// can reproduce the hash using the cookie value it reads via document.cookie.
func ComputeSessionState(clientID, rpOrigin, browserState string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	saltStr := base64.RawURLEncoding.EncodeToString(salt)
	return computeSessionStateWithSalt(clientID, rpOrigin, browserState, saltStr)
}

// computeSessionStateWithSalt is the deterministic inner function, split out for tests.
func computeSessionStateWithSalt(clientID, rpOrigin, browserState, saltStr string) string {
	h := sha256.Sum256([]byte(clientID + " " + rpOrigin + " " + browserState + " " + saltStr))
	return base64.RawURLEncoding.EncodeToString(h[:]) + "." + saltStr
}

// RPOriginFromRedirectURI extracts the RP origin (scheme://host[:port]) from a
// redirect_uri. Returns "" if the URI is not parseable or has no host.
func RPOriginFromRedirectURI(redirectURI string) string {
	// Use a simple parsing approach to avoid importing net/url in this package.
	// The redirect_uri must have the form scheme://host[:port][/path][?query].
	// We split at the first "/" after "://".
	schemeEnd := 0
	for i := 0; i+2 < len(redirectURI); i++ {
		if redirectURI[i] == ':' && redirectURI[i+1] == '/' && redirectURI[i+2] == '/' {
			schemeEnd = i + 3
			break
		}
	}
	if schemeEnd == 0 {
		return ""
	}
	scheme := redirectURI[:schemeEnd-3] // e.g. "https"
	rest := redirectURI[schemeEnd:]     // e.g. "example.com/callback"
	// host[:port] ends at the first "/" or "?" or end of string
	hostEnd := len(rest)
	for i, c := range rest {
		if c == '/' || c == '?' || c == '#' {
			hostEnd = i
			break
		}
	}
	host := rest[:hostEnd]
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

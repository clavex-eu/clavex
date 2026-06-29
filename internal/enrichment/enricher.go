// Package enrichment implements the synchronous claims-enrichment hook.
//
// When an organization configures a ClaimsEnrichmentURL, Clavex POSTs a JSON
// payload to that URL during token issuance and merges the returned claims into
// the access token.  The call has a hard 500 ms timeout; any error (network,
// timeout, non-2xx, invalid JSON) is logged and silently ignored so that token
// issuance always succeeds (graceful fallback).
//
// Wire-protocol:
//
//	POST <url>
//	Authorization: Bearer <secret>    (omitted when secret is empty)
//	Content-Type: application/json
//
//	Request body:
//	  {
//	    "sub":        "<user id>",
//	    "org_id":     "<org id>",
//	    "email":      "<email>",
//	    "client_id":  "<client id>",
//	    "scope":      "<space-separated scopes>",
//	    "extra":      { ...existing extra claims from mappers... }
//	  }
//
//	Response (200 OK):
//	  {
//	    "subscription_plan": "enterprise",
//	    "tenant_region":     "eu-west"
//	    ...any flat key/value pairs...
//	  }
//
// Reserved claim names (sub, iss, aud, exp, iat, jti, scope, org_id, email,
// realm_access, groups, cnf, at_hash, req_claims, authorization_details) are
// stripped from the response to prevent the hook from overwriting them.
package enrichment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/safehttp"
)

// Timeout is the maximum time Clavex waits for the enrichment endpoint.
const Timeout = 500 * time.Millisecond

// reservedClaims lists standard/internal claim names that the hook may not
// override.  Rejection is case-insensitive.
var reservedClaims = map[string]struct{}{
	"sub": {}, "iss": {}, "aud": {}, "exp": {}, "iat": {}, "jti": {},
	"scope": {}, "org_id": {}, "email": {}, "realm_access": {}, "groups": {},
	"cnf": {}, "at_hash": {}, "req_claims": {}, "authorization_details": {},
	"client_id": {}, "nonce": {}, "acr": {}, "auth_time": {},
}

// httpClient is the SSRF-safe client used to call the org-configured enrichment
// URL: connections to private/loopback/link-local targets are blocked so the hook
// cannot be pointed at internal services or cloud metadata. Per-call timeout is
// applied via context. SetHTTPClient overrides it (e.g. an SSRF-relaxed client
// when the operator has opted into private outbound targets).
var httpClient = safehttp.Client(0, false)

// SetHTTPClient overrides the enrichment HTTP client.
func SetHTTPClient(c *http.Client) {
	if c != nil {
		httpClient = c
	}
}

// Payload is the request body sent to the enrichment endpoint.
type Payload struct {
	Sub      string         `json:"sub"`
	OrgID    string         `json:"org_id"`
	Email    string         `json:"email"`
	ClientID string         `json:"client_id"`
	Scope    string         `json:"scope"`
	Extra    map[string]any `json:"extra,omitempty"`
}

// Enrich calls the enrichment endpoint and returns additional claims to merge
// into the token.  It always returns a non-nil map (may be empty).
// Errors are wrapped and returned for logging, but callers should treat them as
// non-fatal (graceful fallback: proceed with token issuance).
func Enrich(ctx context.Context, url, secret string, p Payload) (map[string]any, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return map[string]any{}, fmt.Errorf("enrichment: marshal payload: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return map[string]any{}, fmt.Errorf("enrichment: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return map[string]any{}, fmt.Errorf("enrichment: http call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return map[string]any{}, fmt.Errorf("enrichment: non-2xx status %d", resp.StatusCode)
	}

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return map[string]any{}, fmt.Errorf("enrichment: decode response: %w", err)
	}

	return sanitise(raw), nil
}

// sanitise removes reserved claim names and any non-string-keyed entries.
func sanitise(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		lower := strings.ToLower(k)
		if _, reserved := reservedClaims[lower]; !reserved {
			out[k] = v
		}
	}
	return out
}

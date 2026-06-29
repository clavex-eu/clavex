package oid4w

// CallPreIssuanceHook calls the issuer-configured external endpoint synchronously
// before emitting a Verifiable Credential.
//
// The hook lets issuers verify prerequisites on-demand — e.g. "has this student
// completed the required course in our LMS?" — without pre-loading data into Clavex.
//
// Request: POST to webhookURL
//
//	Content-Type: application/json
//	X-Clavex-Signature: sha256=<hmac-hex>   (when secret != "")
//	X-Clavex-Event: credential.pre_issuance
//
//	{
//	  "event":   "credential.pre_issuance",
//	  "vct":     "https://university.eu/credentials/training/v1",
//	  "org_id":  "...",
//	  "user_id": "..." | null,
//	  "payload": {...}          // claims the issuer intends to embed
//	}
//
// Expected response (2xx):
//
//	{"allowed": true,  "claims": {"course_completed": true, "score": 95}}
//	{"allowed": false, "reason": "course not yet completed"}
//
// Behaviour:
//   - 10 s hard timeout; no retries (failure = deny).
//   - Non-2xx response = deny with "hook_error".
//   - On allow, returned claims are merged into the credential payload
//     (hook claims take precedence over existing payload keys).
//   - On deny, Credential() returns HTTP 400 with error "credential_denied".

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// PreIssuanceRequest is the body POSTed to the issuer's webhook.
type PreIssuanceRequest struct {
	Event   string                 `json:"event"`   // always "credential.pre_issuance"
	VCT     string                 `json:"vct"`
	OrgID   string                 `json:"org_id"`
	UserID  *string                `json:"user_id"` // nil when no user is bound to the offer
	Payload map[string]interface{} `json:"payload"`
}

// PreIssuanceResponse is the hook's expected JSON response.
type PreIssuanceResponse struct {
	Allowed bool                   `json:"allowed"`
	// Claims are merged into the credential payload when Allowed is true.
	// Hook-supplied values override the original payload.
	Claims  map[string]interface{} `json:"claims"`
	// Reason is a human-readable explanation when Allowed is false.
	Reason  string                 `json:"reason"`
}

var preIssuanceClient = &http.Client{Timeout: 10 * time.Second}

// CallPreIssuanceHook invokes the external verification endpoint and returns
// the merged payload and whether issuance is allowed.
//
// Parameters:
//   - ctx       — request context (deadline respected)
//   - webhookURL — issuer's HTTPS endpoint
//   - secret    — HMAC-SHA256 signing secret ("" = no signature)
//   - req       — body to POST
//
// Returns (mergedPayload, allowed, reason, error).
// On error the caller MUST deny issuance.
func CallPreIssuanceHook(
	ctx context.Context,
	webhookURL string,
	secret string,
	req PreIssuanceRequest,
) (map[string]interface{}, bool, string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, false, "", fmt.Errorf("pre-issuance hook: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return nil, false, "", fmt.Errorf("pre-issuance hook: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Clavex-Event", "credential.pre_issuance")
	if secret != "" {
		httpReq.Header.Set("X-Clavex-Signature", "sha256="+signHMAC(body, secret))
	}

	resp, err := preIssuanceClient.Do(httpReq)
	if err != nil {
		log.Warn().Err(err).Str("url", webhookURL).Msg("pre-issuance hook: delivery failed")
		return nil, false, "hook_unreachable", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Warn().
			Int("status", resp.StatusCode).
			Str("url", webhookURL).
			Msg("pre-issuance hook: non-2xx response")
		return nil, false, fmt.Sprintf("hook_error: HTTP %d", resp.StatusCode), nil
	}

	var hookResp PreIssuanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&hookResp); err != nil {
		return nil, false, "hook_invalid_response", fmt.Errorf("pre-issuance hook: decode response: %w", err)
	}

	if !hookResp.Allowed {
		reason := hookResp.Reason
		if reason == "" {
			reason = "denied by pre-issuance hook"
		}
		return nil, false, reason, nil
	}

	// Merge hook-supplied claims into the original payload.
	merged := make(map[string]interface{}, len(req.Payload)+len(hookResp.Claims))
	for k, v := range req.Payload {
		merged[k] = v
	}
	for k, v := range hookResp.Claims {
		merged[k] = v // hook claims take precedence
	}

	return merged, true, "", nil
}

// signHMAC returns the HMAC-SHA256 hex digest of body.
func signHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

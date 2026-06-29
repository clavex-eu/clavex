// Package actionsrunner implements the Actions V2 HTTP hook dispatcher.
//
// Actions V2 lets operators bind external HTTP endpoints (targets) to internal
// event types (executions). When an event fires:
//
//   - Synchronous events (user.pre_login, user.pre_token): Clavex POSTs the
//     event payload to the target, waits for a response, and uses that
//     response to modify behaviour (deny login, inject claims, etc.).
//
//   - Asynchronous events (user.created, user.updated, user.deleted): Clavex
//     fires a goroutine and does not wait for the response.
//
// # Request format
//
//	POST <target_url>
//	Content-Type: application/json
//	X-Clavex-Signature: sha256=<HMAC-SHA256 of body with signing_secret>
//	{
//	  "event": "user.pre_login",
//	  "occurred_at": "2026-05-15T10:00:00Z",
//	  "org_id": "...",
//	  "data": { ... event-specific payload ... }
//	}
//
// # Response format (sync events only)
//
//	{
//	  "action":      "continue" | "deny",
//	  "deny_reason": "optional human-readable message",
//	  "claims":      { "key": "value", ... }
//	}
package actionsrunner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	defaultTimeoutMs = 3000
	maxBodyBytes     = 64 * 1024
)

// actionResponse is the JSON shape returned by a target for sync events.
type actionResponse struct {
	Action     string         `json:"action"`      // "continue" | "deny"
	DenyReason string         `json:"deny_reason"`
	Claims     map[string]any `json:"claims"`
}

// actionPayload is the JSON body posted to the target.
type actionPayload struct {
	Event      string    `json:"event"`
	OccurredAt time.Time `json:"occurred_at"`
	OrgID      string    `json:"org_id"`
	Data       any       `json:"data"`
}

// Runner dispatches actions when events fire.
type Runner struct {
	repo   *repository.ActionsRepository
	client *http.Client
}

// New creates a Runner with a default HTTP client.
func New(repo *repository.ActionsRepository) *Runner {
	return &Runner{
		repo:   repo,
		client: &http.Client{Timeout: time.Duration(defaultTimeoutMs) * time.Millisecond},
	}
}

// RunSync fires all active executions for the given event synchronously and
// returns a merged result. The first "deny" response short-circuits.
// On any HTTP / timeout error the execution is skipped (fail-open).
func (r *Runner) RunSync(ctx context.Context, orgID uuid.UUID, eventType string, data map[string]any) (deny bool, denyReason string, claims map[string]any) {
	execs, err := r.repo.ListActiveByOrgAndEvent(ctx, orgID, eventType)
	if err != nil {
		log.Warn().Err(err).Str("event", eventType).Msg("actionsrunner: list executions failed")
		return
	}

	for _, ex := range execs {
		if !r.conditionMatches(ex, data) {
			continue
		}
		target, err := r.repo.GetTarget(ctx, orgID, ex.TargetID)
		if err != nil || target == nil || !target.IsActive {
			continue
		}
		resp := r.callTarget(ctx, target, eventType, orgID, data)
		if resp == nil {
			continue
		}
		if resp.Action == "deny" {
			return true, resp.DenyReason, nil
		}
		for k, v := range resp.Claims {
			if claims == nil {
				claims = map[string]any{}
			}
			claims[k] = v
		}
	}
	return
}

// RunAsync fires all active executions for the given event in background
// goroutines. Response bodies are discarded.
func (r *Runner) RunAsync(orgID uuid.UUID, eventType string, data map[string]any) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		execs, err := r.repo.ListActiveByOrgAndEvent(ctx, orgID, eventType)
		if err != nil {
			log.Warn().Err(err).Str("event", eventType).Msg("actionsrunner: async list failed")
			return
		}
		for _, ex := range execs {
			if !r.conditionMatches(ex, data) {
				continue
			}
			target, err := r.repo.GetTarget(ctx, orgID, ex.TargetID)
			if err != nil || target == nil || !target.IsActive {
				continue
			}
			r.callTarget(ctx, target, eventType, orgID, data)
		}
	}()
}

// MutationResult is the outcome of RunMutation.
type MutationResult struct {
	// Allowed is false when any execution responded with action="deny".
	Allowed    bool
	DenyReason string
	// MutatedData is the data map returned by the target when action="mutate".
	// Callers should merge / replace their original request data with this.
	// nil means no mutation was requested (all targets returned action="continue").
	MutatedData map[string]any
}

// RunMutation fires all active mutation-mode executions for the given event
// synchronously. The first "deny" response short-circuits. The last "mutate"
// response wins (mutations are applied sequentially).
//
// On any HTTP / timeout error the execution is skipped (fail-open — the
// original data is preserved).
func (r *Runner) RunMutation(ctx context.Context, orgID uuid.UUID, eventType string, data map[string]any) MutationResult {
	execs, err := r.repo.ListActiveByOrgAndEvent(ctx, orgID, eventType)
	if err != nil {
		log.Warn().Err(err).Str("event", eventType).Msg("actionsrunner: mutation list failed")
		return MutationResult{Allowed: true}
	}

	result := MutationResult{Allowed: true}
	for _, ex := range execs {
		if ex.Mode != "mutation" {
			continue // only fire mutation-mode executions here
		}
		if !r.conditionMatches(ex, data) {
			continue
		}
		target, err := r.repo.GetTarget(ctx, orgID, ex.TargetID)
		if err != nil || target == nil || !target.IsActive {
			continue
		}
		resp := r.callTarget(ctx, target, eventType, orgID, data)
		if resp == nil {
			continue // fail-open
		}
		switch resp.Action {
		case "deny":
			return MutationResult{Allowed: false, DenyReason: resp.DenyReason}
		case "mutate":
			// Use the returned claims/data map as the mutated payload.
			if resp.Claims != nil {
				result.MutatedData = resp.Claims
			}
		}
		// "continue" → keep existing data unchanged
	}
	return result
}

// callTarget builds and sends the HTTP POST to a single target and returns the
// parsed response (nil on error or for async calls where parsing is skipped).
// For sandbox targets the JS code is executed in-process instead.
func (r *Runner) callTarget(ctx context.Context, target *models.ActionTarget, eventType string, orgID uuid.UUID, data map[string]any) *actionResponse {
	if target.TargetType == "sandbox" {
		sctx := sandboxContextFromData(data)
		return runSandbox(ctx, target, eventType, orgID, data, sctx, r.orgEnvVars(ctx, orgID))
	}
	return r.callHTTPTarget(ctx, target, eventType, orgID, data)
}

// orgEnvVars returns the operator-configured env var allowlist for a given org.
// Currently reads from the target's own metadata; override this hook to load
// from a DB table or Vault in the future.
func (r *Runner) orgEnvVars(_ context.Context, _ uuid.UUID) SandboxEnv {
	return SandboxEnv{}
}

// sandboxContextFromData extracts structured context hints from the event data
// map so the sandbox can access user / client identifiers without parsing raw data.
func sandboxContextFromData(data map[string]any) SandboxContext {
	str := func(key string) string {
		if v, ok := data[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	strs := func(key string) []string {
		if v, ok := data[key]; ok {
			switch t := v.(type) {
			case []string:
				return t
			case []any:
				out := make([]string, 0, len(t))
				for _, item := range t {
					if s, ok := item.(string); ok {
						out = append(out, s)
					}
				}
				return out
			}
		}
		return nil
	}
	return SandboxContext{
		UserID:   str("user_id"),
		Email:    str("email"),
		ClientID: str("client_id"),
		Roles:    strs("roles"),
		Groups:   strs("groups"),
	}
}

// callHTTPTarget is the original HTTP POST implementation (factored out of callTarget).
func (r *Runner) callHTTPTarget(ctx context.Context, target *models.ActionTarget, eventType string, orgID uuid.UUID, data map[string]any) *actionResponse {
	payload := actionPayload{
		Event:      eventType,
		OccurredAt: time.Now().UTC(),
		OrgID:      orgID.String(),
		Data:       data,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	timeout := time.Duration(target.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Duration(defaultTimeoutMs) * time.Millisecond
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target.URL, bytes.NewReader(body))
	if err != nil {
		log.Warn().Err(err).Str("target", target.Name).Msg("actionsrunner: build request failed")
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	if target.SigningSecret != nil && *target.SigningSecret != "" {
		sig := hmacSHA256(body, *target.SigningSecret)
		req.Header.Set("X-Clavex-Signature", "sha256="+sig)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("target", target.Name).Str("event", eventType).Msg("actionsrunner: request failed")
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Warn().Int("status", resp.StatusCode).Str("target", target.Name).Msg("actionsrunner: non-2xx response")
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	var ar actionResponse
	if err := json.Unmarshal(respBody, &ar); err != nil {
		return nil
	}
	return &ar
}

// conditionMatches checks whether the execution's condition filter is satisfied
// by the event data. An empty condition always matches.
func (r *Runner) conditionMatches(ex *models.ActionExecution, data map[string]any) bool {
	if len(ex.Condition) == 0 || string(ex.Condition) == "{}" || string(ex.Condition) == "null" {
		return true
	}
	var cond map[string]any
	if err := json.Unmarshal(ex.Condition, &cond); err != nil || len(cond) == 0 {
		return true
	}
	for k, expected := range cond {
		actual, ok := data[k]
		if !ok {
			return false
		}
		if fmt.Sprintf("%v", actual) != fmt.Sprintf("%v", expected) {
			return false
		}
	}
	return true
}

func hmacSHA256(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

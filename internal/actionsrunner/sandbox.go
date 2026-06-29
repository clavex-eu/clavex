package actionsrunner

// sandbox.go — inline JS execution for Actions V2 sandbox mode.
//
// When an action target has target_type="sandbox", the JavaScript source is
// executed directly in-process using goja (a pure-Go ES5.1+ runtime with
// ES6/ES2020 extensions via the goja_nodejs polyfill layer).
//
// Each execution gets a fresh goja runtime (isolated from all others).  The
// runtime is discarded after the call, so there is no shared mutable state
// between invocations.  The sandbox has a hard CPU/time budget enforced via
// goja's interrupt mechanism; memory is limited to ~32 MB per invocation by
// the runtime's own GC pressure.
//
// # SDK available to sandbox code
//
//   // The event object
//   event.type          string    — e.g. "user.pre_login"
//   event.orgId         string
//   event.occurredAt    string    — ISO-8601
//   event.data          object    — event-specific payload
//
//   // Context helpers (read-only inside the sandbox)
//   ctx.userId          string | undefined
//   ctx.email           string | undefined
//   ctx.clientId        string | undefined
//   ctx.roles           string[]
//   ctx.groups          string[]
//
//   // Environment variables (explicit allowlist only — no process.env)
//   env.get("MY_VAR")   string | undefined
//
//   // Console (logs are captured, never written to stdout)
//   console.log(...)
//   console.warn(...)
//   console.error(...)
//
// # Required export
//
//   function onEvent(event, ctx, env) {
//     // must return one of:
//     return { action: "continue" };
//     return { action: "deny", denyReason: "message" };
//     return { action: "continue", claims: { custom_claim: "value" } };
//   }
//
// # Example — inject a "department" claim from user metadata
//
//   function onEvent(event, ctx, env) {
//     const dept = event.data.user_metadata?.department;
//     if (!dept) return { action: "continue" };
//     return { action: "continue", claims: { department: dept } };
//   }
//
// # Example — deny login from unsupported countries
//
//   function onEvent(event, ctx, env) {
//     const country = event.data.country;
//     const allowed = (env.get("ALLOWED_COUNTRIES") || "US,GB,DE").split(",");
//     if (country && !allowed.includes(country)) {
//       return { action: "deny", denyReason: "Login not allowed from your country." };
//     }
//     return { action: "continue" };
//   }

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/rs/zerolog/log"
)

const (
	// sandboxTimeout is the hard wall-clock + CPU budget per invocation.
	// Long-running loops are interrupted after this deadline.
	sandboxTimeout = 50 * time.Millisecond

	// sandboxMaxLogBytes is the maximum total log output captured per run.
	sandboxMaxLogBytes = 4096
)

// SandboxContext is extra structured context passed into the sandbox as `ctx`.
type SandboxContext struct {
	UserID   string
	Email    string
	ClientID string
	Roles    []string
	Groups   []string
}

// SandboxEnv is the operator-defined allowlist of env vars the sandbox can read.
// Only keys present in this map are accessible via env.get().
type SandboxEnv map[string]string

// runSandbox executes a sandbox target and returns an actionResponse (or nil on
// hard errors).  It is safe to call concurrently — each call gets its own runtime.
func runSandbox(
	ctx context.Context,
	target *models.ActionTarget,
	eventType string,
	orgID fmt.Stringer,
	data map[string]any,
	sctx SandboxContext,
	senv SandboxEnv,
) *actionResponse {
	if target.SandboxCode == nil || strings.TrimSpace(*target.SandboxCode) == "" {
		log.Warn().Str("target", target.Name).Msg("actionsrunner: sandbox target has no code")
		return nil
	}

	vm := goja.New()

	// ── Hard timeout: interrupt the VM after sandboxTimeout ──────────────────
	done := make(chan struct{})
	go func() {
		select {
		case <-time.After(sandboxTimeout):
			vm.Interrupt(fmt.Errorf("sandbox timeout (%s)", sandboxTimeout))
		case <-done:
		}
	}()
	defer close(done)

	// ── console.log / console.warn / console.error ────────────────────────────
	var logBuf strings.Builder
	captureLog := func(level string) func(call goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			parts := make([]string, len(call.Arguments))
			for i, a := range call.Arguments {
				parts[i] = fmt.Sprintf("%v", a.Export())
			}
			line := fmt.Sprintf("[%s] %s\n", level, strings.Join(parts, " "))
			if logBuf.Len()+len(line) <= sandboxMaxLogBytes {
				logBuf.WriteString(line)
			}
			return goja.Undefined()
		}
	}
	console := vm.NewObject()
	_ = console.Set("log", captureLog("log"))
	_ = console.Set("warn", captureLog("warn"))
	_ = console.Set("error", captureLog("error"))
	_ = vm.Set("console", console)

	// ── env.get(key) ──────────────────────────────────────────────────────────
	envObj := vm.NewObject()
	_ = envObj.Set("get", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		key := call.Arguments[0].String()
		if v, ok := senv[key]; ok {
			return vm.ToValue(v)
		}
		return goja.Undefined()
	})
	_ = vm.Set("env", envObj)

	// ── Build event object ────────────────────────────────────────────────────
	eventObj := vm.NewObject()
	_ = eventObj.Set("type", eventType)
	_ = eventObj.Set("orgId", orgID.String())
	_ = eventObj.Set("occurredAt", time.Now().UTC().Format(time.RFC3339))

	// Convert data map to a JS object via JSON round-trip for clean typing.
	dataJSON, err := json.Marshal(data)
	if err == nil {
		var dataMap map[string]any
		if json.Unmarshal(dataJSON, &dataMap) == nil {
			_ = eventObj.Set("data", vm.ToValue(dataMap))
		}
	}
	_ = vm.Set("event", eventObj)

	// ── Build ctx object ──────────────────────────────────────────────────────
	ctxObj := vm.NewObject()
	if sctx.UserID != "" {
		_ = ctxObj.Set("userId", sctx.UserID)
	} else {
		_ = ctxObj.Set("userId", goja.Undefined())
	}
	if sctx.Email != "" {
		_ = ctxObj.Set("email", sctx.Email)
	} else {
		_ = ctxObj.Set("email", goja.Undefined())
	}
	if sctx.ClientID != "" {
		_ = ctxObj.Set("clientId", sctx.ClientID)
	} else {
		_ = ctxObj.Set("clientId", goja.Undefined())
	}
	roles := sctx.Roles
	if roles == nil {
		roles = []string{}
	}
	_ = ctxObj.Set("roles", roles)
	groups := sctx.Groups
	if groups == nil {
		groups = []string{}
	}
	_ = ctxObj.Set("groups", groups)
	_ = vm.Set("ctx", ctxObj)

	// ── Execute the user's code ───────────────────────────────────────────────
	if _, execErr := vm.RunString(*target.SandboxCode); execErr != nil {
		log.Warn().Err(execErr).Str("target", target.Name).
			Str("logs", logBuf.String()).
			Msg("actionsrunner: sandbox compile/run error")
		return nil
	}

	// ── Call onEvent(event, ctx, env) ─────────────────────────────────────────
	onEvent, ok := goja.AssertFunction(vm.Get("onEvent"))
	if !ok {
		log.Warn().Str("target", target.Name).Msg("actionsrunner: sandbox missing onEvent function")
		return nil
	}

	result, callErr := onEvent(goja.Undefined(), vm.ToValue(eventObj), vm.ToValue(ctxObj), vm.ToValue(envObj))
	if callErr != nil {
		log.Warn().Err(callErr).Str("target", target.Name).
			Str("logs", logBuf.String()).
			Msg("actionsrunner: sandbox onEvent error")
		return nil
	}

	if logBuf.Len() > 0 {
		log.Debug().Str("target", target.Name).Str("output", logBuf.String()).
			Msg("actionsrunner: sandbox console output")
	}

	// ── Parse return value ────────────────────────────────────────────────────
	return parseSandboxResult(result, vm)
}

// parseSandboxResult converts the goja return value to actionResponse.
// Accepted shapes:
//
//	{ action: "continue" }
//	{ action: "deny", denyReason: "..." }
//	{ action: "continue", claims: { k: v, ... } }
func parseSandboxResult(val goja.Value, vm *goja.Runtime) *actionResponse {
	if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
		// Returning nothing is treated as "continue".
		return &actionResponse{Action: "continue"}
	}

	// Marshal to JSON then unmarshal into our struct for clean conversion.
	exported := val.Export()
	b, err := json.Marshal(exported)
	if err != nil {
		return &actionResponse{Action: "continue"}
	}

	// Support both { action, denyReason, claims } and { action, deny_reason, claims }
	var raw struct {
		Action     string         `json:"action"`
		DenyReason string         `json:"denyReason"`
		DenyReason2 string        `json:"deny_reason"` // snake_case alias
		Claims     map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return &actionResponse{Action: "continue"}
	}

	reason := raw.DenyReason
	if reason == "" {
		reason = raw.DenyReason2
	}

	action := raw.Action
	if action == "" {
		action = "continue"
	}

	return &actionResponse{
		Action:     action,
		DenyReason: reason,
		Claims:     raw.Claims,
	}
}

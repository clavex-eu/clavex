package main

// clavexctl org export / apply / diff / plan
//
// Implements a Terraform-style IaC workflow for Clavex org configuration.
//
//   clavexctl org export --org acme -o acme.yaml
//   clavexctl org diff   --org acme --file acme.yaml
//   clavexctl org plan   --org acme --file acme.yaml
//   clavexctl org apply  --org acme --file acme.yaml [--dry-run]

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// ── OrgSpec — the declarative schema written to / read from YAML ──────────────

// OrgSpec is the top-level document.  Fields map 1-to-1 with Clavex API
// resources so that export → edit → apply round-trips losslessly.
type OrgSpec struct {
	// Metadata (read-only on apply — used only to identify the target org)
	APIVersion string      `yaml:"apiVersion" json:"apiVersion"`
	Kind       string      `yaml:"kind"       json:"kind"`
	Org        OrgMeta     `yaml:"org"        json:"org"`
	Spec       OrgSpecBody `yaml:"spec"       json:"spec"`
}

type OrgMeta struct {
	Slug string `yaml:"slug" json:"slug"`
	ID   string `yaml:"id"   json:"id"`
	Name string `yaml:"name" json:"name"`
}

type OrgSpecBody struct {
	// ── Security ────────────────────────────────────────────────────────────
	PasswordPolicy *PasswordPolicySpec `yaml:"passwordPolicy,omitempty" json:"passwordPolicy,omitempty"`
	LockoutPolicy  *LockoutSpec        `yaml:"lockoutPolicy,omitempty"  json:"lockoutPolicy,omitempty"`
	RateLimits     *RateLimitsSpec     `yaml:"rateLimits,omitempty"     json:"rateLimits,omitempty"`
	EmailPolicy    *EmailPolicySpec    `yaml:"emailPolicy,omitempty"    json:"emailPolicy,omitempty"`

	// ── Feature flags ───────────────────────────────────────────────────────
	FeatureFlags []FeatureFlagSpec `yaml:"featureFlags,omitempty" json:"featureFlags,omitempty"`

	// ── Auth policies (IP/country/time rules) ────────────────────────────────
	AuthPolicies []AuthPolicySpec `yaml:"authPolicies,omitempty" json:"authPolicies,omitempty"`

	// ── OIDC Clients ────────────────────────────────────────────────────────
	Clients []ClientSpec `yaml:"clients,omitempty" json:"clients,omitempty"`

	// ── Roles ───────────────────────────────────────────────────────────────
	Roles []RoleSpec `yaml:"roles,omitempty" json:"roles,omitempty"`

	// ── Groups ──────────────────────────────────────────────────────────────
	Groups []GroupSpec `yaml:"groups,omitempty" json:"groups,omitempty"`

	// ── Webhooks ────────────────────────────────────────────────────────────
	Webhooks []WebhookSpec `yaml:"webhooks,omitempty" json:"webhooks,omitempty"`

	// ── Identity Providers (social / OIDC / SAML) ────────────────────────────
	IdentityProviders []IDPSpec `yaml:"identityProviders,omitempty" json:"identityProviders,omitempty"`
}

// ── Individual resource specs ─────────────────────────────────────────────────

type PasswordPolicySpec struct {
	MinLength        int  `yaml:"minLength"        json:"min_length"`
	RequireUppercase bool `yaml:"requireUppercase" json:"require_uppercase"`
	RequireLowercase bool `yaml:"requireLowercase" json:"require_lowercase"`
	RequireDigit     bool `yaml:"requireDigit"     json:"require_digit"`
	RequireSymbol    bool `yaml:"requireSymbol"    json:"require_symbol"`
	MaxAgeDays       int  `yaml:"maxAgeDays"       json:"max_age_days"`
}

type LockoutSpec struct {
	MaxAttempts     int `yaml:"maxAttempts"     json:"max_attempts"`
	WindowSeconds   int `yaml:"windowSeconds"   json:"window_seconds"`
	LockoutSeconds  int `yaml:"lockoutSeconds"  json:"lockout_seconds"`
}

type RateLimitsSpec struct {
	LoginPerMinute    int `yaml:"loginPerMinute"    json:"login_per_minute"`
	LoginPerHour      int `yaml:"loginPerHour"      json:"login_per_hour"`
	SignupPerMinute   int `yaml:"signupPerMinute"   json:"signup_per_minute"`
}

type EmailPolicySpec struct {
	Blocklist []string `yaml:"blocklist,omitempty" json:"email_blocklist,omitempty"`
	Allowlist []string `yaml:"allowlist,omitempty" json:"email_allowlist,omitempty"`
}

type FeatureFlagSpec struct {
	Key         string `yaml:"key"         json:"key"`
	Value       bool   `yaml:"value"       json:"value"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

type AuthPolicySpec struct {
	// Name is used as a stable key for reconciliation (matched by name).
	Name         string            `yaml:"name"                json:"name"`
	Enabled      bool              `yaml:"enabled"             json:"enabled"`
	Action       string            `yaml:"action"              json:"action"` // allow|deny|mfa
	Priority     int               `yaml:"priority"            json:"priority"`
	Conditions   map[string]any    `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	// _id is populated on export, ignored on apply (reconciled by Name).
	ID           string            `yaml:"_id,omitempty"       json:"id,omitempty"`
}

type ClientSpec struct {
	// ClientID is the stable key.  On apply, if a client with this ID already
	// exists it is updated (PATCH); otherwise it is created.
	ClientID                string   `yaml:"clientId"                         json:"client_id"`
	Name                    string   `yaml:"name"                             json:"name"`
	RedirectURIs            []string `yaml:"redirectUris"                     json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `yaml:"postLogoutRedirectUris,omitempty" json:"post_logout_redirect_uris,omitempty"`
	GrantTypes              []string `yaml:"grantTypes"                       json:"grant_types"`
	ResponseTypes           []string `yaml:"responseTypes,omitempty"          json:"response_types,omitempty"`
	Scopes                  []string `yaml:"scopes,omitempty"                 json:"scopes,omitempty"`
	IsPublic                bool     `yaml:"isPublic"                         json:"is_public"`
	IsActive                bool     `yaml:"isActive"                         json:"is_active"`
	TokenEndpointAuthMethod string   `yaml:"tokenEndpointAuthMethod,omitempty" json:"token_endpoint_auth_method,omitempty"`
	IDTokenSignedResponseAlg string  `yaml:"idTokenSignedResponseAlg,omitempty" json:"id_token_signed_response_alg,omitempty"`
}

type RoleSpec struct {
	// Name is the stable key.
	Name        string `yaml:"name"              json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

type GroupSpec struct {
	// Name is the stable key.
	Name  string   `yaml:"name"            json:"name"`
	Roles []string `yaml:"roles,omitempty" json:"roles,omitempty"` // role names
}

type WebhookSpec struct {
	// Name is the stable key.
	Name      string   `yaml:"name"               json:"name"`
	URL       string   `yaml:"url"                json:"url"`
	Events    []string `yaml:"events"             json:"events"`
	IsActive  bool     `yaml:"isActive"           json:"is_active"`
	SigningKey string  `yaml:"signingKey,omitempty" json:"signing_key,omitempty"`
}

type IDPSpec struct {
	// Name is the stable key.
	Name         string         `yaml:"name"                    json:"name"`
	Provider     string         `yaml:"provider"                json:"provider"`   // google, github, oidc, saml, …
	ClientID     string         `yaml:"clientId,omitempty"      json:"client_id,omitempty"`
	// ClientSecret intentionally omitted from export for security.
	// Use  --include-secrets  to export it (base64-encoded).
	Scopes       []string       `yaml:"scopes,omitempty"        json:"scopes,omitempty"`
	IsActive     bool           `yaml:"isActive"                json:"is_active"`
	Extra        map[string]any `yaml:"extra,omitempty"         json:"extra,omitempty"`
}

// ── orgIaC command tree ───────────────────────────────────────────────────────

func orgIaCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "org",
		Short: "Org-as-code: export, diff, plan and apply declarative configuration",
		Long: `Manage an entire Clavex organisation as a YAML file — think Terraform without
the provider. Every resource (clients, roles, webhooks, policies, …) is
represented declaratively; apply reconciles the live state to match the file.

Workflow:
  1. clavexctl org export --org acme -o acme.yaml   # snapshot current state
  2. Edit acme.yaml in your favourite editor / git
  3. clavexctl org plan  --org acme -f acme.yaml    # preview changes (dry-run)
  4. clavexctl org apply --org acme -f acme.yaml    # apply to the live org`,
		// org itself needs --server/--token but its children inherit PersistentPreRunE.
	}
	cmd.AddCommand(orgExportCmd(), orgDiffCmd(), orgPlanCmd(), orgApplyCmd())
	return cmd
}

// ── export ────────────────────────────────────────────────────────────────────

func orgExportCmd() *cobra.Command {
	var (
		orgSlug        string
		outFile        string
		outputFmt      string
		includeSecrets bool
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export org configuration to a YAML (or JSON) file",
		Example: `  clavexctl org export --org acme -o acme.yaml
  clavexctl org export --org acme --format json -o acme.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			spec, err := fetchOrgSpec(orgSlug, includeSecrets)
			if err != nil {
				return err
			}

			var out []byte
			switch outputFmt {
			case "json":
				out, err = json.MarshalIndent(spec, "", "  ")
			default:
				out, err = yaml.Marshal(spec)
			}
			if err != nil {
				return fmt.Errorf("serialising spec: %w", err)
			}

			if outFile == "" || outFile == "-" {
				fmt.Print(string(out))
				return nil
			}
			if err := os.WriteFile(outFile, out, 0600); err != nil {
				return fmt.Errorf("writing %s: %w", outFile, err)
			}
			fmt.Fprintf(os.Stderr, "✓ Exported org %q to %s\n", orgSlug, outFile)
			return nil
		},
	}
	cmd.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&outputFmt, "format", "yaml", "Output format: yaml|json")
	cmd.Flags().BoolVar(&includeSecrets, "include-secrets", false, "Include client secrets (handle with care)")
	return cmd
}

// ── diff ──────────────────────────────────────────────────────────────────────

func orgDiffCmd() *cobra.Command {
	var (
		orgSlug string
		file    string
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show a human-readable diff between file and live state",
		Example: `  clavexctl org diff --org acme -f acme.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" || file == "" {
				return fmt.Errorf("--org and --file are required")
			}
			desired, err := loadOrgSpec(file)
			if err != nil {
				return err
			}
			live, err := fetchOrgSpec(orgSlug, false)
			if err != nil {
				return err
			}
			changes := computeChanges(live, desired)
			if len(changes) == 0 {
				fmt.Println("No differences — live state matches the file.")
				return nil
			}
			for _, c := range changes {
				fmt.Println(c.String())
			}
			fmt.Fprintf(os.Stderr, "\n%d change(s) detected.\n", len(changes))
			return nil
		},
	}
	cmd.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to org spec YAML/JSON (required)")
	return cmd
}

// ── plan ──────────────────────────────────────────────────────────────────────

func orgPlanCmd() *cobra.Command {
	var (
		orgSlug string
		file    string
	)
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Preview changes that 'apply' would make (dry-run)",
		Example: `  clavexctl org plan --org acme -f acme.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" || file == "" {
				return fmt.Errorf("--org and --file are required")
			}
			desired, err := loadOrgSpec(file)
			if err != nil {
				return err
			}
			live, err := fetchOrgSpec(orgSlug, false)
			if err != nil {
				return err
			}
			changes := computeChanges(live, desired)
			if len(changes) == 0 {
				fmt.Println("No changes. Org is already in the desired state.")
				return nil
			}
			fmt.Printf("Plan: %d change(s) to apply to org %q:\n\n", len(changes), orgSlug)
			for _, c := range changes {
				fmt.Println(c.PlanLine())
			}
			fmt.Println("\nRun 'clavexctl org apply' to execute these changes.")
			return nil
		},
	}
	cmd.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to org spec YAML/JSON (required)")
	return cmd
}

// ── apply ─────────────────────────────────────────────────────────────────────

func orgApplyCmd() *cobra.Command {
	var (
		orgSlug string
		file    string
		dryRun  bool
		force   bool
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a declarative org spec to the live environment",
		Long: `Apply reconciles the live Clavex org to match the desired state described
in the YAML/JSON file. Resources that exist in the file but not in the org are
created; resources that exist in both are updated if they differ; resources in
the org but not in the file are left untouched (no implicit deletes — use
--prune to remove orphans).

Safe by default: always shows a plan and asks for confirmation unless --auto-approve is set.`,
		Example: `  clavexctl org apply --org acme -f acme.yaml
  clavexctl org apply --org acme -f acme.yaml --dry-run
  clavexctl org apply --org acme -f acme.yaml --auto-approve`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" || file == "" {
				return fmt.Errorf("--org and --file are required")
			}
			desired, err := loadOrgSpec(file)
			if err != nil {
				return err
			}
			live, err := fetchOrgSpec(orgSlug, false)
			if err != nil {
				return err
			}
			orgID := live.Org.ID

			changes := computeChanges(live, desired)
			if len(changes) == 0 {
				fmt.Println("Nothing to do — org is already in the desired state.")
				return nil
			}

			fmt.Printf("Plan: %d change(s) to apply to org %q (%s):\n\n", len(changes), orgSlug, orgID)
			for _, c := range changes {
				fmt.Println(c.PlanLine())
			}

			if dryRun {
				fmt.Println("\n[dry-run] No changes applied.")
				return nil
			}
			if !force {
				fmt.Print("\nApply these changes? [y/N] ")
				var answer string
				fmt.Scanln(&answer) //nolint:errcheck
				if !strings.EqualFold(strings.TrimSpace(answer), "y") {
					fmt.Println("Aborted.")
					return nil
				}
			}

			applied, failed := 0, 0
			for _, c := range changes {
				if err := c.Apply(orgID); err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", c.Description(), err)
					failed++
				} else {
					fmt.Printf("  ✓ %s\n", c.Description())
					applied++
				}
			}

			fmt.Printf("\nApply complete. %d applied, %d failed.\n", applied, failed)
			if failed > 0 {
				return fmt.Errorf("%d change(s) failed", failed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to org spec YAML/JSON (required)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show changes without applying them")
	cmd.Flags().BoolVar(&force, "auto-approve", false, "Skip confirmation prompt")
	return cmd
}

// ── Change type ───────────────────────────────────────────────────────────────

type changeKind string

const (
	changeCreate changeKind = "create"
	changeUpdate changeKind = "update"
)

type Change struct {
	kind     changeKind
	resource string // e.g. "client", "role", "webhook"
	key      string // e.g. client_id or name
	payload  any    // body to POST or PATCH
	apiPath  func(orgID string) string
	method   string // POST or PATCH
}

func (c *Change) Description() string {
	return fmt.Sprintf("%s %s %q", c.kind, c.resource, c.key)
}

func (c *Change) PlanLine() string {
	symbol := "+"
	if c.kind == changeUpdate {
		symbol = "~"
	}
	return fmt.Sprintf("  %s %s %s", symbol, c.resource, c.key)
}

func (c *Change) String() string {
	return c.PlanLine()
}

func (c *Change) Apply(orgID string) error {
	path := c.apiPath(orgID)
	var (
		body []byte
		err  error
	)
	body, err = json.Marshal(c.payload)
	if err != nil {
		return err
	}
	switch c.method {
	case "POST":
		_, err = apiPost(path, c.payload)
	case "PATCH":
		_, err = apiPatch(path, c.payload)
	case "PUT":
		_, err = apiPut(path, c.payload)
	default:
		_, err = apiPost(path, c.payload)
	}
	_ = body
	return err
}

// ── fetchOrgSpec — read live state from the API ───────────────────────────────

func fetchOrgSpec(orgSlug string, includeSecrets bool) (*OrgSpec, error) {
	orgID, err := resolveOrgID(orgSlug)
	if err != nil {
		return nil, err
	}

	spec := &OrgSpec{
		APIVersion: "clavex.io/v1",
		Kind:       "OrgSpec",
		Org:        OrgMeta{Slug: orgSlug, ID: orgID},
	}

	prefix := fmt.Sprintf("/api/v1/organizations/%s", orgID)

	// ── Password policy ────────────────────────────────────────────────────
	if pp, err := fetchJSON[PasswordPolicySpec](prefix + "/password-policy"); err == nil {
		spec.Spec.PasswordPolicy = &pp
	}

	// ── Lockout policy ─────────────────────────────────────────────────────
	if lp, err := fetchJSON[LockoutSpec](prefix + "/lockout"); err == nil {
		spec.Spec.LockoutPolicy = &lp
	}

	// ── Rate limits ────────────────────────────────────────────────────────
	if rl, err := fetchJSON[RateLimitsSpec](prefix + "/rate-limits"); err == nil {
		spec.Spec.RateLimits = &rl
	}

	// ── Email policy ───────────────────────────────────────────────────────
	if ep, err := fetchJSON[EmailPolicySpec](prefix + "/email-policy"); err == nil {
		spec.Spec.EmailPolicy = &ep
	}

	// ── Feature flags ──────────────────────────────────────────────────────
	if flags, err := fetchList[FeatureFlagSpec](prefix + "/feature-flags"); err == nil {
		spec.Spec.FeatureFlags = flags
	}

	// ── Auth policies ──────────────────────────────────────────────────────
	if policies, err := fetchList[AuthPolicySpec](prefix + "/auth-policies"); err == nil {
		spec.Spec.AuthPolicies = policies
	}

	// ── OIDC Clients ───────────────────────────────────────────────────────
	if clients, err := fetchList[ClientSpec](prefix + "/clients"); err == nil {
		spec.Spec.Clients = clients
	}

	// ── Roles ──────────────────────────────────────────────────────────────
	if roles, err := fetchList[RoleSpec](prefix + "/roles"); err == nil {
		spec.Spec.Roles = roles
	}

	// ── Groups ─────────────────────────────────────────────────────────────
	if groups, err := fetchList[GroupSpec](prefix + "/groups"); err == nil {
		spec.Spec.Groups = groups
	}

	// ── Webhooks ───────────────────────────────────────────────────────────
	if webhooks, err := fetchList[WebhookSpec](prefix + "/webhooks"); err == nil {
		spec.Spec.Webhooks = webhooks
	}

	// ── Identity providers ─────────────────────────────────────────────────
	if idps, err := fetchList[IDPSpec](prefix + "/identity-providers"); err == nil {
		if !includeSecrets {
			for i := range idps {
				idps[i].Extra = redactSecrets(idps[i].Extra)
			}
		}
		spec.Spec.IdentityProviders = idps
	}

	return spec, nil
}

// redactSecrets removes known secret keys from an extra-fields map.
func redactSecrets(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	secretKeys := map[string]bool{
		"client_secret": true, "secret": true, "private_key": true,
		"password": true, "token": true, "api_key": true,
	}
	for k, v := range m {
		if secretKeys[strings.ToLower(k)] {
			out[k] = "<redacted>"
		} else {
			out[k] = v
		}
	}
	return out
}

// ── computeChanges ────────────────────────────────────────────────────────────

func computeChanges(live, desired *OrgSpec) []Change {
	var changes []Change
	orgID := live.Org.ID
	prefix := fmt.Sprintf("/api/v1/organizations/%s", orgID)

	// ── Password policy ────────────────────────────────────────────────────
	if desired.Spec.PasswordPolicy != nil {
		if !reflect.DeepEqual(live.Spec.PasswordPolicy, desired.Spec.PasswordPolicy) {
			changes = append(changes, Change{
				kind: changeUpdate, resource: "passwordPolicy", key: "singleton",
				payload: desired.Spec.PasswordPolicy,
				method:  "PUT",
				apiPath: func(id string) string { return prefix + "/password-policy" },
			})
		}
	}

	// ── Lockout policy ─────────────────────────────────────────────────────
	if desired.Spec.LockoutPolicy != nil {
		if !reflect.DeepEqual(live.Spec.LockoutPolicy, desired.Spec.LockoutPolicy) {
			changes = append(changes, Change{
				kind: changeUpdate, resource: "lockoutPolicy", key: "singleton",
				payload: desired.Spec.LockoutPolicy,
				method:  "PUT",
				apiPath: func(id string) string { return prefix + "/lockout" },
			})
		}
	}

	// ── Rate limits ────────────────────────────────────────────────────────
	if desired.Spec.RateLimits != nil {
		if !reflect.DeepEqual(live.Spec.RateLimits, desired.Spec.RateLimits) {
			changes = append(changes, Change{
				kind: changeUpdate, resource: "rateLimits", key: "singleton",
				payload: desired.Spec.RateLimits,
				method:  "PUT",
				apiPath: func(id string) string { return prefix + "/rate-limits" },
			})
		}
	}

	// ── Email policy ───────────────────────────────────────────────────────
	if desired.Spec.EmailPolicy != nil {
		if !reflect.DeepEqual(live.Spec.EmailPolicy, desired.Spec.EmailPolicy) {
			changes = append(changes, Change{
				kind: changeUpdate, resource: "emailPolicy", key: "singleton",
				payload: desired.Spec.EmailPolicy,
				method:  "PUT",
				apiPath: func(id string) string { return prefix + "/email-policy" },
			})
		}
	}

	// ── Feature flags ──────────────────────────────────────────────────────
	liveFlags := indexBy(live.Spec.FeatureFlags, func(f FeatureFlagSpec) string { return f.Key })
	for _, df := range desired.Spec.FeatureFlags {
		df := df
		if lf, ok := liveFlags[df.Key]; !ok {
			changes = append(changes, Change{
				kind: changeCreate, resource: "featureFlag", key: df.Key,
				payload: df, method: "POST",
				apiPath: func(id string) string { return prefix + "/feature-flags" },
			})
		} else if !reflect.DeepEqual(lf, df) {
			changes = append(changes, Change{
				kind: changeUpdate, resource: "featureFlag", key: df.Key,
				payload: df, method: "POST",
				apiPath: func(id string) string { return prefix + "/feature-flags" },
			})
		}
	}

	// ── Auth policies ──────────────────────────────────────────────────────
	livePolicies := indexBy(live.Spec.AuthPolicies, func(p AuthPolicySpec) string { return p.Name })
	for _, dp := range desired.Spec.AuthPolicies {
		dp := dp
		if lp, ok := livePolicies[dp.Name]; !ok {
			changes = append(changes, Change{
				kind: changeCreate, resource: "authPolicy", key: dp.Name,
				payload: dp, method: "POST",
				apiPath: func(id string) string { return prefix + "/auth-policies" },
			})
		} else if !reflect.DeepEqual(lp, dp) {
			ruleID := lp.ID
			changes = append(changes, Change{
				kind: changeUpdate, resource: "authPolicy", key: dp.Name,
				payload: dp, method: "PUT",
				apiPath: func(id string) string {
					return fmt.Sprintf("%s/auth-policies/%s", prefix, ruleID)
				},
			})
		}
	}

	// ── OIDC Clients ───────────────────────────────────────────────────────
	liveClients := indexBy(live.Spec.Clients, func(c ClientSpec) string { return c.ClientID })
	for _, dc := range desired.Spec.Clients {
		dc := dc
		if lc, ok := liveClients[dc.ClientID]; !ok {
			changes = append(changes, Change{
				kind: changeCreate, resource: "client", key: dc.ClientID,
				payload: dc, method: "POST",
				apiPath: func(id string) string { return prefix + "/clients" },
			})
		} else if !reflect.DeepEqual(lc, dc) {
			cid := dc.ClientID
			changes = append(changes, Change{
				kind: changeUpdate, resource: "client", key: dc.ClientID,
				payload: dc, method: "PATCH",
				apiPath: func(id string) string {
					return fmt.Sprintf("%s/clients/%s", prefix, cid)
				},
			})
		}
	}

	// ── Roles ──────────────────────────────────────────────────────────────
	liveRoles := indexBy(live.Spec.Roles, func(r RoleSpec) string { return r.Name })
	for _, dr := range desired.Spec.Roles {
		dr := dr
		if _, ok := liveRoles[dr.Name]; !ok {
			changes = append(changes, Change{
				kind: changeCreate, resource: "role", key: dr.Name,
				payload: dr, method: "POST",
				apiPath: func(id string) string { return prefix + "/roles" },
			})
		}
		// Roles have no updateable fields beyond name so skip update.
	}

	// ── Groups ─────────────────────────────────────────────────────────────
	liveGroups := indexBy(live.Spec.Groups, func(g GroupSpec) string { return g.Name })
	for _, dg := range desired.Spec.Groups {
		dg := dg
		if _, ok := liveGroups[dg.Name]; !ok {
			changes = append(changes, Change{
				kind: changeCreate, resource: "group", key: dg.Name,
				payload: dg, method: "POST",
				apiPath: func(id string) string { return prefix + "/groups" },
			})
		}
	}

	// ── Webhooks ───────────────────────────────────────────────────────────
	liveWebhooks := indexBy(live.Spec.Webhooks, func(w WebhookSpec) string { return w.Name })
	for _, dw := range desired.Spec.Webhooks {
		dw := dw
		if lw, ok := liveWebhooks[dw.Name]; !ok {
			changes = append(changes, Change{
				kind: changeCreate, resource: "webhook", key: dw.Name,
				payload: dw, method: "POST",
				apiPath: func(id string) string { return prefix + "/webhooks" },
			})
		} else if !reflect.DeepEqual(lw, dw) {
			wname := dw.Name
			_ = wname
			changes = append(changes, Change{
				kind: changeUpdate, resource: "webhook", key: dw.Name,
				payload: dw, method: "POST", // webhooks use upsert-by-name semantics
				apiPath: func(id string) string { return prefix + "/webhooks" },
			})
		}
	}

	// ── Identity Providers ─────────────────────────────────────────────────
	liveIDPs := indexBy(live.Spec.IdentityProviders, func(p IDPSpec) string { return p.Name })
	for _, di := range desired.Spec.IdentityProviders {
		di := di
		if _, ok := liveIDPs[di.Name]; !ok {
			changes = append(changes, Change{
				kind: changeCreate, resource: "identityProvider", key: di.Name,
				payload: di, method: "POST",
				apiPath: func(id string) string { return prefix + "/identity-providers" },
			})
		}
		// IDP updates are intentionally not auto-applied (contain credentials).
	}

	return changes
}

// ── helpers ───────────────────────────────────────────────────────────────────

// loadOrgSpec reads and parses an OrgSpec from a YAML or JSON file.
func loadOrgSpec(path string) (*OrgSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var spec OrgSpec
	// Try YAML first (superset of JSON).
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if spec.APIVersion == "" {
		spec.APIVersion = "clavex.io/v1"
	}
	return &spec, nil
}

// fetchJSON fetches a single resource from the API and decodes it into T.
func fetchJSON[T any](path string) (T, error) {
	var zero T
	body, err := apiGet(path)
	if err != nil {
		return zero, err
	}
	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return zero, err
	}
	return result, nil
}

// fetchList fetches a paginated or plain list from path, returning []T.
// Handles both {"items":[…]} envelopes and bare arrays.
func fetchList[T any](path string) ([]T, error) {
	body, err := apiGet(path)
	if err != nil {
		return nil, err
	}
	// Try bare array first.
	var items []T
	if err := json.Unmarshal(body, &items); err == nil {
		return items, nil
	}
	// Try {"items":[…]} envelope.
	var envelope struct {
		Items []T `json:"items"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parsing list from %s: %w", path, err)
	}
	return envelope.Items, nil
}

// indexBy builds a map keyed by the result of keyFn.
func indexBy[T any](items []T, keyFn func(T) string) map[string]T {
	m := make(map[string]T, len(items))
	for _, item := range items {
		m[keyFn(item)] = item
	}
	return m
}

// apiPatch sends a PATCH request.
func apiPatch(path string, payload any) ([]byte, error) {
	return apiWithMethod("PATCH", flagServer+path, payload)
}

// apiPut sends a PUT request.
func apiPut(path string, payload any) ([]byte, error) {
	return apiWithMethod("PUT", flagServer+path, payload)
}

func apiWithMethod(method, path string, payload any) ([]byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(context.Background(), method, path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+flagToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return doRequest(req)
}

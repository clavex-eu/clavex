// speccheck validates that every route registered in server.go has a
// corresponding path entry in internal/handler/spec/openapi.json.
//
// Usage:
//
//	go run ./tools/speccheck
//	go run ./tools/speccheck -spec internal/handler/spec/openapi.json -server internal/server/server.go
//	go run ./tools/speccheck -update    # scaffold missing stubs into the spec
//	go run ./tools/speccheck -enrich    # fill placeholder (TODO) summaries/tags in-place
//
// Summaries and tags are derived from the Echo handler reference on each
// route line (e.g. `smtpH.Get` → tag "SMTP", summary "Get"), so both the
// scaffold (-update) and the enrich pass produce human-meaningful docs
// instead of "TODO" placeholders.
//
// Exit codes:
//
//	0 — all routes are documented (or stubs were written successfully)
//	1 — one or more routes are missing from the spec (prints diff)
//	2 — usage / IO error
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// routeRE matches Echo route registrations of the form:
//
//	e.GET("/path", health.Liveness)
//	tenant.POST("/path", oidcH.Token, middleware…)
//	orgScoped.DELETE("/path/:id", usersH.Delete)
//
// Group: 1=method, 2=path, 3=handler reference (may be empty for func literals).
var routeRE = regexp.MustCompile(`\b(?:e|tenant|admin|orgScoped|adminUsers|me|acct|loginGroup|scimGroup|[a-zA-Z]+)\.(GET|POST|PUT|PATCH|DELETE)\("(/[^"]*)"(?:\s*,\s*([a-zA-Z_][a-zA-Z0-9_.]*))?`)

// paramRE normalises Echo :param placeholders to OpenAPI {param} style.
var paramRE = regexp.MustCompile(`:([a-zA-Z_][a-zA-Z0-9_]*)`)

// wildcardRE drops Echo wildcard suffixes (/*).
var wildcardRE = regexp.MustCompile(`/\*$`)

func main() {
	specPath := flag.String("spec", "internal/handler/spec/openapi.json", "path to OpenAPI spec JSON")
	serverPath := flag.String("server", "internal/server/server.go", "path to server.go")
	update := flag.Bool("update", false, "scaffold stubs for missing routes into the spec (idempotent)")
	enrich := flag.Bool("enrich", false, "replace placeholder (TODO) summaries/tags with derived values in-place")
	flag.Parse()

	// ── Parse routes from server.go ──────────────────────────────────────────
	routes, err := parseRoutes(*serverPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "speccheck: read %s: %v\n", *serverPath, err)
		os.Exit(2)
	}
	byKey := map[string]route{}
	for _, r := range routes {
		byKey[r.method+" "+r.path] = r
	}

	// ── Load OpenAPI spec ─────────────────────────────────────────────────────
	spec, err := loadSpec(*specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "speccheck: read %s: %v\n", *specPath, err)
		os.Exit(2)
	}

	if spec["paths"] == nil {
		spec["paths"] = map[string]interface{}{}
	}
	specPaths := spec["paths"].(map[string]interface{})

	// ── Enrich: rewrite placeholder summaries/tags in-place ────────────────────
	if *enrich {
		enriched := enrichSpec(specPaths, byKey, componentParamNames(spec))
		if err := writeSpec(*specPath, spec); err != nil {
			fmt.Fprintf(os.Stderr, "speccheck: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("speccheck: enriched %d placeholder operation(s) in %s.\n", enriched, *specPath)
		return
	}

	// ── Diff ──────────────────────────────────────────────────────────────────
	type routeKey struct{ method, path string }
	inSpec := map[routeKey]bool{}
	for path, v := range specPaths {
		if methods, ok := v.(map[string]interface{}); ok {
			for method := range methods {
				inSpec[routeKey{strings.ToUpper(method), path}] = true
			}
		}
	}

	type missingRoute struct{ method, path string }
	var missing []missingRoute
	for _, r := range routes {
		if !inSpec[routeKey{r.method, r.path}] {
			missing = append(missing, missingRoute{r.method, r.path})
		}
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].path != missing[j].path {
			return missing[i].path < missing[j].path
		}
		return missing[i].method < missing[j].method
	})

	if len(missing) == 0 {
		fmt.Printf("speccheck: OK — %d routes, all documented in %s\n", len(routes), *specPath)
		return
	}

	if !*update {
		fmt.Fprintf(os.Stderr, "speccheck: %d route(s) not documented in %s:\n", len(missing), *specPath)
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "  %-7s %s\n", m.method, m.path)
		}
		fmt.Fprintln(os.Stderr, "\nAdd these paths to internal/handler/spec/openapi.json or run 'make openapi-update' to scaffold stubs.")
		os.Exit(1)
	}

	// ── Scaffold stubs ────────────────────────────────────────────────────────
	added := 0
	for _, m := range missing {
		pathItem, ok := specPaths[m.path].(map[string]interface{})
		if !ok {
			pathItem = map[string]interface{}{}
			specPaths[m.path] = pathItem
		}
		method := strings.ToLower(m.method)
		if _, exists := pathItem[method]; !exists {
			r := byKey[m.method+" "+m.path]
			pathItem[method] = map[string]interface{}{
				"summary": deriveSummary(r),
				"tags":    []string{deriveTag(r)},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{"description": "OK"},
				},
			}
			added++
		}
	}

	if err := writeSpec(*specPath, spec); err != nil {
		fmt.Fprintf(os.Stderr, "speccheck: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("speccheck: scaffolded %d stub(s) into %s — review summaries and add request/response schemas.\n", added, *specPath)
}

// enrichSpec replaces placeholder ("TODO") summaries and tags with values
// derived from the matching route's handler. Operations that already carry a
// real summary are left untouched. Returns the number of operations changed.
// componentParamNames maps a #/components/parameters/<Key> reference to the
// path-parameter name it declares (e.g. "OrgID" → "org_id"), so the path-param
// injector treats $ref params as already declared.
func componentParamNames(spec map[string]interface{}) map[string]string {
	out := map[string]string{}
	comps, ok := spec["components"].(map[string]interface{})
	if !ok {
		return out
	}
	params, ok := comps["parameters"].(map[string]interface{})
	if !ok {
		return out
	}
	for key, v := range params {
		pm, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if in, _ := pm["in"].(string); in != "path" {
			continue
		}
		if name, _ := pm["name"].(string); name != "" {
			out[key] = name
		}
	}
	return out
}

func enrichSpec(specPaths map[string]interface{}, byKey map[string]route, paramRefs map[string]string) int {
	changed := 0
	for path, v := range specPaths {
		methods, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		for method, opv := range methods {
			op, ok := opv.(map[string]interface{})
			if !ok {
				continue
			}
			r, hasRoute := byKey[strings.ToUpper(method)+" "+path]
			if !hasRoute {
				// Stale spec entry with no matching route — derive from path only.
				r = route{method: strings.ToUpper(method), path: path}
			}
			touched := false
			if isPlaceholderSummary(op["summary"]) {
				op["summary"] = deriveSummary(r)
				touched = true
			}
			if isPlaceholderTags(op["tags"]) {
				op["tags"] = []string{deriveTag(r)}
				touched = true
			}
			// Every {param} in the path template must be declared as a path
			// parameter or the spec is invalid (OpenAPI 3.1). The scaffolder
			// never added these; inject any that are missing.
			if injectPathParams(op, path, paramRefs) {
				touched = true
			}
			if touched {
				changed++
			}
		}
	}
	return changed
}

// pathParamRE extracts {name} tokens from an OpenAPI path template.
var pathParamRE = regexp.MustCompile(`\{([^}]+)\}`)

// injectPathParams ensures every {param} in path is declared as a path
// parameter on op. Returns true if any were added. Idempotent.
func injectPathParams(op map[string]interface{}, path string, paramRefs map[string]string) bool {
	matches := pathParamRE.FindAllStringSubmatch(path, -1)
	if len(matches) == 0 {
		return false
	}
	var params []interface{}
	if existing, ok := op["parameters"].([]interface{}); ok {
		params = existing
	}
	declared := map[string]bool{}
	for _, p := range params {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		// Inline path param.
		if in, _ := pm["in"].(string); in == "path" {
			if name, _ := pm["name"].(string); name != "" {
				declared[name] = true
			}
		}
		// $ref to a reusable component parameter (resolve to its name).
		if ref, _ := pm["$ref"].(string); ref != "" {
			key := ref[strings.LastIndex(ref, "/")+1:]
			if name, ok := paramRefs[key]; ok {
				declared[name] = true
			}
		}
	}
	added := false
	for _, m := range matches {
		name := m[1]
		if declared[name] {
			continue
		}
		params = append(params, map[string]interface{}{
			"in":       "path",
			"name":     name,
			"required": true,
			"schema":   map[string]interface{}{"type": "string"},
		})
		declared[name] = true
		added = true
	}
	if added {
		op["parameters"] = params
	}
	return added
}

func isPlaceholderSummary(v interface{}) bool {
	s, ok := v.(string)
	return !ok || s == "" || s == "TODO"
}

func isPlaceholderTags(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case []interface{}:
		if len(t) == 0 {
			return true
		}
		if len(t) == 1 {
			s, _ := t[0].(string)
			return s == "TODO" || s == ""
		}
	}
	return false
}

type route struct {
	method  string
	path    string
	handler string // Echo handler reference, e.g. "smtpH.Get" (may be empty)
}

func parseRoutes(serverPath string) ([]route, error) {
	f, err := os.Open(serverPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var routes []route
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := routeRE.FindStringSubmatch(line); m != nil {
			method := strings.ToUpper(m[1])
			path := normalise(m[2])
			key := method + " " + path
			if !seen[key] {
				seen[key] = true
				routes = append(routes, route{method: method, path: path, handler: m[3]})
			}
		}
	}
	return routes, scanner.Err()
}

// normalise converts Echo path syntax to OpenAPI path syntax.
func normalise(p string) string {
	p = paramRE.ReplaceAllString(p, "{$1}")
	p = wildcardRE.ReplaceAllString(p, "")
	return p
}

func loadSpec(specPath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return nil, err
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, err
	}
	return spec, nil
}

func writeSpec(specPath string, spec map[string]interface{}) error {
	out, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(specPath, out, 0644); err != nil {
		return fmt.Errorf("write %s: %w", specPath, err)
	}
	return nil
}

// ── Summary / tag derivation ───────────────────────────────────────────────────

// acronyms maps lowercase tokens to their canonical display form so derived
// text reads "Rotate PQC signing key" rather than "Rotate p q c signing key".
var acronyms = map[string]string{
	"oidc": "OIDC", "oid4vci": "OID4VCI", "oid4vp": "OID4VP", "ssf": "SSF",
	"spid": "SPID", "jwks": "JWKS", "smtp": "SMTP", "sms": "SMS", "saml": "SAML",
	"scim": "SCIM", "ldap": "LDAP", "pqc": "PQC", "mfa": "MFA", "otp": "OTP",
	"fga": "FGA", "gdpr": "GDPR", "ueba": "UEBA", "caep": "CAEP", "eidas": "eIDAS",
	"cie": "CIE", "digid": "DigiD", "bundid": "BundID", "idp": "IdP", "api": "API",
	"mdoc": "mdoc", "vci": "VCI", "vp": "VP", "ciba": "CIBA", "sso": "SSO",
	"acs": "ACS", "dcr": "DCR", "par": "PAR", "mds": "MDS", "mds3": "MDS3",
	"id": "ID", "url": "URL", "ip": "IP", "ca": "CA", "ssh": "SSH", "pam": "PAM",
	"wsfed": "WS-Fed", "dsar": "DSAR", "nis2": "NIS2", "fapi": "FAPI", "jwt": "JWT",
	"qr": "QR", "kek": "KEK", "rp": "RP", "sp": "SP", "ai": "AI",
}

// recvTagOverrides gives nicer tag names for handler receivers whose stripped
// form would otherwise be terse (e.g. "fed" → "Federation").
var recvTagOverrides = map[string]string{
	"fed": "Federation", "fedTA": "Federation Trust Anchor",
	"orgs": "Organizations", "org": "Organizations",
	"users": "Users", "auth": "Authentication", "acct": "Account",
	"clientBranding": "Branding", "caepReceiver": "CAEP",
}

// deriveSummary builds a human-readable summary from the route handler's method
// name (e.g. "smtpH.Get" → "Get", "oidcH.RotatePQCSigningKey" → "Rotate PQC
// signing key"). Falls back to "METHOD path" when no handler name is available.
func deriveSummary(r route) string {
	method := handlerMethod(r.handler)
	if method == "" {
		return fmt.Sprintf("%s %s", r.method, r.path)
	}
	words := splitCamel(method)
	if len(words) == 0 {
		return fmt.Sprintf("%s %s", r.method, r.path)
	}
	parts := make([]string, len(words))
	for i, w := range words {
		if disp, ok := acronyms[strings.ToLower(w)]; ok {
			parts[i] = disp
			continue
		}
		if i == 0 {
			parts[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
		} else {
			parts[i] = strings.ToLower(w)
		}
	}
	return strings.Join(parts, " ")
}

// deriveTag groups the operation. Prefers the handler receiver (e.g. "smtpH" →
// "SMTP"); falls back to the first meaningful path segment.
func deriveTag(r route) string {
	if recv := handlerReceiver(r.handler); recv != "" {
		if t := tagFromReceiver(recv); t != "" {
			return t
		}
	}
	return tagFromPath(r.path)
}

func handlerMethod(h string) string {
	if h == "" {
		return ""
	}
	if i := strings.LastIndex(h, "."); i >= 0 {
		return h[i+1:]
	}
	return h
}

func handlerReceiver(h string) string {
	if i := strings.LastIndex(h, "."); i >= 0 {
		return h[:i]
	}
	return ""
}

// tagFromReceiver strips a "H"/"Handler" suffix and prettifies. Returns "" for
// package-qualified non-handler references (echo, handler, http) so the caller
// falls back to the path.
func tagFromReceiver(recv string) string {
	// Package-qualified non-handler references carry no domain — use the path.
	if recv == "echo" || recv == "handler" || recv == "http" {
		return ""
	}
	base := recv
	switch {
	case strings.HasSuffix(base, "Handler"):
		base = strings.TrimSuffix(base, "Handler")
	case strings.HasSuffix(base, "H"):
		base = strings.TrimSuffix(base, "H")
	}
	if base == "" {
		return ""
	}
	if disp, ok := recvTagOverrides[base]; ok {
		return disp
	}
	return prettify(splitCamel(base))
}

func tagFromPath(path string) string {
	segs := strings.Split(path, "/")
	for _, s := range segs {
		if s == "" || s == "api" || s == "v1" {
			continue
		}
		if strings.HasPrefix(s, "{") {
			continue
		}
		if s == ".well-known" {
			return "Discovery"
		}
		// Use the first meaningful segment; strip a file extension if any.
		if i := strings.IndexByte(s, '.'); i >= 0 {
			s = s[:i]
		}
		return prettify(splitCamel(s))
	}
	return "General"
}

// prettify joins camel-split words into a Title-Case tag, honouring acronyms.
func prettify(words []string) string {
	if len(words) == 0 {
		return "General"
	}
	parts := make([]string, len(words))
	for i, w := range words {
		if disp, ok := acronyms[strings.ToLower(w)]; ok {
			parts[i] = disp
		} else {
			parts[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
		}
	}
	return strings.Join(parts, " ")
}

// splitCamel splits a CamelCase / mixed identifier into word tokens, keeping
// runs of uppercase letters (acronyms) and digits together with their acronym.
// "RotatePQCSigningKey" → [Rotate PQC Signing Key]; "OID4VPResume" → [OID4VP Resume].
func splitCamel(s string) []string {
	var words []string
	runes := []rune(s)
	n := len(runes)
	start := 0
	isUpper := func(r rune) bool { return r >= 'A' && r <= 'Z' }
	isLower := func(r rune) bool { return r >= 'a' && r <= 'z' }
	for i := 1; i < n; i++ {
		prev, cur := runes[i-1], runes[i]
		boundary := false
		switch {
		case isLower(prev) && isUpper(cur):
			// camelCase boundary: foo|Bar
			boundary = true
		case isUpper(prev) && isUpper(cur) && i+1 < n && isLower(runes[i+1]):
			// acronym→word boundary: HTTP|Server, PQC|Signing
			boundary = true
		}
		if boundary {
			words = append(words, string(runes[start:i]))
			start = i
		}
	}
	if start < n {
		words = append(words, string(runes[start:]))
	}
	return words
}

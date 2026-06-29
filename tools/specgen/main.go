// specgen derives OpenAPI requestBody schemas for write endpoints by static
// analysis of the handler code, so the spec reflects the real request structs
// instead of hand-written guesses.
//
// For every POST/PUT/PATCH route registered in internal/server, specgen:
//
//  1. resolves the handler method via go/packages type info,
//  2. finds the request struct it binds (bindAndValidate(c, &req) / c.Bind),
//  3. builds a JSON Schema from that struct's fields (json + validate tags),
//  4. merges it into the operation's requestBody — only when absent, so the
//     hand-written core schemas are never overwritten.
//
// Responses are left as-is: most handlers emit inline maps that carry no type
// information to extract.
//
//	go run ./tools/specgen                       # merge into the default spec
//	go run ./tools/specgen -spec path -dry        # report only, no write
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

func main() {
	specPath := flag.String("spec", "internal/handler/spec/openapi.json", "path to OpenAPI spec JSON")
	dry := flag.Bool("dry", false, "report what would change without writing")
	flag.Parse()

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports | packages.NeedFiles,
	}
	pkgs, err := packages.Load(cfg, "./internal/...")
	if err != nil {
		fmt.Fprintf(os.Stderr, "specgen: load: %v\n", err)
		os.Exit(2)
	}
	if packages.PrintErrors(pkgs) > 0 {
		fmt.Fprintln(os.Stderr, "specgen: package load errors (continuing best-effort)")
	}

	// Map every method *types.Func → its *ast.FuncDecl across all packages.
	funcDecls := map[*types.Func]*ast.FuncDecl{}
	infoOf := map[*types.Func]*packages.Package{}
	var serverPkg *packages.Package
	for _, p := range pkgs {
		if strings.HasSuffix(p.PkgPath, "/internal/server") {
			serverPkg = p
		}
		for _, f := range p.Syntax {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv == nil {
					continue
				}
				if obj, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok {
					funcDecls[obj] = fd
					infoOf[obj] = p
				}
			}
		}
	}
	if serverPkg == nil {
		fmt.Fprintln(os.Stderr, "specgen: internal/server package not found")
		os.Exit(2)
	}

	// Walk server routes → (method, path, handler func).
	routes := collectRoutes(serverPkg)

	// Build requestBody schemas.
	bodies := map[string]map[string]interface{}{} // "METHOD path" → schema
	for _, r := range routes {
		if r.method != "POST" && r.method != "PUT" && r.method != "PATCH" {
			continue
		}
		fd := funcDecls[r.fn]
		ip := infoOf[r.fn]
		if fd == nil || ip == nil {
			continue
		}
		reqType := findRequestType(fd, ip)
		if reqType == nil {
			continue
		}
		sch := schemaFor(reqType, map[string]bool{}, 0)
		if sch == nil || sch["type"] != "object" {
			continue
		}
		bodies[r.method+" "+r.path] = sch
	}

	// Merge into spec.
	specData, err := os.ReadFile(*specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "specgen: read spec: %v\n", err)
		os.Exit(2)
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(specData, &spec); err != nil {
		fmt.Fprintf(os.Stderr, "specgen: parse spec: %v\n", err)
		os.Exit(2)
	}
	paths, _ := spec["paths"].(map[string]interface{})

	added, skippedExisting := 0, 0
	var resolved []string
	for key, sch := range bodies {
		sp := strings.SplitN(key, " ", 2)
		method, path := strings.ToLower(sp[0]), sp[1]
		pi, ok := paths[path].(map[string]interface{})
		if !ok {
			continue
		}
		op, ok := pi[method].(map[string]interface{})
		if !ok {
			continue
		}
		if _, exists := op["requestBody"]; exists {
			skippedExisting++
			continue
		}
		op["requestBody"] = map[string]interface{}{
			"required": true,
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{"schema": sch},
			},
		}
		added++
		resolved = append(resolved, strings.ToUpper(method)+" "+path)
	}

	sort.Strings(resolved)
	for _, r := range resolved {
		fmt.Printf("  + %s\n", r)
	}
	fmt.Printf("specgen: %d request bodies derived, %d added, %d kept (already documented).\n",
		len(bodies), added, skippedExisting)

	if *dry || added == 0 {
		return
	}
	out, _ := json.MarshalIndent(spec, "", "  ")
	out = append(out, '\n')
	if err := os.WriteFile(*specPath, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "specgen: write spec: %v\n", err)
		os.Exit(2)
	}
}

type route struct {
	method string
	path   string
	fn     *types.Func
}

var httpMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// collectRoutes walks the server package AST for Echo route registrations and
// resolves each handler argument to its *types.Func via selection type info.
func collectRoutes(p *packages.Package) []route {
	var out []route
	seen := map[string]bool{}
	for _, f := range p.Syntax {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !httpMethods[sel.Sel.Name] || len(call.Args) < 2 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				return true
			}
			path := normalise(strings.Trim(lit.Value, `"`))
			if !strings.HasPrefix(path, "/") {
				return true
			}
			fn := resolveHandler(call.Args[1], p.TypesInfo)
			if fn == nil {
				return true
			}
			key := sel.Sel.Name + " " + path
			if seen[key] {
				return true
			}
			seen[key] = true
			out = append(out, route{method: sel.Sel.Name, path: path, fn: fn})
			return true
		})
	}
	return out
}

// resolveHandler turns a handler argument expression (e.g. smtpH.Put) into the
// underlying *types.Func.
func resolveHandler(arg ast.Expr, info *types.Info) *types.Func {
	se, ok := arg.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if selnf, ok := info.Selections[se]; ok {
		if fn, ok := selnf.Obj().(*types.Func); ok {
			return fn
		}
	}
	// Package-qualified function reference (e.g. handler.OpenAPI).
	if obj, ok := info.Uses[se.Sel].(*types.Func); ok {
		return obj
	}
	return nil
}

// findRequestType scans a handler body for the request struct passed to
// bindAndValidate / Bind, returning its type (named struct, deref'd).
func findRequestType(fd *ast.FuncDecl, p *packages.Package) types.Type {
	if fd.Body == nil {
		return nil
	}
	var found types.Type
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeName(call.Fun)
		var argIdx int
		switch name {
		case "bindAndValidate":
			argIdx = 1 // bindAndValidate(c, &req)
		case "Bind", "bind":
			argIdx = 0 // c.Bind(&req)
		default:
			return true
		}
		if argIdx >= len(call.Args) {
			return true
		}
		ue, ok := call.Args[argIdx].(*ast.UnaryExpr)
		if !ok {
			return true
		}
		if t := p.TypesInfo.TypeOf(ue.X); t != nil {
			if isStructy(t) {
				found = t
			}
		}
		return true
	})
	return found
}

func calleeName(fun ast.Expr) string {
	switch e := fun.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

func isStructy(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Struct:
		return true
	case *types.Pointer:
		_, ok := u.Elem().Underlying().(*types.Struct)
		return ok
	}
	return false
}

// ── Schema generation ───────────────────────────────────────────────────────────

func schemaFor(t types.Type, seen map[string]bool, depth int) map[string]interface{} {
	if depth > 6 {
		return map[string]interface{}{}
	}
	switch u := t.(type) {
	case *types.Pointer:
		s := schemaFor(u.Elem(), seen, depth)
		if s != nil {
			s["nullable"] = true
		}
		return s
	case *types.Named:
		name := u.Obj().Name()
		full := u.Obj().Pkg().Path() + "." + name
		switch full {
		case "time.Time":
			return map[string]interface{}{"type": "string", "format": "date-time"}
		case "github.com/google/uuid.UUID":
			return map[string]interface{}{"type": "string", "format": "uuid"}
		case "encoding/json.RawMessage":
			return map[string]interface{}{}
		}
		if st, ok := u.Underlying().(*types.Struct); ok {
			if seen[full] {
				return map[string]interface{}{"type": "object"} // break recursion
			}
			seen[full] = true
			defer delete(seen, full)
			return structSchema(st, seen, depth)
		}
		return schemaFor(u.Underlying(), seen, depth)
	case *types.Basic:
		return basicSchema(u)
	case *types.Slice:
		if b, ok := u.Elem().Underlying().(*types.Basic); ok && b.Kind() == types.Byte {
			return map[string]interface{}{"type": "string", "format": "byte"}
		}
		return map[string]interface{}{"type": "array", "items": schemaFor(u.Elem(), seen, depth+1)}
	case *types.Map:
		return map[string]interface{}{"type": "object", "additionalProperties": schemaFor(u.Elem(), seen, depth+1)}
	case *types.Interface:
		return map[string]interface{}{} // any
	case *types.Struct:
		return structSchema(u, seen, depth)
	}
	return map[string]interface{}{}
}

func basicSchema(b *types.Basic) map[string]interface{} {
	switch b.Info() {
	case types.IsBoolean:
		return map[string]interface{}{"type": "boolean"}
	case types.IsInteger:
		return map[string]interface{}{"type": "integer"}
	case types.IsFloat:
		return map[string]interface{}{"type": "number"}
	case types.IsString:
		return map[string]interface{}{"type": "string"}
	}
	if b.Kind() == types.Byte {
		return map[string]interface{}{"type": "integer"}
	}
	return map[string]interface{}{}
}

func structSchema(st *types.Struct, seen map[string]bool, depth int) map[string]interface{} {
	props := map[string]interface{}{}
	var required []string
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		tag := reflect.StructTag(st.Tag(i))
		// Embedded struct: merge its properties inline.
		if f.Anonymous() && tag.Get("json") == "" {
			if inner, ok := f.Type().Underlying().(*types.Struct); ok {
				sub := structSchema(inner, seen, depth)
				for k, v := range sub["properties"].(map[string]interface{}) {
					props[k] = v
				}
				if rq, ok := sub["required"].([]string); ok {
					required = append(required, rq...)
				}
				continue
			}
		}
		jsonTag := tag.Get("json")
		name := strings.Split(jsonTag, ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			if !f.Exported() {
				continue
			}
			name = f.Name()
		}
		s := schemaFor(f.Type(), seen, depth+1)
		applyValidate(s, tag.Get("validate"))
		props[name] = s
		if hasRule(tag.Get("validate"), "required") {
			required = append(required, name)
		}
	}
	out := map[string]interface{}{"type": "object", "properties": props}
	if len(required) > 0 {
		sort.Strings(required)
		out["required"] = required
	}
	return out
}

func hasRule(validate, rule string) bool {
	for _, part := range strings.Split(validate, ",") {
		if strings.SplitN(part, "=", 2)[0] == rule {
			return true
		}
	}
	return false
}

// applyValidate maps a few validator tags to JSON Schema formats/constraints.
func applyValidate(s map[string]interface{}, validate string) {
	if s["type"] != "string" {
		return
	}
	for _, part := range strings.Split(validate, ",") {
		kv := strings.SplitN(part, "=", 2)
		switch kv[0] {
		case "email":
			s["format"] = "email"
		case "uuid", "uuid4":
			s["format"] = "uuid"
		case "url", "uri", "http_url":
			s["format"] = "uri"
		case "e164":
			s["pattern"] = `^\+[1-9]\d{1,14}$`
		case "datetime":
			s["format"] = "date-time"
		}
	}
}

// normalise converts Echo :param syntax to OpenAPI {param} and drops /* wildcards.
func normalise(p string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(p, ':')
		if i < 0 {
			b.WriteString(p)
			break
		}
		b.WriteString(p[:i])
		p = p[i+1:]
		j := 0
		for j < len(p) && (isIdent(p[j])) {
			j++
		}
		b.WriteString("{" + p[:j] + "}")
		p = p[j:]
	}
	out := b.String()
	out = strings.TrimSuffix(out, "/*")
	return out
}

func isIdent(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

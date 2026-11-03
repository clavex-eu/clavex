# Dependency updates — November 2026

This change refreshes compatible application dependencies and build tooling. It does not change application protocols, tenant data, licensing or production configuration.

## Update policy

- Go: update within the current stable module major; use patch updates within existing pre-1.0 lines. Do not migrate Echo to v5, JWX to v3, or Kubernetes/controller-runtime to another API line. `golang.org/x/net` is explicitly advanced to v0.62.0 for two HTML security fixes, retaining Go 1.26 support. Pseudo-version upgrades are not forced.
- JavaScript: update within declared compatible ranges and raise direct dependency minimums to the tested resolved versions. Preserve SDK peer contracts. Do not use `npm audit fix --force` or force incompatible transitive overrides.
- Toolchain: raise the Go 1.26 patch to **1.26.10**, including the backend go.mod, CI matrix and Go build images. Go 1.26.4 triggered 22 reachable standard-library findings in govulncheck; changing go.mod alone does not patch an already-built server. Existing installations need a rebuild/deployment after merge.
- Python conformance tooling: test current requests 2.34.2 and Playwright 1.64.1 on Python 3.12, while retaining existing lower bounds and adding next-major caps. These latest releases require Python >=3.10; pip can still select older compatible releases on older interpreters. Older interpreter graphs have not been security-validated here. No browser-based conformance module was started.

## Selected backend changes

| Module | Previous | Updated |
|---|---|---|
| `github.com/fxamacker/cbor/v2` | `v2.9.1` | `v2.10.0` |
| `github.com/go-webauthn/webauthn` | `v0.17.2` | `v0.17.4` |
| `github.com/jackc/pgx/v5` | `v5.9.2` | `v5.12.0` |
| `github.com/labstack/echo/v4` | `v4.15.2` | `v4.16.3` |
| `github.com/lestrrat-go/jwx/v2` | `v2.1.6` | `v2.1.7` |
| `github.com/redis/go-redis/v9` | `v9.19.0` | `v9.23.0` |
| `go.opentelemetry.io/otel/sdk` | `v1.43.0` | `v1.47.0` |
| `golang.org/x/crypto` | `v0.53.0` | `v0.58.0` |
| `golang.org/x/net` | `v0.56.0` | `v0.62.0` |
| `google.golang.org/grpc` | `v1.82.1` | `v1.85.0` |

77 existing root Go modules change version. The full version list is represented by go.mod/go.sum.

## Frontend

Examples: Axios 1.18.1 → 1.21.0, React/React DOM 19.2.8 → 19.3.1, React Router 8.3.0 → 8.5.1, Vite 8.1.5 → 8.3.5. Refresh compatible direct dependencies and regenerate the complete lockfile, including transitive dependencies. Production frontend build passes. Bundle-size and Vite configuration warnings remain.

## Security scan limits

The npm advisory bulk endpoint was queried using versions from the updated lockfiles. It reports a remaining **moderate minimatch** advisory (`GHSA-g3hv-75wg-m249`): the correction starts at 11.0.1, while current ESLint/TypeScript-ESLint require ^10. The dependency is build tooling. This change does not force minimatch 11 into incompatible parent ranges.

The initial public Dependabot snapshot contained 32 alerts across go.mod/frontend lockfiles, including one critical and 19 high entries. Updated versions exceed the fixed versions listed for those original packages. Alerts on the default branch remain until merge and GitHub rescanning; no claim of an alert-free repository is made. Reachability and deployment exposure are separate questions.

Go govulncheck is run against Go 1.26.10 after updating x/net. A module-only OpenPGP finding (`GO-2026-5932`) can remain because x/crypto contains an unmaintained package, although that package is not imported by the scanned application. Keeping x/crypto for its maintained packages does not require enabling OpenPGP. Module-only results are not marked as passes or suppressed.

## Validation

Local checks completed: frontend production build; complete root Go race tests with isolated PostgreSQL/Redis; final x/net regression checks for safehttp/OIDC/server; govulncheck; Python tooling installation. The detailed results and any remaining CI blockers are recorded in the PR description. No live cluster rollout, conformance test execution, auto-merge or production deployment is part of this change.

References: [Go module update semantics](https://go.dev/ref/mod#go-get), [npm update compatible-range behaviour](https://docs.npmjs.com/cli/v11/commands/npm-update/), [minimatch advisory](https://github.com/advisories/GHSA-g3hv-75wg-m249).

Verified locally: complete backend race suite passes with isolated PostgreSQL/Redis; production frontend build passes; final safehttp/OIDC/server race checks pass; govulncheck finds no reachable vulnerabilities (only the module-level OpenPGP advisory). No conformance modules were executed.

package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Declarative-management marker request headers. The Kubernetes operator (and
// any future declarative source) stamps these on every create/update it makes;
// an ordinary UI / clavexctl / API request omits them and therefore never
// disturbs an existing marker. See migration 000179.
const (
	HeaderManagedBy      = "X-Clavex-Managed-By"
	HeaderManagedRef     = "X-Clavex-Managed-Ref"
	HeaderManagedRelease = "X-Clavex-Managed-Release"
)

// ManagedMarkerInput is the marker parsed off an inbound request. It is a
// no-op unless By is set (adopt/refresh the marker) or Release is true
// (disown: clear the marker without touching the resource itself).
type ManagedMarkerInput struct {
	By      string
	Ref     string
	Release bool
}

// Active reports whether the marker input asks for any DB change (adopt or
// release). An inactive marker — an ordinary UI/API request — is a no-op.
func (m ManagedMarkerInput) Active() bool { return m.Release || m.By != "" }

// managedMarkerTables is the allowlist of tables carrying managed_by/managed_ref
// (migration 000179). Only these may be targeted by ApplyManagedMarker — the
// table name is interpolated into SQL, so it must never come from user input.
var managedMarkerTables = map[string]bool{
	"oidc_clients":        true,
	"roles":               true,
	"groups":              true,
	"org_auth_policies":   true,
	"webhooks":            true,
	"identity_providers":  true,
	"org_password_policy": true,
	"org_rate_limits":     true,
}

// managedMarkerKeyCols is the allowlist of primary-key columns used to locate
// the row. Like the table name these are interpolated into SQL.
var managedMarkerKeyCols = map[string]bool{
	"id":        true,
	"client_id": true,
	"org_id":    true,
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ApplyManagedMarker sets or clears the declarative-management marker on a
// single row identified by (keyCol = keyVal AND org_id = orgID). It is a no-op
// when the marker input is inactive, so update handlers can call it
// unconditionally: only an operator-stamped request (m.By set) or an explicit
// release (m.Release) mutates the columns. Release wins over adopt.
//
// table and keyCol are validated against allowlists because they are
// interpolated into the statement; keyVal, orgID and the marker values are
// always bound as parameters.
//
// The org_password_policy and org_rate_limits tables are keyed by org_id alone
// (one row per org); pass keyCol "org_id" for them and the keyVal is ignored.
func ApplyManagedMarker(ctx context.Context, q execer, table, keyCol string, keyVal any, orgID uuid.UUID, m ManagedMarkerInput) error {
	if !m.Active() {
		return nil
	}
	if !managedMarkerTables[table] {
		return fmt.Errorf("managed marker: table %q not in allowlist", table)
	}
	if !managedMarkerKeyCols[keyCol] {
		return fmt.Errorf("managed marker: key column %q not in allowlist", keyCol)
	}

	byOrgOnly := keyCol == "org_id"

	if m.Release {
		if byOrgOnly {
			_, err := q.Exec(ctx,
				fmt.Sprintf("UPDATE %s SET managed_by = NULL, managed_ref = NULL WHERE org_id = $1", table),
				orgID)
			return err
		}
		_, err := q.Exec(ctx,
			fmt.Sprintf("UPDATE %s SET managed_by = NULL, managed_ref = NULL WHERE %s = $1 AND org_id = $2", table, keyCol),
			keyVal, orgID)
		return err
	}

	// Adopt / refresh. NULLIF collapses an empty ref to NULL.
	if byOrgOnly {
		_, err := q.Exec(ctx,
			fmt.Sprintf("UPDATE %s SET managed_by = $1, managed_ref = NULLIF($2, '') WHERE org_id = $3", table),
			m.By, m.Ref, orgID)
		return err
	}
	_, err := q.Exec(ctx,
		fmt.Sprintf("UPDATE %s SET managed_by = $1, managed_ref = NULLIF($2, '') WHERE %s = $3 AND org_id = $4", table, keyCol),
		m.By, m.Ref, keyVal, orgID)
	return err
}

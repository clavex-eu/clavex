package main

import (
	"context"
	"fmt"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Dedicated registrations keep Final's strict audience rules separate from ID2.
var finalClientSources = []string{
	"conformance-client-fapi", "conformance-client-fapi-2",
	"conformance-client-fapi-dpop", "conformance-client-fapi-dpop-2",
	"conformance-client-fapi-dpop-jar", "conformance-client-fapi-dpop-jar-2",
}

// seedFinalClients only creates missing test registrations. Existing source
// clients, users, signing keys and registrations owned elsewhere are untouched.
func seedFinalClients(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var enabled bool
	if err = tx.QueryRow(ctx, `SELECT conformance_mode FROM organizations WHERE id=$1 AND slug=$2`, orgID, orgSlug).Scan(&enabled); err != nil || !enabled {
		return fmt.Errorf("final clients require the existing conformance organisation in conformance mode")
	}
	for _, source := range finalClientSources {
		target := source + "-final"
		_, err = tx.Exec(ctx, `INSERT INTO oidc_clients
   SELECT (jsonb_populate_record(NULL::oidc_clients, to_jsonb(src) || jsonb_build_object(
    'client_id', $3::text, 'name', src.name || ' (Final)', 'created_at', NOW(), 'updated_at', NOW(),
    'metadata', COALESCE(src.metadata, '{}'::jsonb) || jsonb_build_object(
      $4::text, $5::text, 'conformance_final_source', $2::text)))).*
   FROM oidc_clients src WHERE src.org_id=$1 AND src.client_id=$2
   ON CONFLICT (client_id) DO NOTHING`, orgID, source, target, models.ClientAssertionProfileMetadataKey, models.ClientAssertionProfileFAPIFinal)
		if err != nil {
			return fmt.Errorf("create Final test client %s: %w", target, err)
		}
		var owned bool
		if err = tx.QueryRow(ctx, `SELECT dst.org_id=$1 AND dst.metadata->>$3=$4 AND dst.metadata->>'conformance_final_source'=$5
      AND (to_jsonb(dst)-ARRAY['client_id','name','metadata','created_at','updated_at']) =
          (to_jsonb(src)-ARRAY['client_id','name','metadata','created_at','updated_at'])
      AND (dst.metadata-ARRAY[$3::text,'conformance_final_source']) = src.metadata
   FROM oidc_clients dst JOIN oidc_clients src ON src.client_id=$5 AND src.org_id=$1
   WHERE dst.client_id=$2`, orgID, target, models.ClientAssertionProfileMetadataKey, models.ClientAssertionProfileFAPIFinal, source).Scan(&owned); err != nil || !owned {
			return fmt.Errorf("missing source, conflicting or stale Final test registration %s", target)
		}
	}
	return tx.Commit(ctx)
}

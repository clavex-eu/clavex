package repository

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
)

func (r *OID4WRepository) RecordCredentialParents(ctx context.Context, org uuid.UUID, hash string, parents json.RawMessage) error {
	if len(parents) == 0 {
		parents = json.RawMessage(`[]`)
	}
	_, err := r.pool.Exec(ctx, `UPDATE identity.issued_credentials SET status_parents=$3 WHERE org_id=$1 AND sd_jwt_hash=$2`, org, hash, parents)
	return err
}
func (r *OID4WRepository) CredentialStatusParents(ctx context.Context, org uuid.UUID, issuerHash, coseHash string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := r.pool.QueryRow(ctx, `SELECT status_parents FROM identity.issued_credentials
 WHERE org_id=$1 AND (($2<>'' AND issuer_jwt_hash=$2) OR ($3<>'' AND issuer_cose_hash=$3)) FOR SHARE`, org, issuerHash, coseHash).Scan(&raw)
	return raw, err
}

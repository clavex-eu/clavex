package repository

import (
	"context"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestRandomStatusAllocationConcurrencyRollbackAndCapacity(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	org, _ := twoOrgs(t, ctx, pool)
	type allocation struct {
		list  uuid.UUID
		index int
		err   error
	}
	const workers = 24
	results := make(chan allocation, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			tx, err := pool.Begin(ctx)
			if err != nil {
				results <- allocation{err: err}
				return
			}
			defer tx.Rollback(ctx)
			list, index, err := NewOID4WRepository(tx).AllocateCredentialStatus(ctx, org)
			if err == nil {
				err = tx.Commit(ctx)
			}
			results <- allocation{list, index, err}
		})
	}
	wg.Wait()
	close(results)
	seen := map[int]bool{}
	var list uuid.UUID
	var indices []int
	for result := range results {
		require.NoError(t, result.err)
		if list == uuid.Nil {
			list = result.list
		}
		require.Equal(t, list, result.list)
		require.False(t, seen[result.index], "concurrent reservations must be unique")
		seen[result.index] = true
		indices = append(indices, result.index)
		var reserved int
		require.NoError(t, pool.QueryRow(ctx, `SELECT get_bit(allocated_slots,$2) FROM identity.credential_status_lists WHERE id=$1`, list, result.index).Scan(&reserved))
		require.Equal(t, 1, reserved)
	}
	sort.Ints(indices)
	arithmetic := true
	for i := 2; i < len(indices); i++ {
		arithmetic = arithmetic && indices[i]-indices[i-1] == indices[1]-indices[0]
	}
	require.False(t, arithmetic, "24 independent random reservations must not form an arithmetic progression")
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, rolledBack, err := NewOID4WRepository(tx).AllocateCredentialStatus(ctx, org)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))
	var reserved, count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT get_bit(allocated_slots,$2),next_slot FROM identity.credential_status_lists WHERE id=$1`, list, rolledBack).Scan(&reserved, &count))
	require.Zero(t, reserved)
	require.Equal(t, workers, count)
	// Preserve every existing reservation and leave exactly one free slot.
	hole := 0
	for seen[hole] {
		hole++
	}
	_, err = pool.Exec(ctx, `UPDATE identity.credential_status_lists SET next_slot=65535,allocated_slots=set_bit(decode(repeat('ff',8192),'hex'),$2,0) WHERE id=$1`, list, hole)
	require.NoError(t, err)
	tx, err = pool.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	repo := NewOID4WRepository(tx)
	last, index, err := repo.AllocateCredentialStatus(ctx, org)
	require.NoError(t, err)
	require.Equal(t, list, last)
	require.Equal(t, hole, index)
	rolled, _, err := repo.AllocateCredentialStatus(ctx, org)
	require.NoError(t, err)
	require.NotEqual(t, list, rolled)
	require.NoError(t, tx.Commit(ctx))
}

func TestRandomStatusMigrationPreservesLegacyReservationsAndBlocksUnsafeRollback(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	schema := pgx.Identifier{"status_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
	_, err = tx.Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.credential_status_lists(next_slot int NOT NULL); INSERT INTO `+schema+`.credential_status_lists VALUES(0),(1),(7),(8),(9),(65535),(65536)`)
	require.NoError(t, err)
	up, err := os.ReadFile("../db/migrations/000194_random_status_slots.up.sql")
	require.NoError(t, err)
	down, err := os.ReadFile("../db/migrations/000194_random_status_slots.down.sql")
	require.NoError(t, err)
	apply := func(raw []byte) error {
		_, e := tx.Exec(ctx, strings.ReplaceAll(string(raw), "identity.", schema+"."))
		return e
	}
	require.NoError(t, apply(up))
	var invalid int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.credential_status_lists s CROSS JOIN generate_series(0,65535) i WHERE get_bit(s.allocated_slots,i)<>CASE WHEN i<s.next_slot THEN 1 ELSE 0 END`).Scan(&invalid))
	require.Zero(t, invalid, "every historical reservation, including unrecorded slots, remains reserved")
	require.NoError(t, apply(down), "legacy-only rollback remains possible")
	require.NoError(t, apply(up))
	_, err = tx.Exec(ctx, `UPDATE `+schema+`.credential_status_lists SET allocated_slots=set_bit(set_bit(allocated_slots,0,0),40000,1) WHERE next_slot=1`)
	require.NoError(t, err)
	err = apply(down)
	require.ErrorContains(t, err, "Random status slots are in use")
}

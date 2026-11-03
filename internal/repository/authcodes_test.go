package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type codeLookupErrorRow struct{ err error }

func (r codeLookupErrorRow) Scan(...any) error { return r.err }

type codeLookupErrorDB struct {
	Querier
	err error
}

func (db codeLookupErrorDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return codeLookupErrorRow{db.err}
}

func TestUsedCodeLookupDistinguishesMissingFromStoreFailure(t *testing.T) {
	for _, err := range []error{pgx.ErrNoRows, errors.New("store unavailable")} {
		repo := NewAuthCodeRepository(codeLookupErrorDB{err: err})
		code, gotErr := repo.GetUsedByHash(context.Background(), "code-hash")
		require.Nil(t, code)
		if errors.Is(err, pgx.ErrNoRows) {
			require.NoError(t, gotErr)
		} else {
			require.ErrorIs(t, gotErr, err)
		}
	}
}

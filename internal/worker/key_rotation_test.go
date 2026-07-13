package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/stretchr/testify/assert"
)

type fakeRSARotator struct {
	calls int
	err   error
}

func (f *fakeRSARotator) Rotate() error { f.calls++; return f.err }

type fakePQCRotator struct {
	calls int
	err   error
}

func (f *fakePQCRotator) Rotate(_ context.Context) error { f.calls++; return f.err }

type fakeKeyRotStore struct {
	due    []repository.KeyRotationPolicy
	marked []string
}

func (f *fakeKeyRotStore) ListDue(_ context.Context, _ time.Time) ([]repository.KeyRotationPolicy, error) {
	return f.due, nil
}

func (f *fakeKeyRotStore) MarkRotated(_ context.Context, keyKind string, _ time.Time) error {
	f.marked = append(f.marked, keyKind)
	return nil
}

func TestTickKeyRotation_RotatesDueKinds(t *testing.T) {
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindOIDC, RotationPolicy: "scheduled"},
		{KeyKind: repository.KeyKindPQC, RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{}
	pqc := &fakePQCRotator{}

	tickKeyRotation(context.Background(), store, rsa, pqc)

	assert.Equal(t, 1, rsa.calls)
	assert.Equal(t, 1, pqc.calls)
	assert.ElementsMatch(t, []string{"oidc", "pqc"}, store.marked)
}

func TestTickKeyRotation_SkipsBYOKAndUnknownKinds(t *testing.T) {
	// Even if a bogus/BYOK kind somehow reaches the scheduler, it must never be
	// rotated and never marked.
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: "byok", RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{}
	pqc := &fakePQCRotator{}

	tickKeyRotation(context.Background(), store, rsa, pqc)

	assert.Zero(t, rsa.calls)
	assert.Zero(t, pqc.calls)
	assert.Empty(t, store.marked)
}

func TestTickKeyRotation_NilSignerSkipsKind(t *testing.T) {
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindPQC, RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{}

	// PQC signer not configured (nil interface) — kind is skipped, not marked.
	tickKeyRotation(context.Background(), store, rsa, nil)

	assert.Zero(t, rsa.calls)
	assert.Empty(t, store.marked)
}

func TestTickKeyRotation_RotateErrorDoesNotMark(t *testing.T) {
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindOIDC, RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{err: errors.New("rotate boom")}

	tickKeyRotation(context.Background(), store, rsa, &fakePQCRotator{})

	assert.Equal(t, 1, rsa.calls)
	assert.Empty(t, store.marked, "a failed rotation must not update last_rotated_at")
}

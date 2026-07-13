package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
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

// fakeOrgKeyRotator satisfies both orgRotator and orgPQCRotator (same shape).
type fakeOrgKeyRotator struct {
	rotated []uuid.UUID
	err     error
}

func (f *fakeOrgKeyRotator) RotateForOrg(_ context.Context, orgID uuid.UUID) (string, error) {
	f.rotated = append(f.rotated, orgID)
	return "kid-new", f.err
}

type markedOrg struct {
	kind  string
	orgID uuid.UUID
}

type fakeKeyRotStore struct {
	due        []repository.KeyRotationPolicy
	marked     []string
	markedOrgs []markedOrg
}

func (f *fakeKeyRotStore) ListDue(_ context.Context, _ time.Time) ([]repository.KeyRotationPolicy, error) {
	return f.due, nil
}

func (f *fakeKeyRotStore) MarkRotated(_ context.Context, keyKind string, _ time.Time) error {
	f.marked = append(f.marked, keyKind)
	return nil
}

func (f *fakeKeyRotStore) MarkRotatedForOrg(_ context.Context, keyKind string, orgID uuid.UUID, _ time.Time) error {
	f.markedOrgs = append(f.markedOrgs, markedOrg{kind: keyKind, orgID: orgID})
	return nil
}

func TestTickKeyRotation_RotatesGlobalKinds(t *testing.T) {
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindOIDC, RotationPolicy: "scheduled"},
		{KeyKind: repository.KeyKindPQC, RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{}
	pqc := &fakePQCRotator{}
	orgs := &fakeOrgKeyRotator{}
	orgPQC := &fakeOrgKeyRotator{}

	tickKeyRotation(context.Background(), store, rsa, pqc, orgs, orgPQC)

	assert.Equal(t, 1, rsa.calls)
	assert.Equal(t, 1, pqc.calls)
	assert.Empty(t, orgs.rotated)
	assert.Empty(t, orgPQC.rotated)
	assert.ElementsMatch(t, []string{"oidc", "pqc"}, store.marked)
}

func TestTickKeyRotation_RotatesPerOrgOIDC(t *testing.T) {
	org1, org2 := uuid.New(), uuid.New()
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindOIDC, OrgID: &org1, RotationPolicy: "scheduled"},
		{KeyKind: repository.KeyKindOIDC, OrgID: &org2, RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{}
	orgs := &fakeOrgKeyRotator{}
	orgPQC := &fakeOrgKeyRotator{}

	tickKeyRotation(context.Background(), store, rsa, &fakePQCRotator{}, orgs, orgPQC)

	assert.Zero(t, rsa.calls)
	assert.ElementsMatch(t, []uuid.UUID{org1, org2}, orgs.rotated)
	assert.Empty(t, orgPQC.rotated)
	assert.Empty(t, store.marked)
	assert.Len(t, store.markedOrgs, 2)
}

func TestTickKeyRotation_RotatesPerOrgPQC(t *testing.T) {
	org1, org2 := uuid.New(), uuid.New()
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindPQC, OrgID: &org1, RotationPolicy: "scheduled"},
		{KeyKind: repository.KeyKindPQC, OrgID: &org2, RotationPolicy: "scheduled"},
	}}
	pqc := &fakePQCRotator{}
	orgPQC := &fakeOrgKeyRotator{}

	tickKeyRotation(context.Background(), store, &fakeRSARotator{}, pqc, &fakeOrgKeyRotator{}, orgPQC)

	// Per-org PQC goes to the per-org PQC rotator, not the global PQC signer.
	assert.Zero(t, pqc.calls)
	assert.ElementsMatch(t, []uuid.UUID{org1, org2}, orgPQC.rotated)
	assert.Empty(t, store.marked)
	assert.Len(t, store.markedOrgs, 2)
	for _, m := range store.markedOrgs {
		assert.Equal(t, repository.KeyKindPQC, m.kind)
	}
}

func TestTickKeyRotation_SkipsBYOKAndUnknownKinds(t *testing.T) {
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: "byok", RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{}
	pqc := &fakePQCRotator{}

	tickKeyRotation(context.Background(), store, rsa, pqc, &fakeOrgKeyRotator{}, &fakeOrgKeyRotator{})

	assert.Zero(t, rsa.calls)
	assert.Zero(t, pqc.calls)
	assert.Empty(t, store.marked)
	assert.Empty(t, store.markedOrgs)
}

func TestTickKeyRotation_NilSignerSkipsKind(t *testing.T) {
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindPQC, RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{}

	tickKeyRotation(context.Background(), store, rsa, nil, nil, nil)

	assert.Zero(t, rsa.calls)
	assert.Empty(t, store.marked)
}

func TestTickKeyRotation_NilOrgRotatorSkipsPerOrg(t *testing.T) {
	org1 := uuid.New()
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindOIDC, OrgID: &org1, RotationPolicy: "scheduled"},
		{KeyKind: repository.KeyKindPQC, OrgID: &org1, RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{}

	// Non-db backend / PQC disabled: per-org caches absent — both skipped.
	tickKeyRotation(context.Background(), store, rsa, &fakePQCRotator{}, nil, nil)

	assert.Zero(t, rsa.calls)
	assert.Empty(t, store.marked)
	assert.Empty(t, store.markedOrgs)
}

func TestTickKeyRotation_RotateErrorDoesNotMark(t *testing.T) {
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindOIDC, RotationPolicy: "scheduled"},
	}}
	rsa := &fakeRSARotator{err: errors.New("rotate boom")}

	tickKeyRotation(context.Background(), store, rsa, &fakePQCRotator{}, &fakeOrgKeyRotator{}, &fakeOrgKeyRotator{})

	assert.Equal(t, 1, rsa.calls)
	assert.Empty(t, store.marked)
}

func TestTickKeyRotation_PerOrgPQCRotateErrorDoesNotMark(t *testing.T) {
	org1 := uuid.New()
	store := &fakeKeyRotStore{due: []repository.KeyRotationPolicy{
		{KeyKind: repository.KeyKindPQC, OrgID: &org1, RotationPolicy: "scheduled"},
	}}
	orgPQC := &fakeOrgKeyRotator{err: errors.New("rotate boom")}

	tickKeyRotation(context.Background(), store, &fakeRSARotator{}, &fakePQCRotator{}, &fakeOrgKeyRotator{}, orgPQC)

	assert.Equal(t, []uuid.UUID{org1}, orgPQC.rotated)
	assert.Empty(t, store.markedOrgs)
}

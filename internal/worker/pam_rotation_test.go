package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/vaultssh"
	"github.com/clavex-eu/clavex/internal/webhook"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// ── Fakes ────────────────────────────────────────────────────────────────────

type fakeRotationStore struct {
	rotateCalls   int
	logCalls      []string // rotationType of each LogRotation call
	lastEncSecret string
}

func (f *fakeRotationStore) RotateCredentialSecret(_ context.Context, _ uuid.UUID, encryptedSecret string) error {
	f.rotateCalls++
	f.lastEncSecret = encryptedSecret
	return nil
}

func (f *fakeRotationStore) LogRotation(_ context.Context, _, _ uuid.UUID, _, rotationType, _ string) error {
	f.logCalls = append(f.logCalls, rotationType)
	return nil
}

type dispatchCall struct {
	orgID uuid.UUID
	event string
	data  any
}

type fakeDispatcher struct {
	calls []dispatchCall
}

func (f *fakeDispatcher) Dispatch(orgID uuid.UUID, event string, data any) {
	f.calls = append(f.calls, dispatchCall{orgID: orgID, event: event, data: data})
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestRotatePAMCredential_AutoType_DispatchesEvent(t *testing.T) {
	store := &fakeRotationStore{}
	disp := &fakeDispatcher{}
	enc := crypto.NewEncryptor("unit-test-master-secret")

	orgID := uuid.New()
	credID := uuid.New()
	cred := repository.PAMCredential{
		ID:             credID,
		OrgID:          orgID,
		Name:           "db-admin",
		CredentialType: "password",
	}

	err := rotatePAMCredential(context.Background(), store, enc, disp, cred)
	require.NoError(t, err)

	assert.Equal(t, 1, store.rotateCalls, "auto type should rotate the secret")
	assert.NotEmpty(t, store.lastEncSecret, "rotated secret should be persisted encrypted")
	assert.Equal(t, []string{"auto"}, store.logCalls)

	require.Len(t, disp.calls, 1, "exactly one webhook should fire")
	c := disp.calls[0]
	assert.Equal(t, orgID, c.orgID)
	assert.Equal(t, webhook.EventPAMCredentialRotated, c.event)

	data, ok := c.data.(map[string]any)
	require.True(t, ok, "payload should be a map")
	assert.Equal(t, orgID, data["org_id"])
	assert.Equal(t, credID, data["credential_id"])
	assert.Equal(t, "password", data["credential_type"])
	assert.Equal(t, "system", data["rotated_by"])
	assert.NotNil(t, data["rotated_at"])
}

func TestRotatePAMCredential_ManualType_NoDispatch(t *testing.T) {
	for _, credType := range []string{"ssh_key", "certificate"} {
		t.Run(credType, func(t *testing.T) {
			store := &fakeRotationStore{}
			disp := &fakeDispatcher{}
			enc := crypto.NewEncryptor("unit-test-master-secret")

			cred := repository.PAMCredential{
				ID:             uuid.New(),
				OrgID:          uuid.New(),
				Name:           "fleet-ca",
				CredentialType: credType,
			}

			err := rotatePAMCredential(context.Background(), store, enc, disp, cred)
			require.NoError(t, err)

			assert.Zero(t, store.rotateCalls, "manual types must not rotate the secret")
			assert.Equal(t, []string{"manual_required"}, store.logCalls)
			assert.Empty(t, disp.calls, "manual rotation must not emit pam.credential.rotated")
		})
	}
}

// ── SSH CA reconciliation ────────────────────────────────────────────────────

type fakeSSHCAStore struct {
	rows      []repository.SSHCAReconcileRow
	updated   map[uuid.UUID]string
	updateErr error
}

func (f *fakeSSHCAStore) ListSSHCAConfigsForReconcile(_ context.Context) ([]repository.SSHCAReconcileRow, error) {
	return f.rows, nil
}

func (f *fakeSSHCAStore) UpdateSSHCAPublicKey(_ context.Context, orgID uuid.UUID, pubKey string) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	if f.updated == nil {
		f.updated = map[uuid.UUID]string{}
	}
	f.updated[orgID] = pubKey
	return nil
}

// genSSHPublicKey returns a fresh, valid OpenSSH authorized_keys line.
func genSSHPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func ptr(s string) *string { return &s }

func staticFetcher(key string) caKeyFetcher {
	return func(_ context.Context, _, _, _ string) (string, error) { return key, nil }
}

func TestProcessSSHCARotations_RotationDispatchesEvent(t *testing.T) {
	enc := crypto.NewEncryptor("unit-test-master-secret")
	encTok, err := enc.Encrypt("vault-token")
	require.NoError(t, err)

	oldKey := genSSHPublicKey(t)
	newKey := genSSHPublicKey(t)
	orgID := uuid.New()

	store := &fakeSSHCAStore{rows: []repository.SSHCAReconcileRow{{
		OrgID:          orgID,
		VaultAddr:      "https://vault.example:8200",
		VaultMount:     "ssh",
		EncryptedToken: encTok,
		CAPublicKey:    ptr(oldKey),
	}}}
	disp := &fakeDispatcher{}

	processSSHCARotations(context.Background(), store, enc, disp, staticFetcher(newKey))

	assert.Equal(t, newKey, store.updated[orgID], "new key should be cached")
	require.Len(t, disp.calls, 1)
	c := disp.calls[0]
	assert.Equal(t, orgID, c.orgID)
	assert.Equal(t, webhook.EventPAMSSHCARotated, c.event)

	data := c.data.(map[string]any)
	wantNew, _ := vaultssh.FingerprintSHA256(newKey)
	wantPrev, _ := vaultssh.FingerprintSHA256(oldKey)
	assert.Equal(t, wantNew, data["new_fingerprint"])
	assert.Equal(t, wantPrev, data["previous_fingerprint"])
	assert.Equal(t, orgID, data["org_id"])
	assert.NotNil(t, data["rotated_at"])
}

func TestProcessSSHCARotations_NoChange_NoEvent(t *testing.T) {
	enc := crypto.NewEncryptor("unit-test-master-secret")
	encTok, _ := enc.Encrypt("vault-token")
	key := genSSHPublicKey(t)
	orgID := uuid.New()

	store := &fakeSSHCAStore{rows: []repository.SSHCAReconcileRow{{
		OrgID: orgID, VaultAddr: "a", VaultMount: "ssh", EncryptedToken: encTok, CAPublicKey: ptr(key),
	}}}
	disp := &fakeDispatcher{}

	processSSHCARotations(context.Background(), store, enc, disp, staticFetcher(key))

	assert.Empty(t, disp.calls, "unchanged key must not emit an event")
	assert.Empty(t, store.updated, "unchanged key must not re-cache")
}

func TestProcessSSHCARotations_FirstObservation_SeedsCacheNoEvent(t *testing.T) {
	enc := crypto.NewEncryptor("unit-test-master-secret")
	encTok, _ := enc.Encrypt("vault-token")
	key := genSSHPublicKey(t)
	orgID := uuid.New()

	store := &fakeSSHCAStore{rows: []repository.SSHCAReconcileRow{{
		OrgID: orgID, VaultAddr: "a", VaultMount: "ssh", EncryptedToken: encTok, CAPublicKey: nil,
	}}}
	disp := &fakeDispatcher{}

	processSSHCARotations(context.Background(), store, enc, disp, staticFetcher(key))

	assert.Equal(t, key, store.updated[orgID], "first observation should seed the cache")
	assert.Empty(t, disp.calls, "first observation must not emit an event")
}

func TestProcessSSHCARotations_FetchError_NoEvent(t *testing.T) {
	enc := crypto.NewEncryptor("unit-test-master-secret")
	encTok, _ := enc.Encrypt("vault-token")
	orgID := uuid.New()

	store := &fakeSSHCAStore{rows: []repository.SSHCAReconcileRow{{
		OrgID: orgID, VaultAddr: "a", VaultMount: "ssh", EncryptedToken: encTok, CAPublicKey: ptr(genSSHPublicKey(t)),
	}}}
	disp := &fakeDispatcher{}
	failing := func(_ context.Context, _, _, _ string) (string, error) { return "", errors.New("vault down") }

	processSSHCARotations(context.Background(), store, enc, disp, failing)

	assert.Empty(t, disp.calls)
	assert.Empty(t, store.updated)
}

func TestProcessSSHCARotations_PersistFails_NoEvent(t *testing.T) {
	enc := crypto.NewEncryptor("unit-test-master-secret")
	encTok, _ := enc.Encrypt("vault-token")
	orgID := uuid.New()

	store := &fakeSSHCAStore{
		rows: []repository.SSHCAReconcileRow{{
			OrgID: orgID, VaultAddr: "a", VaultMount: "ssh", EncryptedToken: encTok, CAPublicKey: ptr(genSSHPublicKey(t)),
		}},
		updateErr: errors.New("db down"),
	}
	disp := &fakeDispatcher{}

	processSSHCARotations(context.Background(), store, enc, disp, staticFetcher(genSSHPublicKey(t)))

	assert.Empty(t, disp.calls, "must not emit an event if the new key failed to persist")
}

func TestRotatePAMCredential_NilDispatcher_NoPanic(t *testing.T) {
	store := &fakeRotationStore{}
	enc := crypto.NewEncryptor("unit-test-master-secret")

	cred := repository.PAMCredential{
		ID:             uuid.New(),
		OrgID:          uuid.New(),
		Name:           "svc-token",
		CredentialType: "token",
	}

	err := rotatePAMCredential(context.Background(), store, enc, nil, cred)
	require.NoError(t, err)
	assert.Equal(t, 1, store.rotateCalls)
}

package ingressreconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
)

type fakeLister struct {
	mats []*repository.DomainCertMaterial
}

func (f *fakeLister) ListActiveForReconcile(context.Context) ([]*repository.DomainCertMaterial, error) {
	return f.mats, nil
}

// fakeDec "decrypts" by stripping a prefix, so tests avoid real crypto.
type fakeDec struct{ fail bool }

func (d *fakeDec) DecryptBytes(ct []byte) ([]byte, error) {
	if d.fail {
		return nil, errors.New("boom")
	}
	return append([]byte("KEY:"), ct...), nil
}

type fakeBackend struct{ applied []DesiredDomain }

func (b *fakeBackend) Apply(_ context.Context, d []DesiredDomain) error {
	b.applied = d
	return nil
}

func mat(domain, source string, keyEnc []byte) *repository.DomainCertMaterial {
	return &repository.DomainCertMaterial{Domain: domain, OrgID: uuid.New(), CertSource: source, CertPEM: "CERT", CertKeyEnc: keyEnc}
}

func TestReconcile_SkipsWildcardSubdomains(t *testing.T) {
	lister := &fakeLister{mats: []*repository.DomainCertMaterial{
		mat("acme.cloud.clavex.eu", "acme", nil), // default subdomain → skipped
		mat("auth.acme.com", "acme", nil),        // real custom domain → kept
	}}
	be := &fakeBackend{}
	r := New(lister, &fakeDec{}, be, Config{WildcardBase: "cloud.clavex.eu"})
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(be.applied) != 1 || be.applied[0].Host != "auth.acme.com" {
		t.Fatalf("expected only auth.acme.com, got %+v", be.applied)
	}
	if !be.applied[0].UseACME {
		t.Error("acme domain should use ACME")
	}
}

func TestReconcile_BYODecryptsAndBuildsSecret(t *testing.T) {
	lister := &fakeLister{mats: []*repository.DomainCertMaterial{
		mat("auth.acme.com", "byo", []byte("enc")),
	}}
	be := &fakeBackend{}
	r := New(lister, &fakeDec{}, be, Config{WildcardBase: "cloud.clavex.eu"})
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(be.applied) != 1 {
		t.Fatalf("want 1 domain, got %d", len(be.applied))
	}
	d := be.applied[0]
	if d.UseACME {
		t.Error("byo domain must not use ACME")
	}
	if d.KeyPEM != "KEY:enc" {
		t.Errorf("key not decrypted: %q", d.KeyPEM)
	}
	if d.CertPEM != "CERT" || d.SecretName == "" {
		t.Errorf("byo cert material missing: %+v", d)
	}
}

func TestReconcile_UndecryptableKeySkipped(t *testing.T) {
	lister := &fakeLister{mats: []*repository.DomainCertMaterial{
		mat("bad.acme.com", "byo", []byte("enc")),
		mat("good.acme.com", "acme", nil),
	}}
	be := &fakeBackend{}
	r := New(lister, &fakeDec{fail: true}, be, Config{WildcardBase: "cloud.clavex.eu"})
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The BYO row with a bad key is skipped; the ACME one survives.
	if len(be.applied) != 1 || be.applied[0].Host != "good.acme.com" {
		t.Fatalf("undecryptable BYO row must be skipped: %+v", be.applied)
	}
}

func TestSecretNameStable(t *testing.T) {
	if secretName("auth.acme.com") != secretName("auth.acme.com") {
		t.Error("secretName must be deterministic")
	}
	if secretName("a.com") == secretName("b.com") {
		t.Error("distinct hosts must yield distinct secret names")
	}
}

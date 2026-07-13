package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"testing"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/require"
)

// These tests exercise per-org signing-key auto-provisioning. They require a
// migrated Postgres via TEST_DATABASE_URL and are skipped otherwise.
//
// They deliberately avoid NewDBSigner: the shared CI database may already hold a
// global signing key encrypted with a different KEK, which NewDBSigner would try
// (and fail) to decrypt. A stub global Signer is used instead — For() only falls
// back to it when auto-provisioning is disabled, which is exactly what we test.
//
//	TEST_DATABASE_URL=postgres://...@localhost/clavex_test go test ./internal/oidc/ -run TestOrgSigner

func orgSignerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed org signer tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path = identity, sessions, audit, public`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func testKEK() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func newTestOrg(t *testing.T, ctx context.Context, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	orgs := repository.NewOrgRepository(pool)
	o, err := orgs.Create(ctx, "orgsigner-"+uuid.NewString(), "orgsigner-"+uuid.NewString(), nil)
	require.NoError(t, err)
	return o.ID
}

// testRSAPKCS8 returns a fresh RSA-2048 private key encoded as PKCS#8 DER.
func testRSAPKCS8(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return der
}

// stubSigner is an in-memory Signer used as the cache's "global" fallback so
// tests do not touch the shared global DB key.
type stubSigner struct {
	priv *rsa.PrivateKey
	kid  string
}

func newStubSigner(t *testing.T, kid string) *stubSigner {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &stubSigner{priv: priv, kid: kid}
}

func (s *stubSigner) PrivateKey() *rsa.PrivateKey       { return s.priv }
func (s *stubSigner) PublicKey() *rsa.PublicKey         { return &s.priv.PublicKey }
func (s *stubSigner) KID() string                       { return s.kid }
func (s *stubSigner) JWKS() []byte                      { return []byte(`{"keys":[]}`) }
func (s *stubSigner) Algorithm() jwa.SignatureAlgorithm { return jwa.PS256 }
func (s *stubSigner) CryptoSigner() crypto.Signer       { return s.priv }
func (s *stubSigner) Rotate() error                     { return nil }

// TestOrgSigner_ForAutoProvisions verifies that For() on an org without a key
// mints a fresh org-specific key instead of falling back to the global signer.
func TestOrgSigner_ForAutoProvisions(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()

	cache := NewOrgSignerCacheFromKEK(pool, testKEK(), newStubSigner(t, "global-stub"))
	orgID := newTestOrg(t, ctx, pool)

	s := cache.For(ctx, orgID)
	require.NotEqual(t, "global-stub", s.KID(), "org must sign with its own key, not the global fallback")

	// A real active org key row must now exist, tagged 'generated'.
	repo := repository.NewSigningKeyRepository(pool)
	src, err := repo.GetActiveKeySourceForOrg(ctx, orgID)
	require.NoError(t, err)
	require.Equal(t, "generated", src)

	// The org's own kid is published in its JWKS.
	require.Contains(t, string(s.JWKS()), s.KID())
}

// TestOrgSigner_DisableAutoProvisionFallsBackToGlobal verifies the opt-out path.
func TestOrgSigner_DisableAutoProvisionFallsBackToGlobal(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()

	cache := NewOrgSignerCacheFromKEK(pool, testKEK(), newStubSigner(t, "global-stub")).DisableAutoProvision()
	orgID := newTestOrg(t, ctx, pool)

	s := cache.For(ctx, orgID)
	require.Equal(t, "global-stub", s.KID(), "with auto-provision disabled, For() must return the global signer")

	repo := repository.NewSigningKeyRepository(pool)
	_, err := repo.GetActiveForOrg(ctx, orgID)
	require.ErrorIs(t, err, pgx.ErrNoRows)
}

// TestOrgSigner_GenerateForOrgIsDistinctPerOrg verifies each org gets its own
// distinct key (the shape the backfill relies on).
func TestOrgSigner_GenerateForOrgIsDistinctPerOrg(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()

	cache := NewOrgSignerCacheFromKEK(pool, testKEK(), newStubSigner(t, "global-stub"))
	orgA := newTestOrg(t, ctx, pool)
	orgB := newTestOrg(t, ctx, pool)

	kidA, err := cache.GenerateForOrg(ctx, orgA)
	require.NoError(t, err)
	kidB, err := cache.GenerateForOrg(ctx, orgB)
	require.NoError(t, err)
	require.NotEqual(t, kidA, kidB, "distinct orgs must get distinct keys")

	require.Contains(t, string(cache.For(ctx, orgA).JWKS()), kidA)
	require.Contains(t, string(cache.For(ctx, orgB).JWKS()), kidB)
}

// TestOrgSigner_ImportedTaggedImported verifies imported keys are tagged so the
// rotation worker never regenerates them.
func TestOrgSigner_ImportedTaggedImported(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()
	repo := repository.NewSigningKeyRepository(pool)

	cache := NewOrgSignerCacheFromKEK(pool, testKEK(), newStubSigner(t, "global-stub"))
	orgID := newTestOrg(t, ctx, pool)

	_, err := cache.GenerateForOrg(ctx, orgID)
	require.NoError(t, err)
	src, err := repo.GetActiveKeySourceForOrg(ctx, orgID)
	require.NoError(t, err)
	require.Equal(t, "generated", src)

	_, err = cache.ImportForOrg(ctx, orgID, testRSAPKCS8(t))
	require.NoError(t, err)
	src, err = repo.GetActiveKeySourceForOrg(ctx, orgID)
	require.NoError(t, err)
	require.Equal(t, "imported", src)
}

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// DB-backed tests for BYO-cert custom domain methods. Reuse idorPool / twoOrgs;
// skipped without TEST_DATABASE_URL.

func TestCustomDomain_BYOCertLifecycle(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	repo := NewCustomDomainRepository(pool)

	d, err := repo.Create(ctx, orgA, "auth-"+shortID()+".acme.test")
	require.NoError(t, err)
	require.Equal(t, "acme", d.CertSource, "new domain defaults to acme")
	require.Equal(t, "pending", d.Status)

	// Cross-org SetBYOCert is rejected.
	exp := time.Now().Add(90 * 24 * time.Hour)
	require.ErrorIs(t, repo.SetBYOCert(ctx, d.ID, orgB, "certpem", []byte("enc"), &exp), pgx.ErrNoRows)

	// Owning org stores the BYO cert → source flips to byo.
	require.NoError(t, repo.SetBYOCert(ctx, d.ID, orgA, "certpem", []byte("enc-key"), &exp))
	got, err := repo.GetByDomain(ctx, d.Domain)
	require.NoError(t, err)
	require.Equal(t, "byo", got.CertSource)
	require.NotNil(t, got.CertExpiry)

	// Activate so the reconciler picks it up, then verify cert material is returned.
	require.NoError(t, repo.Activate(ctx, d.ID, &exp))
	mats, err := repo.ListActiveForReconcile(ctx)
	require.NoError(t, err)
	var found *DomainCertMaterial
	for _, m := range mats {
		if m.Domain == d.Domain {
			found = m
		}
	}
	require.NotNil(t, found, "active byo domain must appear in reconcile list")
	require.Equal(t, "byo", found.CertSource)
	require.Equal(t, "certpem", found.CertPEM)
	require.Equal(t, []byte("enc-key"), found.CertKeyEnc)

	// Revert to ACME clears the cert material.
	require.NoError(t, repo.RevertToACME(ctx, d.ID, orgA))
	got2, err := repo.GetByDomain(ctx, d.Domain)
	require.NoError(t, err)
	require.Equal(t, "acme", got2.CertSource)
}

func shortID() string {
	return time.Now().Format("150405.000000")
}

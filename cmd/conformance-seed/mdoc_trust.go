package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/walletsigning"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedMdocTrust explicitly provisions only the existing conformance issuer's
// public IACA. Never enable trust from an untrusted credential, or reactivate an
// anchor an operator has disabled. No DS key or certificate is replaced here.
func seedMdocTrust(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) error {
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT conformance_mode FROM organizations WHERE id=$1 AND slug=$2`, orgID, orgSlug).Scan(&enabled); err != nil || !enabled {
		return fmt.Errorf("mdoc trust provisioning requires the existing conformance organisation")
	}
	issuer, err := repository.NewMdocIssuerRepository(pool).GetActiveByDocType(ctx, orgID, mdoc.DocTypeMdl)
	if err != nil {
		return err
	}
	if issuer == nil || issuer.IACACertificatePEM == nil {
		return fmt.Errorf("configured conformance mDL issuer and IACA are required")
	}
	if _, _, err = walletsigning.Certificates(issuer.DSCertificatePEM, issuer.IACACertificatePEM, true); err != nil {
		return fmt.Errorf("invalid conformance DS/IACA chain: %w", err)
	}
	// Certificates has already validated the leaf-first CA chain. The last
	// public certificate is its root; intermediates are carried by IssuerAuth.
	rest := []byte(strings.TrimSpace(*issuer.IACACertificatePEM))
	var root *x509.Certificate
	for len(rest) > 0 {
		block, tail := pem.Decode(rest)
		if block == nil {
			return fmt.Errorf("invalid conformance IACA PEM")
		}
		root, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		rest = []byte(strings.TrimSpace(string(tail)))
	}
	if root == nil {
		return fmt.Errorf("missing conformance IACA root")
	}
	hash := sha256.Sum256(root.Raw)
	fingerprint := hex.EncodeToString(hash[:])
	repo := repository.NewIACARepository(pool)
	roots, err := repo.List(ctx, orgID)
	if err != nil {
		return err
	}
	for _, existing := range roots {
		if existing.SHA256Fingerprint == fingerprint {
			supported := len(existing.DocTypes) == 0
			for _, docType := range existing.DocTypes {
				supported = supported || docType == mdoc.DocTypeMdl
			}
			if !existing.IsActive || !supported {
				return fmt.Errorf("existing conformance IACA is disabled or excludes mDL; explicit operator review required")
			}
			return nil
		}
	}
	_, err = repo.Create(ctx, orgID, "Conformance mDL IACA", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})), []string{mdoc.DocTypeMdl}, nil)
	return err
}

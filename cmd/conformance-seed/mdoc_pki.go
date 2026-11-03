package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // ISO 18013-5 SKI identifier, not a signature or security hash.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/walletsigning"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func mdocKeyID(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err = asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	//nolint:gosec // Annex B specifies SHA-1 over subjectPublicKey for SKI.
	sum := sha1.Sum(spki.PublicKey.Bytes)
	return sum[:], nil
}

func mdocFixtureCertificates(rootKey, dsKey *ecdsa.PrivateKey, issuer string, now time.Time) (*x509.Certificate, *x509.Certificate, error) {
	keyID, err := mdocKeyID(rootKey)
	if err != nil {
		return nil, nil, err
	}
	contact, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte(issuer)}})
	if err != nil {
		return nil, nil, err
	}
	ian := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 18}, Value: contact}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	serial.Add(serial, big.NewInt(1))
	rootTemplate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Clavex conformance test IACA", Country: []string{"IT"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(9 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: keyID, ExtraExtensions: []pkix.Extension{ian}}
	der, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	fingerprint := sha256.Sum256(root.Raw)
	crlURL := issuer + "/oid4vci/iaca-crl/" + hex.EncodeToString(fingerprint[:])
	dsID, err := mdocKeyID(dsKey)
	if err != nil {
		return nil, nil, err
	}
	serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	serial.Add(serial, big.NewInt(1))
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 2}})
	if err != nil {
		return nil, nil, err
	}
	dsTemplate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Clavex conformance test mDL DS", Country: []string{"IT"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: dsID, CRLDistributionPoints: []string{crlURL}, ExtraExtensions: []pkix.Extension{ian, {Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}}
	der, err = x509.CreateCertificate(rand.Reader, dsTemplate, root, &dsKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	ds, err := x509.ParseCertificate(der)
	return root, ds, err
}

// Explicit laboratory-only provisioning. Never call this from the full seed or
// normal application startup: certificate replacement changes public trust.
func seedMdocPKI(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID, keyDir, base string, crlOnly bool) error {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("fixture-base-url must be an explicit HTTPS origin")
	}
	issuer := strings.TrimSuffix(base, "/") + "/" + orgSlug
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var enabled bool
	if err = tx.QueryRow(ctx, `SELECT conformance_mode FROM identity.organizations WHERE id=$1 AND slug=$2 FOR UPDATE`, org, orgSlug).Scan(&enabled); err != nil || !enabled {
		return fmt.Errorf("test PKI provisioning requires the existing conformance tenant")
	}
	configured, err := repository.NewMdocIssuerRepository(tx).GetActiveByDocType(ctx, org, mdoc.DocTypeMdl)
	if err != nil {
		return err
	}
	if configured == nil || configured.IACACertificatePEM == nil || configured.VaultSignerRef != "" {
		return fmt.Errorf("existing local conformance DS and IACA required; Vault issuers are not changed")
	}
	rootPEM := *configured.IACACertificatePEM
	rawKey, err := os.ReadFile(filepath.Join(keyDir, "mdoc-iaca-private-key.pem"))
	if err != nil {
		return err
	}
	rootSigner, err := walletsigning.LocalKey(rootPEM, string(rawKey))
	if err != nil {
		return fmt.Errorf("local IACA key does not match configured IACA: %w", err)
	}
	rootKey, ok := rootSigner.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("test IACA must use an EC key")
	}
	dsPEM := configured.DSCertificatePEM
	if !crlOnly {
		rawDSKey, err := os.ReadFile(filepath.Join(keyDir, "mdoc-ds-private-key.pem"))
		if err != nil {
			return err
		}
		signer, err := walletsigning.LocalKey(dsPEM, string(rawDSKey))
		if err != nil {
			return fmt.Errorf("local DS key does not match configured DS: %w", err)
		}
		dsKey, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("test DS must use an EC key")
		}
		root, ds, err := mdocFixtureCertificates(rootKey, dsKey, issuer, time.Now().UTC())
		if err != nil {
			return err
		}
		rootPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
		dsPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ds.Raw}))
	}
	// Reparse the selected certificate to avoid shadowing the original root.
	rootBlock, _ := pem.Decode([]byte(rootPEM))
	if rootBlock == nil {
		return fmt.Errorf("missing IACA certificate")
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return err
	}
	fp := sha256.Sum256(root.Raw)
	fingerprint := hex.EncodeToString(fp[:])
	crls := repository.NewMdocCRLRepository(tx)
	number, err := crls.NextNumber(ctx, org, fingerprint)
	if err != nil {
		return err
	}
	var previous []byte
	err = tx.QueryRow(ctx, `SELECT der FROM identity.mdoc_iaca_crls WHERE org_id=$1 AND fingerprint=$2`, org, fingerprint).Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var entries []x509.RevocationListEntry
	if len(previous) > 0 {
		old, err := x509.ParseRevocationList(previous)
		if err != nil {
			return err
		}
		if err = old.CheckSignatureFrom(root); err != nil {
			return err
		}
		entries = old.RevokedCertificateEntries
	}
	now := time.Now().UTC().Truncate(time.Second)
	next := now.Add(7 * 24 * time.Hour)
	if root.NotAfter.Before(next) {
		next = root.NotAfter
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: now, NextUpdate: next, RevokedCertificateEntries: entries}, root, rootKey)
	if err != nil {
		return err
	}
	if _, err = crls.Put(ctx, org, root, der); err != nil {
		return err
	}
	if !crlOnly {
		if _, _, err = walletsigning.Certificates(dsPEM, &rootPEM, false); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE identity.org_mdoc_issuers SET ds_certificate_pem=$3,iaca_certificate_pem=$4,updated_at=NOW() WHERE id=$1 AND org_id=$2`, configured.ID, org, dsPEM, rootPEM)
		if err != nil {
			return err
		}
		// Keep historical roots active. Never reactivate a disabled trust anchor.
		var active bool
		err = tx.QueryRow(ctx, `INSERT INTO identity.org_iaca_roots(org_id,label,subject_dn,sha256_fingerprint,pem,doc_types) VALUES($1,'Conformance profile mDL IACA',$2,$3,$4,$5)
 ON CONFLICT(org_id,sha256_fingerprint) DO UPDATE SET label=identity.org_iaca_roots.label RETURNING is_active`, org, root.Subject.String(), fingerprint, rootPEM, []string{mdoc.DocTypeMdl}).Scan(&active)
		if err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("target IACA is disabled; explicit trust review required")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	// Public certificate cache only; private key files are never overwritten.
	if !crlOnly {
		for name, data := range map[string]string{"mdoc-iaca-cert.pem": rootPEM, "mdoc-ds-cert.pem": dsPEM} {
			if err = os.WriteFile(filepath.Join(keyDir, name), []byte(data), 0o644); err != nil {
				return fmt.Errorf("DB committed; repair public certificate cache: %w", err)
			}
		}
		for _, name := range []string{"oid4vci-issuer-mso-mdoc-plan.json", "oid4vci-issuer-mso-mdoc-encrypted-plan.json"} {
			path := filepath.Join(keyDir, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("DB committed; update mdoc plan trust manually: %w", err)
			}
			var plan map[string]any
			if err = json.Unmarshal(raw, &plan); err != nil {
				return err
			}
			credential, ok := plan["credential"].(map[string]any)
			if !ok {
				return fmt.Errorf("mdoc plan has no credential configuration")
			}
			credential["trust_anchor_pem"] = rootPEM
			raw, err = json.MarshalIndent(plan, "", "  ")
			if err != nil {
				return err
			}
			if err = os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
				return err
			}
		}
	}
	fmt.Printf("Conformance IACA CRL published: %s/oid4vci/iaca-crl/%s; number %d; next update %s\n", issuer, fingerprint, number, next.Format(time.RFC3339))
	return nil
}

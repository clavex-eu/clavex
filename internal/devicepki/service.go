// Package devicepki orchestrates the Device CA used to authenticate IoT
// device fleets to an external MQTT broker via mTLS. It is the X.509
// counterpart to internal/sshca (which orchestrates the Vault SSH CA for PAM)
// — same Vault-backed-CA custody pattern, deliberately separate
// implementation, separate Vault PKI mounts, so the two CAs never share a
// blast radius.
//
// Subject CN is fixed by the external broker's client-auth contract to
// "<deviceID>@<orgID>".
package devicepki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/connector"
	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/vaultpki"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Sentinel errors surfaced to callers (handlers map these to HTTP statuses).
var (
	ErrNotConfigured      = errors.New("Device CA not configured")
	ErrInvalidCSR         = errors.New("invalid certificate signing request")
	ErrCNMismatch         = errors.New("CSR common name does not match expected device identity")
	ErrDeviceNotActive    = errors.New("device is not active")
	ErrCertificateInvalid = errors.New("certificate is not active")
	// ErrVaultMountCapability mirrors sshca's operator-facing capability error.
	ErrVaultMountCapability = errors.New(`missing sys/mounts capability required for Device CA rotation: grant Clavex's Vault token a policy including path "sys/mounts/*" { capabilities = ["create", "read", "delete"] } and try again`)
)

// Dispatcher is the connector/webhook subset the service needs.
type Dispatcher interface {
	Dispatch(orgID uuid.UUID, event string, data any)
}

// Service performs Device CA enrollment, renewal, revocation and rotation.
type Service struct {
	repo *repository.DevicePKIRepository
	enc  *crypto.Encryptor
	disp Dispatcher
}

// NewService builds the service. disp may be nil (events skipped).
func NewService(repo *repository.DevicePKIRepository, enc *crypto.Encryptor, disp Dispatcher) *Service {
	return &Service{repo: repo, enc: enc, disp: disp}
}

// DefaultGracePeriod is the window the retired CA stays trusted after a
// rotation Complete — matches sshca.DefaultGracePeriod for operational
// consistency across Clavex's Vault-backed CAs.
const DefaultGracePeriod = 72 * time.Hour

func (s *Service) tokenFor(ctx context.Context, orgID uuid.UUID) (*repository.DeviceCAConfig, string, error) {
	cfg, encToken, err := s.repo.GetDeviceCAConfigWithToken(ctx, orgID)
	if err != nil || cfg == nil {
		return nil, "", ErrNotConfigured
	}
	token, err := s.enc.Decrypt(encToken)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt vault token: %w", err)
	}
	return cfg, token, nil
}

// expectedCN builds the external, non-negotiable CN contract the MQTT broker
// requires: "<deviceID>@<orgID>".
func expectedCN(deviceExternalID string, orgID uuid.UUID) string {
	return deviceExternalID + "@" + orgID.String()
}

// parseCSR decodes a PEM PKCS#10 CSR, verifies its self-signature (proving
// possession of the matching private key — the private key itself never
// crosses the network), and checks its CN matches wantCN exactly.
func parseCSR(csrPEM []byte, wantCN string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return nil, ErrInvalidCSR
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature invalid: %v", ErrInvalidCSR, err)
	}
	if csr.Subject.CommonName != wantCN {
		return nil, ErrCNMismatch
	}
	return csr, nil
}

// EnrollResult is what a device receives on successful enrollment/renewal.
type EnrollResult struct {
	CertificatePEM string
	IssuingCAPEM   string
	SerialNumber   string
	NotAfter       time.Time
}

// Enroll consumes a one-time bootstrap secret and a CSR to mint the device's
// first certificate. The secret's "used" transition and the certificate
// insert happen in one DB transaction, so there is never a window where the
// secret is still valid in parallel with an already-issued certificate.
func (s *Service) Enroll(ctx context.Context, orgID uuid.UUID, deviceExternalID, rawSecret string, csrPEM []byte) (*EnrollResult, error) {
	cfg, token, err := s.tokenFor(ctx, orgID)
	if err != nil {
		return nil, err
	}

	dev, err := s.repo.GetDeviceByExternalID(ctx, orgID, deviceExternalID)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, repository.ErrDeviceNotFound
	}

	wantCN := expectedCN(deviceExternalID, orgID)
	csr, err := parseCSR(csrPEM, wantCN)
	if err != nil {
		return nil, err
	}

	tx, err := s.repo.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	secret, err := s.repo.LockPendingSecretForDeviceTx(ctx, tx, orgID, dev.ID)
	if err != nil {
		return nil, err
	}
	if time.Now().After(secret.ExpiresAt) {
		return nil, repository.ErrEnrollmentSecretExpired
	}
	if !secret.VerifySecret(rawSecret) {
		return nil, repository.ErrEnrollmentSecretMismatch
	}

	signed, err := vaultpki.SignCSR(ctx, cfg.VaultAddr, cfg.VaultMount, cfg.VaultRole, token,
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})),
		wantCN, cfg.CertTTLSeconds)
	if err != nil {
		return nil, fmt.Errorf("vault pki sign: %w", err)
	}
	issued, serial, err := parseIssuedCertificate(signed.CertificatePEM)
	if err != nil {
		return nil, err
	}

	if err := s.repo.MarkSecretUsedTx(ctx, tx, secret.ID); err != nil {
		return nil, err
	}
	cert, err := s.repo.InsertCertificateTx(ctx, tx, repository.InsertCertParams{
		OrgID:        orgID,
		DeviceID:     dev.ID,
		SerialNumber: serial,
		CN:           wantCN,
		NotBefore:    issued.NotBefore,
		NotAfter:     issued.NotAfter,
	})
	if err != nil {
		return nil, err
	}
	if err := s.repo.MarkDeviceEnrolledTx(ctx, tx, dev.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	connector.Dispatch(orgID.String(), connector.EventDeviceEnrolled, map[string]any{
		"device_id": deviceExternalID,
		"tenant_id": orgID.String(),
		"serial":    cert.SerialNumber,
	})

	return &EnrollResult{
		CertificatePEM: signed.CertificatePEM,
		IssuingCAPEM:   signed.IssuingCAPEM,
		SerialNumber:   cert.SerialNumber,
		NotAfter:       cert.NotAfter,
	}, nil
}

// parseIssuedCertificate parses Vault's returned leaf certificate and derives
// its canonical serial via FormatSerial — never trust Vault's own
// "serial_number" response string verbatim, since it must match byte-for-byte
// whatever a client independently derives from cert.SerialNumber when it
// presents this same certificate over TLS at renewal time.
func parseIssuedCertificate(certPEM string) (*x509.Certificate, string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, "", fmt.Errorf("parse issued certificate: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse issued certificate: %w", err)
	}
	return cert, FormatSerial(cert.SerialNumber), nil
}

// EnsureMountProvisioned provisions the Vault PKI mount + root CA + device
// signing role on first save of an org's Device CA config, and caches the CA
// certificate. On subsequent saves (CA cert already cached), it only
// re-applies the signing role so TTL/role changes take effect without
// re-provisioning the mount. vaultToken is the plaintext token (the caller
// has just encrypted it for storage; this avoids an immediate decrypt
// round-trip).
func (s *Service) EnsureMountProvisioned(ctx context.Context, orgID uuid.UUID, vaultAddr, vaultToken, mount, role string, ttlSeconds int) error {
	cfg, err := s.repo.GetDeviceCAConfig(ctx, orgID)
	if err != nil {
		return err
	}
	if cfg != nil && cfg.CACertificatePEM != nil && *cfg.CACertificatePEM != "" {
		return vaultpki.ConfigureDeviceRole(ctx, vaultAddr, mount, role, vaultToken, ttlSeconds)
	}
	if err := vaultpki.EnablePKIMount(ctx, vaultAddr, mount, vaultToken); err != nil {
		return fmt.Errorf("enable vault PKI mount: %w", err)
	}
	caCert, err := vaultpki.GenerateRootCA(ctx, vaultAddr, mount, vaultToken,
		fmt.Sprintf("Clavex Device CA - %s", orgID), 87600*3600)
	if err != nil {
		return fmt.Errorf("generate root CA: %w", err)
	}
	if err := vaultpki.ConfigureDeviceRole(ctx, vaultAddr, mount, role, vaultToken, ttlSeconds); err != nil {
		return fmt.Errorf("configure device signing role: %w", err)
	}
	return s.repo.UpdateDeviceCACertificate(ctx, orgID, caCert)
}

// BuildClientCAPool builds the union x509.CertPool of every org's cached
// Device CA certificate, for the dedicated renewal mTLS listener's
// tls.Config.ClientCAs. Accepting a handshake against this pool only proves
// "signed by SOME org's Device CA" — callers MUST still call
// VerifyPresentedCertForOrg against the specific tenant named in the
// presented cert's own CN before trusting it for anything.
func (s *Service) BuildClientCAPool(ctx context.Context) (*x509.CertPool, error) {
	pems, err := s.repo.ListActiveCACertificates(ctx)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, p := range pems {
		pool.AppendCertsFromPEM([]byte(p))
	}
	return pool, nil
}

// VerifyPresentedCertForOrg re-verifies a presented client certificate's chain
// against THAT SPECIFIC org's Device CA certificate — not just "chained to
// some member of the listener's union CA pool". This is required
// defense-in-depth: the dedicated renewal listener's tls.Config.ClientCAs is a
// union across every org's Device CA (a single port serves every tenant), so
// generic pool verification alone would accept a cert legitimately signed by
// org A's CA whose CN merely *claims* to belong to org B.
func (s *Service) VerifyPresentedCertForOrg(ctx context.Context, orgID uuid.UUID, cert *x509.Certificate) error {
	cfg, err := s.repo.GetDeviceCAConfig(ctx, orgID)
	if err != nil {
		return err
	}
	if cfg == nil || cfg.CACertificatePEM == nil || *cfg.CACertificatePEM == "" {
		return ErrNotConfigured
	}
	return verifyCertAgainstCAPEM(cert, *cfg.CACertificatePEM, orgID.String())
}

// verifyCertAgainstCAPEM is the pure chain-verification core of
// VerifyPresentedCertForOrg, split out so it is unit-testable without a
// DB-backed repository — it does the actual "does this cert chain to THIS
// specific CA" check that must never be satisfied merely by "chains to some
// member of a multi-tenant union pool".
func verifyCertAgainstCAPEM(cert *x509.Certificate, caCertPEM, orgLabel string) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caCertPEM)) {
		return fmt.Errorf("org %s: failed to parse cached Device CA certificate", orgLabel)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("certificate does not chain to org %s's Device CA: %w", orgLabel, err)
	}
	return nil
}

// Renew authenticates the device by its currently-valid certificate (verified
// at the TLS layer and re-verified against the specific tenant's CA by the
// caller before this is invoked) and issues a fresh certificate for the same
// identity. No bootstrap secret or operator is involved — this must be able
// to run unattended indefinitely, like ACME/kubelet renewal.
func (s *Service) Renew(ctx context.Context, orgID uuid.UUID, presentedSerial, presentedCN string, csrPEM []byte) (*EnrollResult, error) {
	cfg, token, err := s.tokenFor(ctx, orgID)
	if err != nil {
		return nil, err
	}

	oldCert, err := s.repo.GetCertificateBySerial(ctx, orgID, presentedSerial)
	if err != nil {
		return nil, err
	}
	if oldCert == nil || oldCert.Status != repository.DeviceCertActive {
		return nil, ErrCertificateInvalid
	}
	if oldCert.CN != presentedCN {
		return nil, ErrCNMismatch
	}

	dev, err := s.repo.GetDevice(ctx, orgID, oldCert.DeviceID)
	if err != nil {
		return nil, err
	}
	if dev == nil || dev.Status != repository.DeviceStatusActive {
		return nil, ErrDeviceNotActive
	}

	csr, err := parseCSR(csrPEM, presentedCN)
	if err != nil {
		return nil, err
	}

	signed, err := vaultpki.SignCSR(ctx, cfg.VaultAddr, cfg.VaultMount, cfg.VaultRole, token,
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})),
		presentedCN, cfg.CertTTLSeconds)
	if err != nil {
		return nil, fmt.Errorf("vault pki sign: %w", err)
	}
	issued, serial, err := parseIssuedCertificate(signed.CertificatePEM)
	if err != nil {
		return nil, err
	}

	tx, err := s.repo.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := s.repo.SupersedeCertificateTx(ctx, tx, oldCert.ID); err != nil {
		return nil, err
	}
	cert, err := s.repo.InsertCertificateTx(ctx, tx, repository.InsertCertParams{
		OrgID:        orgID,
		DeviceID:     dev.ID,
		SerialNumber: serial,
		CN:           presentedCN,
		NotBefore:    issued.NotBefore,
		NotAfter:     issued.NotAfter,
	})
	if err != nil {
		return nil, err
	}
	if err := s.repo.MarkDeviceRenewedTx(ctx, tx, dev.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &EnrollResult{
		CertificatePEM: signed.CertificatePEM,
		IssuingCAPEM:   signed.IssuingCAPEM,
		SerialNumber:   cert.SerialNumber,
		NotAfter:       cert.NotAfter,
	}, nil
}

// RevokeCertificateBySerial revokes a single issued certificate: the real,
// immediate defense for a compromised device (unlike SSH CA rotation, "wait
// for expiry" is not acceptable here — this is field hardware with no TPM).
func (s *Service) RevokeCertificateBySerial(ctx context.Context, orgID uuid.UUID, serial, reason, revokedBy string) error {
	cert, err := s.repo.GetCertificateBySerial(ctx, orgID, serial)
	if err != nil {
		return err
	}
	if cert == nil {
		return ErrCertificateInvalid
	}
	if err := s.repo.RevokeCertificate(ctx, orgID, cert.ID, reason, revokedBy); err != nil {
		return err
	}

	// Best-effort: also revoke at Vault so its own CRL reflects it. Clavex's
	// own active-check at renewal + the connector event below are the primary
	// enforcement points, so a Vault-side failure here must not fail the call.
	if cfg, token, terr := s.tokenFor(ctx, orgID); terr == nil {
		if verr := vaultpki.RevokeCertificate(ctx, cfg.VaultAddr, cfg.VaultMount, token, serial); verr != nil {
			log.Warn().Err(verr).Str("org_id", orgID.String()).Str("serial", serial).
				Msg("devicepki: best-effort Vault revoke failed")
		}
	}

	deviceExternalID, _, _ := ParseCN(cert.CN)
	connector.Dispatch(orgID.String(), connector.EventDeviceCertRevoked, map[string]any{
		"device_id":  deviceExternalID,
		"tenant_id":  orgID.String(),
		"serial":     serial,
		"revoked_at": time.Now().UTC(),
		"reason":     reason,
	})
	return nil
}

// RevokeDevice is the "whole device stolen" convenience path: revokes every
// currently-active certificate for the device, flags the device itself
// revoked, and revokes any still-pending enrollment secret so it cannot be
// used to re-enroll a replacement under the same device_id.
func (s *Service) RevokeDevice(ctx context.Context, orgID, deviceID uuid.UUID, reason, revokedBy string) error {
	certs, err := s.repo.ListActiveCertificatesForDevice(ctx, orgID, deviceID)
	if err != nil {
		return err
	}
	for _, c := range certs {
		if err := s.RevokeCertificateBySerial(ctx, orgID, c.SerialNumber, reason, revokedBy); err != nil {
			return err
		}
	}
	return s.repo.SetDeviceStatus(ctx, orgID, deviceID, repository.DeviceStatusRevoked)
}

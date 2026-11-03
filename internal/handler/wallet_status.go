package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/fxamacker/cbor/v2"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
)

var errWalletStatusRejected = errors.New("credential status is invalid or required status is missing")
var errWalletStatusUnavailable = errors.New("credential status cannot be verified with the available resolver")

// All status decisions share the caller's approval/delivery transaction. Remote
// JWT lists require explicit tenant delegation; certificate CRLs use verified
// chain issuers and a transport that blocks private and special-use addresses.
func checkWalletStatus(ctx context.Context, repo *repository.OID4WRepository, org uuid.UUID, issuer string, settings map[string]interface{}, result *oid4w.VerificationResult, required bool) error {
	if result != nil && len(result.Credentials) > 0 {
		for _, credential := range result.Credentials {
			if credential.Result == nil || len(credential.Result.Credentials) > 0 {
				return errWalletStatusRejected
			}
			if err := checkWalletStatus(ctx, repo, org, issuer, settings, credential.Result, required); err != nil {
				return err
			}
		}
		result.StatusAssessment = "per_credential"
		result.RefreshDCQLClaims()
		return nil
	}
	// Re-read the policy under the caller's transaction lock; a stale request
	// snapshot must not bypass a concurrent policy tightening.
	certificateRequired := required
	locked, err := repo.LockWalletStatusPolicy(ctx, org)
	if errors.Is(err, pgx.ErrNoRows) {
		return errWalletStatusRejected
	}
	if err != nil {
		return errWalletStatusUnavailable
	}
	settings = locked
	if value, ok := settings["wallet_status_required"]; ok {
		flag, valid := value.(bool)
		if !valid {
			return errWalletStatusUnavailable
		}
		required = flag
	}
	if result == nil || result.Identity == nil {
		return errWalletStatusRejected
	}
	e := result.Identity
	if !e.ExpiresAt.IsZero() && !time.Now().Before(e.ExpiresAt) {
		return errWalletStatusRejected
	}

	if e.Format == "mso_mdoc" {
		if len(e.CertificateChains) == 0 || len(e.CertificateChains[0]) < 2 {
			return errWalletStatusRejected
		}
		chain := e.CertificateChains[0]
		if err := repo.LockActiveIACA(ctx, org, e.CredentialType, oid4w.CertificateFingerprint(chain[len(chain)-1])); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errWalletStatusRejected
			}
			return errWalletStatusUnavailable
		}
		assessment, err := oid4w.StatusResolverFor(ctx).CheckCertificateChain(ctx, org.String(), settings, e.CertificateChains, certificateRequired)
		if err != nil {
			if errors.Is(err, oid4w.ErrStatusUnavailable) {
				return errWalletStatusUnavailable
			}
			return errWalletStatusRejected
		}
		result.CertificateStatusAssessment = assessment
	}
	if len(e.Status) == 0 {
		if _, disclosed := result.Claims["status"]; disclosed {
			return fmt.Errorf("%w: status must be in the signed issuer JWT", errWalletStatusRejected)
		}
		if required {
			return errWalletStatusRejected
		}
		result.StatusAssessment = "missing_permitted"
		return nil // explicit compatibility policy; not an active-status assertion
	}
	ref, err := oid4w.ParseStatusClaim(e.Status)
	if err != nil {
		return fmt.Errorf("%w: unsupported or invalid status reference", errWalletStatusRejected)
	}
	prefix := strings.TrimRight(issuer, "/") + "/oid4vci/status-list/"
	local := (e.Format == "dc+sd-jwt" && e.Issuer == issuer && e.SignedByLocalIssuer) || (e.Format == "mso_mdoc" && e.IssuerTrusted && e.IssuerCOSEHash != "")
	if !local || !strings.HasPrefix(ref.StatusList.URI, prefix) {
		if !e.IssuerTrusted && (!e.SignedByLocalIssuer || e.Issuer != issuer) {
			return errWalletStatusRejected
		}
		sources, err := oid4w.StatusSources(settings)
		if err != nil {
			return errWalletStatusUnavailable
		}
		for _, source := range sources {
			if source.Format != e.Format || source.CredentialIssuer != e.Issuer || source.CredentialType != e.CredentialType {
				continue
			}
			for _, uri := range source.ListURIs {
				if uri != ref.StatusList.URI {
					continue
				}
				err := oid4w.StatusResolverFor(ctx).Check(ctx, org.String(), source, ref)
				if err == nil {
					result.StatusAssessment = "valid_remote"
					return nil
				}
				if errors.Is(err, oid4w.ErrStatusUnavailable) {
					return errWalletStatusUnavailable
				}
				return errWalletStatusRejected
			}
		}
		return errWalletStatusUnavailable
	}
	id, err := uuid.Parse(strings.TrimPrefix(ref.StatusList.URI, prefix))
	if err != nil {
		return errWalletStatusRejected
	}
	if ref.StatusList.URI != prefix+id.String() {
		return errWalletStatusRejected
	}
	parents, err := repo.CredentialStatusParents(ctx, org, e.IssuerJWTHash, e.IssuerCOSEHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errWalletStatusRejected
		}
		return errWalletStatusUnavailable
	}
	if err := oid4w.CheckStatusParents(ctx, org.String(), settings, parents); err != nil {
		if errors.Is(err, oid4w.ErrRevoked) || errors.Is(err, oid4w.ErrSuspended) {
			return errWalletStatusRejected
		}
		return errWalletStatusUnavailable
	}
	encoded, bits, err := repo.LockCredentialStatus(ctx, org, id, ref.StatusList.IDX, e.IssuerJWTHash, e.IssuerCOSEHash, e.CredentialType)
	if errors.Is(err, pgx.ErrNoRows) {
		return errWalletStatusRejected
	}
	if err != nil {
		return errWalletStatusUnavailable
	}
	list, err := oid4w.DecodeStatusListWithBits(encoded, bits)
	if err != nil {
		return errWalletStatusUnavailable
	}
	state, err := list.Get(ref.StatusList.IDX)
	if err != nil || state != oid4w.StatusValid {
		return errWalletStatusRejected
	}
	result.StatusAssessment = "valid_local"
	return nil
}

func walletStatusError(c echo.Context, err error) error {
	if errors.Is(err, errWalletStatusRejected) {
		return c.JSON(400, map[string]string{"error": "credential_status_invalid"})
	}
	return echo.ErrServiceUnavailable
}

// Record the stable issuer JWT digest and signed status pointer in the same
// transaction that allocated the slot and consumes the issuance authorization.
func (h *OID4VCIHandler) recordWalletCredential(ctx context.Context, org uuid.UUID, user *uuid.UUID, vct, raw string, format string, parents ...[]oid4w.StatusParent) error {
	if err := h.recordWalletCredentialState(ctx, org, user, vct, raw, format); err != nil {
		return err
	}
	var all []oid4w.StatusParent
	for _, set := range parents {
		all = append(all, set...)
	}
	encoded, err := json.Marshal(all)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		encoded = []byte(`[]`)
	}
	return h.repo.RecordCredentialParents(ctx, org, oid4w.HashToken(raw), encoded)
}
func (h *OID4VCIHandler) recordWalletCredentialState(ctx context.Context, org uuid.UUID, user *uuid.UUID, vct, raw string, format string) error {
	if format == "mso_mdoc" {
		verified, err := h.verifiedIssuedMdoc(ctx, org, vct, raw)
		if err != nil {
			return err
		}
		ref, err := oid4w.ParseStatusClaim(verified.Status)
		if err != nil {
			return err
		}
		list, err := uuid.Parse(ref.StatusList.URI[strings.LastIndex(ref.StatusList.URI, "/")+1:])
		if err != nil {
			return err
		}
		// The signed MSO's actual expiry is authoritative, including hour rounding.
		expires := &verified.ValidUntil
		return h.repo.RecordCredentialWithStatus(ctx, org, user, vct, oid4w.HashToken(raw), expires, repository.CredentialStatusBinding{ListID: list, Index: ref.StatusList.IDX, IssuerCOSEHash: verified.IssuerAuthHash})
	}
	issuer, _, _, err := oid4w.ParseSDJWT(raw)
	if err != nil {
		return err
	}
	// Signature was just created locally; extraction here retains signed fields.
	result, err := h.verifyLocalIssuedSDJWT(raw)
	if err != nil {
		return err
	}
	ref, err := oid4w.ParseStatusClaim(result.Identity.Status)
	if err != nil {
		return err
	}
	list, err := uuid.Parse(ref.StatusList.URI[strings.LastIndex(ref.StatusList.URI, "/")+1:])
	if err != nil {
		return err
	}
	expires := &result.Identity.ExpiresAt
	return h.repo.RecordCredentialWithStatus(ctx, org, user, vct, oid4w.HashToken(raw), expires, repository.CredentialStatusBinding{ListID: list, Index: ref.StatusList.IDX, IssuerJWTHash: oid4w.HashToken(issuer)})
}

// Keep the authoritative time check on the signed JWT when a database expiry
// was extended independently by legacy maintenance code.
func (h *OID4VCIHandler) checkDeferredCredentialStatus(ctx context.Context, org *models.Organization, cfg *models.CredentialConfig, raw string) error {
	if err := h.repo.LockCredentialDelivery(ctx, org.ID, oid4w.HashToken(raw)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errWalletStatusRejected
		}
		return errWalletStatusUnavailable
	}
	if cfg.CredentialFormat == "mso_mdoc" {
		verified, err := h.verifiedIssuedMdoc(ctx, org.ID, cfg.VCT, raw)
		if err != nil {
			return errWalletStatusRejected
		}
		result := &oid4w.VerificationResult{Claims: map[string]interface{}{}, Identity: &oid4w.VerifiedCredentialIdentity{Format: "mso_mdoc", Issuer: oid4w.MDOCIssuerIdentity(verified.IssuerCert), CredentialType: verified.DocType, ExpiresAt: verified.ValidUntil, IssuerTrusted: true, Status: verified.Status, CertificateChains: verified.VerifiedChains, IssuerCOSEHash: verified.IssuerAuthHash}}
		return checkWalletStatus(ctx, h.repo, org.ID, h.cfg.BaseURL()+"/"+org.Slug, org.Settings, result, true)
	}
	result, err := h.verifyLocalIssuedSDJWT(raw)
	if err != nil {
		return errWalletStatusRejected
	}
	if result.Identity.Issuer != h.cfg.BaseURL()+"/"+org.Slug || result.Identity.CredentialType != cfg.VCT {
		return errWalletStatusRejected
	}
	return checkWalletStatus(ctx, h.repo, org.ID, h.cfg.BaseURL()+"/"+org.Slug, org.Settings, result, true)
}

// Deferred delivery must continue to recognise both previously issued local
// credentials and credentials made with the configured dedicated signing key.
// No key embedded in the credential is ever used as a trust anchor.
func (h *OID4VCIHandler) verifyLocalIssuedSDJWT(raw string) (*oid4w.VerificationResult, error) {
	result, err := oid4w.VerifyLocalIssuedCredential(raw, h.keys.CryptoSigner().Public())
	if err == nil || h.credentialSigner == nil {
		return result, err
	}
	result, err = oid4w.VerifyLocalIssuedCredential(raw, h.credentialSigner.CryptoSigner().Public())
	if err != nil {
		return nil, err
	}
	_, end, err := h.credentialSigner.MetadataCertificateChain(result.Identity.Issuer)
	if err != nil {
		return nil, err
	}
	start, _ := h.credentialSigner.CertificateValidity()
	if result.Identity.IssuedAt.Before(start) || result.Identity.ExpiresAt.After(end) {
		return nil, errWalletStatusRejected
	}
	return result, nil
}

func (h *OID4VCIHandler) verifiedIssuedMdoc(ctx context.Context, org uuid.UUID, docType, raw string) (*mdoc.VerifiedDocument, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var signed mdoc.IssuerSigned
	if err := cbor.Unmarshal(data, &signed); err != nil {
		return nil, err
	}
	roots, err := h.repo.LockIACAPool(ctx, org, docType)
	if err != nil {
		return nil, err
	}
	verified, errs := mdoc.VerifyDeviceResponse(&mdoc.DeviceResponse{Version: "1.0", Status: 0, Documents: []mdoc.Document{{DocType: docType, IssuerSigned: signed}}}, mdoc.VerificationOptions{TrustedRoots: roots, RequireTrustedIssuer: true})
	if len(errs) > 0 || len(verified) != 1 {
		return nil, fmt.Errorf("invalid locally issued mdoc")
	}
	return verified[0], nil
}

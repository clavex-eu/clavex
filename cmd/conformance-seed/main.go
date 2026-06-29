// cmd/conformance-seed seeds clavex with the org, test user, and OIDC client
// required by the OpenID Connect Conformance Suite.
//
// Usage:
//
//	go run ./cmd/conformance-seed [--config path/to/config.yaml]
//
// Or via Make:
//
//	make conformance-setup
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/db"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/crypto/bcrypt"
)

const (
	orgSlug      = "conformance"
	orgName      = "OIDC Conformance"
	testEmail    = "testuser@conformance.local"
	testPassword = "TestUser1!"
	testFirst    = "Test"
	testLast     = "User"

	clientID     = "conformance-client"
	clientSecret = "conformance-secret-12345"

	// clientPost is a dedicated client for oidcc-test-plan with
	// client_auth_type=client_secret_post. The suite validates that
	// token_endpoint_auth_method matches the plan variant, so a separate
	// client is required — the primary client uses client_secret_basic.
	clientPostID     = "conformance-client-post"
	clientPostSecret = "conformance-secret-post-abcde"

	// client2 is a DISTINCT second client used by the conformance suite to verify
	// that refresh tokens (and other artefacts) are correctly bound to the issuing
	// client.  It MUST have a different client_id from the primary client so the
	// server can reject cross-client token use (RFC 6749 §4.1.2).
	client2ID     = "conformance-client-2"
	client2Secret = "conformance-secret-2-67890"

	// fapiClientID is a private_key_jwt client for FAPI 2.0 conformance plans.
	// It has NO client_secret; authentication uses a JWT signed with the private
	// key generated at seed time. The public key is stored inline (jwks column).
	fapiClientID = "conformance-client-fapi"

	// fapi2ClientID is the second private_key_jwt client required by FAPI2
	// conformance tests that verify cross-client token binding (e.g.
	// user-rejects-authentication). It shares the same public JWKS as fapiClientID
	// so the tester only needs one private key file.
	fapi2ClientID = "conformance-client-fapi-2"

	// cibaClientID is the CIBA-poll private_key_jwt client.
	// It shares the FAPI RSA key (same key file, different client_id) so the
	// tester only needs to configure one key for both FAPI and CIBA plans.
	cibaClientID = "conformance-client-ciba"

	// cibaClient2ID is the second CIBA-poll client required by fapi-ciba-id1-test-plan.
	// Uses fapi2ClientID's key (pub2JWKSBytes) so keypairs are distinct.
	// Both CIBA clients carry tls_client_certificate_bound_access_tokens=true.
	cibaClient2ID = "conformance-client-ciba-2"

	// fapiDpopClientID / fapi2DpopClientID are DPoP-specific variants of the
	// FAPI clients used by fapi2-baseline-dpop-plan.json.
	// They share the same RSA key-pair files as fapiClientID / fapi2ClientID
	// but carry dpop_bound_access_tokens=true so the token endpoint enforces
	// DPoP regardless of auth-code binding (RFC 9449 §5).
	// These clients do NOT enforce JAR — the FAPI2 Security Profile basic plan
	// always runs with fapi_request_method=unsigned (FAPI2SPID2TestPlan.java).
	fapiDpopClientID  = "conformance-client-fapi-dpop"
	fapi2DpopClientID = "conformance-client-fapi-dpop-2"

	// fapiDpopJarClientID / fapi2DpopJarClientID are DPoP clients used by
	// fapi2-message-signing-plan.json (JARM plan).  They enforce JAR via
	// request_object_signing_alg=PS256 so the PAR endpoint rejects unsigned
	// requests, as tested by FAPI2SPID2EnsureUnsignedRequestAtParEndpointFails.
	fapiDpopJarClientID  = "conformance-client-fapi-dpop-jar"
	fapi2DpopJarClientID = "conformance-client-fapi-dpop-jar-2"

	// oid4vciWalletClientID is the OID4VCI issuer conformance wallet client.
	// It uses private_key_jwt with the FAPI key and DPoP-bound access tokens.
	oid4vciWalletClientID = "conformance-oid4vci-wallet"

	// oid4vciWallet2ClientID is the second OID4VCI wallet client required by
	// oid4vci-1_0-issuer-happy-flow-multiple-clients.  It MUST carry a distinct
	// EC P-256 keypair so the OIDF suite can authenticate as two different wallets.
	oid4vciWallet2ClientID = "conformance-oid4vci-wallet-2"
)

var conformanceRedirectURIs = []string{
	// Basic plan — online certification tool
	"https://www.certification.openid.net/test/a/clavex-basic/callback",
	"https://www.certification.openid.net/test/a/clavex-basic/callback?dummy1=lorem&dummy2=ipsum",
	// Basic-post plan
	"https://www.certification.openid.net/test/a/clavex-basic-post/callback",
	"https://www.certification.openid.net/test/a/clavex-basic-post/callback?dummy1=lorem&dummy2=ipsum",
	// Config plan
	"https://www.certification.openid.net/test/a/clavex-config/callback",
	"https://www.certification.openid.net/test/a/clavex-config/callback?dummy1=lorem&dummy2=ipsum",
	// Dynamic plan (static client used for non-dynamic sub-tests)
	"https://www.certification.openid.net/test/a/clavex-dynamic/callback",
	"https://www.certification.openid.net/test/a/clavex-dynamic/callback?dummy1=lorem&dummy2=ipsum",
	// Form Post plan
	"https://www.certification.openid.net/test/a/clavex-form-post/callback",
	"https://www.certification.openid.net/test/a/clavex-form-post/callback?dummy1=lorem&dummy2=ipsum",
	// Hybrid Flow plan
	"https://www.certification.openid.net/test/a/clavex-hybrid/callback",
	"https://www.certification.openid.net/test/a/clavex-hybrid/callback?dummy1=lorem&dummy2=ipsum",
	// PAR plan
	"https://www.certification.openid.net/test/a/clavex-par/callback",
	"https://www.certification.openid.net/test/a/clavex-par/callback?dummy1=lorem&dummy2=ipsum",
	// Device Authorization Grant plan
	"https://www.certification.openid.net/test/a/clavex-device/callback",
	"https://www.certification.openid.net/test/a/clavex-device/callback?dummy1=lorem&dummy2=ipsum",
	// FAPI 2.0 plan (fapi2-baseline-dpop)
	"https://www.certification.openid.net/test/a/clavex-fapi/callback",
	"https://www.certification.openid.net/test/a/clavex-fapi/callback?dummy1=lorem&dummy2=ipsum",
	// FAPI 2.0 Message Signing / JARM plan (fapi2-message-signing)
	"https://www.certification.openid.net/test/a/clavex-fapi-jarm/callback",
	"https://www.certification.openid.net/test/a/clavex-fapi-jarm/callback?dummy1=lorem&dummy2=ipsum",
	// FAPI 2.0 baseline mTLS plan
	"https://www.certification.openid.net/test/a/clavex-fapi-mtls/callback",
	"https://www.certification.openid.net/test/a/clavex-fapi-mtls/callback?dummy1=lorem&dummy2=ipsum",
	// FAPI 2.0 CIBA Poll plan
	"https://www.certification.openid.net/test/a/clavex-fapi2-ciba-poll/callback",
	"https://www.certification.openid.net/test/a/clavex-fapi2-ciba-poll/callback?dummy1=lorem&dummy2=ipsum",
	// OID4VCI issuer plan
	"https://www.certification.openid.net/test/a/clavex-oid4vci-issuer/callback",
	"https://www.certification.openid.net/test/a/clavex-oid4vci-issuer/callback?dummy1=lorem&dummy2=ipsum",
	// OID4VCI issuer encrypted variant plan
	"https://www.certification.openid.net/test/a/clavex-oid4vci-issuer-encrypted/callback",
	"https://www.certification.openid.net/test/a/clavex-oid4vci-issuer-encrypted/callback?dummy1=lorem&dummy2=ipsum",
	// OID4VCI issuer mso_mdoc plan
	"https://www.certification.openid.net/test/a/clavex-oid4vci-issuer-mso-mdoc/callback",
	"https://www.certification.openid.net/test/a/clavex-oid4vci-issuer-mso-mdoc/callback?dummy1=lorem&dummy2=ipsum",
	// OID4VCI issuer mso_mdoc encrypted variant plan
	"https://www.certification.openid.net/test/a/clavex-oid4vci-issuer-mso-mdoc-encrypted/callback",
	"https://www.certification.openid.net/test/a/clavex-oid4vci-issuer-mso-mdoc-encrypted/callback?dummy1=lorem&dummy2=ipsum",
	// HAIP plan
	"https://www.certification.openid.net/test/a/clavex-haip/callback",
	"https://www.certification.openid.net/test/a/clavex-haip/callback?dummy1=lorem&dummy2=ipsum",
}

var conformancePostLogoutURIs = []string{
	"https://www.certification.openid.net/test/a/clavex-basic/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-basic-post/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-config/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-dynamic/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-form-post/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-hybrid/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-par/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-device/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-fapi/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-fapi-jarm/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-fapi-mtls/post_logout_redirect",
	"https://www.certification.openid.net/test/a/clavex-fapi2-ciba-poll/post_logout_redirect",
}

func main() {
	cfgPath := flag.String("config", "", "path to config file (default: config.yaml)")
	keyDir := flag.String("key-dir", "conformance", "directory where fapi-private-key.jwk is saved/loaded")
	flag.Parse()

	cfg, err := config.LoadFrom(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load config:", err)
		os.Exit(1)
	}

	dbMgr, err := db.Open(cfg.Database)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to open database:", err)
		os.Exit(1)
	}
	defer dbMgr.Close()

	// Ensure schema is up-to-date.
	if err := db.Migrate(dbMgr.Pool); err != nil {
		fmt.Fprintln(os.Stderr, "migrations failed:", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// ── 1. Organisation ────────────────────────────────────────────────────────
	orgRepo := repository.NewOrgRepository(dbMgr.Pool)
	org, err := orgRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		org, err = orgRepo.Create(ctx, orgName, orgSlug, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create org failed:", err)
			os.Exit(1)
		}
		fmt.Printf("org created:  %s  (%s)\n", org.Slug, org.ID)
	} else {
		fmt.Printf("org exists:   %s  (%s)\n", org.Slug, org.ID)
	}
	if _, err := dbMgr.Pool.Exec(ctx, `
		UPDATE organizations SET conformance_mode = TRUE, updated_at = NOW() WHERE id = $1
	`, org.ID); err != nil {
		fmt.Fprintln(os.Stderr, "set conformance_mode failed:", err)
		os.Exit(1)
	}

	// ── 2. Test user ───────────────────────────────────────────────────────────
	userRepo := repository.NewUserRepository(dbMgr.Pool)
	first := testFirst
	last := testLast
	user, err := userRepo.GetByEmail(ctx, org.ID, testEmail)
	if err != nil {
		user, err = userRepo.Create(ctx, org.ID, testEmail, &first, &last)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create user failed:", err)
			os.Exit(1)
		}
		if err := userRepo.SetPassword(ctx, user.ID, testPassword); err != nil {
			fmt.Fprintln(os.Stderr, "set user password failed:", err)
			os.Exit(1)
		}
		fmt.Printf("user created: %s  (%s)\n", user.Email, user.ID)
	} else {
		fmt.Printf("user exists:  %s  (%s)\n", user.Email, user.ID)
	}

	// Mark the user's email as verified so the conformance suite can rely on
	// email_verified=true in the ID token.
	// Also populate extended OIDC profile claims in metadata so the UserInfo
	// endpoint can return all 14 standard profile scope claims per OIDC Core §5.1.
	// Additionally populate IDA (_ida) evidence so the conformance suite can test
	// OpenID Connect for Identity Assurance 1.0 verified_claims support.
	if _, err := dbMgr.Pool.Exec(ctx, `
		UPDATE users SET
			is_email_verified = TRUE,
			first_name        = 'Test',
			last_name         = 'User',
			metadata          = $2
		WHERE id = $1`,
		user.ID,
		map[string]interface{}{
			"nickname":           "testuser",
			"preferred_username": testEmail,
			"profile":            "https://conformance.example.com/profile/testuser",
			"picture":            "https://conformance.example.com/profile/testuser/photo.jpg",
			"website":            "https://conformance.example.com",
			"gender":             "other",
			"birthdate":          "1990-01-01",
			"zoneinfo":           "Europe/Rome",
			"locale":             "en-US",
			"middle_name":        "Conformance",
			// OpenID Connect for Identity Assurance 1.0 §5 — verified_claims evidence.
			// trust_framework "eidas" with assurance_level "substantial" covers the broadest
			// set of conformance test scenarios. The conformance suite can filter by framework.
			"_ida": map[string]interface{}{
				"trust_framework":  "eidas",
				"assurance_level":  "substantial",
				"time":             "2024-01-15T09:00:00Z",
				"evidence": []interface{}{
					map[string]interface{}{
						"type": "electronic_record",
						"record": map[string]interface{}{
							"type": "population_register",
							"source": map[string]interface{}{
								"name":         "Test Identity Authority",
								"country":      "Italy",
								"country_code": "ITA",
							},
						},
					},
				},
			},
		},
	); err != nil {
		fmt.Fprintln(os.Stderr, "mark email verified failed:", err)
		os.Exit(1)
	}

	// ── 2b. OID4VCI credential configuration ────────────────────────────────────
	// The OID4VCI conformance tests require at least one active credential config
	// in the metadata document (credential_configurations_supported).
	oid4wRepo := repository.NewOID4WRepository(dbMgr.Pool)
	const vciVCT = "https://id.clavex.eu/vct/conformance-identity"
	vciCfg, cfgErr := oid4wRepo.GetCredentialConfigByVCT(ctx, org.ID, vciVCT)
	if cfgErr != nil {
		vciCfg, err = oid4wRepo.CreateCredentialConfig(
			ctx,
			org.ID,
			vciVCT,
			"Conformance Identity Credential",
			nil,
			map[string]interface{}{
				"given_name":  "{given_name}",
				"family_name": "{family_name}",
				"email":       "{email}",
			},
			3600,
			"identity",
			[]models.SchemaFieldDef{
				{Name: "given_name", Label: "Given Name", Type: "string", Mandatory: true},
				{Name: "family_name", Label: "Family Name", Type: "string", Mandatory: true},
				{Name: "email", Label: "Email", Type: "string", Mandatory: false},
			},
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create credential config failed:", err)
			os.Exit(1)
		}
		fmt.Printf("credential config created: %s\n", vciVCT)
	} else {
		fmt.Printf("credential config exists:  %s\n", vciVCT)
	}
	// key_attestations_required must be advertised so the conformance suite runs
	// key-attestation tests (oid4vci-1_0-issuer-fail-invalid-key-attestation-*).
	if err := oid4wRepo.SetRequireKeyAttestation(ctx, vciCfg.ID, org.ID, true); err != nil {
		fmt.Fprintln(os.Stderr, "set require_key_attestation failed:", err)
		os.Exit(1)
	}
	fmt.Printf("require_key_attestation enabled: %s\n", vciVCT)

	// ── 2c. mso_mdoc credential configuration (org.iso.18013.5.1.mDL) ──────────
	// Conformance mDL: the suite validates ISO 18013-5 mso_mdoc format credentials.
	// Requires an active OrgMdocIssuer (DS key + cert signed by IACA CA).
	const mdocDocType = "org.iso.18013.5.1.mDL"
	mdocPlanPath := filepath.Join(*keyDir, "oid4vci-issuer-mso-mdoc-plan.json")
	mdocEncryptedPlanPath := filepath.Join(*keyDir, "oid4vci-issuer-mso-mdoc-encrypted-plan.json")

	mdocCfg, mdocCfgErr := oid4wRepo.GetCredentialConfigByVCT(ctx, org.ID, mdocDocType)
	if mdocCfgErr != nil {
		mdocCfg, err = oid4wRepo.CreateCredentialConfig(
			ctx,
			org.ID,
			mdocDocType,
			"Conformance mDL Credential",
			nil,
			map[string]interface{}{
				"family_name": "last_name",
				"given_name":  "first_name",
				"birth_date":  "metadata.birthdate",
			},
			3600,
			"identity",
			[]models.SchemaFieldDef{
				{Name: "family_name", Label: "Family Name", Type: "string", Mandatory: true},
				{Name: "given_name", Label: "Given Name", Type: "string", Mandatory: true},
				{Name: "birth_date", Label: "Birth Date", Type: "string", Mandatory: false},
			},
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create mdoc credential config failed:", err)
			os.Exit(1)
		}
		fmt.Printf("credential config created: %s\n", mdocDocType)
	} else {
		fmt.Printf("credential config exists:  %s\n", mdocDocType)
	}
	if err := oid4wRepo.SetCredentialFormat(ctx, mdocCfg.ID, org.ID, "mso_mdoc"); err != nil {
		fmt.Fprintln(os.Stderr, "set mdoc credential_format failed:", err)
		os.Exit(1)
	}
	fmt.Printf("credential_format set: mso_mdoc (%s)\n", mdocDocType)
	// Advertise key_attestations_required for the mso_mdoc config so the
	// key-attestation conformance tests (e.g. fail-invalid-key-attestation-
	// signature) run instead of being skipped. The SD-JWT config already
	// enables this above.
	if err := oid4wRepo.SetRequireKeyAttestation(ctx, mdocCfg.ID, org.ID, true); err != nil {
		fmt.Fprintln(os.Stderr, "set mdoc require_key_attestation failed:", err)
		os.Exit(1)
	}
	fmt.Printf("require_key_attestation enabled: %s\n", mdocDocType)

	// Load or generate the IACA CA + DS key pair.
	mdocIACAKeyPath := filepath.Join(*keyDir, "mdoc-iaca-private-key.pem")
	mdocIACACertPath := filepath.Join(*keyDir, "mdoc-iaca-cert.pem")
	mdocDSKeyPath := filepath.Join(*keyDir, "mdoc-ds-private-key.pem")
	mdocDSCertPath := filepath.Join(*keyDir, "mdoc-ds-cert.pem")

	var (
		mdocIACAKey  *ecdsa.PrivateKey
		mdocIACACert *x509.Certificate
		mdocDSKey    *ecdsa.PrivateKey
		mdocDSCert   *x509.Certificate
	)

	{
		k1, e1 := os.ReadFile(mdocIACAKeyPath)
		k2, e2 := os.ReadFile(mdocIACACertPath)
		k3, e3 := os.ReadFile(mdocDSKeyPath)
		k4, e4 := os.ReadFile(mdocDSCertPath)
		if e1 == nil && e2 == nil && e3 == nil && e4 == nil {
			if blk, _ := pem.Decode(k1); blk != nil {
				mdocIACAKey, _ = x509.ParseECPrivateKey(blk.Bytes)
			}
			if blk, _ := pem.Decode(k2); blk != nil {
				mdocIACACert, _ = x509.ParseCertificate(blk.Bytes)
			}
			if blk, _ := pem.Decode(k3); blk != nil {
				mdocDSKey, _ = x509.ParseECPrivateKey(blk.Bytes)
			}
			if blk, _ := pem.Decode(k4); blk != nil {
				mdocDSCert, _ = x509.ParseCertificate(blk.Bytes)
			}
			if mdocIACAKey != nil && mdocIACACert != nil && mdocDSKey != nil && mdocDSCert != nil {
				fmt.Println("mdoc IACA+DS keys loaded")
			} else {
				// Parse failure — clear to trigger regeneration.
				mdocIACAKey, mdocIACACert, mdocDSKey, mdocDSCert = nil, nil, nil, nil
			}
		}
	}

	if mdocIACAKey == nil {
		// Generate IACA CA (self-signed P-256, 10-year validity).
		mdocIACAKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, "generate mdoc IACA key failed:", err)
			os.Exit(1)
		}
		iacaTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "clavex-credential-issuer-iaca"},
			NotBefore:             time.Now().UTC().Add(-time.Hour),
			NotAfter:              time.Now().UTC().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		iacaCertDER, err := x509.CreateCertificate(rand.Reader, iacaTemplate, iacaTemplate, &mdocIACAKey.PublicKey, mdocIACAKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create mdoc IACA cert failed:", err)
			os.Exit(1)
		}
		mdocIACACert, _ = x509.ParseCertificate(iacaCertDER)
		mdocIACAKeyDER, _ := x509.MarshalECPrivateKey(mdocIACAKey)
		_ = os.WriteFile(mdocIACAKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mdocIACAKeyDER}), 0o600)
		_ = os.WriteFile(mdocIACACertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: iacaCertDER}), 0o644)

		// Generate DS key + cert signed by IACA CA (2-year validity).
		mdocDSKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, "generate mdoc DS key failed:", err)
			os.Exit(1)
		}
		dsTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "clavex-credential-issuer-ds"},
			NotBefore:    time.Now().UTC().Add(-time.Hour),
			NotAfter:     time.Now().UTC().Add(2 * 365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		dsCertDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, mdocIACACert, &mdocDSKey.PublicKey, mdocIACAKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create mdoc DS cert failed:", err)
			os.Exit(1)
		}
		mdocDSCert, _ = x509.ParseCertificate(dsCertDER)
		mdocDSKeyDER, _ := x509.MarshalECPrivateKey(mdocDSKey)
		_ = os.WriteFile(mdocDSKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mdocDSKeyDER}), 0o600)
		_ = os.WriteFile(mdocDSCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dsCertDER}), 0o644)
		fmt.Println("mdoc IACA+DS keys generated")
	}

	// Upsert the OrgMdocIssuer record with the DS key/cert.
	mdocIssuersRepo := repository.NewMdocIssuerRepository(dbMgr.Pool)
	mdocIACACertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mdocIACACert.Raw}))
	mdocDSCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mdocDSCert.Raw}))
	mdocDSKeyDERBytes, _ := x509.MarshalECPrivateKey(mdocDSKey)
	mdocDSKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mdocDSKeyDERBytes}))
	if _, err := mdocIssuersRepo.Create(ctx, org.ID, "Conformance mDL Issuer", mdocDocType, mdocDSKeyPEM, mdocDSCertPEM, &mdocIACACertPEM, 8760); err != nil {
		fmt.Fprintln(os.Stderr, "upsert mdoc issuer failed:", err)
		os.Exit(1)
	}
	fmt.Printf("mdoc issuer upserted: %s (DS cert signed by IACA)\n", mdocDocType)

	// Update the mdoc plan JSONs with the IACA cert (trust_anchor_pem).
	for _, pp := range []string{mdocPlanPath, mdocEncryptedPlanPath} {
		if planBytes, readErr := os.ReadFile(pp); readErr == nil {
			var plan map[string]interface{}
			if jsonErr := json.Unmarshal(planBytes, &plan); jsonErr == nil {
				credSection, _ := plan["credential"].(map[string]interface{})
				if credSection == nil {
					credSection = map[string]interface{}{}
				}
				credSection["trust_anchor_pem"] = mdocIACACertPEM
				plan["credential"] = credSection
				if updated, marshalErr := json.MarshalIndent(plan, "", "  "); marshalErr == nil {
					if writeErr := os.WriteFile(pp, append(updated, '\n'), 0o644); writeErr == nil {
						fmt.Printf("plan updated:   %s (trust_anchor_pem set to IACA cert)\n", pp)
					}
				}
			}
		}
	}

	// ── 3. OIDC client with a known, stable secret ─────────────────────────────
	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bcrypt failed:", err)
		os.Exit(1)
	}

	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			client_secret_hash, token_endpoint_auth_method,
			grant_types, response_types, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, 'client_secret_basic', $7, $8, TRUE)
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                       = EXCLUDED.org_id,
			name                         = EXCLUDED.name,
			redirect_uris                = EXCLUDED.redirect_uris,
			post_logout_redirect_uris    = EXCLUDED.post_logout_redirect_uris,
			client_secret_hash           = EXCLUDED.client_secret_hash,
			grant_types                  = EXCLUDED.grant_types,
			response_types               = EXCLUDED.response_types,
			request_object_signing_alg   = '',
			is_active                    = TRUE
	`,
		clientID, org.ID, "Conformance Suite",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(secretHash),
		[]string{"authorization_code", "refresh_token"},
		[]string{"code", "code id_token", "code token", "code id_token token", "id_token", "token"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s\n", clientID)

	// ── 3b. client_secret_post client — required for oidcc-test-plan (client_secret_post) ──
	// The OIDF conformance suite validates that token_endpoint_auth_method in the
	// server's client registration matches the plan's client_auth_type variant.
	// Because the primary client uses client_secret_basic, a separate client is
	// needed for the client_secret_post plan variant.
	postSecretHash, err := bcrypt.GenerateFromPassword([]byte(clientPostSecret), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bcrypt failed (client-post):", err)
		os.Exit(1)
	}

	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			client_secret_hash, token_endpoint_auth_method,
			grant_types, response_types, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, 'client_secret_post', $7, $8, TRUE)
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                       = EXCLUDED.org_id,
			name                         = EXCLUDED.name,
			redirect_uris                = EXCLUDED.redirect_uris,
			post_logout_redirect_uris    = EXCLUDED.post_logout_redirect_uris,
			client_secret_hash           = EXCLUDED.client_secret_hash,
			token_endpoint_auth_method   = EXCLUDED.token_endpoint_auth_method,
			grant_types                  = EXCLUDED.grant_types,
			response_types               = EXCLUDED.response_types,
			request_object_signing_alg   = '',
			is_active                    = TRUE
	`,
		clientPostID, org.ID, "Conformance Suite (client_secret_post)",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(postSecretHash),
		[]string{"authorization_code", "refresh_token"},
		[]string{"code", "code id_token", "code token", "code id_token token", "id_token", "token"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert client-post failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s\n", clientPostID)

	// ── 4. Second OIDC client — required for cross-client binding tests ─────────
	// The conformance suite sends a refresh token obtained by client1 to the
	// token endpoint using client2's credentials and expects an error.  Both
	// clients must have genuinely different client_ids for the server's check
	// `rt.ClientID != clientID` to fire correctly.
	secret2Hash, err := bcrypt.GenerateFromPassword([]byte(client2Secret), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bcrypt failed (client2):", err)
		os.Exit(1)
	}

	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			client_secret_hash, token_endpoint_auth_method,
			grant_types, response_types, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, 'client_secret_basic', $7, $8, TRUE)
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                       = EXCLUDED.org_id,
			name                         = EXCLUDED.name,
			redirect_uris                = EXCLUDED.redirect_uris,
			post_logout_redirect_uris    = EXCLUDED.post_logout_redirect_uris,
			client_secret_hash           = EXCLUDED.client_secret_hash,
			grant_types                  = EXCLUDED.grant_types,
			response_types               = EXCLUDED.response_types,
			request_object_signing_alg   = '',
			is_active                    = TRUE
	`,
		client2ID, org.ID, "Conformance Suite Client 2",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(secret2Hash),
		[]string{"authorization_code", "refresh_token"},
		[]string{"code", "code id_token", "code token", "code id_token token", "id_token", "token"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert client2 failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s\n", client2ID)

	// ── 5. FAPI client (private_key_jwt, inline JWKS) ─────────────────────────
	// The private key is persisted to <key-dir>/fapi-private-key.jwk so that
	// re-running the seed does NOT rotate the key — the tester only needs to
	// configure the suite once. If the file already exists its key is reused and
	// the DB public JWKS is refreshed to match. Generate fresh only on first run.
	keyPath := filepath.Join(*keyDir, "fapi-private-key.jwk")

	var fapiPrivJWK jwk.Key
	var keyIsNew bool

	existingKeyBytes, readErr := os.ReadFile(keyPath)
	if readErr == nil {
		// Reuse the existing private key.
		set, err := jwk.ParseString(string(existingKeyBytes))
		if err != nil || set.Len() == 0 {
			fmt.Fprintf(os.Stderr, "warn: could not parse %s (%v) — regenerating\n", keyPath, err)
			readErr = errors.New("unparseable")
		} else {
			fapiPrivJWK, _ = set.Key(0)
			fmt.Printf("fapi key loaded: %s\n", keyPath)
		}
	}
	if errors.Is(readErr, os.ErrNotExist) || readErr != nil {
		// Generate a new keypair.
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rsa key generation failed:", err)
			os.Exit(1)
		}
		fapiPrivJWK, err = jwk.FromRaw(priv)
		if err != nil {
			fmt.Fprintln(os.Stderr, "jwk from private key failed:", err)
			os.Exit(1)
		}
		_ = fapiPrivJWK.Set(jwk.KeyIDKey, "conformance-fapi-1")
		_ = fapiPrivJWK.Set(jwk.AlgorithmKey, "PS256")
		_ = fapiPrivJWK.Set(jwk.KeyUsageKey, "sig")

		// Persist to file so subsequent runs reuse the same key.
		if err := os.MkdirAll(*keyDir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "mkdir key-dir failed:", err)
			os.Exit(1)
		}
		keyJSON, err := json.MarshalIndent(fapiPrivJWK, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal private jwk failed:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(keyPath, keyJSON, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write key file failed:", err)
			os.Exit(1)
		}
		keyIsNew = true
		fmt.Printf("fapi key generated: %s\n", keyPath)
	}

	// Unconditionally enforce FAPI2-compliant key attributes on the loaded or
	// generated key. Keys stored before alg/use were added to the seed file
	// would otherwise produce a JWKS without alg, which FAPI2 §5.4 rejects
	// (RSA keys without an explicit alg are treated as RS256, not permitted).
	_ = fapiPrivJWK.Set(jwk.AlgorithmKey, "PS256")
	_ = fapiPrivJWK.Set(jwk.KeyUsageKey, "sig")

	// Build JWK for the public key only (stored in the DB).
	fapiPubJWK, err := jwk.PublicKeyOf(fapiPrivJWK)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jwk public key failed:", err)
		os.Exit(1)
	}
	// jwk.PublicKeyOf does NOT copy alg/use from the private key.
	// FAPI2 §5.4 (FAPI2CheckKeyAlgInClientJWKs) rejects a JWKS entry that lacks
	// an explicit alg — RSA keys without alg are treated as RS256, not PS256.
	_ = fapiPubJWK.Set(jwk.AlgorithmKey, "PS256")
	_ = fapiPubJWK.Set(jwk.KeyUsageKey, "sig")

	// Serialise the public JWKS as a JSON object for the jwks column.
	pubJWKSBytes, err := json.Marshal(map[string]interface{}{
		"keys": []jwk.Key{fapiPubJWK},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal public jwks failed:", err)
		os.Exit(1)
	}

	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			grant_types, is_active, dpop_bound_access_tokens, require_pkce,
			tls_client_certificate_bound_access_tokens, require_par,
			request_object_signing_alg
		) VALUES ($1, $2, $3, $4, $5, 'private_key_jwt', $6::jsonb, $7, TRUE, FALSE, TRUE, TRUE, TRUE, '')
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                                  = EXCLUDED.org_id,
			name                                    = EXCLUDED.name,
			redirect_uris                           = EXCLUDED.redirect_uris,
			post_logout_redirect_uris               = EXCLUDED.post_logout_redirect_uris,
			jwks                                    = EXCLUDED.jwks,
			grant_types                             = EXCLUDED.grant_types,
			is_active                               = TRUE,
			dpop_bound_access_tokens                = FALSE,
			require_pkce                            = TRUE,
			tls_client_certificate_bound_access_tokens = TRUE,
			require_par                             = TRUE,
			request_object_signing_alg              = ''
	`,
		fapiClientID, org.ID, "Conformance Suite FAPI Client",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(pubJWKSBytes),
		[]string{"authorization_code", "refresh_token"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert fapi client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt, inline jwks)\n", fapiClientID)

	// ── 6. Second FAPI client — required by FAPI2 cross-client binding tests ───
	// ValidateClientPrivateKeysAreDifferent (FAPI2 conformance check) requires
	// client and client2 to hold DISTINCT keypairs.  We generate a second RSA key
	// saved to <key-dir>/fapi2-private-key.jwk alongside the primary key.
	key2Path := filepath.Join(*keyDir, "fapi2-private-key.jwk")

	var fapi2PrivJWK jwk.Key
	var key2IsNew bool

	existingKey2Bytes, readErr2 := os.ReadFile(key2Path)
	if readErr2 == nil {
		set2, err := jwk.ParseString(string(existingKey2Bytes))
		if err != nil || set2.Len() == 0 {
			fmt.Fprintf(os.Stderr, "warn: could not parse %s (%v) — regenerating\n", key2Path, err)
			readErr2 = errors.New("unparseable")
		} else {
			fapi2PrivJWK, _ = set2.Key(0)
			fmt.Printf("fapi2 key loaded: %s\n", key2Path)
		}
	}
	if errors.Is(readErr2, os.ErrNotExist) || readErr2 != nil {
		priv2, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rsa key2 generation failed:", err)
			os.Exit(1)
		}
		fapi2PrivJWK, err = jwk.FromRaw(priv2)
		if err != nil {
			fmt.Fprintln(os.Stderr, "jwk from private key2 failed:", err)
			os.Exit(1)
		}
		_ = fapi2PrivJWK.Set(jwk.KeyIDKey, "conformance-fapi-2")
		_ = fapi2PrivJWK.Set(jwk.AlgorithmKey, "PS256")
		_ = fapi2PrivJWK.Set(jwk.KeyUsageKey, "sig")

		keyJSON2, err := json.MarshalIndent(fapi2PrivJWK, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal private jwk2 failed:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(key2Path, keyJSON2, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write key2 file failed:", err)
			os.Exit(1)
		}
		key2IsNew = true
		fmt.Printf("fapi2 key generated: %s\n", key2Path)
	}

	// Unconditionally enforce alg/use on the loaded/generated second key.
	_ = fapi2PrivJWK.Set(jwk.AlgorithmKey, "PS256")
	_ = fapi2PrivJWK.Set(jwk.KeyUsageKey, "sig")

	fapi2PubJWK, err := jwk.PublicKeyOf(fapi2PrivJWK)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jwk public key2 failed:", err)
		os.Exit(1)
	}
	// Explicitly set alg/use on the public key — PublicKeyOf does not copy them.
	_ = fapi2PubJWK.Set(jwk.AlgorithmKey, "PS256")
	_ = fapi2PubJWK.Set(jwk.KeyUsageKey, "sig")

	pub2JWKSBytes, err := json.Marshal(map[string]interface{}{
		"keys": []jwk.Key{fapi2PubJWK},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal public jwks2 failed:", err)
		os.Exit(1)
	}

	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			grant_types, is_active, dpop_bound_access_tokens, require_pkce,
			tls_client_certificate_bound_access_tokens, require_par,
			request_object_signing_alg
		) VALUES ($1, $2, $3, $4, $5, 'private_key_jwt', $6::jsonb, $7, TRUE, FALSE, TRUE, TRUE, TRUE, '')
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                                  = EXCLUDED.org_id,
			name                                    = EXCLUDED.name,
			redirect_uris                           = EXCLUDED.redirect_uris,
			post_logout_redirect_uris               = EXCLUDED.post_logout_redirect_uris,
			jwks                                    = EXCLUDED.jwks,
			grant_types                             = EXCLUDED.grant_types,
			is_active                               = TRUE,
			dpop_bound_access_tokens                = FALSE,
			require_pkce                            = TRUE,
			tls_client_certificate_bound_access_tokens = TRUE,
			require_par                             = TRUE,
			request_object_signing_alg              = ''
	`,
		fapi2ClientID, org.ID, "Conformance Suite FAPI Client 2",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(pub2JWKSBytes),
		[]string{"authorization_code", "refresh_token"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert fapi client2 failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt, distinct key)\n", fapi2ClientID)

	// ── 7. CIBA poll clients — reuse FAPI RSA keys ────────────────────────────
	// Grant type: urn:openid:params:grant-type:ciba (CIBA Core 1.0).
	// No redirect_uris needed for poll delivery mode.
	// tls_client_certificate_bound_access_tokens=TRUE required by fapi-ciba-id1
	// test plan even when client_auth_type=private_key_jwt (RFC 8705 sender constraint).
	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			tls_client_certificate_bound_access_tokens,
			grant_types, is_active
		) VALUES ($1, $2, $3, '{}', '{}', 'private_key_jwt', $4::jsonb, TRUE, $5, TRUE)
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                                    = EXCLUDED.org_id,
			name                                      = EXCLUDED.name,
			jwks                                      = EXCLUDED.jwks,
			tls_client_certificate_bound_access_tokens = TRUE,
			grant_types                               = EXCLUDED.grant_types,
			is_active                                 = TRUE
	`,
		cibaClientID, org.ID, "Conformance Suite CIBA Client",
		string(pubJWKSBytes),
		[]string{"urn:openid:params:grant-type:ciba"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert ciba client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt, CIBA poll, mtls-bound)\n", cibaClientID)

	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			tls_client_certificate_bound_access_tokens,
			grant_types, is_active
		) VALUES ($1, $2, $3, '{}', '{}', 'private_key_jwt', $4::jsonb, TRUE, $5, TRUE)
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                                    = EXCLUDED.org_id,
			name                                      = EXCLUDED.name,
			jwks                                      = EXCLUDED.jwks,
			tls_client_certificate_bound_access_tokens = TRUE,
			grant_types                               = EXCLUDED.grant_types,
			is_active                                 = TRUE
	`,
		cibaClient2ID, org.ID, "Conformance Suite CIBA Client 2",
		string(pub2JWKSBytes),
		[]string{"urn:openid:params:grant-type:ciba"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert ciba client2 failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt, CIBA poll, mtls-bound, distinct key)\n", cibaClient2ID)

	// Bake the FAPI private JWKS into the CIBA plan JSON.  fapi-ciba-id1 uses
	// client_auth_type=private_key_jwt, so the OIDF suite (acting as the client)
	// must sign assertions with the same private key whose public half the seed
	// registered above (client -> fapiPrivJWK, client2 -> fapi2PrivJWK).  The
	// committed plan only carries client_id + mtls/mtls2 certs; without the
	// private jwks the suite has no signing key, and without the certs MTLS
	// extraction fails ("Couldn't find TLS client certificate or key for MTLS").
	// We read-modify-write so the manually-committed mtls/mtls2 blocks survive.
	cibaPlanPath := filepath.Join(*keyDir, "fapi2-ciba-poll-plan.json")
	if planBytes, readErr := os.ReadFile(cibaPlanPath); readErr == nil {
		var plan map[string]interface{}
		if json.Unmarshal(planBytes, &plan) == nil {
			setClientJWKS := func(section string, key jwk.Key) {
				privBytes, _ := json.Marshal(key)
				var privMap map[string]interface{}
				_ = json.Unmarshal(privBytes, &privMap)
				c, _ := plan[section].(map[string]interface{})
				if c == nil {
					c = map[string]interface{}{}
				}
				c["jwks"] = map[string]interface{}{"keys": []interface{}{privMap}}
				// The OIDF CIBA suite reads client.scope to build the
				// backchannel authentication request (AddScopeToAuthorization
				// EndpointRequest fails with "scope missing/empty in client
				// object" otherwise). Two scopes are required so the
				// ensure-other-scope-order-succeeds test (which reverses scope
				// order) has something to reverse; FilterScope ignores order.
				if _, ok := c["scope"]; !ok {
					c["scope"] = "openid profile"
				}
				// The CIBA suite builds the backchannel request hint from
				// client.hint_type + client.hint_value (AddHintToAuthorization
				// EndpointRequest). hint_type must be one of login_hint_token,
				// id_token_hint or login_hint; we use a plain login_hint that
				// clavex resolves to the seeded conformance user.
				if _, ok := c["hint_type"]; !ok {
					c["hint_type"] = "login_hint"
				}
				if _, ok := c["hint_value"]; !ok {
					c["hint_value"] = "testuser@conformance.local"
				}
				plan[section] = c
			}
			setClientJWKS("client", fapiPrivJWK)
			setClientJWKS("client2", fapi2PrivJWK)

			// The CIBA poll tests have no device to tap; the suite drives
			// approval/denial by calling automated_ciba_approval_url with the
			// auth_req_id and an action of allow/deny ({...} placeholders are
			// substituted by the suite). clavex's ConformanceCIBAAutomate
			// endpoint (gated to the conformance org) performs the action.
			if _, ok := plan["automated_ciba_approval_url"]; !ok {
				plan["automated_ciba_approval_url"] = "https://id.clavex.eu/conformance/ciba/automate?auth_req_id={auth_req_id}&action={action}"
			}

			if updated, marshalErr := json.MarshalIndent(plan, "", "  "); marshalErr == nil {
				if writeErr := os.WriteFile(cibaPlanPath, append(updated, '\n'), 0o644); writeErr == nil {
					fmt.Printf("plan updated:   %s (client/client2 jwks set to FAPI private keys)\n", cibaPlanPath)
				}
			}
		}
	}

	// ── 8. DPoP FAPI client — same key as fapiClientID, dpop_bound=true ────────
	// Used by fapi2-baseline-dpop-plan.json (basic plan, unsigned variant).
	// No JAR enforcement: request_object_signing_alg is left empty so the PAR
	// endpoint accepts plain (unsigned) authorization requests, as required by
	// fapi_request_method=unsigned.  require_par=true ensures the authorization
	// endpoint rejects direct (non-PAR) requests per FAPI 2.0 §5.2.2-1.
	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			request_object_signing_alg,
			response_types,
			grant_types, is_active,
			dpop_bound_access_tokens, require_pkce, require_par
		) VALUES ($1, $2, $3, $4, $5, 'private_key_jwt', $6::jsonb, '', '{"code"}', $7, TRUE, TRUE, TRUE, TRUE)
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                    = EXCLUDED.org_id,
			name                      = EXCLUDED.name,
			redirect_uris             = EXCLUDED.redirect_uris,
			post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
			jwks                      = EXCLUDED.jwks,
			request_object_signing_alg = EXCLUDED.request_object_signing_alg,
			response_types            = EXCLUDED.response_types,
			grant_types               = EXCLUDED.grant_types,
			is_active                 = TRUE,
			dpop_bound_access_tokens  = TRUE,
			require_pkce              = TRUE,
			require_par               = TRUE
	`,
		fapiDpopClientID, org.ID, "Conformance Suite FAPI DPoP Client",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(pubJWKSBytes),
		[]string{"authorization_code", "refresh_token"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert fapi-dpop client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt, dpop_bound=true, no JAR)\n", fapiDpopClientID)

	// ── 9. DPoP FAPI client 2 — same key as fapi2ClientID, dpop_bound=true ─────
	// No JAR enforcement (basic plan, unsigned variant). require_par=true.
	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			request_object_signing_alg,
			response_types,
			grant_types, is_active,
			dpop_bound_access_tokens, require_pkce, require_par
		) VALUES ($1, $2, $3, $4, $5, 'private_key_jwt', $6::jsonb, '', '{"code"}', $7, TRUE, TRUE, TRUE, TRUE)
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                    = EXCLUDED.org_id,
			name                      = EXCLUDED.name,
			redirect_uris             = EXCLUDED.redirect_uris,
			post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
			jwks                      = EXCLUDED.jwks,
			request_object_signing_alg = EXCLUDED.request_object_signing_alg,
			response_types            = EXCLUDED.response_types,
			grant_types               = EXCLUDED.grant_types,
			is_active                 = TRUE,
			dpop_bound_access_tokens  = TRUE,
			require_pkce              = TRUE,
			require_par               = TRUE
	`,
		fapi2DpopClientID, org.ID, "Conformance Suite FAPI DPoP Client 2",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(pub2JWKSBytes),
		[]string{"authorization_code", "refresh_token"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert fapi2-dpop client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt, dpop_bound=true, no JAR)\n", fapi2DpopClientID)

	// ── 10. DPoP FAPI JAR client — same key as fapiClientID, JAR enforced ───────
	// Used by fapi2-message-signing-plan.json (JARM plan).
	// request_object_signing_alg=PS256 causes the PAR endpoint to require a
	// signed JAR, enabling FAPI2SPID2EnsureUnsignedRequestAtParEndpointFails.
	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			request_object_signing_alg,
			response_types,
			grant_types, is_active,
			dpop_bound_access_tokens, require_pkce
		) VALUES ($1, $2, $3, $4, $5, 'private_key_jwt', $6::jsonb, 'PS256', '{"code"}', $7, TRUE, TRUE, TRUE)
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                    = EXCLUDED.org_id,
			name                      = EXCLUDED.name,
			redirect_uris             = EXCLUDED.redirect_uris,
			post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
			jwks                      = EXCLUDED.jwks,
			request_object_signing_alg = EXCLUDED.request_object_signing_alg,
			response_types            = EXCLUDED.response_types,
			grant_types               = EXCLUDED.grant_types,
			is_active                 = TRUE,
			dpop_bound_access_tokens  = TRUE,
			require_pkce              = TRUE
	`,
		fapiDpopJarClientID, org.ID, "Conformance Suite FAPI DPoP JAR Client",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(pubJWKSBytes),
		[]string{"authorization_code", "refresh_token"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert fapi-dpop-jar client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt, dpop_bound=true, JAR=PS256)\n", fapiDpopJarClientID)

	// ── 11. DPoP FAPI JAR client 2 — same key as fapi2ClientID, JAR enforced ────
	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			request_object_signing_alg,
			response_types,
			grant_types, is_active,
			dpop_bound_access_tokens, require_pkce
		) VALUES ($1, $2, $3, $4, $5, 'private_key_jwt', $6::jsonb, 'PS256', '{"code"}', $7, TRUE, TRUE, TRUE)
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                    = EXCLUDED.org_id,
			name                      = EXCLUDED.name,
			redirect_uris             = EXCLUDED.redirect_uris,
			post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
			jwks                      = EXCLUDED.jwks,
			request_object_signing_alg = EXCLUDED.request_object_signing_alg,
			response_types            = EXCLUDED.response_types,
			grant_types               = EXCLUDED.grant_types,
			is_active                 = TRUE,
			dpop_bound_access_tokens  = TRUE,
			require_pkce              = TRUE
	`,
		fapi2DpopJarClientID, org.ID, "Conformance Suite FAPI DPoP JAR Client 2",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(pub2JWKSBytes),
		[]string{"authorization_code", "refresh_token"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert fapi2-dpop-jar client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt, dpop_bound=true, JAR=PS256)\n", fapi2DpopJarClientID)

	// ── 12. OID4VCI wallet client — private_key_jwt, DPoP, EC P-256 key ─────────
	// The OID4VCI issuer conformance plan uses this client to perform the
	// wallet-initiated authorization_code flow with DPoP-bound access tokens.
	//
	// IMPORTANT: VCIGenerateJwtProof.java in the OIDF conformance suite (v4) calls
	// ECKey.parse on every key in client_jwks.  This means the wallet client MUST
	// have an EC P-256 key — NOT the RSA FAPI key — as its registered JWKS.
	// The same EC key is used for both private_key_jwt client auth (ES256) and
	// the OID4VCI proof JWT.
	walletKeyPath := filepath.Join(*keyDir, "oid4vci-wallet-private-key.jwk")

	var walletPrivJWK jwk.Key
	var walletKeyIsNew bool

	existingWalletKeyBytes, walletReadErr := os.ReadFile(walletKeyPath)
	if walletReadErr == nil {
		set, err := jwk.ParseString(string(existingWalletKeyBytes))
		if err != nil || set.Len() == 0 {
			fmt.Fprintf(os.Stderr, "warn: could not parse %s (%v) — regenerating\n", walletKeyPath, err)
			walletReadErr = errors.New("unparseable")
		} else {
			walletPrivJWK, _ = set.Key(0)
			fmt.Printf("oid4vci wallet key loaded: %s\n", walletKeyPath)
		}
	}
	if errors.Is(walletReadErr, os.ErrNotExist) || walletReadErr != nil {
		// Generate EC P-256 private key.
		ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ec key generation failed:", err)
			os.Exit(1)
		}
		walletPrivJWK, err = jwk.FromRaw(ecPriv)
		if err != nil {
			fmt.Fprintln(os.Stderr, "jwk from ec private key failed:", err)
			os.Exit(1)
		}
		_ = walletPrivJWK.Set(jwk.KeyIDKey, "conformance-oid4vci-ec")
		_ = walletPrivJWK.Set(jwk.AlgorithmKey, "ES256")
		_ = walletPrivJWK.Set(jwk.KeyUsageKey, "sig")

		keyJSON, err := json.MarshalIndent(walletPrivJWK, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal wallet private jwk failed:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(walletKeyPath, keyJSON, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write wallet key file failed:", err)
			os.Exit(1)
		}
		walletKeyIsNew = true
		fmt.Printf("oid4vci wallet key generated: %s\n", walletKeyPath)
	}
	_ = walletPrivJWK.Set(jwk.AlgorithmKey, "ES256")
	_ = walletPrivJWK.Set(jwk.KeyUsageKey, "sig")

	walletPubJWK, err := jwk.PublicKeyOf(walletPrivJWK)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jwk wallet public key failed:", err)
		os.Exit(1)
	}
	_ = walletPubJWK.Set(jwk.AlgorithmKey, "ES256")
	_ = walletPubJWK.Set(jwk.KeyUsageKey, "sig")

	walletPubJWKSBytes, err := json.Marshal(map[string]interface{}{
		"keys": []jwk.Key{walletPubJWK},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal wallet public jwks failed:", err)
		os.Exit(1)
	}

	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			grant_types, is_active,
			dpop_bound_access_tokens, require_pkce, require_par,
			tls_client_certificate_bound_access_tokens,
			request_object_signing_alg
		) VALUES ($1, $2, $3, $4, $5, 'private_key_jwt', $6::jsonb, $7, TRUE, TRUE, TRUE, FALSE, FALSE, '')
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                                     = EXCLUDED.org_id,
			name                                       = EXCLUDED.name,
			redirect_uris                              = EXCLUDED.redirect_uris,
			post_logout_redirect_uris                  = EXCLUDED.post_logout_redirect_uris,
			jwks                                       = EXCLUDED.jwks,
			grant_types                                = EXCLUDED.grant_types,
			is_active                                  = TRUE,
			dpop_bound_access_tokens                   = TRUE,
			require_pkce                               = TRUE,
			require_par                                = FALSE,
			tls_client_certificate_bound_access_tokens = FALSE,
			request_object_signing_alg                 = ''
	`,
		oid4vciWalletClientID, org.ID, "Conformance OID4VCI Wallet Client",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(walletPubJWKSBytes),
		[]string{"authorization_code"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert oid4vci-wallet client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt ES256, dpop_bound=true)\n", oid4vciWalletClientID)

	// Update the OID4VCI issuer plan JSON with the wallet client's private JWKS.
	// VCIGenerateClientJwksIfMissing skips EC key generation when client.jwks is
	// already set (e.g. the RSA FAPI key).  We must bake the EC private key into
	// the plan so the OIDF suite uses it instead of (or before) trying RSA.
	planPath := filepath.Join(*keyDir, "oid4vci-issuer-plan.json")
	encryptedPlanPath := filepath.Join(*keyDir, "oid4vci-issuer-encrypted-plan.json")
	for _, pp := range []string{planPath, encryptedPlanPath, mdocPlanPath, mdocEncryptedPlanPath} {
		if planBytes, readErr := os.ReadFile(pp); readErr == nil {
			var plan map[string]interface{}
			if jsonErr := json.Unmarshal(planBytes, &plan); jsonErr == nil {
				// Serialise private JWKS (with "d") for embedding.
				walletPrivJWKBytes, _ := json.Marshal(walletPrivJWK)
				var walletPrivJWKMap map[string]interface{}
				_ = json.Unmarshal(walletPrivJWKBytes, &walletPrivJWKMap)

				clientSection, _ := plan["client"].(map[string]interface{})
				if clientSection == nil {
					clientSection = map[string]interface{}{}
				}
				clientSection["jwks"] = map[string]interface{}{
					"keys": []interface{}{walletPrivJWKMap},
				}
				plan["client"] = clientSection

				if updated, marshalErr := json.MarshalIndent(plan, "", "  "); marshalErr == nil {
					if writeErr := os.WriteFile(pp, append(updated, '\n'), 0o644); writeErr == nil {
						fmt.Printf("plan updated:   %s (client.jwks set to EC P-256)\n", pp)
					}
				}
			}
		}
	}

	walletKeyAction := "reused"
	if walletKeyIsNew {
		walletKeyAction = "generated (NEW — recreate the OID4VCI and HAIP test plans in the suite)"
	}

	// ── 12b. OID4VCI wallet client 2 — distinct EC P-256 key ─────────────────────
	// Required by oid4vci-1_0-issuer-happy-flow-multiple-clients: the suite calls
	// GetStaticClient2Configuration and uses client2 to issue a second credential
	// in the same test run.  A distinct keypair satisfies any cross-client checks.
	wallet2KeyPath := filepath.Join(*keyDir, "oid4vci-wallet2-private-key.jwk")

	var wallet2PrivJWK jwk.Key
	var wallet2KeyIsNew bool

	existingWallet2KeyBytes, wallet2ReadErr := os.ReadFile(wallet2KeyPath)
	if wallet2ReadErr == nil {
		set, err := jwk.ParseString(string(existingWallet2KeyBytes))
		if err != nil || set.Len() == 0 {
			fmt.Fprintf(os.Stderr, "warn: could not parse %s (%v) — regenerating\n", wallet2KeyPath, err)
			wallet2ReadErr = errors.New("unparseable")
		} else {
			wallet2PrivJWK, _ = set.Key(0)
			fmt.Printf("oid4vci wallet2 key loaded: %s\n", wallet2KeyPath)
		}
	}
	if errors.Is(wallet2ReadErr, os.ErrNotExist) || wallet2ReadErr != nil {
		// Before generating a fresh random key, try to recover the key that is
		// already committed in the plan file.  This prevents a drift where the
		// file is missing (e.g. after a fresh clone) but the DB and the committed
		// plan already agree on a specific key.
		if planBytes, planReadErr := os.ReadFile(planPath); planReadErr == nil {
			var plan map[string]interface{}
			if json.Unmarshal(planBytes, &plan) == nil {
				if c2, ok := plan["client2"].(map[string]interface{}); ok {
					if jwksMap, ok := c2["jwks"].(map[string]interface{}); ok {
						if keysArr, ok := jwksMap["keys"].([]interface{}); ok && len(keysArr) > 0 {
							keyBytes, _ := json.Marshal(keysArr[0])
							if set, parseErr := jwk.ParseString(`{"keys":[` + string(keyBytes) + `]}`); parseErr == nil && set.Len() > 0 {
								wallet2PrivJWK, _ = set.Key(0)
								// Save recovered key to file so future runs load it directly.
								keyJSON2, _ := json.MarshalIndent(wallet2PrivJWK, "", "  ")
								_ = os.WriteFile(wallet2KeyPath, keyJSON2, 0o600)
								fmt.Printf("oid4vci wallet2 key recovered from plan: %s\n", wallet2KeyPath)
							}
						}
					}
				}
			}
		}

		if wallet2PrivJWK == nil {
			ecPriv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				fmt.Fprintln(os.Stderr, "ec key2 generation failed:", err)
				os.Exit(1)
			}
			wallet2PrivJWK, err = jwk.FromRaw(ecPriv2)
			if err != nil {
				fmt.Fprintln(os.Stderr, "jwk from ec private key2 failed:", err)
				os.Exit(1)
			}
			_ = wallet2PrivJWK.Set(jwk.KeyIDKey, "conformance-oid4vci-ec-2")
			_ = wallet2PrivJWK.Set(jwk.AlgorithmKey, "ES256")
			_ = wallet2PrivJWK.Set(jwk.KeyUsageKey, "sig")

			keyJSON2, err := json.MarshalIndent(wallet2PrivJWK, "", "  ")
			if err != nil {
				fmt.Fprintln(os.Stderr, "marshal wallet2 private jwk failed:", err)
				os.Exit(1)
			}
			if err := os.WriteFile(wallet2KeyPath, keyJSON2, 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "write wallet2 key file failed:", err)
				os.Exit(1)
			}
			wallet2KeyIsNew = true
			fmt.Printf("oid4vci wallet2 key generated: %s\n", wallet2KeyPath)
		}
	}
	_ = wallet2PrivJWK.Set(jwk.AlgorithmKey, "ES256")
	_ = wallet2PrivJWK.Set(jwk.KeyUsageKey, "sig")

	wallet2PubJWK, err := jwk.PublicKeyOf(wallet2PrivJWK)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jwk wallet2 public key failed:", err)
		os.Exit(1)
	}
	_ = wallet2PubJWK.Set(jwk.AlgorithmKey, "ES256")
	_ = wallet2PubJWK.Set(jwk.KeyUsageKey, "sig")

	wallet2PubJWKSBytes, err := json.Marshal(map[string]interface{}{
		"keys": []jwk.Key{wallet2PubJWK},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal wallet2 public jwks failed:", err)
		os.Exit(1)
	}

	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			grant_types, is_active,
			dpop_bound_access_tokens, require_pkce, require_par,
			tls_client_certificate_bound_access_tokens,
			request_object_signing_alg
		) VALUES ($1, $2, $3, $4, $5, 'private_key_jwt', $6::jsonb, $7, TRUE, TRUE, TRUE, FALSE, FALSE, '')
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                                     = EXCLUDED.org_id,
			name                                       = EXCLUDED.name,
			redirect_uris                              = EXCLUDED.redirect_uris,
			post_logout_redirect_uris                  = EXCLUDED.post_logout_redirect_uris,
			jwks                                       = EXCLUDED.jwks,
			grant_types                                = EXCLUDED.grant_types,
			is_active                                  = TRUE,
			dpop_bound_access_tokens                   = TRUE,
			require_pkce                               = TRUE,
			require_par                                = FALSE,
			tls_client_certificate_bound_access_tokens = FALSE,
			request_object_signing_alg                 = ''
	`,
		oid4vciWallet2ClientID, org.ID, "Conformance OID4VCI Wallet Client 2",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(wallet2PubJWKSBytes),
		[]string{"authorization_code"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert oid4vci-wallet-2 client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (private_key_jwt ES256, dpop_bound=true)\n", oid4vciWallet2ClientID)

	// Update every OID4VCI issuer plan JSON with client2's private JWKS.
	// The mso-mdoc plans must be included alongside the standard/encrypted
	// plans — otherwise client2 drifts out of sync with the DB and the
	// multiple-clients test fails PAR with "client_assertion verification
	// failed" (client1 is already synced into them above).
	for _, pp := range []string{planPath, encryptedPlanPath, mdocPlanPath, mdocEncryptedPlanPath} {
		if planBytes, readErr := os.ReadFile(pp); readErr == nil {
			var plan map[string]interface{}
			if jsonErr := json.Unmarshal(planBytes, &plan); jsonErr == nil {
				wallet2PrivJWKBytes, _ := json.Marshal(wallet2PrivJWK)
				var wallet2PrivJWKMap map[string]interface{}
				_ = json.Unmarshal(wallet2PrivJWKBytes, &wallet2PrivJWKMap)

				client2Section, _ := plan["client2"].(map[string]interface{})
				if client2Section == nil {
					client2Section = map[string]interface{}{}
				}
				client2Section["client_id"] = oid4vciWallet2ClientID
				client2Section["jwks"] = map[string]interface{}{
					"keys": []interface{}{wallet2PrivJWKMap},
				}
				plan["client2"] = client2Section

				if updated, marshalErr := json.MarshalIndent(plan, "", "  "); marshalErr == nil {
					if writeErr := os.WriteFile(pp, append(updated, '\n'), 0o644); writeErr == nil {
						fmt.Printf("plan updated:   %s (client2.jwks set to EC P-256)\n", pp)
					}
				}
			}
		}
	}

	wallet2KeyAction := "reused"
	if wallet2KeyIsNew {
		wallet2KeyAction = "generated (NEW — recreate the OID4VCI test plan in the suite)"
	}
	_ = wallet2KeyAction

	// ── 13. HAIP wallet client ────────────────────────────────────────────────
	// HAIP 1.0 requires attest_jwt_client_auth (OAuth 2.0 Attestation-Based
	// Client Authentication, draft-ietf-oauth-attestation-based-client-auth).
	// The conformance suite self-attests: it signs the attestation JWT with the
	// same EC P-256 key registered in the client's JWKS, sets iss =
	// client_attestation_issuer (our issuer URL), sub = client_id, and
	// cnf.jwk = the key used to sign the PoP JWT.
	// We reuse walletPubJWKSBytes (EC P-256, already prepared above).
	const haipWalletClientID = "conformance-haip-wallet"
	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			grant_types, is_active,
			dpop_bound_access_tokens, require_pkce, require_par,
			tls_client_certificate_bound_access_tokens,
			request_object_signing_alg
		) VALUES ($1, $2, $3, $4, $5, 'attest_jwt_client_auth', $6::jsonb, $7, TRUE, TRUE, TRUE, TRUE, FALSE, '')
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                                     = EXCLUDED.org_id,
			name                                       = EXCLUDED.name,
			redirect_uris                              = EXCLUDED.redirect_uris,
			post_logout_redirect_uris                  = EXCLUDED.post_logout_redirect_uris,
			token_endpoint_auth_method                 = 'attest_jwt_client_auth',
			jwks                                       = EXCLUDED.jwks,
			grant_types                                = EXCLUDED.grant_types,
			is_active                                  = TRUE,
			dpop_bound_access_tokens                   = TRUE,
			require_pkce                               = TRUE,
			require_par                                = TRUE,
			tls_client_certificate_bound_access_tokens = FALSE,
			request_object_signing_alg                 = ''
	`,
		haipWalletClientID, org.ID, "Conformance HAIP Wallet Client",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(walletPubJWKSBytes),
		[]string{"authorization_code"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert haip-wallet client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (attest_jwt_client_auth ES256, dpop_bound=true)\n", haipWalletClientID)

	// ── 13b. Second HAIP wallet client ───────────────────────────────────────
	// oid4vci-1_0-issuer-happy-flow-multiple-clients requires a second wallet
	// client (GetStaticClient2Configuration). For HAIP the conformance suite
	// signs both clients' attestation JWTs with the SAME vci.client_attester_keys_jwks
	// key (sub changes to the respective client_id), so both clients must be
	// registered in the DB with the same public JWKS.
	const haipWallet2ClientID = "conformance-haip-wallet-2"
	_, err = dbMgr.Pool.Exec(ctx, `
		INSERT INTO oidc_clients (
			client_id, org_id, name,
			redirect_uris, post_logout_redirect_uris,
			token_endpoint_auth_method,
			jwks,
			grant_types, is_active,
			dpop_bound_access_tokens, require_pkce, require_par,
			tls_client_certificate_bound_access_tokens,
			request_object_signing_alg
		) VALUES ($1, $2, $3, $4, $5, 'attest_jwt_client_auth', $6::jsonb, $7, TRUE, TRUE, TRUE, TRUE, FALSE, '')
		ON CONFLICT (client_id) DO UPDATE SET
			org_id                                     = EXCLUDED.org_id,
			name                                       = EXCLUDED.name,
			redirect_uris                              = EXCLUDED.redirect_uris,
			post_logout_redirect_uris                  = EXCLUDED.post_logout_redirect_uris,
			token_endpoint_auth_method                 = 'attest_jwt_client_auth',
			jwks                                       = EXCLUDED.jwks,
			grant_types                                = EXCLUDED.grant_types,
			is_active                                  = TRUE,
			dpop_bound_access_tokens                   = TRUE,
			require_pkce                               = TRUE,
			require_par                                = TRUE,
			tls_client_certificate_bound_access_tokens = FALSE,
			request_object_signing_alg                 = ''
	`,
		haipWallet2ClientID, org.ID, "Conformance HAIP Wallet Client 2",
		conformanceRedirectURIs,
		conformancePostLogoutURIs,
		string(walletPubJWKSBytes), // same attester key as client 1
		[]string{"authorization_code"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upsert haip-wallet-2 client failed:", err)
		os.Exit(1)
	}
	fmt.Printf("client upserted: %s (attest_jwt_client_auth ES256, dpop_bound=true)\n", haipWallet2ClientID)

	// Update the HAIP plan JSON with the wallet client's private key.
	//
	// HAIP uses attest_jwt_client_auth: the suite signs the attestation JWT with
	// client_attestation.attester_jwks (not client.jwks, which is hidden by the
	// HAIP plan for client_attestation auth type). Both point to the same wallet
	// key so Clavex can verify the attestation JWT against the registered JWKS.
	haipPlanPath := filepath.Join(*keyDir, "haip-plan.json")
	if planBytes, readErr := os.ReadFile(haipPlanPath); readErr == nil {
		var plan map[string]interface{}
		if jsonErr := json.Unmarshal(planBytes, &plan); jsonErr == nil {
			walletPrivJWKBytes, _ := json.Marshal(walletPrivJWK)
			var walletPrivJWKMap map[string]interface{}
			_ = json.Unmarshal(walletPrivJWKBytes, &walletPrivJWKMap)

			// HAIP conformance suite v5.1.43 (OAuth2-ATCA07-1) requires an x5c entry
			// in the attester signing key. Generate a self-signed cert for the EC key
			// and embed it so the suite finds a valid certificate chain.
			var ecPrivForCert ecdsa.PrivateKey
			if rawErr := walletPrivJWK.Raw(&ecPrivForCert); rawErr == nil {
				certTemplate := &x509.Certificate{
					SerialNumber:          big.NewInt(1),
					Subject:               pkix.Name{CommonName: "conformance-haip-wallet"},
					NotBefore:             time.Now().UTC().Add(-time.Hour),
					NotAfter:              time.Now().UTC().Add(10 * 365 * 24 * time.Hour),
					KeyUsage:              x509.KeyUsageDigitalSignature,
					BasicConstraintsValid: true,
				}
				certDER, certErr := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &ecPrivForCert.PublicKey, &ecPrivForCert)
				if certErr == nil {
					walletPrivJWKMap["x5c"] = []interface{}{base64.StdEncoding.EncodeToString(certDER)}
				} else {
					fmt.Fprintf(os.Stderr, "warn: could not generate x5c cert for HAIP plan (%v) — x5c omitted\n", certErr)
				}
			}

			jwksVal := map[string]interface{}{
				"keys": []interface{}{walletPrivJWKMap},
			}

			// vci.client_attester_keys_jwks — path read by conformance suite v5.1.43
			// (CreateClientAttestationJwt.java in release-v5.1.43).
			vciSection, _ := plan["vci"].(map[string]interface{})
			if vciSection == nil {
				vciSection = map[string]interface{}{}
			}
			vciSection["client_attester_keys_jwks"] = jwksVal
			plan["vci"] = vciSection

			// client_attestation.attester_jwks — forward-compat with master branch
			// which reads this path as the primary location.
			clientAttestSection, _ := plan["client_attestation"].(map[string]interface{})
			if clientAttestSection == nil {
				clientAttestSection = map[string]interface{}{}
			}
			clientAttestSection["attester_jwks"] = jwksVal
			plan["client_attestation"] = clientAttestSection

			// client2.client_id — required by multiple-clients test
			// (GetStaticClient2Configuration reads this field).
			client2Section, _ := plan["client2"].(map[string]interface{})
			if client2Section == nil {
				client2Section = map[string]interface{}{}
			}
			client2Section["client_id"] = haipWallet2ClientID
			plan["client2"] = client2Section

			if updated, marshalErr := json.MarshalIndent(plan, "", "  "); marshalErr == nil {
				if writeErr := os.WriteFile(haipPlanPath, append(updated, '\n'), 0o644); writeErr == nil {
					fmt.Printf("plan updated:   %s (vci.client_attester_keys_jwks + client_attestation.attester_jwks set to EC P-256)\n", haipPlanPath)
				}
			}
		}
	}

	keyAction := "reused"
	if keyIsNew {
		keyAction = "generated (NEW — configure the suite once)"
	}
	key2Action := "reused"
	if key2IsNew {
		key2Action = "generated (NEW — configure the suite once)"
	}
	_ = walletKeyAction // printed inline above

	// ── Print summary ──────────────────────────────────────────────────────────
	fmt.Printf(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 clavex — conformance seed complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  org slug      : %s
  test user     : %s
  test password : %s

  client_id     : %s
  client_secret : %s

  client2_id    : %s
  client2_secret: %s

  fapi_client_id : %s  (key: %s)
  fapi_client2_id: %s  (key: %s)
  ciba_client_id : %s
  ciba_client2_id: %s  (key: fapi2, mtls-bound)
  fapi_dpop_client_id     : %s  (dpop_bound=true, no JAR — basic plan)
  fapi_dpop_client2_id    : %s  (dpop_bound=true, no JAR — basic plan)
  fapi_dpop_jar_client_id : %s  (dpop_bound=true, JAR=PS256 — JARM plan)
  fapi_dpop_jar_client2_id: %s  (dpop_bound=true, JAR=PS256 — JARM plan)
  (no client_secret — authenticate via private_key_jwt; FAPI clients use distinct keys)
  ┌─────────────────────────────────────────────────────────────┐
  │  FAPI client 1 key (%s)
  │  File: %s
  │  FAPI client 2 key (%s)
  │  File: %s
  │  create-plans.sh injects both keys automatically.           │
  └─────────────────────────────────────────────────────────────┘
  Discovery URL (from browser):
    http://localhost:8080/%s/.well-known/openid-configuration

  Conformance suite UI:
    https://localhost:8443   (or https://localhost.emobix.co.uk:8443)

  Import:
    conformance/oidcc-basic-plan.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`,
		orgSlug, testEmail, testPassword,
		clientID, clientSecret,
		client2ID, client2Secret,
		fapiClientID, keyAction,
		fapi2ClientID, key2Action,
		cibaClientID,
		cibaClient2ID,
		fapiDpopClientID,
		fapi2DpopClientID,
		fapiDpopJarClientID,
		fapi2DpopJarClientID,
		keyAction, keyPath,
		key2Action, key2Path,
		orgSlug,
	)
}

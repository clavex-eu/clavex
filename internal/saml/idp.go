// Package saml implements SAML 2.0 Identity Provider support for clavex.
// It wraps github.com/crewjam/saml and provides per-tenant IdP instances.
package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
)

// IDPConfig holds per-request (per-tenant) IdP parameters.
type IDPConfig struct {
	OrgSlug   string
	OrgID     uuid.UUID
	IssuerURL string // e.g. https://clavex.eu/inwit
}

// NewIDP builds a crewjam/saml IdentityProvider for the given org.
// It loads (or auto-generates) the org's signing certificate from the DB.
func NewIDP(
	ctx context.Context,
	cfg *config.Config,
	samlRepo *repository.SAMLRepository,
	orgRepo *repository.OrgRepository,
	idpCfg IDPConfig,
) (*saml.IdentityProvider, error) {
	cert, key, err := loadOrGenerateCert(ctx, samlRepo, idpCfg.OrgID)
	if err != nil {
		return nil, fmt.Errorf("saml: load cert: %w", err)
	}

	issuerURL, err := url.Parse(idpCfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("saml: parse issuer url: %w", err)
	}
	_ = issuerURL

	idp := &saml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		MetadataURL: *mustParseURL(idpCfg.IssuerURL + "/saml/metadata"),
		SSOURL:      *mustParseURL(idpCfg.IssuerURL + "/saml/sso"),
		LogoutURL:   *mustParseURL(idpCfg.IssuerURL + "/saml/slo"),
		ServiceProviderProvider: &dbSPProvider{
			samlRepo: samlRepo,
			orgID:    idpCfg.OrgID,
		},
		// SessionProvider is set by the handler on each request
		// because it needs access to the HTTP response writer.
	}
	_ = issuerURL // used indirectly via MetadataURL / SSOURL
	return idp, nil
}

// ── SP provider (loads SPs from DB) ──────────────────────────────────────────

type dbSPProvider struct {
	samlRepo *repository.SAMLRepository
	orgID    uuid.UUID
}

func (p *dbSPProvider) GetServiceProvider(r *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	sp, err := p.samlRepo.GetSPByEntityID(r.Context(), p.orgID, entityID)
	if err != nil {
		return nil, os.ErrNotExist
	}
	if sp.MetadataXML == nil {
		// Build minimal SP descriptor from stored fields
		return buildSPDescriptor(sp), nil
	}
	// Parse the SP's own metadata XML
	desc := &saml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(*sp.MetadataXML), desc); err != nil {
		return nil, fmt.Errorf("saml: parse sp metadata: %w", err)
	}
	return desc, nil
}

// ── Certificate helpers ───────────────────────────────────────────────────────

// loadOrGenerateCert returns the active IdP cert for the org, generating one
// if none exists yet.
func loadOrGenerateCert(ctx context.Context, repo *repository.SAMLRepository, orgID uuid.UUID) (*x509.Certificate, *rsa.PrivateKey, error) {
	idpCert, err := repo.GetActiveIDPCert(ctx, orgID)
	if err == nil {
		return idpCert.Cert, idpCert.PrivateKey, nil
	}
	if err != repository.ErrNotFound {
		return nil, nil, err
	}

	// Auto-generate a 3-year self-signed certificate for this org.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate rsa key: %w", err)
	}

	expiresAt := time.Now().Add(3 * 365 * 24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "clavex-idp-" + orgID.String(),
			Organization: []string{"clavex"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	if err := repo.StoreIDPCert(ctx, orgID, certPEM, keyPEM, expiresAt); err != nil {
		return nil, nil, fmt.Errorf("store idp cert: %w", err)
	}
	return cert, key, nil
}

// buildSPDescriptor constructs a minimal EntityDescriptor when the SP didn't
// provide full metadata XML (SP was registered manually with just ACS URL).
func buildSPDescriptor(sp interface {
	GetEntityID() string
	GetACSURL() string
	GetSLOURL() *string
	GetNameIDFormat() string
}) *saml.EntityDescriptor {
	acsURL, _ := url.Parse(sp.GetACSURL())
	ssoDesc := saml.SSODescriptor{}
	ssoDesc.ProtocolSupportEnumeration = "urn:oasis:names:tc:SAML:2.0:protocol"
	if sloURL := sp.GetSLOURL(); sloURL != nil {
		u, _ := url.Parse(*sloURL)
		ssoDesc.SingleLogoutServices = []saml.Endpoint{
			{Binding: saml.HTTPPostBinding, Location: u.String()},
		}
	}
	return &saml.EntityDescriptor{
		EntityID: sp.GetEntityID(),
		SPSSODescriptors: []saml.SPSSODescriptor{
			{
				SSODescriptor: ssoDesc,
				AssertionConsumerServices: []saml.IndexedEndpoint{
					{
						Binding:  saml.HTTPPostBinding,
						Location: acsURL.String(),
						Index:    1,
					},
				},
			},
		},
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic("saml: invalid url: " + raw)
	}
	return u
}

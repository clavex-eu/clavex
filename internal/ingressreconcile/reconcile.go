// Package ingressreconcile turns the active per-org custom domains into k8s
// ingress state on the shared Clavex Cloud cluster. For each custom domain it
// ensures an Ingress (host → Clavex service) and, for BYO certs, a TLS Secret;
// ACME domains carry a cert-resolver annotation instead and let Traefik/ACME
// fill the certificate.
//
// The default tenant subdomains ({slug}.<wildcard-base>) are served by the
// shared wildcard certificate and are skipped — only genuine customer domains
// need per-domain ingress.
package ingressreconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/rs/zerolog/log"
)

// DesiredDomain is the reconciler's target state for one custom domain.
type DesiredDomain struct {
	Host string
	// UseACME true → annotate the Ingress for the ACME resolver, no Secret.
	// false → BYO: a TLS Secret holds CertPEM + KeyPEM.
	UseACME    bool
	SecretName string // BYO only
	CertPEM    string // BYO only
	KeyPEM     string // BYO only (decrypted)
}

// Backend applies the desired ingress state and prunes managed resources for
// hosts no longer present. Implemented by the k8s adapter (or a fake in tests).
type Backend interface {
	Apply(ctx context.Context, desired []DesiredDomain) error
}

// Config parameterises the reconciler.
type Config struct {
	// WildcardBase is the shared subdomain suffix (e.g. "cloud.clavex.eu").
	// Domains ending in "."+WildcardBase are wildcard-served and skipped.
	WildcardBase string
}

// domainLister reads the active domains' cert material. Satisfied by
// *repository.CustomDomainRepository; faked in tests.
type domainLister interface {
	ListActiveForReconcile(ctx context.Context) ([]*repository.DomainCertMaterial, error)
}

// keyDecryptor decrypts a BYO private key. Satisfied by *crypto.Encryptor.
type keyDecryptor interface {
	DecryptBytes(ciphertext []byte) ([]byte, error)
}

// Reconciler builds desired ingress state from the active custom domains.
type Reconciler struct {
	domains domainLister
	enc     keyDecryptor
	backend Backend
	cfg     Config
}

// New constructs a Reconciler.
func New(domains domainLister, enc keyDecryptor, backend Backend, cfg Config) *Reconciler {
	return &Reconciler{domains: domains, enc: enc, backend: backend, cfg: cfg}
}

// secretName derives a stable, DNS-safe Secret name for a host.
func secretName(host string) string {
	sum := sha256.Sum256([]byte(host))
	return "clavex-tls-" + hex.EncodeToString(sum[:8])
}

// Reconcile reads the active custom domains, decrypts BYO keys, and applies the
// resulting desired state via the backend. Default wildcard subdomains are
// skipped. A single bad row (e.g. undecryptable key) is logged and skipped so
// it does not block the rest.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	mats, err := r.domains.ListActiveForReconcile(ctx)
	if err != nil {
		return fmt.Errorf("ingressreconcile: list active domains: %w", err)
	}

	suffix := "." + strings.TrimPrefix(r.cfg.WildcardBase, ".")
	desired := make([]DesiredDomain, 0, len(mats))
	for _, m := range mats {
		// Default tenant subdomains are covered by the wildcard cert.
		if r.cfg.WildcardBase != "" && strings.HasSuffix(m.Domain, suffix) {
			continue
		}

		d := DesiredDomain{Host: m.Domain}
		if m.CertSource == "byo" && len(m.CertKeyEnc) > 0 {
			keyPEM, err := r.enc.DecryptBytes(m.CertKeyEnc)
			if err != nil {
				log.Error().Err(err).Str("domain", m.Domain).Msg("ingressreconcile: decrypt BYO key failed; skipping")
				continue
			}
			d.UseACME = false
			d.SecretName = secretName(m.Domain)
			d.CertPEM = m.CertPEM
			d.KeyPEM = string(keyPEM)
		} else {
			d.UseACME = true
		}
		desired = append(desired, d)
	}

	if err := r.backend.Apply(ctx, desired); err != nil {
		return fmt.Errorf("ingressreconcile: apply: %w", err)
	}
	log.Info().Int("domains", len(desired)).Msg("ingressreconcile: applied ingress state")
	return nil
}

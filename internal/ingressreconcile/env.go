package ingressreconcile

import (
	"os"
	"strconv"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewFromEnv builds a Reconciler from environment configuration. It returns
// (nil, false, nil) when disabled (CLAVEX_CLOUD_INGRESS_RECONCILE != "true"), so
// callers can skip starting the worker without treating it as an error.
//
//	CLAVEX_CLOUD_INGRESS_RECONCILE — "true" to enable
//	CLAVEX_CLOUD_WILDCARD_BASE     — e.g. "cloud.clavex.eu" (default subdomains skipped)
//	CLAVEX_CLOUD_K8S_NAMESPACE     — namespace for Ingresses/Secrets (default: SA namespace)
//	CLAVEX_CLOUD_K8S_SERVICE       — Clavex service name the Ingress routes to
//	CLAVEX_CLOUD_K8S_SERVICE_PORT  — service port (default 80)
//	CLAVEX_CLOUD_INGRESS_CLASS     — ingressClassName (e.g. "traefik")
//	CLAVEX_CLOUD_CERT_RESOLVER     — Traefik ACME resolver name for non-BYO domains
func NewFromEnv(pool *pgxpool.Pool, enc *crypto.Encryptor) (*Reconciler, bool, error) {
	if os.Getenv("CLAVEX_CLOUD_INGRESS_RECONCILE") != "true" {
		return nil, false, nil
	}
	port := 80
	if p := os.Getenv("CLAVEX_CLOUD_K8S_SERVICE_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	k8sCfg, err := InClusterK8sConfig(
		os.Getenv("CLAVEX_CLOUD_K8S_NAMESPACE"),
		os.Getenv("CLAVEX_CLOUD_K8S_SERVICE"),
		port,
		os.Getenv("CLAVEX_CLOUD_INGRESS_CLASS"),
		os.Getenv("CLAVEX_CLOUD_CERT_RESOLVER"),
	)
	if err != nil {
		return nil, false, err
	}
	r := New(
		repository.NewCustomDomainRepository(pool),
		enc,
		NewK8sBackend(k8sCfg),
		Config{WildcardBase: os.Getenv("CLAVEX_CLOUD_WILDCARD_BASE")},
	)
	return r, true, nil
}

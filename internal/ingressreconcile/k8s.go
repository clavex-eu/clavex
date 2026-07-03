package ingressreconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// K8sConfig configures the in-cluster k8s backend.
type K8sConfig struct {
	// APIServer base URL (e.g. https://10.0.0.1:443). In-cluster it is derived
	// from KUBERNETES_SERVICE_HOST/PORT; tests inject an httptest URL.
	APIServer string
	Token     string
	// CAPool verifies the API server cert; nil skips (tests / injected client).
	CAPool *x509.CertPool

	Namespace        string // where Clavex + the Ingresses/Secrets live
	ServiceName      string // Clavex service name the Ingress routes to
	ServicePort      int
	IngressClassName string // e.g. "traefik"
	CertResolver     string // Traefik ACME resolver name for non-BYO domains

	// httpClient is used as-is when set (tests); otherwise built from CAPool.
	httpClient *http.Client
}

const managedByLabel = "app.kubernetes.io/managed-by"
const managedByValue = "clavex-reconciler"
const fieldManager = "clavex-reconciler"

// InClusterK8sConfig loads the service-account token, CA, and API server from
// the standard in-cluster mount, and returns a K8sConfig with the given tenant
// settings filled in.
func InClusterK8sConfig(namespace, service string, port int, className, certResolver string) (K8sConfig, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port443 := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port443 == "" {
		return K8sConfig{}, fmt.Errorf("not running in-cluster (KUBERNETES_SERVICE_HOST unset)")
	}
	const base = "/var/run/secrets/kubernetes.io/serviceaccount"
	token, err := os.ReadFile(base + "/token")
	if err != nil {
		return K8sConfig{}, fmt.Errorf("read SA token: %w", err)
	}
	caPEM, err := os.ReadFile(base + "/ca.crt")
	if err != nil {
		return K8sConfig{}, fmt.Errorf("read SA CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return K8sConfig{}, fmt.Errorf("parse SA CA")
	}
	if namespace == "" {
		if ns, err := os.ReadFile(base + "/namespace"); err == nil {
			namespace = strings.TrimSpace(string(ns))
		}
	}
	return K8sConfig{
		APIServer:        "https://" + host + ":" + port443,
		Token:            strings.TrimSpace(string(token)),
		CAPool:           pool,
		Namespace:        namespace,
		ServiceName:      service,
		ServicePort:      port,
		IngressClassName: className,
		CertResolver:     certResolver,
	}, nil
}

// K8sBackend applies ingress state via the k8s REST API using Server-Side Apply
// (idempotent create-or-update) and stdlib net/http — no client-go dependency.
type K8sBackend struct {
	cfg    K8sConfig
	client *http.Client
}

// NewK8sBackend builds a backend from config.
func NewK8sBackend(cfg K8sConfig) *K8sBackend {
	client := cfg.httpClient
	if client == nil {
		client = &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: cfg.CAPool, MinVersion: tls.VersionTLS12},
			},
		}
	}
	return &K8sBackend{cfg: cfg, client: client}
}

func ingressName(host string) string {
	sum := sha256.Sum256([]byte(host))
	return "clavex-cd-" + hex.EncodeToString(sum[:8])
}

// Apply upserts an Ingress (+ Secret for BYO) per desired domain, then prunes
// managed Ingresses/Secrets whose host is no longer desired.
func (b *K8sBackend) Apply(ctx context.Context, desired []DesiredDomain) error {
	wantHosts := make(map[string]bool, len(desired))
	for _, d := range desired {
		wantHosts[d.Host] = true
		if !d.UseACME {
			if err := b.applySecret(ctx, d); err != nil {
				return fmt.Errorf("apply secret for %s: %w", d.Host, err)
			}
		}
		if err := b.applyIngress(ctx, d); err != nil {
			return fmt.Errorf("apply ingress for %s: %w", d.Host, err)
		}
	}
	return b.prune(ctx, wantHosts)
}

func (b *K8sBackend) applySecret(ctx context.Context, d DesiredDomain) error {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/tls",
		"metadata": map[string]any{
			"name":   d.SecretName,
			"labels": map[string]string{managedByLabel: managedByValue, "clavex.eu/host": hostLabel(d.Host)},
		},
		"stringData": map[string]string{"tls.crt": d.CertPEM, "tls.key": d.KeyPEM},
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", b.cfg.Namespace, d.SecretName)
	return b.serverSideApply(ctx, path, obj)
}

func (b *K8sBackend) applyIngress(ctx context.Context, d DesiredDomain) error {
	annotations := map[string]string{}
	tlsEntry := map[string]any{"hosts": []string{d.Host}}
	if d.UseACME {
		if b.cfg.CertResolver != "" {
			annotations["traefik.ingress.kubernetes.io/router.tls.certresolver"] = b.cfg.CertResolver
		}
	} else {
		tlsEntry["secretName"] = d.SecretName
	}

	meta := map[string]any{
		"name":   ingressName(d.Host),
		"labels": map[string]string{managedByLabel: managedByValue, "clavex.eu/host": hostLabel(d.Host)},
	}
	if len(annotations) > 0 {
		meta["annotations"] = annotations
	}
	spec := map[string]any{
		"rules": []any{map[string]any{
			"host": d.Host,
			"http": map[string]any{"paths": []any{map[string]any{
				"path":     "/",
				"pathType": "Prefix",
				"backend": map[string]any{"service": map[string]any{
					"name": b.cfg.ServiceName,
					"port": map[string]any{"number": b.cfg.ServicePort},
				}},
			}}},
		}},
		"tls": []any{tlsEntry},
	}
	if b.cfg.IngressClassName != "" {
		spec["ingressClassName"] = b.cfg.IngressClassName
	}
	obj := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "Ingress",
		"metadata":   meta,
		"spec":       spec,
	}
	path := fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/ingresses/%s", b.cfg.Namespace, ingressName(d.Host))
	return b.serverSideApply(ctx, path, obj)
}

// prune deletes managed Ingresses (and their Secrets) whose host is not wanted.
func (b *K8sBackend) prune(ctx context.Context, wantHosts map[string]bool) error {
	sel := "?labelSelector=" + managedByLabel + "%3D" + managedByValue
	var list struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				Rules []struct {
					Host string `json:"host"`
				} `json:"rules"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := b.getJSON(ctx, "/apis/networking.k8s.io/v1/namespaces/"+b.cfg.Namespace+"/ingresses"+sel, &list); err != nil {
		return fmt.Errorf("list managed ingresses: %w", err)
	}
	for _, it := range list.Items {
		host := ""
		if len(it.Spec.Rules) > 0 {
			host = it.Spec.Rules[0].Host
		}
		if wantHosts[host] {
			continue
		}
		_ = b.delete(ctx, "/apis/networking.k8s.io/v1/namespaces/"+b.cfg.Namespace+"/ingresses/"+it.Metadata.Name)
		// Best-effort: delete the paired secret if present.
		_ = b.delete(ctx, "/api/v1/namespaces/"+b.cfg.Namespace+"/secrets/"+secretName(host))
	}
	return nil
}

// serverSideApply issues an idempotent SSA PATCH.
func (b *K8sBackend) serverSideApply(ctx context.Context, path string, obj any) error {
	body, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	url := b.cfg.APIServer + path + "?fieldManager=" + fieldManager + "&force=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/apply-patch+yaml") // JSON is valid YAML
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.cfg.Token)
	return b.do(req, nil)
}

func (b *K8sBackend) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.cfg.APIServer+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.cfg.Token)
	req.Header.Set("Accept", "application/json")
	return b.do(req, out)
}

func (b *K8sBackend) delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, b.cfg.APIServer+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.cfg.Token)
	return b.do(req, nil)
}

func (b *K8sBackend) do(req *http.Request, out any) error {
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusNotFound && req.Method == http.MethodDelete {
			return nil // already gone
		}
		return fmt.Errorf("k8s %s %s: %d: %s", req.Method, req.URL.Path, resp.StatusCode, body)
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// hostLabel makes a host safe for a k8s label value (<=63 chars, no dots).
func hostLabel(host string) string {
	h := strings.ReplaceAll(host, ".", "-")
	if len(h) > 63 {
		h = h[:63]
	}
	return h
}

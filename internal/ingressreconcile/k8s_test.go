package ingressreconcile

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type captured struct {
	method, path, contentType, auth, query string
	body                                   map[string]any
}

// testBackend spins an httptest k8s API server and returns the backend + a
// pointer to the captured PATCH/GET/DELETE requests.
func testBackend(t *testing.T, ingressList any) (*K8sBackend, *[]captured) {
	t.Helper()
	var reqs []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := captured{method: r.Method, path: r.URL.Path, contentType: r.Header.Get("Content-Type"),
			auth: r.Header.Get("Authorization"), query: r.URL.RawQuery}
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			_ = json.Unmarshal(b, &c.body)
		}
		reqs = append(reqs, c)
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(ingressList)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	be := NewK8sBackend(K8sConfig{
		APIServer: srv.URL, Token: "tok", Namespace: "clavex",
		ServiceName: "clavex", ServicePort: 80, IngressClassName: "traefik",
		CertResolver: "le", httpClient: srv.Client(),
	})
	return be, &reqs
}

func TestK8s_ApplyACMEDomain(t *testing.T) {
	be, reqs := testBackend(t, map[string]any{"items": []any{}})
	err := be.Apply(context.Background(), []DesiredDomain{{Host: "auth.acme.com", UseACME: true}})
	if err != nil {
		t.Fatal(err)
	}
	// Expect: PATCH ingress, GET list (prune). No secret PATCH for ACME.
	var ingressPatch *captured
	for i := range *reqs {
		r := &(*reqs)[i]
		if r.method == http.MethodPatch && strings.Contains(r.path, "/ingresses/") {
			ingressPatch = r
		}
		if r.method == http.MethodPatch && strings.Contains(r.path, "/secrets/") {
			t.Error("ACME domain must not create a Secret")
		}
	}
	if ingressPatch == nil {
		t.Fatal("no ingress PATCH")
	}
	if ingressPatch.contentType != "application/apply-patch+yaml" {
		t.Errorf("SSA content-type: %s", ingressPatch.contentType)
	}
	if ingressPatch.auth != "Bearer tok" {
		t.Errorf("auth: %s", ingressPatch.auth)
	}
	if !strings.Contains(ingressPatch.query, "fieldManager=clavex-reconciler") {
		t.Errorf("missing fieldManager: %s", ingressPatch.query)
	}
	meta, _ := ingressPatch.body["metadata"].(map[string]any)
	ann, _ := meta["annotations"].(map[string]any)
	if ann["traefik.ingress.kubernetes.io/router.tls.certresolver"] != "le" {
		t.Errorf("ACME cert-resolver annotation missing: %+v", ann)
	}
}

func TestK8s_ApplyBYODomain(t *testing.T) {
	be, reqs := testBackend(t, map[string]any{"items": []any{}})
	err := be.Apply(context.Background(), []DesiredDomain{{
		Host: "auth.acme.com", UseACME: false, SecretName: "clavex-tls-abc",
		CertPEM: "CERTPEM", KeyPEM: "KEYPEM",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var secretPatch *captured
	for i := range *reqs {
		r := &(*reqs)[i]
		if r.method == http.MethodPatch && strings.Contains(r.path, "/secrets/") {
			secretPatch = r
		}
	}
	if secretPatch == nil {
		t.Fatal("BYO domain must create a Secret")
	}
	if secretPatch.body["type"] != "kubernetes.io/tls" {
		t.Errorf("secret type: %v", secretPatch.body["type"])
	}
	sd, _ := secretPatch.body["stringData"].(map[string]any)
	if sd["tls.crt"] != "CERTPEM" || sd["tls.key"] != "KEYPEM" {
		t.Errorf("secret data wrong: %+v", sd)
	}
}

func TestK8s_PrunesStaleIngress(t *testing.T) {
	// The API lists one managed ingress for stale.acme.com; desired set does not
	// include it → it must be DELETEd.
	list := map[string]any{"items": []any{
		map[string]any{
			"metadata": map[string]any{"name": "clavex-cd-stale", "labels": map[string]any{managedByLabel: managedByValue}},
			"spec":     map[string]any{"rules": []any{map[string]any{"host": "stale.acme.com"}}},
		},
	}}
	be, reqs := testBackend(t, list)
	err := be.Apply(context.Background(), []DesiredDomain{{Host: "keep.acme.com", UseACME: true}})
	if err != nil {
		t.Fatal(err)
	}
	var deletedStale bool
	for _, r := range *reqs {
		if r.method == http.MethodDelete && strings.Contains(r.path, "clavex-cd-stale") {
			deletedStale = true
		}
	}
	if !deletedStale {
		t.Error("stale managed ingress must be pruned")
	}
}

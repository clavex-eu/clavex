// Package vaultssh centralises access to a Vault SSH secrets engine: the
// SSRF-hardened HTTP client, CA public-key retrieval, and OpenSSH fingerprint
// computation. Both the PAM HTTP handler and the reconciliation worker share
// this package so the (optionally SSRF-relaxed) client is configured once and
// honoured everywhere.
package vaultssh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/safehttp"
	"golang.org/x/crypto/ssh"
)

// httpClient is SSRF-hardened by default. server wiring may replace it with an
// SSRF-relaxed client via SetHTTPClient when an org's Vault lives on a private
// network.
var httpClient = safehttp.Client(10*time.Second, false)

// SetHTTPClient overrides the Vault HTTP client (SSRF-relaxed opt-in).
func SetHTTPClient(hc *http.Client) {
	if hc != nil {
		httpClient = hc
	}
}

// HTTPClient returns the shared Vault HTTP client.
func HTTPClient() *http.Client { return httpClient }

// FetchCAPublicKey fetches the CA public key from the Vault SSH secrets engine.
// The returned value is the OpenSSH authorized_keys line (e.g. "ssh-rsa AAAA…").
func FetchCAPublicKey(ctx context.Context, vaultAddr, mount, token string) (string, error) {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + mount + "/ca/public-key"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// vaultDo issues an authenticated Vault request with an optional JSON body and
// enforces the expected status code.
func vaultDo(ctx context.Context, method, url, token string, body any, okStatus ...int) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	ok := false
	for _, s := range okStatus {
		if resp.StatusCode == s {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("vault returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

// CheckCapabilities queries the Vault token's effective capabilities on a path
// via POST /v1/sys/capabilities-self.
func CheckCapabilities(ctx context.Context, vaultAddr, token, path string) ([]string, error) {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/sys/capabilities-self"
	body, err := vaultDo(ctx, http.MethodPost, url, token,
		map[string]any{"paths": []string{path}}, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var r struct {
		Data struct {
			Capabilities []string `json:"capabilities"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("parse capabilities response: %w", err)
	}
	return r.Data.Capabilities, nil
}

// HasCapability reports whether caps grants want (or the wildcard root/sudo
// capabilities that imply everything).
func HasCapability(caps []string, want string) bool {
	for _, c := range caps {
		if c == want || c == "root" || c == "sudo" {
			return true
		}
	}
	return false
}

// EnableSSHMount enables a new SSH secrets engine at the given mount path.
func EnableSSHMount(ctx context.Context, vaultAddr, mount, token string) error {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/sys/mounts/" + mount
	_, err := vaultDo(ctx, http.MethodPost, url, token, map[string]any{"type": "ssh"},
		http.StatusOK, http.StatusNoContent)
	return err
}

// GenerateCASigningKey generates an internal CA signing key in the mount and
// returns the CA public key (OpenSSH authorized_keys format).
func GenerateCASigningKey(ctx context.Context, vaultAddr, mount, token string) (string, error) {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + mount + "/config/ca"
	body, err := vaultDo(ctx, http.MethodPost, url, token,
		map[string]any{"generate_signing_key": true}, http.StatusOK, http.StatusNoContent)
	if err != nil {
		return "", err
	}
	var result struct {
		Data struct {
			PublicKey string `json:"public_key"`
		} `json:"data"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &result)
	}
	if result.Data.PublicKey != "" {
		return strings.TrimSpace(result.Data.PublicKey), nil
	}
	// Some Vault versions return 204 on config/ca; fetch the key explicitly.
	return FetchCAPublicKey(ctx, vaultAddr, mount, token)
}

// ConfigureSignRole creates/updates a user-certificate signing role in the mount.
func ConfigureSignRole(ctx context.Context, vaultAddr, mount, role, token string, ttlSeconds int) error {
	if ttlSeconds <= 0 {
		ttlSeconds = 3600
	}
	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + mount + "/roles/" + role
	_, err := vaultDo(ctx, http.MethodPost, url, token, map[string]any{
		"key_type":                "ca",
		"allow_user_certificates": true,
		"allowed_users":           "*",
		"ttl":                     fmt.Sprintf("%ds", ttlSeconds),
		"default_extensions":      map[string]string{"permit-pty": ""},
	}, http.StatusOK, http.StatusNoContent)
	return err
}

// DisableSSHMount removes an SSH secrets engine mount (used to retire the old CA
// after grace, or to clean up a half-provisioned new mount on failure).
func DisableSSHMount(ctx context.Context, vaultAddr, mount, token string) error {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/sys/mounts/" + mount
	_, err := vaultDo(ctx, http.MethodDelete, url, token, nil,
		http.StatusOK, http.StatusNoContent)
	return err
}

// FingerprintSHA256 parses an OpenSSH authorized_keys line and returns its
// canonical SHA256 fingerprint (the "SHA256:…" form printed by ssh-keygen -l).
func FingerprintSHA256(authorizedKey string) (string, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", fmt.Errorf("parse ssh public key: %w", err)
	}
	return ssh.FingerprintSHA256(pk), nil
}

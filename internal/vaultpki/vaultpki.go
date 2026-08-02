// Package vaultpki centralises access to a Vault PKI secrets engine: the
// SSRF-hardened HTTP client, mount/role provisioning, CSR signing, and
// revocation. This is the Device CA counterpart to internal/vaultssh (which
// talks to Vault's SSH secrets engine for the PAM SSH CA) — same shape,
// deliberately separate implementation and separate Vault mounts, since the
// two CAs must never share a blast radius.
package vaultpki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/safehttp"
)

// httpClient is SSRF-hardened by default. Server wiring may replace it with an
// SSRF-relaxed client via SetHTTPClient when an org's Vault lives on a private
// network.
var httpClient = safehttp.Client(10*time.Second, false)

// allowPrivate mirrors the client: when the operator opts into private outbound
// targets, pre-flight URL validation must not reject private/loopback Vault
// addresses.
var allowPrivate = false

// SetHTTPClient overrides the Vault HTTP client. allowPrivateHosts must match
// the client's SSRF posture so ValidateURL agrees with the dialer.
func SetHTTPClient(hc *http.Client, allowPrivateHosts bool) {
	if hc != nil {
		httpClient = hc
		allowPrivate = allowPrivateHosts
	}
}

// HTTPClient returns the shared Vault HTTP client.
func HTTPClient() *http.Client { return httpClient }

// vaultDo issues an authenticated Vault request with an optional JSON body and
// enforces the expected status code.
func vaultDo(ctx context.Context, method, url, token string, body any, okStatus ...int) ([]byte, error) {
	url, err := safehttp.ValidateURL(url, allowPrivate)
	if err != nil {
		return nil, err
	}
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

// EnablePKIMount enables a new PKI secrets engine at the given mount path, with
// a max lease TTL generous enough for a long-lived root (the mount's own root
// cert lifetime, not the short-lived leaf device certs it issues).
func EnablePKIMount(ctx context.Context, vaultAddr, mount, token string) error {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/sys/mounts/" + mount
	_, err := vaultDo(ctx, http.MethodPost, url, token, map[string]any{
		"type":   "pki",
		"config": map[string]any{"max_lease_ttl": "87600h"}, // 10y ceiling for the root
	}, http.StatusOK, http.StatusNoContent)
	return err
}

// GenerateRootCA generates a self-signed internal root CA in the mount and
// returns its PEM certificate. commonName is a display label for the CA
// itself (not a device identity), e.g. "Clavex Device CA - <org>".
func GenerateRootCA(ctx context.Context, vaultAddr, mount, token, commonName string, ttlSeconds int) (string, error) {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + mount + "/root/generate/internal"
	body, err := vaultDo(ctx, http.MethodPost, url, token, map[string]any{
		"common_name": commonName,
		"ttl":         fmt.Sprintf("%ds", ttlSeconds),
		"key_type":    "ec",
		"key_bits":    256,
	}, http.StatusOK, http.StatusNoContent)
	if err != nil {
		return "", err
	}
	var result struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &result)
	}
	if result.Data.Certificate != "" {
		return result.Data.Certificate, nil
	}
	return FetchCACertificate(ctx, vaultAddr, mount, token)
}

// FetchCACertificate fetches the mount's CA certificate in PEM form.
func FetchCACertificate(ctx context.Context, vaultAddr, mount, token string) (string, error) {
	url, err := safehttp.ValidateURL(strings.TrimRight(vaultAddr, "/")+"/v1/"+mount+"/ca/pem", allowPrivate)
	if err != nil {
		return "", err
	}
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// ConfigureDeviceRole creates/updates a CSR-signing role for device leaf
// certificates. allow_any_name+enforce_hostnames=false is required because the
// CN is "<deviceID>@<tenantID>", not a DNS hostname; ext_key_usage is
// restricted to ClientAuth since these certs only ever authenticate a device
// to the MQTT broker.
func ConfigureDeviceRole(ctx context.Context, vaultAddr, mount, role, token string, ttlSeconds int) error {
	if ttlSeconds <= 0 {
		ttlSeconds = 604800
	}
	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + mount + "/roles/" + role
	_, err := vaultDo(ctx, http.MethodPost, url, token, map[string]any{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"require_cn":        true,
		"cn_validations":    []string{"disabled"},
		"client_flag":       true,
		"server_flag":       false,
		"key_usage":         []string{"DigitalSignature", "KeyEncipherment"},
		"ext_key_usage":     []string{"ClientAuth"},
		"ttl":               fmt.Sprintf("%ds", ttlSeconds),
		"max_ttl":           fmt.Sprintf("%ds", ttlSeconds),
	}, http.StatusOK, http.StatusNoContent)
	return err
}

// SignResult is a signed leaf certificate as returned by Vault's PKI sign
// endpoint.
type SignResult struct {
	CertificatePEM string `json:"certificate"`
	IssuingCAPEM   string `json:"issuing_ca"`
	SerialNumber   string `json:"serial_number"`
	NotAfter       int64  `json:"expiration"`
}

// SignCSR signs a PEM-encoded PKCS#10 CSR against mount/role, binding the
// given common name (which must match the CSR's own CN — callers verify this
// before calling). ttlSeconds must not exceed the role's max_ttl.
func SignCSR(ctx context.Context, vaultAddr, mount, role, token, csrPEM, commonName string, ttlSeconds int) (*SignResult, error) {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + mount + "/sign/" + role
	body, err := vaultDo(ctx, http.MethodPost, url, token, map[string]any{
		"csr":         csrPEM,
		"common_name": commonName,
		"ttl":         fmt.Sprintf("%ds", ttlSeconds),
	}, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var r struct {
		Data SignResult `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("parse sign response: %w", err)
	}
	if r.Data.CertificatePEM == "" || r.Data.SerialNumber == "" {
		return nil, fmt.Errorf("vault sign response missing certificate/serial")
	}
	return &r.Data, nil
}

// RevokeCertificate revokes a previously issued certificate by serial number.
// This is belt-and-suspenders alongside Clavex's own device_certificates
// status check — the primary enforcement point is Clavex rejecting renewal
// for a non-active serial, not Vault's CRL.
func RevokeCertificate(ctx context.Context, vaultAddr, mount, token, serialNumber string) error {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + mount + "/revoke"
	_, err := vaultDo(ctx, http.MethodPost, url, token,
		map[string]any{"serial_number": serialNumber}, http.StatusOK, http.StatusNoContent)
	return err
}

// DisableMount removes a PKI secrets engine mount (used to retire the old CA
// after grace, or to clean up a half-provisioned new mount on failure).
func DisableMount(ctx context.Context, vaultAddr, mount, token string) error {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/sys/mounts/" + mount
	_, err := vaultDo(ctx, http.MethodDelete, url, token, nil,
		http.StatusOK, http.StatusNoContent)
	return err
}

// FingerprintSHA256 returns the hex SHA-256 fingerprint of a PEM certificate's
// DER bytes (the CA-rotation analog of vaultssh.FingerprintSHA256, but for an
// X.509 cert instead of an OpenSSH public key).
func FingerprintSHA256(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("parse PEM certificate: no PEM block found")
	}
	sum := sha256.Sum256(block.Bytes)
	return fmt.Sprintf("SHA256:%x", sum), nil
}

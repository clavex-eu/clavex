// Package assets provides storage backends for org binary assets
// (logos, favicons, backgrounds). Backends implement the Backend interface;
// two implementations are provided: S3Client (S3-compatible, SigV4) and
// LocalClient (filesystem, served via a static HTTP route).
package assets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Backend is the minimal interface required by OrgAssetHandler.
// Both S3Client and LocalClient implement it.
type Backend interface {
	// PutObject stores body under key with the given content-type and returns
	// the public URL that clients can use to download the asset.
	PutObject(ctx context.Context, key, contentType string, body []byte) (string, error)
	// DeleteObject removes the object identified by key.
	DeleteObject(ctx context.Context, key string) error
	// PublicURL returns the public download URL for key without performing any
	// network operation.
	PublicURL(key string) string
}

// S3Config holds connection parameters for an S3-compatible endpoint.
type S3Config struct {
	Endpoint  string // e.g. "https://s3.eu-west-1.amazonaws.com" or "http://minio:9000"
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	// PublicBaseURL is the public URL prefix used to build asset download URLs.
	// If empty, it is derived from Endpoint + "/" + Bucket.
	PublicBaseURL string
}

// S3Client is a minimal S3-compatible client supporting PutObject and DeleteObject.
type S3Client struct {
	cfg    S3Config
	client *http.Client
}

// NewS3Client creates a new S3Client with the given configuration.
func NewS3Client(cfg S3Config) *S3Client {
	return &S3Client{cfg: cfg, client: &http.Client{Timeout: 30 * time.Second}}
}

// PublicURL returns the public URL for a given S3 key.
func (c *S3Client) PublicURL(key string) string {
	base := c.cfg.PublicBaseURL
	if base == "" {
		base = strings.TrimRight(c.cfg.Endpoint, "/") + "/" + c.cfg.Bucket
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(key, "/")
}

// PutObject uploads body to S3 under the given key and content-type.
// Returns the public URL of the uploaded object.
func (c *S3Client) PutObject(ctx context.Context, key, contentType string, body []byte) (string, error) {
	endpoint := strings.TrimRight(c.cfg.Endpoint, "/")
	urlStr := fmt.Sprintf("%s/%s/%s", endpoint, c.cfg.Bucket, strings.TrimLeft(key, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, urlStr, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("assets: build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-amz-content-sha256", hexSHA256(body))

	if err := signRequest(req, c.cfg, body); err != nil {
		return "", fmt.Errorf("assets: sign request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("assets: put object: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body2, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("assets: put object: status %d: %s", resp.StatusCode, body2)
	}

	return c.PublicURL(key), nil
}

// DeleteObject removes an object from S3.
func (c *S3Client) DeleteObject(ctx context.Context, key string) error {
	endpoint := strings.TrimRight(c.cfg.Endpoint, "/")
	urlStr := fmt.Sprintf("%s/%s/%s", endpoint, c.cfg.Bucket, strings.TrimLeft(key, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return fmt.Errorf("assets: build delete request: %w", err)
	}
	req.Header.Set("x-amz-content-sha256", hexSHA256(nil))

	if err := signRequest(req, c.cfg, nil); err != nil {
		return fmt.Errorf("assets: sign delete request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("assets: delete object: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("assets: delete: status %d", resp.StatusCode)
	}
	return nil
}

// ── AWS SigV4 signing ─────────────────────────────────────────────────────────

func signRequest(req *http.Request, cfg S3Config, body []byte) error {
	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	dateTimeStr := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", dateTimeStr)
	req.Header.Set("host", req.URL.Host)

	payloadHash := hexSHA256(body)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	// Canonical headers (sorted by name).
	canonHeaders, signedHeaders := buildCanonHeaders(req)

	canonRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStr, cfg.Region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		dateTimeStr,
		scope,
		hexSHA256([]byte(canonRequest)),
	}, "\n")

	signingKey := deriveSigningKey(cfg.SecretKey, dateStr, cfg.Region, "s3")
	signature := hex.EncodeToString(hmacSHA256Bytes(signingKey, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		cfg.AccessKey, scope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
	return nil
}

func buildCanonHeaders(req *http.Request) (canonical, signed string) {
	type kv struct{ k, v string }
	var headers []kv
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		headers = append(headers, kv{lk, strings.Join(vs, ",")})
	}
	// Always include host.
	sort.Slice(headers, func(i, j int) bool { return headers[i].k < headers[j].k })

	var sb, sn strings.Builder
	for _, h := range headers {
		sb.WriteString(h.k + ":" + strings.TrimSpace(h.v) + "\n")
		if sn.Len() > 0 {
			sn.WriteString(";")
		}
		sn.WriteString(h.k)
	}
	return sb.String(), sn.String()
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256Bytes([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256Bytes(kDate, []byte(region))
	kService := hmacSHA256Bytes(kRegion, []byte(service))
	return hmacSHA256Bytes(kService, []byte("aws4_request"))
}

func hmacSHA256Bytes(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

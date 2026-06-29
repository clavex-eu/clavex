// Package fga provides a lightweight HTTP client for OpenFGA — the CNCF
// open-source implementation of Google Zanzibar relationship-based access
// control (ReBAC).
//
// OpenFGA exposes a REST API; this client wraps the four operations Clavex needs:
//
//   - CreateStore — provision a new OpenFGA store (one per Clavex organization)
//   - WriteModel  — push a Zanzibar type-definition graph (authorization model)
//   - Check       — evaluate a single relationship query ("can user U do R on O?")
//   - Write       — create or delete relationship tuples
//   - Read        — list relationship tuples for a given filter
//
// No OpenFGA Go SDK dependency is added — OpenFGA's REST API is stable and
// straightforward enough to drive with stdlib net/http.
package fga

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TupleKey is the fundamental unit of an OpenFGA relationship:
//
//	user:<id> → relation → object:<id>
//
// Clavex maps the authenticated user's OIDC subject (UUID) to the user field:
//
//	"user:01925f3a-..." can_read "document:budget-Q1"
type TupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// Tuple is a stored TupleKey with server-assigned metadata.
type Tuple struct {
	Key       TupleKey  `json:"key"`
	Timestamp time.Time `json:"timestamp"`
}

// Client is a minimal OpenFGA REST API client.
type Client struct {
	endpoint string
	apiKey   string
	hc       *http.Client
}

// NewClient constructs a Client pointing at endpoint (e.g. "http://openfga:8080").
// apiKey is optional; leave empty for unauthenticated/mTLS-protected deployments.
func NewClient(endpoint, apiKey string) *Client {
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		hc:       &http.Client{Timeout: 10 * time.Second},
	}
}

// ── Public API ─────────────────────────────────────────────────────────────────

// CreateStore provisions a new OpenFGA store and returns its store ID.
// Typically called once when a Clavex org first enables FGA.
func (c *Client) CreateStore(ctx context.Context, name string) (string, error) {
	body := map[string]string{"name": name}
	var resp struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/stores", nil, body, &resp); err != nil {
		return "", fmt.Errorf("fga: create store: %w", err)
	}
	return resp.ID, nil
}

// WriteModel uploads a Zanzibar-style authorization model to an existing store.
// model must be a valid OpenFGA schema_version 1.1 JSON object.
// Returns the new authorization_model_id.
func (c *Client) WriteModel(ctx context.Context, storeID string, model json.RawMessage) (string, error) {
	var resp struct {
		ModelID string `json:"authorization_model_id"`
	}
	if err := c.do(ctx, http.MethodPost, "/stores/"+storeID+"/authorization-models", nil, model, &resp); err != nil {
		return "", fmt.Errorf("fga: write model: %w", err)
	}
	return resp.ModelID, nil
}

// GetModel retrieves the active authorization model for a store.
// Returns the raw JSON of the model.
func (c *Client) GetModel(ctx context.Context, storeID, modelID string) (json.RawMessage, error) {
	var resp struct {
		Model json.RawMessage `json:"authorization_model"`
	}
	path := "/stores/" + storeID + "/authorization-models"
	if modelID != "" {
		path += "/" + modelID
	}
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &resp); err != nil {
		return nil, fmt.Errorf("fga: get model: %w", err)
	}
	return resp.Model, nil
}

// Check evaluates a single relationship query.
// Returns (true, nil) when allowed, (false, nil) when denied, and
// (false, err) on transport or OpenFGA errors.
func (c *Client) Check(ctx context.Context, storeID, modelID string, tuple TupleKey) (bool, error) {
	body := map[string]any{
		"tuple_key": tuple,
	}
	if modelID != "" {
		body["authorization_model_id"] = modelID
	}
	var resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := c.do(ctx, http.MethodPost, "/stores/"+storeID+"/check", nil, body, &resp); err != nil {
		return false, fmt.Errorf("fga: check: %w", err)
	}
	return resp.Allowed, nil
}

// Write creates and/or deletes relationship tuples atomically.
// Either writes or deletes may be nil/empty.
func (c *Client) Write(ctx context.Context, storeID, modelID string, writes, deletes []TupleKey) error {
	body := map[string]any{}
	if modelID != "" {
		body["authorization_model_id"] = modelID
	}
	if len(writes) > 0 {
		body["writes"] = map[string]any{"tuple_keys": writes}
	}
	if len(deletes) > 0 {
		body["deletes"] = map[string]any{"tuple_keys": deletes}
	}
	if len(body) == 0 {
		return nil
	}
	if err := c.do(ctx, http.MethodPost, "/stores/"+storeID+"/write", nil, body, nil); err != nil {
		return fmt.Errorf("fga: write: %w", err)
	}
	return nil
}

// Read lists relationship tuples matching filter. Empty filter fields are wildcards.
// Returns up to pageSize tuples and a continuation token for pagination.
func (c *Client) Read(ctx context.Context, storeID string, filter TupleKey, pageSize int, continuationToken string) ([]Tuple, string, error) {
	body := map[string]any{"tuple_key": filter}
	if pageSize > 0 {
		body["page_size"] = pageSize
	}
	if continuationToken != "" {
		body["continuation_token"] = continuationToken
	}
	var resp struct {
		Tuples            []Tuple `json:"tuples"`
		ContinuationToken string  `json:"continuation_token"`
	}
	if err := c.do(ctx, http.MethodPost, "/stores/"+storeID+"/read", nil, body, &resp); err != nil {
		return nil, "", fmt.Errorf("fga: read: %w", err)
	}
	return resp.Tuples, resp.ContinuationToken, nil
}

// Ping checks that the OpenFGA server is reachable by calling GET /healthz.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/healthz", nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("fga: ping: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("fga: ping: status %d", resp.StatusCode)
	}
	return nil
}

// ── Internal ───────────────────────────────────────────────────────────────────

// do sends an HTTP request to the OpenFGA API. body is JSON-encoded when non-nil.
// v is JSON-decoded from the response body when non-nil.
func (c *Client) do(ctx context.Context, method, path string, query map[string]string, body, v any) error {
	var bodyReader io.Reader
	if body != nil {
		var b []byte
		var err error
		switch bv := body.(type) {
		case json.RawMessage:
			b = bv
		default:
			b, err = json.Marshal(body)
			if err != nil {
				return err
			}
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bodyReader)
	if err != nil {
		return err
	}
	c.setHeaders(req)

	if len(query) > 0 {
		q := req.URL.Query()
		for k, val := range query {
			q.Set(k, val)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	if v != nil {
		return json.NewDecoder(resp.Body).Decode(v)
	}
	return nil
}

func (c *Client) setHeaders(req *http.Request) {
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
}

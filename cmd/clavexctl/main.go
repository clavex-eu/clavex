// clavexctl — CLI for the Clavex Identity Platform admin API.
//
// Usage:
//
//	clavexctl orgs list
//	clavexctl users create --org myorg --email alice@example.com --first Alice --last Smith
//	clavexctl audit export --org myorg --from 2026-01-01
//	clavexctl audit verify --proof proof.json [--jwks <url>]
//	clavexctl merkle verify --org myorg
//	clavexctl clients list --org myorg
//	clavexctl clients create --org myorg --name "My App" --redirect https://app.example.com/cb
//	clavexctl policies list --org myorg
//	clavexctl policies simulate --org myorg --ip 1.2.3.4 --country IT --client my-client
//	clavexctl risk-score --org myorg --user <user-id>
//	clavexctl gdpr erase --org myorg --user <user-id>
//	clavexctl elevate create --org myorg --token <access-token> --reason "sudo action"
//	clavexctl ai suggest-policy --org myorg "blocca da paesi extra-EU di notte"
//	clavexctl ai suggest-fga --org myorg "i manager approvano le richieste dei loro team"
//	clavexctl ai explain-error --org myorg --code invalid_request --context "PAR endpoint"
//	clavexctl ai audit-copilot --org myorg "failed logins per country last 7 days"
//
// Authentication: set CLAVEX_SERVER and CLAVEX_TOKEN, or use --server / --token flags.
// The `audit verify` sub-command is fully offline — no server or token required.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// ── globals set by persistent flags ──────────────────────────────────────────

var (
	flagServer string
	flagToken  string
	flagJSON   bool
)

func main() {
	root := &cobra.Command{
		Use:   "clavexctl",
		Short: "Clavex admin CLI",
		Long:  "clavexctl wraps the Clavex admin REST API. Pattern: kubectl-style.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if flagServer == "" {
				flagServer = os.Getenv("CLAVEX_SERVER")
			}
			if flagToken == "" {
				flagToken = os.Getenv("CLAVEX_TOKEN")
			}
			if flagServer == "" {
				return fmt.Errorf("--server or CLAVEX_SERVER is required")
			}
			if flagToken == "" {
				return fmt.Errorf("--token or CLAVEX_TOKEN is required")
			}
			return nil
		},
	}
	root.PersistentFlags().StringVar(&flagServer, "server", "", "Clavex base URL (e.g. https://clavex.example.com)")
	root.PersistentFlags().StringVar(&flagToken, "token", "", "Admin JWT (or set CLAVEX_TOKEN)")
	root.PersistentFlags().BoolVar(&flagJSON, "json", false, "Output raw JSON instead of table")

	// Load stored credentials from ~/.config/clavex/credentials.json
	// before flags are parsed so --server / --token can override them.
	loadCredentials()

	root.AddCommand(orgsCmd(), usersCmd(), auditCmd(), merkleCmd(),
		clientsCmd(), policiesCmd(), riskScoreCmd(), gdprCmd(), elevateCmd(),
		aiCmd(), pamCmd(), vaultCmd(), orgIaCCmd(), completionCmd(), loginCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── orgs ─────────────────────────────────────────────────────────────────────

func orgsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "orgs", Short: "Manage organisations"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List all organisations",
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := apiGet("/api/v1/superadmin/organizations")
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Items []struct {
					ID       string `json:"id"`
					Name     string `json:"name"`
					Slug     string `json:"slug"`
					IsActive bool   `json:"is_active"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tSLUG\tACTIVE")
			for _, o := range resp.Items {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%v\n", o.ID, o.Name, o.Slug, o.IsActive)
			}
			return tw.Flush()
		},
	}

	cmd.AddCommand(list)
	return cmd
}

// ── users ─────────────────────────────────────────────────────────────────────

func usersCmd() *cobra.Command {
	var (
		orgSlug   string
		email     string
		firstName string
		lastName  string
		password  string
	)

	cmd := &cobra.Command{Use: "users", Short: "Manage users"}

	create := &cobra.Command{
		Use:   "create",
		Short: "Create a user in an organisation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" || email == "" {
				return fmt.Errorf("--org and --email are required")
			}
			// First resolve org slug → ID.
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			payload := map[string]any{
				"email":      email,
				"first_name": firstName,
				"last_name":  lastName,
			}
			if password != "" {
				payload["password"] = password
			}
			body, err := apiPost(fmt.Sprintf("/api/v1/organizations/%s/users", orgID), payload)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var user struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			}
			if err := json.Unmarshal(body, &user); err != nil {
				fmt.Println(string(body))
				return nil
			}
			fmt.Printf("Created user %s  (%s)\n", user.Email, user.ID)
			return nil
		},
	}
	create.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	create.Flags().StringVar(&email, "email", "", "User email (required)")
	create.Flags().StringVar(&firstName, "first", "", "First name")
	create.Flags().StringVar(&lastName, "last", "", "Last name")
	create.Flags().StringVar(&password, "password", "", "Initial password (if empty, user gets magic-link on first login)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List users in an organisation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiGet(fmt.Sprintf("/api/v1/organizations/%s/users", orgID))
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Items []struct {
					ID        string `json:"id"`
					Email     string `json:"email"`
					FirstName string `json:"first_name"`
					LastName  string `json:"last_name"`
					IsActive  bool   `json:"is_active"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tEMAIL\tNAME\tACTIVE")
			for _, u := range resp.Items {
				fmt.Fprintf(tw, "%s\t%s\t%s %s\t%v\n", u.ID, u.Email, u.FirstName, u.LastName, u.IsActive)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")

	cmd.AddCommand(create, list)
	return cmd
}

// ── audit ─────────────────────────────────────────────────────────────────────

func auditCmd() *cobra.Command {
	var (
		orgSlug string
		from    string
		to      string
		limit   int
	)

	cmd := &cobra.Command{Use: "audit", Short: "Audit log operations"}

	export := &cobra.Command{
		Use:   "export",
		Short: "Export audit log entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}

			q := url.Values{}
			if from != "" {
				q.Set("since", from)
			}
			if to != "" {
				q.Set("until", to)
			}
			if limit > 0 {
				q.Set("limit", fmt.Sprint(limit))
			}
			path := fmt.Sprintf("/api/v1/organizations/%s/audit", orgID)
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			body, err := apiGet(path)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Items []struct {
					ID         int64  `json:"id"`
					Action     string `json:"action"`
					ActorEmail string `json:"actor_email"`
					Status     string `json:"status"`
					CreatedAt  string `json:"created_at"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tTIME\tACTION\tACTOR\tSTATUS")
			for _, e := range resp.Items {
				t, _ := time.Parse(time.RFC3339, e.CreatedAt)
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n",
					e.ID, t.Format("2006-01-02 15:04:05"),
					e.Action, e.ActorEmail, e.Status)
			}
			return tw.Flush()
		},
	}
	export.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	export.Flags().StringVar(&from, "from", "", "Start date (RFC3339 or YYYY-MM-DD)")
	export.Flags().StringVar(&to, "to", "", "End date (RFC3339 or YYYY-MM-DD)")
	export.Flags().IntVar(&limit, "limit", 100, "Max entries (default 100)")

	verify := auditVerifyCmd()
	fetchProof := auditFetchProofCmd()
	cmd.AddCommand(export, verify, fetchProof)
	return cmd
}

// auditFetchProofCmd builds the `audit fetch-proof` sub-command.
// Fetches the latest Merkle proof bundle from the public endpoint by org slug
// and saves it to a file for offline verification.
//
// Example (no auth required):
//
//	clavexctl audit fetch-proof --server https://id.clavex.eu --org acme --out proof.json
//	clavexctl audit verify --proof proof.json
func auditFetchProofCmd() *cobra.Command {
	var (
		orgSlug string
		outFile string
	)

	cmd := &cobra.Command{
		Use:   "fetch-proof",
		Short: "Download the latest audit Merkle proof bundle by org slug (no auth needed)",
		Long: `Fetch the latest Merkle checkpoint proof bundle from the public endpoint and
save it to a local file. The bundle can then be verified offline:

  clavexctl audit fetch-proof --server https://id.clavex.eu --org acme --out proof.json
  clavexctl audit verify --proof proof.json

No --token is required — the endpoint is public and the bundle is self-authenticating
via its RS256 signature (verified by the JWKS endpoint embedded in the bundle).`,
		// Override the root PersistentPreRunE so that --token is not required.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if flagServer == "" {
				flagServer = os.Getenv("CLAVEX_SERVER")
			}
			if flagServer == "" {
				return fmt.Errorf("--server or CLAVEX_SERVER is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			path := fmt.Sprintf("/api/v1/organizations/by-slug/%s/audit/proof/latest",
				url.PathEscape(orgSlug))

			// Use a plain GET without an Authorization header.
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
				flagServer+path, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Accept", "application/json")

			resp, err := httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close() //nolint:errcheck
			if resp.StatusCode == http.StatusNotFound {
				return fmt.Errorf("organization %q not found or no proofs sealed yet", orgSlug)
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("reading response: %w", err)
			}

			if outFile == "" {
				outFile = orgSlug + "-audit-proof.json"
			}
			if err := os.WriteFile(outFile, body, 0o644); err != nil {
				return fmt.Errorf("writing proof file: %w", err)
			}
			fmt.Printf("Proof bundle saved to %s\n", outFile)
			fmt.Printf("Verify offline with:\n  clavexctl audit verify --proof %s\n", outFile)
			return nil
		},
	}
	cmd.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	cmd.Flags().StringVar(&outFile, "out", "", "Output file path (default: <slug>-audit-proof.json)")
	return cmd
}

// auditVerifyCmd builds the `audit verify` sub-command.
// It is FULLY OFFLINE — no --server or --token is required.
func auditVerifyCmd() *cobra.Command {
	var (
		proofFile string
		jwksURL   string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an audit Merkle proof bundle offline (no auth required)",
		Long: `Verify the RS256 signature and chain hash of an audit proof bundle.

The proof bundle is a JSON file produced by:
  GET /api/v1/organizations/:org_id/audit/proof/latest

Example:
  curl -o proof.json https://id.example.com/api/v1/organizations/UUID/audit/proof/latest
  clavexctl audit verify --proof proof.json

The JWKS URL is read from proof.json (field: jwks_uri). Override with --jwks.`,
		// PersistentPreRunE on this command replaces the root's auth check
		// so that audit verify can be used without --server / --token.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditVerify(proofFile, jwksURL)
		},
	}
	cmd.Flags().StringVar(&proofFile, "proof", "", "Path to proof bundle JSON file (required)")
	cmd.Flags().StringVar(&jwksURL, "jwks", "", "JWKS URL to fetch the signing public key from (overrides proof.jwks_uri)")
	_ = cmd.MarkFlagRequired("proof")
	return cmd
}

// proofBundle mirrors the JSON shape produced by the /audit/proof/latest endpoint.
type proofBundle struct {
	Clavex  string `json:"_clavex"`
	OrgID   string `json:"org_id"`
	OrgSlug string `json:"org_slug"`
	JWKSUri string `json:"jwks_uri"`
	Checkpoint struct {
		ID         int64  `json:"id"`
		FirstLogID int64  `json:"first_log_id"`
		LastLogID  int64  `json:"last_log_id"`
		LogCount   int    `json:"log_count"`
		MerkleRoot string `json:"merkle_root"`
		PrevRoot   string `json:"prev_root"`
		ChainHash  string `json:"chain_hash"`
		Signature  string `json:"signature"`
		KID        string `json:"kid"`
		CreatedAt  string `json:"created_at"`
	} `json:"checkpoint"`
}

func runAuditVerify(proofFile, jwksOverride string) error {
	// ── 1. Read and parse the proof bundle ───────────────────────────────────
	raw, err := os.ReadFile(proofFile)
	if err != nil {
		return fmt.Errorf("reading proof file: %w", err)
	}
	var bundle proofBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return fmt.Errorf("parsing proof file: %w", err)
	}
	if bundle.Clavex != "audit-proof-bundle/v1" {
		return fmt.Errorf("unsupported proof format %q (expected audit-proof-bundle/v1)", bundle.Clavex)
	}
	cp := bundle.Checkpoint

	fmt.Printf("Proof bundle\n")
	fmt.Printf("  Org           : %s", bundle.OrgID)
	if bundle.OrgSlug != "" {
		fmt.Printf(" (%s)", bundle.OrgSlug)
	}
	fmt.Println()
	fmt.Printf("  Checkpoint    : #%d  rows %d–%d  (%d entries)\n", cp.ID, cp.FirstLogID, cp.LastLogID, cp.LogCount)
	fmt.Printf("  Sealed at     : %s\n", cp.CreatedAt)
	fmt.Printf("  Merkle root   : %s\n", cp.MerkleRoot)
	fmt.Printf("  Chain hash    : %s\n", cp.ChainHash)
	fmt.Println()

	// ── 2. Verify chain hash ─────────────────────────────────────────────────
	chainInput := cp.PrevRoot + cp.MerkleRoot
	computed := sha256.Sum256([]byte(chainInput))
	computedHex := hex.EncodeToString(computed[:])
	if computedHex != cp.ChainHash {
		return fmt.Errorf("✗ CHAIN HASH MISMATCH\n  expected: %s\n  computed: %s", cp.ChainHash, computedHex)
	}
	fmt.Println("  [1/2] Chain hash   ✓  SHA-256(prev_root || merkle_root) matches")

	// ── 3. Fetch JWKS and extract the public key ─────────────────────────────
	jwksEndpoint := bundle.JWKSUri
	if jwksOverride != "" {
		jwksEndpoint = jwksOverride
	}
	if jwksEndpoint == "" {
		return fmt.Errorf("no JWKS URL found in proof bundle — provide one with --jwks <url>")
	}
	fmt.Printf("  Fetching JWKS  : %s\n", jwksEndpoint)

	pubKey, err := fetchRSAPublicKey(jwksEndpoint, cp.KID)
	if err != nil {
		return fmt.Errorf("JWKS key fetch failed: %w", err)
	}

	// ── 4. Verify RS256 signature ────────────────────────────────────────────
	chainHashBytes, err := hex.DecodeString(cp.ChainHash)
	if err != nil {
		return fmt.Errorf("decoding chain_hash hex: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(cp.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature base64url: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, chainHashBytes, sigBytes); err != nil {
		return fmt.Errorf("✗ SIGNATURE INVALID: %w", err)
	}
	fmt.Printf("  [2/2] Signature    ✓  RS256 verified against kid=%q from JWKS\n", cp.KID)
	fmt.Println()
	fmt.Println("  ✓ PROOF VALID — the audit log checkpoint is authentic and unmodified.")
	fmt.Println()
	fmt.Println("  To also verify data integrity, export the audit rows and rebuild the Merkle tree:")
	fmt.Printf("    rows %d–%d, SHA-256 each canonical JSON {id,event_id,org_id,action,status,created_at},\n", cp.FirstLogID, cp.LastLogID)
	fmt.Printf("    build tree (pair SHA-256(left||right)), compare root to: %s\n", cp.MerkleRoot)
	return nil
}

// jwkSet is the minimal JWKS JSON structure for RS256 key extraction.
type jwkSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"` // base64url-encoded modulus
		E   string `json:"e"` // base64url-encoded public exponent
	} `json:"keys"`
}

// fetchRSAPublicKey fetches the JWKS and returns the RSA public key matching kid.
func fetchRSAPublicKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", jwksURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	for _, k := range set.Keys {
		if k.Kid != kid {
			continue
		}
		if k.Kty != "RSA" {
			return nil, fmt.Errorf("key %q has type %q, expected RSA", kid, k.Kty)
		}
		return jwkToRSA(k.N, k.E)
	}
	return nil, fmt.Errorf("key with kid=%q not found in JWKS (found %d key(s))", kid, len(set.Keys))
}

// jwkToRSA converts base64url-encoded n and e into an *rsa.PublicKey.
func jwkToRSA(n, e string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("decode JWK n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("decode JWK e: %w", err)
	}
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 | int(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}

// ── merkle ────────────────────────────────────────────────────────────────────

func merkleCmd() *cobra.Command {
	var orgSlug string

	cmd := &cobra.Command{Use: "merkle", Short: "Audit Merkle proof operations"}

	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the Merkle proof for the latest sealed audit batch",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiGet(fmt.Sprintf("/api/v1/organizations/%s/audit/merkle/proof", orgID))
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var proof struct {
				Root      string `json:"root"`
				Timestamp string `json:"sealed_at"`
				BatchID   string `json:"batch_id"`
				Valid     bool   `json:"valid"`
			}
			if err := json.Unmarshal(body, &proof); err != nil {
				fmt.Println(string(body))
				return nil
			}
			status := "✓ VALID"
			if !proof.Valid {
				status = "✗ INVALID"
			}
			fmt.Printf("Batch   : %s\n", proof.BatchID)
			fmt.Printf("Sealed  : %s\n", proof.Timestamp)
			fmt.Printf("Root    : %s\n", proof.Root)
			fmt.Printf("Status  : %s\n", status)
			return nil
		},
	}
	verify.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")

	cmd.AddCommand(verify)
	return cmd
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 30 * time.Second}

func apiGet(path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, flagServer+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+flagToken)
	req.Header.Set("Accept", "application/json")
	return doRequest(req)
}

func apiPost(path string, payload any) ([]byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, flagServer+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+flagToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return doRequest(req)
}

func doRequest(req *http.Request) ([]byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, body)
	}
	return body, nil
}

func apiDelete(path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, flagServer+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+flagToken)
	req.Header.Set("Accept", "application/json")
	return doRequest(req)
}

// resolveOrgID fetches the org list and returns the UUID matching the slug.
func resolveOrgID(slug string) (string, error) {
	body, err := apiGet("/api/v1/superadmin/organizations")
	if err != nil {
		return "", fmt.Errorf("resolving org %q: %w", slug, err)
	}
	var resp struct {
		Items []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parsing org list: %w", err)
	}
	for _, o := range resp.Items {
		if o.Slug == slug {
			return o.ID, nil
		}
	}
	return "", fmt.Errorf("organisation %q not found", slug)
}

// ── clients ───────────────────────────────────────────────────────────────────

func clientsCmd() *cobra.Command {
	var (
		orgSlug      string
		name         string
		redirectURIs []string
		isPublic     bool
	)

	cmd := &cobra.Command{Use: "clients", Short: "Manage OIDC clients"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List OIDC clients in an organisation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiGet(fmt.Sprintf("/api/v1/organizations/%s/clients", orgID))
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Items []struct {
					ClientID string `json:"client_id"`
					Name     string `json:"name"`
					IsPublic bool   `json:"is_public"`
					IsActive bool   `json:"is_active"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "CLIENT_ID\tNAME\tPUBLIC\tACTIVE")
			for _, cl := range resp.Items {
				fmt.Fprintf(tw, "%s\t%s\t%v\t%v\n", cl.ClientID, cl.Name, cl.IsPublic, cl.IsActive)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")

	create := &cobra.Command{
		Use:   "create",
		Short: "Register a new OIDC client",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" || name == "" || len(redirectURIs) == 0 {
				return fmt.Errorf("--org, --name and at least one --redirect are required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			payload := map[string]any{
				"name":          name,
				"redirect_uris": redirectURIs,
				"is_public":     isPublic,
			}
			body, err := apiPost(fmt.Sprintf("/api/v1/organizations/%s/clients", orgID), payload)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Client struct {
					ClientID string `json:"client_id"`
					Name     string `json:"name"`
				} `json:"client"`
				ClientSecret *string `json:"client_secret"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			fmt.Printf("Created client %s  (%s)\n", resp.Client.Name, resp.Client.ClientID)
			if resp.ClientSecret != nil {
				fmt.Printf("Client secret  : %s\n", *resp.ClientSecret)
				fmt.Println("(store this — it will not be shown again)")
			}
			return nil
		},
	}
	create.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	create.Flags().StringVar(&name, "name", "", "Client display name (required)")
	create.Flags().StringArrayVar(&redirectURIs, "redirect", nil, "Allowed redirect URI (repeatable, required)")
	create.Flags().BoolVar(&isPublic, "public", false, "Register as a public client (SPA/mobile — no secret)")

	cmd.AddCommand(list, create)
	return cmd
}

// ── policies ──────────────────────────────────────────────────────────────────

func policiesCmd() *cobra.Command {
	var (
		orgSlug   string
		userID    string
		clientID  string
		ipAddr    string
		country   string
		userAgent string
	)

	cmd := &cobra.Command{Use: "policies", Short: "Manage and simulate auth policies"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List auth policy rules for an organisation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiGet(fmt.Sprintf("/api/v1/organizations/%s/auth-policies", orgID))
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var rules []struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				Priority int    `json:"priority"`
				Action   string `json:"action"`
				Enabled  bool   `json:"enabled"`
			}
			if err := json.Unmarshal(body, &rules); err != nil {
				fmt.Println(string(body))
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PRIORITY\tNAME\tACTION\tENABLED\tID")
			for _, r := range rules {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%v\t%s\n", r.Priority, r.Name, r.Action, r.Enabled, r.ID)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")

	simulate := &cobra.Command{
		Use:   "simulate",
		Short: "Dry-run the policy engine for a given set of signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			payload := map[string]any{
				"ip_address": ipAddr,
				"country":    country,
				"client_id":  clientID,
				"user_agent": userAgent,
				"user_id":    userID,
			}
			body, err := apiPost(
				fmt.Sprintf("/api/v1/organizations/%s/auth-policies/simulate", orgID),
				payload,
			)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Outcome struct {
					Action string `json:"action"`
					Reason string `json:"reason"`
				} `json:"outcome"`
				MFARequired bool `json:"mfa_required"`
				Trace       []struct {
					RuleName string `json:"rule_name"`
					Priority int    `json:"priority"`
					Matched  bool   `json:"matched"`
					Action   string `json:"action"`
				} `json:"trace"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			fmt.Printf("Decision  : %s\n", resp.Outcome.Action)
			if resp.Outcome.Reason != "" {
				fmt.Printf("Reason    : %s\n", resp.Outcome.Reason)
			}
			fmt.Printf("MFA forced: %v\n", resp.MFARequired)
			if len(resp.Trace) > 0 {
				fmt.Println()
				tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "PRIORITY\tRULE\tMATCHED\tACTION")
				for _, t := range resp.Trace {
					fmt.Fprintf(tw, "%d\t%s\t%v\t%s\n", t.Priority, t.RuleName, t.Matched, t.Action)
				}
				tw.Flush() //nolint:errcheck
			}
			return nil
		},
	}
	simulate.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	simulate.Flags().StringVar(&userID, "user", "", "User ID to include user signals")
	simulate.Flags().StringVar(&clientID, "client", "", "OIDC client_id")
	simulate.Flags().StringVar(&ipAddr, "ip", "", "Simulated IP address")
	simulate.Flags().StringVar(&country, "country", "", "ISO 3166-1 country code override")
	simulate.Flags().StringVar(&userAgent, "ua", "", "User-agent string")

	cmd.AddCommand(list, simulate)
	return cmd
}

// ── risk-score ────────────────────────────────────────────────────────────────

func riskScoreCmd() *cobra.Command {
	var (
		orgSlug string
		userID  string
	)

	cmd := &cobra.Command{
		Use:   "risk-score",
		Short: "Compute the identity risk score for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" || userID == "" {
				return fmt.Errorf("--org and --user are required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiGet(fmt.Sprintf("/api/v1/organizations/%s/users/%s/risk-score", orgID, userID))
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var score struct {
				Score   int      `json:"score"`
				Level   string   `json:"level"`
				Reasons []string `json:"reasons"`
			}
			if err := json.Unmarshal(body, &score); err != nil {
				fmt.Println(string(body))
				return nil
			}
			fmt.Printf("Score  : %d / 100\n", score.Score)
			fmt.Printf("Level  : %s\n", score.Level)
			if len(score.Reasons) > 0 {
				fmt.Println("Signals:")
				for _, r := range score.Reasons {
					fmt.Printf("  • %s\n", r)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	cmd.Flags().StringVar(&userID, "user", "", "User UUID (required)")
	return cmd
}

// ── gdpr ──────────────────────────────────────────────────────────────────────

func gdprCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "gdpr", Short: "GDPR Art.17 right-to-erasure operations"}

	var (
		orgSlug string
		userID  string
		force   bool
	)

	erase := &cobra.Command{
		Use:   "erase",
		Short: "Immediately erase a user's personal data (admin-initiated, GDPR Art.17)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" || userID == "" {
				return fmt.Errorf("--org and --user are required")
			}
			if !force {
				fmt.Fprintf(os.Stderr,
					"WARNING: This will permanently anonymise user %s.\nRe-run with --force to confirm.\n", userID)
				return nil
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiDelete(fmt.Sprintf("/api/v1/organizations/%s/compliance/gdpr-erasure/%s", orgID, userID))
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			fmt.Printf("User %s erased successfully.\n", userID)
			return nil
		},
	}
	erase.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	erase.Flags().StringVar(&userID, "user", "", "User UUID to erase (required)")
	erase.Flags().BoolVar(&force, "force", false, "Confirm destructive erasure")

	cmd.AddCommand(erase)
	return cmd
}

// ── elevate ───────────────────────────────────────────────────────────────────

func elevateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "elevate", Short: "Step-up authentication challenge operations"}

	var (
		orgSlug        string
		bearerToken    string
		reason         string
		allowedMethods []string
	)

	create := &cobra.Command{
		Use:   "create",
		Short: "Create a step-up (elevate) challenge for an authenticated user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" || bearerToken == "" || reason == "" {
				return fmt.Errorf("--org, --token and --reason are required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			payload := map[string]any{
				"bearer_token":    bearerToken,
				"reason":          reason,
				"allowed_methods": allowedMethods,
			}
			body, err := apiPost(fmt.Sprintf("/api/v1/organizations/%s/elevate", orgID), payload)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				ChallengeID string   `json:"challenge_id"`
				Methods     []string `json:"available_methods"`
				ExpiresIn   int      `json:"expires_in"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			fmt.Printf("Challenge ID     : %s\n", resp.ChallengeID)
			fmt.Printf("Available methods: %v\n", resp.Methods)
			fmt.Printf("Expires in       : %ds\n", resp.ExpiresIn)
			return nil
		},
	}
	create.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	create.Flags().StringVar(&bearerToken, "token", "", "User's access token (required)")
	create.Flags().StringVar(&reason, "reason", "", "Human-readable reason for step-up (required)")
	create.Flags().StringArrayVar(&allowedMethods, "method", nil, "Allowed MFA method: totp or webauthn (repeatable; default: all)")

	cmd.AddCommand(create)
	return cmd
}

// ── completion ────────────────────────────────────────────────────────────────

// completionCmd generates shell completion scripts for bash, zsh, fish, and
// PowerShell. The output can be sourced directly or written to the appropriate
// completion directory.
//
// Quick setup:
//
//	bash:  clavexctl completion bash >> ~/.bashrc   (or /etc/bash_completion.d/clavexctl)
//	zsh:   clavexctl completion zsh  >> "${fpath[1]}/_clavexctl"
//	fish:  clavexctl completion fish > ~/.config/fish/completions/clavexctl.fish

// ── ai ───────────────────────────────────────────────────────────────────────

func aiCmd() *cobra.Command {
	var orgSlug string

	cmd := &cobra.Command{
		Use:   "ai",
		Short: "AI-assisted policy, model generation and error diagnosis",
	}

	// ── suggest-policy ────────────────────────────────────────────────────────
	suggestPolicy := &cobra.Command{
		Use:     "suggest-policy <description>",
		Short:   "Generate an auth-flow policy JSON from a natural-language description",
		Example: `  clavexctl ai suggest-policy --org myorg "blocca da paesi extra-EU di notte"`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiPost(
				fmt.Sprintf("/api/v1/organizations/%s/ai/suggest-policy", orgID),
				map[string]any{"description": args[0]},
			)
			if err != nil {
				return err
			}
			var resp struct {
				Policy json.RawMessage `json:"policy"`
			}
			if err := json.Unmarshal(body, &resp); err != nil || resp.Policy == nil {
				fmt.Println(string(body))
				return nil
			}
			out, err := json.MarshalIndent(resp.Policy, "", "  ")
			if err != nil {
				fmt.Println(string(resp.Policy))
				return nil
			}
			fmt.Println(string(out))
			return nil
		},
	}
	suggestPolicy.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")

	// ── suggest-fga ───────────────────────────────────────────────────────────
	suggestFGA := &cobra.Command{
		Use:     "suggest-fga <description>",
		Short:   "Generate an OpenFGA 1.1 authorization model from a natural-language description",
		Example: `  clavexctl ai suggest-fga --org myorg "i manager approvano le richieste dei loro team"`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiPost(
				fmt.Sprintf("/api/v1/organizations/%s/ai/suggest-fga-model", orgID),
				map[string]any{"description": args[0]},
			)
			if err != nil {
				return err
			}
			var resp struct {
				Model json.RawMessage `json:"model"`
			}
			if err := json.Unmarshal(body, &resp); err != nil || resp.Model == nil {
				fmt.Println(string(body))
				return nil
			}
			out, err := json.MarshalIndent(resp.Model, "", "  ")
			if err != nil {
				fmt.Println(string(resp.Model))
				return nil
			}
			fmt.Println(string(out))
			return nil
		},
	}
	suggestFGA.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")

	// ── explain-error ─────────────────────────────────────────────────────────
	var (
		explainCode    string
		explainCtx     string
		explainDesc    string
		explainLang    string
		explainOrgSlug string
	)
	explainError := &cobra.Command{
		Use:   "explain-error",
		Short: "Explain an OAuth2/OIDC error code in plain language",
		Example: `  clavexctl ai explain-error --org myorg --code invalid_request --context "PAR endpoint"
  clavexctl ai explain-error --org myorg --code invalid_grant --context "refresh token" --description "token has expired"
  clavexctl ai explain-error --org myorg --code access_denied --lang it`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if explainOrgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			if explainCode == "" {
				return fmt.Errorf("--code is required")
			}
			orgID, err := resolveOrgID(explainOrgSlug)
			if err != nil {
				return err
			}
			body, err := apiPost(
				fmt.Sprintf("/api/v1/organizations/%s/ai/explain-error", orgID),
				map[string]any{
					"code":        explainCode,
					"context":     explainCtx,
					"description": explainDesc,
					"lang":        explainLang,
				},
			)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Code        string   `json:"code"`
				Explanation string   `json:"explanation"`
				LikelyCause string   `json:"likely_cause"`
				HowToFix    []string `json:"how_to_fix"`
				References  []string `json:"references"`
				Raw         string   `json:"raw"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			if resp.Raw != "" {
				fmt.Println(resp.Raw)
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "Error:\t%s\n", resp.Code)
			if explainCtx != "" {
				fmt.Fprintf(w, "Context:\t%s\n", explainCtx)
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Explanation:\t%s\n", resp.Explanation)
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Likely cause:\t%s\n", resp.LikelyCause)
			if len(resp.HowToFix) > 0 {
				fmt.Fprintln(w)
				fmt.Fprintln(w, "How to fix:")
				for i, step := range resp.HowToFix {
					fmt.Fprintf(w, "  %d.\t%s\n", i+1, step)
				}
			}
			if len(resp.References) > 0 {
				fmt.Fprintln(w)
				fmt.Fprintf(w, "References:\t%s\n", strings.Join(resp.References, "  ·  "))
			}
			_ = w.Flush()
			return nil
		},
	}
	explainError.Flags().StringVar(&explainOrgSlug, "org", "", "Organisation slug (required)")
	explainError.Flags().StringVar(&explainCode, "code", "", "OAuth2/OIDC error code, e.g. invalid_request (required)")
	explainError.Flags().StringVar(&explainCtx, "context", "", "Context where the error occurred, e.g. \"PAR endpoint\"")
	explainError.Flags().StringVar(&explainDesc, "description", "", "Raw error_description string from the response")
	explainError.Flags().StringVar(&explainLang, "lang", "", "Response language BCP-47 code, e.g. it, fr, de")

	// ── audit-copilot ─────────────────────────────────────────────────────────
	var (
		auditOrgSlug string
		auditContext string
		auditLang    string
	)
	auditCopilot := &cobra.Command{
		Use:   "audit-copilot <question>",
		Short: "Query the audit log in plain language — AI generates and runs the SQL",
		Example: `  clavexctl ai audit-copilot --org myorg "failed logins in the last 24 hours"
  clavexctl ai audit-copilot --org myorg "PAM accesses to production resources last 48h from non-approved users" \
    --context "Approved users: alice@example.com, bob@example.com. Production resources: prod-db, prod-k8s"
  clavexctl ai audit-copilot --org myorg "quanti utenti si sono loggati oggi per paese" --lang it`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if auditOrgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(auditOrgSlug)
			if err != nil {
				return err
			}
			body, err := apiPost(
				fmt.Sprintf("/api/v1/organizations/%s/ai/audit-copilot", orgID),
				map[string]any{
					"query":   args[0],
					"context": auditContext,
					"lang":    auditLang,
				},
			)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Query          string                   `json:"query"`
				GeneratedSQL   string                   `json:"generated_sql"`
				Columns        []string                 `json:"columns"`
				Results        []map[string]interface{} `json:"results"`
				RowCount       int                      `json:"row_count"`
				Interpretation string                   `json:"interpretation"`
				Error          string                   `json:"error"`
				Detail         string                   `json:"detail"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			if resp.Error != "" {
				fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Error)
				if resp.Detail != "" {
					fmt.Fprintf(os.Stderr, "Detail: %s\n", resp.Detail)
				}
				if resp.GeneratedSQL != "" {
					fmt.Fprintf(os.Stderr, "\nGenerated SQL:\n%s\n", resp.GeneratedSQL)
				}
				return fmt.Errorf("audit copilot failed")
			}
			fmt.Printf("Query: %s\n\n", resp.Query)
			fmt.Printf("SQL: %s\n\n", resp.GeneratedSQL)
			if resp.RowCount == 0 {
				fmt.Println("No results found.")
			} else {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, strings.Join(resp.Columns, "\t"))
				for _, row := range resp.Results {
					vals := make([]string, len(resp.Columns))
					for i, col := range resp.Columns {
						if v := row[col]; v != nil {
							vals[i] = fmt.Sprintf("%v", v)
						} else {
							vals[i] = "—"
						}
					}
					fmt.Fprintln(w, strings.Join(vals, "\t"))
				}
				_ = w.Flush()
				fmt.Printf("\n%d row(s)\n", resp.RowCount)
			}
			if resp.Interpretation != "" {
				fmt.Printf("\nAnalysis: %s\n", resp.Interpretation)
			}
			return nil
		},
	}
	auditCopilot.Flags().StringVar(&auditOrgSlug, "org", "", "Organisation slug (required)")
	auditCopilot.Flags().StringVar(&auditContext, "context", "", "Additional context for the query (approved users, resource names, etc.)")
	auditCopilot.Flags().StringVar(&auditLang, "lang", "", "Response language BCP-47 code, e.g. it, fr, de")

	cmd.AddCommand(suggestPolicy, suggestFGA, explainError, auditCopilot)
	return cmd
}

// ── pam ──────────────────────────────────────────────────────────────────────

func pamCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pam",
		Short: "Privileged Access Management — JIT access requests and approvals",
	}

	var (
		orgSlug      string
		resourceName string
		resourceType string
		resourceID   string
		reason       string
		duration     string
		note         string
	)

	// ── pam request ──────────────────────────────────────────────────────────
	request := &cobra.Command{
		Use:     "request",
		Short:   "Submit a JIT privileged-access request",
		Example: `  clavexctl pam request --org myorg --resource prod-db --duration 2h --reason "deploy hotfix"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" || resourceName == "" || reason == "" {
				return fmt.Errorf("--org, --resource, and --reason are required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			if resourceID == "" {
				resourceID = resourceName
			}
			if resourceType == "" {
				resourceType = "generic"
			}
			minutes, err := parseDurationMinutes(duration)
			if err != nil {
				return fmt.Errorf("--duration: %w", err)
			}
			body, err := apiPost(
				fmt.Sprintf("/api/v1/organizations/%s/pam/access-requests", orgID),
				map[string]any{
					"resource_name":      resourceName,
					"resource_type":      resourceType,
					"resource_id":        resourceID,
					"justification":      reason,
					"requested_duration": minutes,
				},
			)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var req struct {
				ID           string `json:"id"`
				Status       string `json:"status"`
				ResourceName string `json:"resource_name"`
				CreatedAt    string `json:"created_at"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				fmt.Println(string(body))
				return nil
			}
			fmt.Printf("Request ID : %s\n", req.ID)
			fmt.Printf("Resource   : %s\n", req.ResourceName)
			fmt.Printf("Status     : %s\n", req.Status)
			fmt.Printf("Created    : %s\n", req.CreatedAt)
			fmt.Printf("\nAwaiting security team approval.\n")
			fmt.Printf("Check with: clavexctl pam pending --org %s\n", orgSlug)
			return nil
		},
	}
	request.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	request.Flags().StringVar(&resourceName, "resource", "", "Resource name, e.g. prod-db (required)")
	request.Flags().StringVar(&resourceType, "resource-type", "generic", "Resource category: database, server, kubernetes, api, generic")
	request.Flags().StringVar(&resourceID, "resource-id", "", "Unique resource identifier (defaults to --resource value)")
	request.Flags().StringVar(&reason, "reason", "", "Justification for access (required)")
	request.Flags().StringVar(&duration, "duration", "1h", "Requested access duration, e.g. 30m or 2h (max 8h)")

	// ── pam pending ──────────────────────────────────────────────────────────
	pending := &cobra.Command{
		Use:   "pending",
		Short: "List pending PAM access requests awaiting approval",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiGet(
				fmt.Sprintf("/api/v1/organizations/%s/pam/access-requests?status=pending", orgID),
			)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Data []struct {
					ID            string `json:"id"`
					ResourceName  string `json:"resource_name"`
					ResourceType  string `json:"resource_type"`
					Justification string `json:"justification"`
					Duration      int    `json:"requested_duration"`
					CreatedAt     string `json:"created_at"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			if len(resp.Data) == 0 {
				fmt.Println("No pending PAM access requests.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tRESOURCE\tTYPE\tDUR(min)\tJUSTIFICATION\tCREATED")
			for _, r := range resp.Data {
				t, _ := time.Parse(time.RFC3339, r.CreatedAt)
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
					r.ID, r.ResourceName, r.ResourceType, r.Duration,
					truncateStr(r.Justification, 40), t.Format("2006-01-02 15:04"))
			}
			return tw.Flush()
		},
	}
	pending.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")

	// ── pam approve ───────────────────────────────────────────────────────────
	approve := &cobra.Command{
		Use:   "approve <request-id>",
		Short: "Approve a pending PAM access request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiPost(
				fmt.Sprintf("/api/v1/organizations/%s/pam/access-requests/%s/approve", orgID, args[0]),
				map[string]any{"note": note},
			)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var req struct {
				ID           string `json:"id"`
				Status       string `json:"status"`
				ResourceName string `json:"resource_name"`
				ExpiresAt    string `json:"expires_at"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				fmt.Println(string(body))
				return nil
			}
			exp, _ := time.Parse(time.RFC3339, req.ExpiresAt)
			fmt.Printf("✓ Approved : %s (%s)\n", req.ID, req.ResourceName)
			fmt.Printf("  Status   : %s\n", req.Status)
			fmt.Printf("  Expires  : %s\n", exp.Format("2006-01-02 15:04:05"))
			return nil
		},
	}
	approve.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	approve.Flags().StringVar(&note, "note", "", "Approval note visible to the requester (optional)")

	// ── pam deny ─────────────────────────────────────────────────────────────
	deny := &cobra.Command{
		Use:   "deny <request-id>",
		Short: "Deny a pending PAM access request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiPost(
				fmt.Sprintf("/api/v1/organizations/%s/pam/access-requests/%s/deny", orgID, args[0]),
				map[string]any{"note": note},
			)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			fmt.Printf("✗ Denied: %s\n", args[0])
			_ = body
			return nil
		},
	}
	deny.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	deny.Flags().StringVar(&note, "note", "", "Denial reason visible to the requester (optional)")

	cmd.AddCommand(request, pending, approve, deny)
	return cmd
}

// ── vault ─────────────────────────────────────────────────────────────────────

func vaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "PAM credential vault — list and checkout secrets",
	}

	var (
		orgSlug         string
		reason          string
		accessRequestID string
	)

	// ── vault list ────────────────────────────────────────────────────────────
	list := &cobra.Command{
		Use:   "list",
		Short: "List vault credentials (secrets are never shown)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			body, err := apiGet(fmt.Sprintf("/api/v1/organizations/%s/pam/credentials", orgID))
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Data []struct {
					ID             string `json:"id"`
					Name           string `json:"name"`
					CredentialType string `json:"credential_type"`
					Username       string `json:"username"`
					TargetHost     string `json:"target_host"`
					CheckoutDur    int    `json:"checkout_duration"`
					RequireAR      bool   `json:"require_access_request"`
					IsActive       bool   `json:"is_active"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			if len(resp.Data) == 0 {
				fmt.Println("No vault credentials found.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tTYPE\tUSERNAME\tHOST\tCHECKOUT_MIN\tREQ_AR\tACTIVE")
			for _, c := range resp.Data {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%v\t%v\n",
					c.ID, c.Name, c.CredentialType, c.Username,
					c.TargetHost, c.CheckoutDur, c.RequireAR, c.IsActive)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")

	// ── vault checkout ────────────────────────────────────────────────────────
	checkout := &cobra.Command{
		Use:     "checkout <cred-id>",
		Short:   "Check out a vault credential — secret is printed once",
		Example: `  clavexctl vault checkout <cred-id> --org myorg --reason "hotfix deploy"`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgSlug == "" {
				return fmt.Errorf("--org is required")
			}
			orgID, err := resolveOrgID(orgSlug)
			if err != nil {
				return err
			}
			payload := map[string]any{"reason": reason}
			if accessRequestID != "" {
				payload["access_request_id"] = accessRequestID
			}
			body, err := apiPost(
				fmt.Sprintf("/api/v1/organizations/%s/pam/credentials/%s/checkout", orgID, args[0]),
				payload,
			)
			if err != nil {
				return err
			}
			if flagJSON {
				fmt.Println(string(body))
				return nil
			}
			var resp struct {
				Checkout struct {
					ID           string `json:"id"`
					ExpiresAt    string `json:"expires_at"`
					CheckedOutAt string `json:"checked_out_at"`
				} `json:"checkout"`
				Secret  string `json:"secret"`
				Warning string `json:"warning"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Println(string(body))
				return nil
			}
			exp, _ := time.Parse(time.RFC3339, resp.Checkout.ExpiresAt)
			fmt.Printf("⚠  %s\n\n", resp.Warning)
			fmt.Printf("SECRET      : %s\n", resp.Secret)
			fmt.Printf("checkout_id : %s\n", resp.Checkout.ID)
			fmt.Printf("expires_at  : %s\n", exp.Format("2006-01-02 15:04:05"))
			return nil
		},
	}
	checkout.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	checkout.Flags().StringVar(&reason, "reason", "", "Reason for checkout (audit trail)")
	checkout.Flags().StringVar(&accessRequestID, "request-id", "", "Approved PAM access request UUID (required when credential policy demands it)")

	cmd.AddCommand(list, checkout)
	return cmd
}

// ── PAM/vault helpers ─────────────────────────────────────────────────────────

// parseDurationMinutes parses a human duration string (e.g. "2h", "30m") into minutes.
func parseDurationMinutes(s string) (int, error) {
	if s == "" {
		return 60, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q — use format like 30m or 2h", s)
	}
	m := int(d.Minutes())
	if m < 1 {
		return 0, fmt.Errorf("duration must be at least 1 minute")
	}
	if m > 480 {
		return 0, fmt.Errorf("maximum duration is 480 minutes (8 hours)")
	}
	return m, nil
}

// truncateStr clips s to at most n runes, appending "…" if clipped.
func truncateStr(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

func completionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script for clavexctl.

Bash:
  clavexctl completion bash >> ~/.bashrc
  # or system-wide:
  clavexctl completion bash > /etc/bash_completion.d/clavexctl

Zsh:
  clavexctl completion zsh > "${fpath[1]}/_clavexctl"
  # then restart your shell or run: compinit

Fish:
  clavexctl completion fish > ~/.config/fish/completions/clavexctl.fish

PowerShell:
  clavexctl completion powershell | Out-String | Invoke-Expression
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		// completion does not need --server / --token; skip PersistentPreRunE.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(os.Stdout)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
	return cmd
}

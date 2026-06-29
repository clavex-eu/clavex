package main

// login implements interactive device-flow authentication for clavexctl.
//
// Usage:
//
//	clavexctl login --server https://clavex.example.com --org myorg
//
// The command:
//  1. POSTs to /{org}/device_authorization with client_id=clavexctl.
//  2. Prints the user_code and verification_uri.
//  3. Polls the token endpoint until the user approves, denies, or the code expires.
//  4. Writes the issued access token to ~/.config/clavex/credentials.json.
//
// Subsequent commands pick up the token automatically from that file.
//
// The login command overrides PersistentPreRunE so it does NOT require
// --token / CLAVEX_TOKEN — obtaining the token is the whole point.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const clavexctlClientID = "clavexctl"

// credentials is the on-disk token store (~/.config/clavex/credentials.json).
type credentials struct {
	Server string `json:"server"`
	Org    string `json:"org"`
	Token  string `json:"token"`
}

// credentialsPath returns the path to the credentials file.
func credentialsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", "clavex", "credentials.json"), nil
}

// loadCredentials reads the stored credentials and applies them to the global
// flagServer / flagToken so all other commands work without flags.
func loadCredentials() {
	path, err := credentialsPath()
	if err != nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var creds credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return
	}
	if flagServer == "" && creds.Server != "" {
		flagServer = creds.Server
	}
	if flagToken == "" && creds.Token != "" {
		flagToken = creds.Token
	}
}

// saveCredentials writes server + token to ~/.config/clavex/credentials.json.
func saveCredentials(server, org, token string) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	creds := credentials{Server: server, Org: org, Token: token}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	// 0600 — token file must not be world-readable.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}

// loginCmd builds the `clavexctl login` Cobra command.
func loginCmd() *cobra.Command {
	var orgSlug string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate interactively via OAuth 2.0 Device Flow",
		Long: `Authenticate clavexctl using the OAuth 2.0 Device Authorization Grant
(RFC 8628) — no browser required.

clavexctl opens a device authorization request, prints a user_code, then polls
until you approve it in the admin console.  The resulting token is saved to
~/.config/clavex/credentials.json and used automatically by subsequent commands.`,

		// Override the root PersistentPreRunE so we do NOT require --token.
		// We only need --server (and optionally --org) to start device flow.
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
			return runLogin(cmd.Context(), flagServer, orgSlug)
		},
	}

	cmd.Flags().StringVar(&orgSlug, "org", "", "Organisation slug (required)")
	_ = cmd.MarkFlagRequired("org")

	return cmd
}

// ── device flow implementation ────────────────────────────────────────────────

type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func runLogin(ctx context.Context, server, orgSlug string) error {
	server = strings.TrimRight(server, "/")

	// ── Step 1: device authorization request ─────────────────────────────────
	deviceAuthURL := fmt.Sprintf("%s/%s/device_authorization", server, orgSlug)
	resp, err := requestDeviceCode(ctx, deviceAuthURL)
	if err != nil {
		return fmt.Errorf("device authorization request failed: %w", err)
	}

	// ── Step 2: instruct the user ─────────────────────────────────────────────
	fmt.Println()
	fmt.Println("Open the following URL in your browser and enter the code:")
	fmt.Println()
	fmt.Printf("  URL:  %s\n", resp.VerificationURI)
	fmt.Printf("  Code: %s\n", resp.UserCode)
	if resp.VerificationURIComplete != "" {
		fmt.Println()
		fmt.Printf("  Quick link: %s\n", resp.VerificationURIComplete)
	}
	fmt.Println()
	fmt.Print("Waiting for approval")

	// ── Step 3: polling loop ──────────────────────────────────────────────────
	tokenURL := fmt.Sprintf("%s/%s/token", server, orgSlug)
	interval := resp.Interval
	if interval <= 0 {
		interval = 5
	}
	deadline := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			return ctx.Err()
		default:
		}

		if time.Now().After(deadline) {
			fmt.Println()
			return errors.New("device code expired — run `clavexctl login` again")
		}

		timer := time.NewTimer(time.Duration(interval) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			fmt.Println()
			return ctx.Err()
		case <-timer.C:
		}

		tok, pollErr := pollToken(ctx, tokenURL, resp.DeviceCode)
		if pollErr == nil {
			// ── Step 4: save token ────────────────────────────────────────────
			fmt.Println("\nAuthenticated.")
			if err := saveCredentials(server, orgSlug, tok.AccessToken); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not save credentials: %v\n", err)
				fmt.Printf("token: %s\n", tok.AccessToken)
			} else {
				path, _ := credentialsPath()
				fmt.Printf("Token saved to %s\n", path)
			}
			flagToken = tok.AccessToken
			return nil
		}

		var tokenErr *deviceFlowError
		if errors.As(pollErr, &tokenErr) {
			switch tokenErr.Code {
			case "authorization_pending":
				fmt.Print(".")
				continue
			case "slow_down":
				interval += 5
				fmt.Print(".")
				continue
			case "access_denied":
				fmt.Println()
				return errors.New("access denied — the user rejected the request")
			case "expired_token":
				fmt.Println()
				return errors.New("device code expired — run `clavexctl login` again")
			default:
				fmt.Println()
				return fmt.Errorf("token error: %s — %s", tokenErr.Code, tokenErr.Description)
			}
		}
		fmt.Println()
		return fmt.Errorf("poll token: %w", pollErr)
	}
}

// deviceFlowError is returned when the token endpoint responds with a known
// RFC 8628 error code (authorization_pending, slow_down, etc.).
type deviceFlowError struct {
	Code        string
	Description string
}

func (e *deviceFlowError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

func requestDeviceCode(ctx context.Context, endpoint string) (*deviceAuthResponse, error) {
	body := url.Values{}
	body.Set("client_id", clavexctlClientID)
	body.Set("scope", "openid")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp tokenErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var dar deviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&dar); err != nil {
		return nil, fmt.Errorf("decode device auth response: %w", err)
	}
	return &dar, nil
}

func pollToken(ctx context.Context, endpoint, deviceCode string) (*tokenResponse, error) {
	body := url.Values{}
	body.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	body.Set("device_code", deviceCode)
	body.Set("client_id", clavexctlClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var tok tokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
			return nil, fmt.Errorf("decode token response: %w", err)
		}
		return &tok, nil
	}

	var errResp tokenErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil, &deviceFlowError{Code: errResp.Error, Description: errResp.ErrorDescription}
}

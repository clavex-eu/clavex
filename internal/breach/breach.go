// Package breach checks passwords against the HaveIBeenPwned corpus using
// k-anonymity (Cloudflare-cached range API). Only the first 5 hex characters
// of the SHA-1 hash are sent to the remote service; the full hash never leaves
// the server.
//
// API reference: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
package breach

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 required by HIBP API spec
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const hibpRangeURL = "https://api.pwnedpasswords.com/range/"

// Action controls what the caller should do when a breached password is found.
type Action string

const (
	ActionOff   Action = "off"   // disabled — never check
	ActionWarn  Action = "warn"  // log/return count but do not block
	ActionBlock Action = "block" // reject the password
)

// Result holds the outcome of a breach check.
type Result struct {
	// Pwned is true when the password appears in the HIBP corpus.
	Pwned bool
	// Count is the number of times the password has been seen in breaches (0 if not pwned).
	Count int
}

// Checker queries the HIBP range API.
type Checker struct {
	client *http.Client
}

// New creates a Checker with a 5-second timeout.
func New() *Checker {
	return &Checker{client: &http.Client{Timeout: 5 * time.Second}}
}

// Check returns the breach status of password. It never returns an error for
// "password found" — errors signal network/API failures only. On error the
// caller should proceed (fail-open) rather than block the user.
func (c *Checker) Check(password string) (*Result, error) {
	//nolint:gosec // SHA-1 required by HIBP k-anonymity API
	sum := sha1.Sum([]byte(password))
	hex := fmt.Sprintf("%X", sum)
	prefix, suffix := hex[:5], hex[5:]

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, hibpRangeURL+prefix, nil)
	if err != nil {
		return nil, fmt.Errorf("breach: build request: %w", err)
	}
	req.Header.Set("Add-Padding", "true") // mitigate traffic analysis

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("breach: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("breach: unexpected status %d", resp.StatusCode)
	}

	return parseResponse(resp.Body, suffix)
}

// parseResponse scans the HIBP line-list (SUFFIX:COUNT\r\n) looking for suffix.
func parseResponse(r io.Reader, suffix string) (*Result, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], suffix) {
			count, _ := strconv.Atoi(parts[1])
			return &Result{Pwned: true, Count: count}, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("breach: read response: %w", err)
	}
	return &Result{Pwned: false}, nil
}

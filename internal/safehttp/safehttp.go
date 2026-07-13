// Package safehttp provides HTTP clients hardened against SSRF for outbound
// requests to operator/tenant-configured URLs (webhooks, SCIM push, SSF push).
//
// The guard runs in net.Dialer.Control, which fires after DNS resolution with the
// concrete IP about to be connected — so it rejects connections to private,
// loopback, link-local and other non-public ranges even when a hostname resolves
// to such an address (defeating DNS-rebinding, unlike a pre-flight URL check).
package safehttp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// Validation errors returned by ValidateURL.
var (
	ErrInvalidURL  = errors.New("safehttp: URL is not parseable")
	ErrBadScheme   = errors.New("safehttp: URL scheme must be http or https")
	ErrNoHost      = errors.New("safehttp: URL has no host")
	ErrPrivateHost = errors.New("safehttp: URL host is a non-public address")
)

// ValidateURL parses raw, enforces an http(s) scheme and a non-empty host, and —
// unless allowPrivate is set — rejects hosts written as private, loopback or
// link-local IP literals. It returns the re-serialised URL so callers pass the
// parsed-and-validated value to the request rather than the raw input.
//
// The connect-time Dialer.Control guard in Client remains the authoritative SSRF
// barrier: it also blocks hostnames that resolve to non-public addresses, which a
// pre-flight check cannot (DNS rebinding). ValidateURL is defence-in-depth and a
// recognisable validation point for callers that build a URL from configured
// input. allowPrivate must mirror the client in use so the operator opt-in for
// private outbound targets is not broken here.
func ValidateURL(raw string, allowPrivate bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", ErrBadScheme
	}
	if u.Hostname() == "" {
		return "", ErrNoHost
	}
	if !allowPrivate {
		if ip := net.ParseIP(u.Hostname()); ip != nil && blockedIP(ip) {
			return "", ErrPrivateHost
		}
	}
	return u.String(), nil
}

//nolint:misspell // blockedIP reports whether ip must not be dialed for SSRF safety. IsPrivate
// covers RFC1918 and IPv6 ULA (fc00::/7).
func blockedIP(ip net.IP) bool {
	return ip == nil ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}

// Client returns an *http.Client that refuses to connect to non-public addresses
// unless allowPrivate is true. Use it for any request to a URL that an operator or
// tenant can configure.
func Client(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if !allowPrivate {
		dialer.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("safehttp: invalid dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if blockedIP(ip) {
				return fmt.Errorf("safehttp: refusing to connect to non-public address %s", host)
			}
			return nil
		}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

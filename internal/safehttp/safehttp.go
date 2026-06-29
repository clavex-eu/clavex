// Package safehttp provides HTTP clients hardened against SSRF for outbound
// requests to operator/tenant-configured URLs (webhooks, SCIM push, SSF push).
//
// The guard runs in net.Dialer.Control, which fires after DNS resolution with the
// concrete IP about to be connected — so it rejects connections to private,
// loopback, link-local and other non-public ranges even when a hostname resolves
// to such an address (defeating DNS-rebinding, unlike a pre-flight URL check).
package safehttp

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

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

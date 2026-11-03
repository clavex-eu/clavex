package oid4w

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// Conservative public Internet profile. IPv4-mapped addresses are unwrapped;
// special-use/translation/tunnelling ranges cannot route a status fetch into
// metadata services or private infrastructure. Enforcement runs after DNS at
// socket creation, and is independent of global private-webhook opt-outs.
var statusBlockedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"), netip.MustParsePrefix("2002::/16"),
}

func publicStatusIP(address string) bool {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range statusBlockedRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func statusHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second, Control: func(_ string, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil || !publicStatusIP(host) {
			return fmt.Errorf("status target is not a public address")
		}
		return nil
	}}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableCompression: true, ForceAttemptHTTP2: true, MaxIdleConns: 32, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 16 * 1024}
	return &http.Client{Timeout: 3 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type statusResolverContextKey struct{}

var defaultStatusResolver = NewStatusResolver()

// Dependency injection is available only to trusted in-process callers, never
// to HTTP parameters or tenant policy. The production default always uses the
// hardened client above, including when private webhook targets are allowed.
func WithStatusResolver(ctx context.Context, resolver *StatusResolver) context.Context {
	return context.WithValue(ctx, statusResolverContextKey{}, resolver)
}
func StatusResolverFor(ctx context.Context) *StatusResolver {
	if resolver, ok := ctx.Value(statusResolverContextKey{}).(*StatusResolver); ok && resolver != nil {
		return resolver
	}
	return defaultStatusResolver
}

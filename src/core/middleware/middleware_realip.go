package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// MiddlewareRealIP resolves the real client IP for each request and writes it
// into r.RemoteAddr (as a bare IP, without a port), so that every downstream
// consumer (rate limiter, session/audit IP, request logger) shares one
// trustworthy value.
//
// It replaces chi's middleware.RealIP, which trusts the leftmost
// X-Forwarded-For entry and is therefore spoofable: a client can put anything
// it likes at the left of that header. Trust here instead flows from the
// unspoofable socket peer inward. See resolveClientIP.
//
// trustProxyHeaders is the master switch:
//   - false (default): headers are ignored and the socket peer is used. Secure
//     default, correct when there is no reverse proxy.
//   - true, trustedProxies empty: a single proxy hop is trusted (the rightmost
//     X-Forwarded-For entry, or X-Real-IP). Sound only when that single proxy
//     overwrites the forwarded headers.
//   - true, trustedProxies set (CIDRs/IPs): the forwarded chain is walked from
//     the right, crossing only trusted hops, which is spoof-resistant across
//     multiple proxies / a CDN.
func MiddlewareRealIP(trustProxyHeaders bool, trustedProxies []string) func(next http.Handler) http.Handler {
	trusted := parseCIDRs(trustedProxies)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = resolveClientIP(
				r.RemoteAddr,
				r.Header.Get("X-Forwarded-For"),
				r.Header.Get("X-Real-IP"),
				trustProxyHeaders,
				trusted,
			)
			next.ServeHTTP(w, r)
		})
	}
}

// resolveClientIP determines the client IP from the unspoofable socket peer, the
// X-Forwarded-For / X-Real-IP headers, and the set of trusted proxies.
//
// A client controls the left of the X-Forwarded-For chain; the proxies you
// control append on the right. So trust flows from the socket peer (the right)
// inward: we anchor to the peer and walk X-Forwarded-For right-to-left, crossing
// only hops that are themselves trusted proxies, and stop at the first untrusted
// entry, which is the real client. A forged leftmost entry is never reached.
func resolveClientIP(remoteAddr, xff, xRealIP string, trustProxyHeaders bool, trusted []*net.IPNet) string {
	peer := hostOnly(remoteAddr)

	if !trustProxyHeaders {
		return peer
	}

	// With a configured allowlist, only believe forwarded headers when the
	// connection actually arrived from a trusted proxy. If it did not, someone
	// reached us directly and their headers cannot be trusted.
	if len(trusted) > 0 && !ipInAny(peer, trusted) {
		return peer
	}

	entries := splitXFF(xff)
	if len(entries) == 0 {
		if ip := hostOnly(xRealIP); ip != "" {
			return ip
		}
		return peer
	}

	// The socket peer is our proxy (implied by trustProxyHeaders, and verified
	// above when an allowlist is configured), so adopt the rightmost entry and
	// keep walking left only while each adopted entry is itself a trusted proxy.
	client := peer
	for i := len(entries) - 1; i >= 0; i-- {
		client = entries[i]
		if !ipInAny(client, trusted) {
			break
		}
	}
	return client
}

// parseCIDRs converts a list of CIDR strings or bare IPs into IP ranges. A bare
// IP becomes a single-host range (/32 for IPv4, /128 for IPv6). Malformed
// entries are logged and skipped.
func parseCIDRs(entries []string) []*net.IPNet {
	var out []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			if ip := net.ParseIP(e); ip != nil {
				if ip.To4() != nil {
					e += "/32"
				} else {
					e += "/128"
				}
			}
		}
		_, ipNet, err := net.ParseCIDR(e)
		if err != nil {
			slog.Warn("ignoring invalid trusted proxy entry", "entry", e, "error", err)
			continue
		}
		out = append(out, ipNet)
	}
	return out
}

// splitXFF splits an X-Forwarded-For header into normalized, non-empty IPs.
func splitXFF(xff string) []string {
	if strings.TrimSpace(xff) == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if ip := hostOnly(p); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// hostOnly strips a :port suffix if present, returning the bare host/IP.
func hostOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// ipInAny reports whether ip (a bare IP string) falls inside any of the ranges.
func ipInAny(ip string, ranges []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, r := range ranges {
		if r.Contains(parsed) {
			return true
		}
	}
	return false
}

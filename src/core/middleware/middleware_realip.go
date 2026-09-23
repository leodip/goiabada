package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/errs"
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
//   - true, trustedProxies set (the ranges ParseTrustedProxies returns): the
//     forwarded chain is walked from the right, crossing only trusted hops,
//     which is spoof-resistant across multiple proxies / a CDN.
func MiddlewareRealIP(trustProxyHeaders bool, trustedProxies []*net.IPNet) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = resolveClientIP(
				r.RemoteAddr,
				r.Header.Get("X-Forwarded-For"),
				r.Header.Get("X-Real-IP"),
				trustProxyHeaders,
				trustedProxies,
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
		// Same check splitXFF applies: a header that does not carry an IP is not
		// evidence of anything, and adopting it would put a bucket, an audit entry
		// and a session record under a caller-chosen string (#219).
		if ip := hostOnly(xRealIP); net.ParseIP(ip) != nil {
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

// ParseTrustedProxies converts the configured trusted-proxy entries, each a
// CIDR range or a bare IP, into the ranges MiddlewareRealIP walks. Each entry is
// trimmed and an empty one is skipped. A bare address Go reads as IPv4 becomes
// that host's /32, and so does its IPv4-mapped IPv6 spelling (::ffff:10.0.0.1):
// the peer Go reports for that proxy is the IPv4 address, and appending /32 to
// the IPv6 text instead yields ::/32, a range that trusts ::1 and not the proxy
// (#425). Any other bare address becomes its /128, and net.ParseCIDR decides
// everything else, a CIDR with host bits set standing for its network.
//
// Every refused entry is named in the one error returned, and a list with any
// refused entry yields no ranges at all. The caller refuses to start on that
// error rather than skipping the entry: an operator who listed a proxy asked
// for a restriction, and a list whose only entries are typos would otherwise
// leave it empty, which MiddlewareRealIP reads as trusting any single hop
// (#425).
func ParseTrustedProxies(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	var refused []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		cidr := e
		if !strings.Contains(e, "/") {
			if ip := net.ParseIP(e); ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					cidr = ip4.String() + "/32"
				} else {
					cidr = e + "/128"
				}
			}
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			refused = append(refused, e)
			continue
		}
		out = append(out, ipNet)
	}
	if len(refused) > 0 {
		quoted := make([]string, len(refused))
		for i, e := range refused {
			quoted[i] = strconv.Quote(e)
		}
		return nil, errs.Errorf("the trusted proxy list has entries that are neither an IP address nor a CIDR range: %s",
			strings.Join(quoted, ", "))
	}
	return out, nil
}

// splitXFF splits an X-Forwarded-For header into normalized, non-empty IPs.
//
// Entries that net.ParseIP rejects are dropped rather than carried through: the header
// is caller-controlled, so without this a value like "<script>" becomes a rate-limit
// bucket, an audit field and a session record. Dropping an entry does not reject the
// whole header, so a chain whose garbage is followed by a real client still resolves to
// that client (#219).
//
// This drops an address carrying an IPv6 zone (fe80::1%eth0), which net.ParseIP rejects:
// a link-local address with a zone is not a client this server can be reached from.
func splitXFF(xff string) []string {
	if strings.TrimSpace(xff) == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if ip := hostOnly(p); net.ParseIP(ip) != nil {
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

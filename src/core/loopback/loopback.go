// Package loopback holds the one answer to "is this the loopback interface", IsHost, and the
// rule built on it, IsPlainHTTPOff: plain http is acceptable only to a loopback host (RFC 9700
// section 2.6, with RFC 8252 section 7.3's exception). The auth server's redirect-URI matching
// grants loopback port flexibility by IsHost, and its redirect-URI intakes refuse by
// IsPlainHTTPOff, so every place that asks the question gets the same answer, with no prefix
// match among them (#590). It is a package of its own, importing nothing beyond the standard
// library, for core/adminpassword's reason: the setup wizard asks the same question of the URLs
// it writes and links whatever this package imports. core/guard's imports_only_lint_test.go
// holds it to that, from there and not from a test here, for the reason core/adminpassword's
// doc gives (#500).
package loopback

import (
	"net"
	"net/url"
	"strings"
)

// IsHost reports whether host targets the loopback interface. It accepts a bare host, a
// host:port pair, and IPv6 forms with or without brackets, so callers may pass either
// url.URL.Host or url.URL.Hostname().
//
// The set is 127.0.0.1, ::1 and localhost. RFC 8252 section 7.3 mandates port flexibility
// for the two IP literals only; section 8.3 marks the localhost hostname NOT RECOMMENDED.
// localhost is included here as a deliberate convenience for native and MCP clients, not
// as RFC compliance (#41).
//
// Host matching is exact after case folding. A prefix match would accept
// localhost.attacker.com; RFC 3986 section 6.2.2.1 makes the host case-insensitive, so
// LOCALHOST is folded in here. The auth server's redirect-URI matching deliberately does not
// fold case in the rest of the URI.
func IsHost(host string) bool {
	h := strings.ToLower(host)

	// Brackets belong to IPv6 literals only, so handle them as their own case. Do not
	// strings.Trim them: the cutset strips any number from either end, so "[[::1]]" would
	// pass. Do not defer to net.SplitHostPort either, which accepts "[localhost]:3000" and
	// returns "localhost". Bracketed hosts are matched explicitly for that reason.
	if strings.HasPrefix(h, "[") {
		if !strings.HasPrefix(h, "[::1]") {
			return false
		}
		suffix := h[len("[::1]"):]
		return suffix == "" || (strings.HasPrefix(suffix, ":") && isDigits(suffix[1:]))
	}
	if strings.ContainsRune(h, ']') {
		return false
	}

	// Strip only a numeric port. net.SplitHostPort is happy with service names and any
	// other junk, so "localhost:evil" and "127.0.0.1:http" would otherwise reduce to a
	// loopback host. An empty port is kept, matching the bracket branch above and the auth
	// server's redirect-URI port stripping, which strips only a numeric port for the same
	// reason.
	if hp, port, err := net.SplitHostPort(h); err == nil && isDigits(port) {
		h = hp
	}
	switch h {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// IsPlainHTTPOff reports whether raw is an http URI on a host other than the loopback
// interface. RFC 9700 section 2.6 forbids carrying an authorization response over an
// unencrypted connection, with the single exception of native clients redirected to the
// loopback interface (RFC 8252 section 7.3), which is what the loopback half of this
// predicate keeps working.
//
// Callers reach it only after their own parse and absolute-URI gates: dynamic registration
// parses first and the admin API checks the absolute-URI rule ahead of it. A value that does
// not parse answers false, because refusing one is those gates' job, not this one's. A
// hostless http URI answers true on its own, so a caller that ever skips its gate still
// refuses one. The scheme is lower-cased by the parse, so HTTP and http are the same rule.
func IsPlainHTTPOff(raw string) bool {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" {
		return false
	}
	return !IsHost(parsed.Host)
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

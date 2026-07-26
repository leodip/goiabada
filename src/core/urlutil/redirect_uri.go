// Package urlutil holds dependency-free helpers for comparing redirect URIs.
//
// It deliberately knows nothing about OAuth2 concepts: callers decide which flows a given
// rule applies to. See docs/issue-41-loopback-redirect-uri.md, decision 12.
package urlutil

import (
	"net"
	"net/url"
	"strings"
)

// IsLoopbackHost reports whether host targets the loopback interface. It accepts a bare
// host, a host:port pair, and IPv6 forms with or without brackets, so callers may pass
// either url.URL.Host or url.URL.Hostname().
//
// The set is 127.0.0.1, ::1 and localhost. RFC 8252 section 7.3 mandates port flexibility
// for the two IP literals only; section 8.3 marks the localhost hostname NOT RECOMMENDED.
// localhost is included here as a deliberate convenience for native and MCP clients, not
// as RFC compliance. See decision 1 in docs/issue-41-loopback-redirect-uri.md.
//
// Host matching is exact after case folding. A prefix match would accept
// localhost.attacker.com; RFC 3986 section 6.2.2.1 makes the host case-insensitive, so
// LOCALHOST is folded in. See decision 10.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(host)

	// Brackets belong to IPv6 literals only, so handle them as their own case. Do not
	// strings.Trim them: the cutset strips any number from either end, so "[[::1]]" would
	// pass. Do not defer to net.SplitHostPort either, which accepts "[localhost]:3000" and
	// returns "localhost". See decision 14.
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
	// loopback host. An empty port is kept, matching the bracket branch above and
	// stripPortRaw. See decision 15.
	if hp, port, err := net.SplitHostPort(h); err == nil && isDigits(port) {
		h = hp
	}
	switch h {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// IsAbsoluteRedirectURI reports whether raw satisfies RFC 6749 section 3.1.2, which requires
// a redirect URI to be an absolute-URI as defined by RFC 3986 section 4.3:
//
//	absolute-URI = scheme ":" hier-part [ "?" query ]
//
// That production carries no fragment, and RFC 6749 states the fragment prohibition
// explicitly as well, so both conditions are checked here.
//
// Two things this rejects that a scheme-only test does not. A scheme-relative value such as
// "//evil.example/cb" is emitted verbatim as a protocol-relative Location, which the user
// agent resolves against the current scheme, delivering the authorization code to that host.
// And a fragment breaks the callback even when the host is legitimate: the code arrives at
// "/cb%23frag" rather than at "/cb".
//
// The fragment test is on the raw string, not on url.URL.Fragment, and that is deliberate.
// RFC 3986 makes "#" the fragment delimiter and requires it to be percent-encoded anywhere
// else, so a literal "#" always introduces a fragment component. url.URL.Fragment cannot
// express the difference: it is "" both for "/cb" and for "/cb#", so testing it accepts a
// bare trailing "#", which is a fragment component per RFC 3986 and breaks the callback the
// same way "#frag" does (the code arrives at "/cb%23"). Verified.
//
// url.ParseRequestURI is not interchangeable with url.Parse here either: it keeps a literal
// "#frag" in the path and reports Fragment as empty, so a caller testing only the scheme
// accepts "http://127.0.0.1/cb#frag". Do not "unify" the two parsers.
//
// A percent-encoded %23 is an ordinary character in a path, not a fragment delimiter, and
// stays accepted. See decision 12 in docs/issue-105-dcr-loopback-host-match.md.
func IsAbsoluteRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.IsAbs() && !strings.Contains(raw, "#")
}

// stripPortRaw removes the port from raw's authority, operating on the raw string so that
// no other component is normalised. Returns false if raw has no authority.
//
// Deliberately textual. Parsing and re-rendering through url.URL.String() would lowercase
// the scheme and re-escape the path, which silently permits differences beyond the port.
// See decision 6 in docs/issue-41-loopback-redirect-uri.md. Do not "simplify" this into a
// parse-and-render: that reintroduces the scheme-case bug this shape exists to avoid.
func stripPortRaw(raw string) (string, bool) {
	i := strings.Index(raw, "://")
	if i < 0 {
		return "", false
	}
	authStart := i + 3
	authEnd := len(raw)
	if n := strings.IndexAny(raw[authStart:], "/?#"); n >= 0 {
		authEnd = authStart + n
	}
	auth := raw[authStart:authEnd]

	hostStart := 0
	if at := strings.LastIndex(auth, "@"); at >= 0 {
		hostStart = at + 1 // userinfo stays put
	}
	host := auth[hostStart:]

	var stripped string
	if strings.HasPrefix(host, "[") {
		b := strings.Index(host, "]")
		if b < 0 {
			return "", false
		}
		// Only an empty suffix or ":digits" may follow the closing bracket. Dropping
		// whatever is there would accept [::1]:evil and [::1].attacker. See decision 13.
		if suffix := host[b+1:]; suffix != "" && !(strings.HasPrefix(suffix, ":") && isDigits(suffix[1:])) {
			return "", false
		}
		stripped = host[:b+1]
	} else if c := strings.LastIndex(host, ":"); c >= 0 && isDigits(host[c+1:]) {
		stripped = host[:c]
	} else {
		stripped = host
	}
	return raw[:authStart] + auth[:hostStart] + stripped + raw[authEnd:], true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// RedirectURIMatches reports whether requested matches registered. Exact equality always
// matches. Beyond that, RFC 8252 section 7.3 port flexibility applies only when the
// registered URI is an http loopback URI, and only the port may differ: everything else is
// compared byte for byte, per RFC 6749 section 3.1.2.3.
//
// This function is flow agnostic. Callers gate it on the authorization code flow, see
// decision 12 in docs/issue-41-loopback-redirect-uri.md.
func RedirectURIMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	reg, err := url.Parse(registered)
	if err != nil {
		return false
	}
	// RFC 8252 section 7.3 scopes loopback redirects to the http scheme. See decision 11.
	if reg.Scheme != "http" {
		return false
	}
	if !IsLoopbackHost(reg.Hostname()) {
		return false
	}
	a, ok1 := stripPortRaw(registered)
	b, ok2 := stripPortRaw(requested)
	return ok1 && ok2 && a == b
}

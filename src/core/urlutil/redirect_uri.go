// Package urlutil holds dependency-free helpers for comparing redirect URIs and for
// canonicalizing browser origins.
//
// It deliberately knows nothing about OAuth2 concepts: callers decide which flows a given
// rule applies to. Loopback port flexibility is scoped to the authorization code flow, and
// that gate lives with the caller rather than here (#41).
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
// as RFC compliance (#41).
//
// Host matching is exact after case folding. A prefix match would accept
// localhost.attacker.com; RFC 3986 section 6.2.2.1 makes the host case-insensitive, so
// LOCALHOST is folded in here. RedirectURIMatches deliberately does not fold case.
func IsLoopbackHost(host string) bool {
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
	// loopback host. An empty port is kept, matching the bracket branch above and
	// stripPortRaw, which strips only a numeric port for the same reason.
	if hp, port, err := net.SplitHostPort(h); err == nil && isDigits(port) {
		h = hp
	}
	switch h {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// IsAbsoluteRedirectURI reports whether raw is usable as a redirect URI: an absolute-URI per
// RFC 3986 section 4.3, as RFC 6749 section 3.1.2 requires,
//
//	absolute-URI = scheme ":" hier-part [ "?" query ]
//
// which is to say a scheme is present and no fragment follows (that production carries no
// fragment, and RFC 6749 states the prohibition explicitly as well), AND, for the http and
// https schemes only, an authority naming a host.
//
// # Why the host rule is here and not only in the grammar
//
// The absolute-URI production alone is not enough to make a redirect URI safe, because it
// admits values that Go parses with no host and a user agent re-reads as an authority. Both
// of these satisfy the production, so a grammar check returns true for them:
//
//	http:/evil.example/cb      hier-part admits path-absolute, so this is a valid absolute-URI
//	https:///evil.example/cb   an empty authority followed by a path
//
// Go reports Host == "" for both and emits them verbatim into a Location header. A browser
// resolving that Location reports host = evil.example and delivers the authorization code
// there. The three-slash and backslash forms reach the attacker whatever scheme the
// deployment itself runs on; the one-slash and opaque forms do so when the value's scheme
// differs from the page's. So the question this predicate has to answer is not "is this an
// absolute-URI" but "will a user agent navigate to the host this string names", and the
// empty-host test is what closes the gap between the two (#122).
//
// # The scoping to http and https is load-bearing. Do not widen it
//
// RFC 8252 section 7.1 gives this as its complete example of a native-app redirect URI:
//
//	com.example.app:/oauth2redirect/example-provider
//
// One slash, no authority, and Go parses it with Host == "". A rule phrased as "an empty host
// is refused" would refuse the document's own example and break every native and MCP client on
// every deployment. Private-use schemes are hostless by design and are resolved by the
// operating system rather than navigated to, so they carry none of the risk above. Refuse an
// empty host for http and https, and for nothing else.
//
// The scheme comparison is against lowercase because url.Parse lowercases the scheme during
// parsing; "HTTP:///evil.example/cb" therefore arrives here as "http" and is refused. That is
// relied upon deliberately rather than overlooked, and a user agent lowercases the scheme too,
// so a rule that did not fold case would be evaded by pressing shift.
//
// # What this does not do
//
// This is a form check plus that one host rule, not a full RFC 3986 grammar validator, and the
// difference is worth knowing before relying on it as a compliance gate. It verifies that
// net/url can parse raw, that a scheme is present, that no fragment is present, that every
// percent-escape is well formed, and that an http or https URI names a host. It does NOT
// validate the character classes of hier-part or query, so values that violate the grammar in
// other ways are still reported as true:
//
//	x:[      a gen-delim that pchar excludes outside an authority
//	x:你好    non-ASCII, which RFC 3986 requires to be percent-encoded
//
// Implementing pchar properly would have to be position-aware, since "[" and "]" are legal in
// an authority ("http://[::1]/cb"), and hand-rolled character validation is where false
// rejections come from. Neither shape is usable as a redirect URI anyway, because no user
// agent will deliver an authorization response to them. Callers needing true grammar
// conformance must add it; callers needing "is this scheme-relative, relative, or
// fragment-bearing" are served exactly.
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
// stays accepted.
//
// Every caller that can move a browser applies this, and it is applied to the value about to
// be used rather than only at registration: the authorization endpoint tests the requested URI
// before matching it against the client's registered set, which is what covers rows stored
// before these rules existed, and the admin API and dynamic registration both apply it at
// intake (#122, #105).
func IsAbsoluteRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if !u.IsAbs() || strings.Contains(raw, "#") {
		return false
	}
	// See "Why the host rule is here" above. Scoped to http and https because RFC 8252
	// section 7.1's own example, "com.example.app:/oauth2redirect/example-provider", is
	// hostless and must stay accepted.
	if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
		return false
	}
	// url.Parse does not validate percent-escapes in an opaque URI, so "x:%zz" and "x:%2"
	// reach here. RFC 3986 section 2.1 requires two hex digits after "%", and a literal "%"
	// to be written "%25", so a malformed escape is unambiguously not a URI. PathUnescape
	// errors on exactly that and on nothing else, which is why it is used rather than a
	// hand-written scan.
	if _, err := url.PathUnescape(raw); err != nil {
		return false
	}
	return true
}

// stripPortRaw removes the port from raw's authority, operating on the raw string so that
// no other component is normalised. Returns false if raw has no authority.
//
// Deliberately textual. Parsing and re-rendering through url.URL.String() would lowercase
// the scheme and re-escape the path, which silently permits differences beyond the port.
// Compare the raw strings with only the port removed, and never parse and re-render. Do not
// "simplify" this into a parse-and-render: that reintroduces the scheme-case bug this shape
// exists to avoid (#41).
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
		// whatever is there would accept [::1]:evil and [::1].attacker.
		if suffix := host[b+1:]; suffix != "" && (!strings.HasPrefix(suffix, ":") || !isDigits(suffix[1:])) {
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
// This function is flow agnostic. Callers gate it on the authorization code flow, which is
// the only flow loopback port flexibility applies to (#41).
func RedirectURIMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	reg, err := url.Parse(registered)
	if err != nil {
		return false
	}
	// RFC 8252 section 7.3 scopes loopback redirects to the http scheme, so port
	// flexibility requires it.
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

// RedirectURIIsRegistered reports whether requested is covered by registered.
//
// Each entry is tested for exact string equality first, and that arm runs whether or not
// allowLoopbackPortFlexibility is set, so a registered value url.Parse rejects is still
// matched by a byte-identical request. Only beyond exact equality does the flag admit
// RedirectURIMatches, which is called registered first and requested second because its
// scheme and host gates read the registered side.
//
// Like RedirectURIMatches this is flow agnostic. The caller supplies the flag from what it
// knows about the request, because loopback port flexibility is scoped to the authorization
// code flow and that gate lives with the caller rather than here (#41).
func RedirectURIIsRegistered(registered []string, requested string, allowLoopbackPortFlexibility bool) bool {
	for _, reg := range registered {
		if reg == requested {
			return true
		}
		if allowLoopbackPortFlexibility && RedirectURIMatches(reg, requested) {
			return true
		}
	}
	return false
}

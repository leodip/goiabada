package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateRedirectURI is the source of truth for what the DCR endpoint accepts as a
// redirect URI. validateRedirectURI is pure, so this table is cheap and exhaustive; the
// integration suite (dynamic_client_registration_test.go) stays deliberately thin and only
// proves the HTTP endpoint reaches this function.
//
// Every row is run against both isPublic values where the two branches differ, because the
// prefix bug this fixes (#105) was duplicated across them and a single-branch table would
// pass with half the fix.
//
// The loopback host decision itself is owned by urlutil.IsLoopbackHost and its 38-row table
// in src/core/urlutil/redirect_uri_test.go. What is pinned here is that this function
// consults it, plus everything else this function decides.
func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		uri      string
		isPublic bool
		want     bool // true = accepted
		reason   string
	}{
		// --- accepted: loopback http, public
		{"http://localhost:3000/callback", true, true, "loopback host with a port"},
		{"http://127.0.0.1:8080/callback", true, true, "IPv4 literal"},
		{"http://[::1]:9000/callback", true, true, "IPv6 literal"},
		{"http://localhost/cb", true, true, "no port"},
		{"http://127.0.0.1/cb", true, true, "IPv4, no port"},
		{"http://[::1]/cb", true, true, "IPv6, no port"},

		// --- accepted: custom schemes, public only
		{"myapp://callback", true, true, "private-use scheme"},
		{"com.example.app:/oauth", true, true, "reverse-DNS private-use scheme"},

		// Keep these two. They REVERSE the previous behaviour: the old prefix test was
		// case-sensitive, so an uppercase host was rejected. RFC 3986 section 6.2.2.1 makes
		// the host case-insensitive and urlutil.IsLoopbackHost folds it, which is the same
		// rule the authorization path already applies (issue #41, decision 10).
		{"http://LOCALHOST/cb", true, true, "host case is not meaningful"},
		{"http://LocalHost:3000/cb", true, true, "host case is not meaningful, with a port"},

		{"http://user@localhost/cb", true, true, "userinfo: Host excludes it, so the host is still loopback"},

		// --- accepted: confidential
		{"https://app.example.com/callback", false, true, "https on any host"},
		{"http://localhost:3000/callback", false, true, "loopback http"},
		{"http://[::1]:9000/cb", false, true, "IPv6 loopback http"},

		// --- rejected: THE BUG. Each of these was accepted before, for both client types.
		{"http://localhost.attacker.com/callback", true, false, "prefix bypass, the reported case"},
		{"http://localhost.attacker.com/callback", false, false, "prefix bypass, sibling branch"},
		{"http://127.0.0.1.attacker.com/callback", true, false, "prefix bypass on the IPv4 literal"},
		{"http://127.0.0.1.attacker.com/callback", false, false, "prefix bypass on the IPv4 literal, sibling branch"},
		{"http://localhost-evil.example.net/cb", true, false, "prefix bypass with a hyphen"},
		{"http://localhost-evil.example.net/cb", false, false, "prefix bypass with a hyphen, sibling branch"},
		{"http://localhost.evil.tld:8080/cb", true, false, "prefix bypass with a port"},
		// Keep this one: it is the sharpest statement of the bug, since the prefix test did
		// not even need a separator to be fooled.
		{"http://127.0.0.1x/cb", true, false, "prefix bypass with no separator at all"},
		{"http://127.0.0.1.evil.tld/cb", false, false, "prefix bypass, sibling branch"},

		// --- rejected: pre-existing rules that must not regress
		{"https://app.example.com/callback", true, false, "public clients may not use https (issue #105 decision 7)"},
		{"http://example.com/callback", true, false, "non-loopback http"},
		{"http://example.com/callback", false, false, "non-loopback http, sibling branch"},
		{"myapp://callback", false, false, "confidential clients may not use custom schemes"},
		{"not a valid uri", true, false, "unparseable"},
		{"http:///cb", true, false, "empty host is not loopback"},

		// These two reach their rejection before urlutil sees them, and the reason column
		// says so deliberately. url.ParseRequestURI rejects a non-numeric port outright, and
		// a parsed Host can never carry a bracketed hostname, so urlutil's decisions 14 and
		// 15 are not reachable from this call site. Their own test file pins them.
		{"http://localhost:evil/cb", true, false, "rejected by ParseRequestURI, not by the host check"},
		{"http://127.0.0.1:80@evil.com/cb", true, false, "userinfo smuggling: the real host is evil.com"},

		// --- rejected by the absolute-URI gate (RFC 6749 section 3.1.2)
		//
		// Keep the first one verbatim. It is the only row that fails if the absolute-URI
		// gate is dropped, and it is the row whose absence leaks an authorization code:
		// a scheme-relative value is emitted as a protocol-relative Location, which the
		// user agent resolves against the current scheme. See issue #122.
		{"//evil.example/cb", true, false, "scheme-relative: the code would go to evil.example"},
		// Not load-bearing for the absolute-URI gate, and labelled so nobody assumes it is:
		// with that gate removed this row still passes, because an empty scheme is neither
		// https nor http and the confidential branch falls through to an error. Verified.
		// Kept because it documents that the confidential branch is not exposed here.
		{"//evil.example/cb", false, false, "scheme-relative; the confidential fallthrough would also reject it"},
		{"//evil.example:8443/cb", true, false, "scheme-relative with a port"},
		{"/relative/cb", true, false, "path-absolute, no scheme"},
		{"relative/cb", true, false, "rejected by ParseRequestURI, before the absolute-URI gate"},

		// Fragments. Each of these has a non-empty scheme, so each passes a scheme-only
		// test: they are the rows that catch that mistake. They also already malfunction
		// today, since the code is delivered to /cb%23frag rather than to the callback.
		{"http://127.0.0.1/cb#frag", true, false, "fragment on a loopback host"},
		{"https://app.example.com/cb#frag", false, false, "fragment on the confidential branch"},
		{"http://127.0.0.1/cb?a=1#f", true, false, "fragment after a query"},
		{"http://127.0.0.1/cb#", true, false, "a bare # is still a fragment component"},
		{"http://127.0.0.1/cb%23frag", true, true, "percent-encoded %23 is not a fragment delimiter"},

		// --- rejected by the character gate
		//
		// The excluded character must sit in the path, not the authority: ParseRequestURI
		// rejects these characters in a host, so an authority-position row would pass for
		// the wrong reason and would still pass with this gate deleted.
		{"x:<svg/onload=alert(1)>", true, false, "the verified admin console payload; scheme x defeats any denylist"},
		{"myapp://x<img/src=x/onerror=alert(1)>", true, false, "markup in the authority"},
		{"myapp://cb\">alert", true, false, "quote"},
		{"http://127.0.0.1/cb with space", true, false, "space"},
		{"http://127.0.0.1/cb`x`", true, false, "backtick"},
		{"http://127.0.0.1/cb{x}", true, false, "braces"},
		{"http://127.0.0.1/cb|x", true, false, "pipe"},
		{"http://127.0.0.1/cb\\x", true, false, "backslash"},
		{"http://127.0.0.1/cb^x", true, false, "caret"},
		// These two pin the gate's placement ahead of the client-type branches. Both fail
		// if it is moved inside the public custom-scheme branch, and their value is
		// invisible once the placement is right.
		{"https://app.example.com/<svg/onload=alert(1)>", false, false, "markup on an https confidential URI"},
		{"http://127.0.0.1/<svg/onload=alert(1)>", true, false, "markup on a loopback URI"},
		// Retained deliberately, labelled: this is rejected by ParseRequestURI because the
		// space is in the authority, so it is NOT a character-gate test. Do not "improve"
		// it into one.
		{"myapp://cb with space", true, false, "rejected by ParseRequestURI, not by the character gate"},

		// --- rejected by the scheme denylist
		{"javascript:alert(1)", true, false, "script execution; carries no excluded character"},
		{"JavaScript:alert(1)", true, false, "scheme comparison folds case"},
		{"vbscript:msgbox(1)", true, false, "script execution"},
		{"file:///etc/passwd", true, false, "local file access"},
		{"about:blank", true, false, "browser internal"},
		{"data:text/plain,hello", true, false, "data URI; carries no excluded character"},
		// ftp is the row that prompted extending the denylist beyond script execution: it
		// gave a public client a callback on a remote host, which is what the loopback
		// restriction exists to prevent.
		{"ftp://evil.example/cb", true, false, "remote callback for a public client"},
		{"FTP://evil.example/cb", true, false, "denylist folds case"},
		{"ws://localhost/cb", true, false, "cannot receive an authorization response"},
		{"chrome://settings", true, false, "browser internal"},
		{"view-source:http://x", true, false, "browser internal navigation primitive"},

		// --- accepted, deliberately, so the gates are not over-tightened
		{"mailto:a@b.c", true, true, "nonsensical but inert; denying merely useless schemes is taste, not security"},
		{"org.example.app.oauth://redirect", true, true, "a real private-use scheme shape"},
		{"myapp://cb/%3Cscript%3E", true, true, "percent-encoded markup is inert; innerHTML does not decode it"},
	}

	for _, tc := range tests {
		name := tc.uri
		if tc.isPublic {
			name += " [public]"
		} else {
			name += " [confidential]"
		}
		t.Run(name, func(t *testing.T) {
			err := validateRedirectURI(tc.uri, tc.isPublic)
			if tc.want {
				assert.NoError(t, err, "expected accepted (%s)", tc.reason)
			} else {
				assert.Error(t, err, "expected rejected (%s)", tc.reason)
			}
		})
	}
}

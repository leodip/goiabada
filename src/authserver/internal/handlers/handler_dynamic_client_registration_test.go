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

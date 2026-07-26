package urlutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsLoopbackHost is the single source of truth for loopback host cases. The malformed
// bracket and non-numeric port rows are not reachable through RedirectURIMatches today,
// which only ever passes url.URL.Hostname(); they are here because decision 9 exports this
// predicate for reuse in #105's DCR validation, where the caller may pass Host instead.
func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// IPv4 literal
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},

		// IPv6 literal, bracketed or not
		{"::1", true},
		{"[::1]", true},
		{"[::1]:9999", true},
		{"[::1]:", true}, // an empty port is still a port
		{"[::1]:80", true},

		// localhost is a deliberate extension beyond RFC 8252 section 7.3 (decision 1)
		{"localhost", true},
		{"localhost:3000", true},
		{"localhost:", true},

		// host case is not meaningful (decision 10)
		{"LOCALHOST", true},
		{"LocalHost:3000", true},

		// matching is exact after folding, never a prefix
		{"localhost.attacker.com", false},
		{"localhost.attacker.com:9", false},
		{"LOCALHOST.ATTACKER.COM", false}, // folding does not weaken the gate
		{"127.0.0.1.evil.tld", false},
		{"localhost-evil.example.net", false},

		// plainly not loopback
		{"example.com", false},
		{"127.0.0.2", false},
		{"127.0.0.1.", false},
		{"", false},

		// brackets are matched explicitly, not trimmed as a cutset (decision 14)
		{"[[::1]]", false},
		{"[[localhost]]", false},
		{"[localhost]", false},
		// survives the obvious fix to decision 14: net.SplitHostPort strips the brackets
		// itself and hands back "localhost", so the bracket check must come first
		{"[localhost]:3000", false},
		{"[127.0.0.1]", false}, // IPv4 is not bracketed
		{"]::1[", false},       // unbalanced
		{"[::1", false},        // unbalanced
		{"[::1]x", false},      // bad suffix after the bracket
		{"[::1]:evil", false},
		{"[::2]", false}, // a different address

		// only a numeric port is stripped (decision 15). The mirror image of
		// "[localhost]:3000": fixing only one branch leaves the two disagreeing about the
		// same input shape.
		{"localhost:evil", false},
		{"localhost:80x", false},
		{"127.0.0.1:http", false}, // service names are legal to net.Dial
		{"127.0.0.1:https", false},
		{"localhost:+80", false}, // signed is not numeric
		{"localhost:-1", false},

		{"::1:80", false}, // unbracketed IPv6 cannot carry a port
	}

	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			assert.Equal(t, tc.want, IsLoopbackHost(tc.host))
		})
	}
}

// TestIsAbsoluteRedirectURI owns the absolute-URI rule from RFC 6749 section 3.1.2. Both
// call sites consume it: DCR registration (#105) and, once it lands, authorization-time
// validation (#122), so the exhaustive table lives here rather than at either caller.
func TestIsAbsoluteRedirectURI(t *testing.T) {
	tests := []struct {
		uri  string
		want bool
	}{
		// absolute, with an authority
		{"http://127.0.0.1/cb", true},
		{"http://127.0.0.1:9000/cb", true},
		{"https://app.example.com/callback", true},
		{"http://[::1]:9000/cb", true},

		// absolute, private-use schemes for native apps
		{"myapp://callback", true},
		{"myapp:/cb", true},
		{"com.example.app:/oauth", true},
		{"org.example.app.oauth://redirect", true},

		// a query is explicitly permitted by the production
		{"http://127.0.0.1/cb?a=1", true},
		{"http://127.0.0.1/cb?a=1&b=2", true},

		// not absolute: no scheme. The first is the code-exfiltration case, since it is
		// emitted as a protocol-relative Location.
		{"//evil.example/cb", false},
		{"//evil.example:8443/cb", false},
		{"/relative/cb", false},
		{"relative/cb", false},
		{"", false},

		// a fragment is not permitted. Each of these has a non-empty scheme, so each one
		// passes a scheme-only test: they are the rows that catch that mistake.
		{"http://127.0.0.1/cb#frag", false},
		{"https://app.example.com/cb#frag", false},
		{"http://127.0.0.1/cb?a=1#f", false},
		{"myapp://callback#f", false},
		{"http://127.0.0.1/cb#", false}, // an empty fragment is still a fragment delimiter

		// a percent-encoded %23 is not a fragment delimiter
		{"http://127.0.0.1/cb%23frag", true},
	}

	for _, tc := range tests {
		t.Run(tc.uri, func(t *testing.T) {
			assert.Equal(t, tc.want, IsAbsoluteRedirectURI(tc.uri))
		})
	}
}

// TestRedirectURIMatches pins that the port is the only component permitted to differ.
// Flow gating is not covered here: RedirectURIMatches is flow agnostic and the caller owns
// that decision (decision 12), so those cases live with the authorization validator.
func TestRedirectURIMatches(t *testing.T) {
	tests := []struct {
		name       string
		registered string
		requested  string
		want       bool
	}{
		// port flexibility, the point of the exercise
		{"identical", "http://127.0.0.1/callback", "http://127.0.0.1/callback", true},
		{"port added", "http://127.0.0.1/callback", "http://127.0.0.1:12345/callback", true},
		{"port changed", "http://127.0.0.1:8080/callback", "http://127.0.0.1:54321/callback", true},
		{"port removed", "http://127.0.0.1:8080/cb", "http://127.0.0.1/cb", true},
		{"ipv6", "http://[::1]/callback", "http://[::1]:9999/callback", true},
		{"localhost", "http://localhost/cb", "http://localhost:3000/cb", true}, // pins decision 1
		{"default port is still port variance", "http://127.0.0.1/cb", "http://127.0.0.1:80/cb", true},
		{"host case consistent on both sides", "http://LOCALHOST/cb", "http://LOCALHOST:3000/cb", true}, // pins decision 10
		{"empty port is still a port", "http://[::1]/cb", "http://[::1]:/cb", true},

		// exact equality still governs everything else
		{"custom scheme exact", "com.example.app:/oauth", "com.example.app:/oauth", true},
		{"https matches exactly", "https://127.0.0.1:8443/cb", "https://127.0.0.1:8443/cb", true},

		// only the port may differ (decision 6)
		{"path differs", "http://127.0.0.1/cb", "http://127.0.0.1:9/other", false},
		{"scheme differs", "http://127.0.0.1:8080/cb", "https://127.0.0.1:8080/cb", false},
		// the row that failed under this spec's original parse-and-render design. Keep it:
		// it fails the moment anyone reintroduces url.URL.String().
		{"scheme case", "http://127.0.0.1/cb", "HTTP://127.0.0.1:9000/cb", false},
		{"scheme case, no port change", "http://127.0.0.1/cb", "HtTp://127.0.0.1/cb", false},
		{"escaping must not be normalised", "http://127.0.0.1/c b", "http://127.0.0.1:9/c%20b", false},
		{"hex case", "http://127.0.0.1/c%2Fb", "http://127.0.0.1:9/c%2fb", false},
		{"query added", "http://127.0.0.1/cb", "http://127.0.0.1:9/cb?injected=evil", false},
		{"query dropped", "http://127.0.0.1/cb?a=1", "http://127.0.0.1:9/cb", false},
		{"empty query added", "http://127.0.0.1/cb", "http://127.0.0.1:9/cb?", false},
		{"fragment added", "http://127.0.0.1/cb", "http://127.0.0.1:9/cb#f", false},
		{"userinfo added", "http://127.0.0.1/cb", "http://user@127.0.0.1:9/cb", false},
		{"double slash", "http://127.0.0.1/cb", "http://127.0.0.1:9//cb", false},
		{"host case differs between the two", "http://LOCALHOST/cb", "http://localhost:3000/cb", false},
		{"v4 is not v6", "http://127.0.0.1/cb", "http://[::1]:9/cb", false},

		// the registered side must be a loopback host
		{"not loopback", "https://example.com/cb", "https://example.com:8080/cb", false},
		{"#105 interaction", "http://localhost.attacker.com/cb", "http://localhost.attacker.com:9/cb", false},

		// the registered side must be http (decision 11)
		{"https ip literal", "https://127.0.0.1/cb", "https://127.0.0.1:9000/cb", false},
		{"https localhost", "https://localhost/cb", "https://localhost:8443/cb", false},
		{"custom scheme on a loopback host", "custom://127.0.0.1/cb", "custom://127.0.0.1:9000/cb", false},
		{"any other scheme", "ftp://127.0.0.1/cb", "ftp://127.0.0.1:2121/cb", false},

		// a bracketed authority may be followed only by an empty suffix or :digits
		// (decision 13). Dropping whatever followed the bracket accepted all five.
		{"bad port after bracket", "http://[::1]/cb", "http://[::1]:evil/cb", false},
		{"suffix after the bracket", "http://[::1]/cb", "http://[::1].attacker/cb", false},
		{"double colon", "http://[::1]/cb", "http://[::1]::443/cb", false},
		{"trailing character", "http://[::1]/cb", "http://[::1]x/cb", false},
		{"userinfo smuggling", "http://[::1]/cb", "http://[::1]:80@evil.com/cb", false},

		// decision 15 through the matcher
		{"non-numeric port", "http://localhost/cb", "http://localhost:evil/cb", false},
		{"service name as a port", "http://127.0.0.1/cb", "http://127.0.0.1:http/cb", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RedirectURIMatches(tc.registered, tc.requested))
		})
	}
}

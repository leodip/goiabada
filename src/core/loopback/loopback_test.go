package loopback

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsHost is the single source of truth for loopback host cases. The malformed bracket and
// non-numeric port rows are not reachable through the auth server's loopback port matching,
// which only ever passes url.URL.Hostname(); they are here because IsPlainHTTPOff passes
// url.URL.Host, as a caller may (#105). The table moved here from the auth server's
// urlmatch with the rule, row for row (#590).
func TestIsHost(t *testing.T) {
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

		// localhost is a deliberate extension beyond RFC 8252 section 7.3 (#41 decision 1)
		{"localhost", true},
		{"localhost:3000", true},
		{"localhost:", true},

		// host case is not meaningful (#41 decision 10)
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

		// brackets are matched explicitly, not trimmed as a cutset (#41 decision 14)
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

		// only a numeric port is stripped (#41 decision 15). The mirror image of
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
			assert.Equal(t, tc.want, IsHost(tc.host))
		})
	}
}

// TestIsPlainHTTPOff owns the RFC 9700 section 2.6 predicate: plain http is refused everywhere
// but the loopback interface of RFC 8252 section 7.3. The loopback rows lean on TestIsHost's
// table for their host halves; these rows pin which URIs reach that decision at all, so every
// non-http scheme answers false whatever its host.
func TestIsPlainHTTPOff(t *testing.T) {
	tests := []struct {
		uri  string
		want bool
	}{
		// Plain http off the loopback interface, which RFC 9700 section 2.6 forbids.
		{"http://app.example.com/callback", true},
		{"http://app.example.com:8443/callback", true},
		{"http://192.168.1.50/callback", true},
		{"http://[2001:db8::1]/callback", true},
		{"HTTP://app.example.com/callback", true}, // the parse folds the scheme to lower case
		{"http:///callback", true},                // hostless: callers' absolute-URI gate refuses it first, and on its own it is not loopback either

		// Loopback http stays, for RFC 8252 native and MCP clients.
		{"http://127.0.0.1:8765/callback", false},
		{"http://[::1]:9000/callback", false},
		{"http://localhost:3000/callback", false},
		{"http://LOCALHOST:80/callback", false},

		// Every other scheme is out of this predicate's scope.
		{"https://app.example.com/callback", false},
		{"com.example.app:/oauth2redirect", false},

		// A value that does not parse is not this predicate's to refuse: the intakes'
		// parse and absolute-URI gates ahead of it own that refusal.
		{"not-a-url", false},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, IsPlainHTTPOff(tc.uri), tc.uri)
	}
}

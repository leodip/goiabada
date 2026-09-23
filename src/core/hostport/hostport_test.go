package hostport

import (
	"net"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJoin pins the address for each spelling of a host a configuration field can carry, and that
// net.SplitHostPort, the parser behind net.Listen and net.Dial, reads back the host that was meant.
// The IPv6 rows are the ones a Sprintf'd `host:port` got wrong (#424).
func TestJoin(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		want     string
		wantHost string
	}{
		{"IPv4 wildcard", "0.0.0.0", "0.0.0.0:9090", "0.0.0.0"},
		{"IPv4 loopback", "127.0.0.1", "127.0.0.1:9090", "127.0.0.1"},
		{"name", "db", "db:9090", "db"},
		{"empty host, which Go reads as every interface", "", ":9090", ""},
		{"IPv6 wildcard", "::", "[::]:9090", "::"},
		{"IPv6 wildcard, bracketed", "[::]", "[::]:9090", "::"},
		{"IPv6 loopback", "::1", "[::1]:9090", "::1"},
		{"IPv6 loopback, bracketed", "[::1]", "[::1]:9090", "::1"},
		{"IPv6 address", "2001:db8::1", "[2001:db8::1]:9090", "2001:db8::1"},
		{"IPv6 address with a zone", "fe80::1%eth0", "[fe80::1%eth0]:9090", "fe80::1%eth0"},
		{"IPv6 address with a zone, bracketed", "[fe80::1%eth0]", "[fe80::1%eth0]:9090", "fe80::1%eth0"},
		{"IPv4-mapped IPv6 address", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]:9090", "::ffff:127.0.0.1"},
		// The bracket rule is SplitHostPort's, which does not ask what is inside: `[db]:9090` is db.
		{"bracketed name", "[db]", "db:9090", "db"},
		// And `[]:9090` is the empty host, so this is what the brackets meant rather than a new
		// reading of them.
		{"empty brackets", "[]", ":9090", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Join(test.host, 9090)
			assert.Equal(t, test.want, got)

			host, port, err := net.SplitHostPort(got)
			require.NoError(t, err, "%q must parse as an address", got)
			assert.Equal(t, test.wantHost, host)
			assert.Equal(t, "9090", port)
		})
	}
}

// TestJoin_MalformedHostIsNotRepaired pins that only one whole pair of brackets is taken off. A
// host with a stray bracket, or two pairs, reaches net.SplitHostPort as written and is refused
// there, which is where the operator's error message comes from.
func TestJoin_MalformedHostIsNotRepaired(t *testing.T) {
	for _, host := range []string{"[::1", "::1]", "[[::1]]"} {
		t.Run(host, func(t *testing.T) {
			_, _, err := net.SplitHostPort(Join(host, 9090))
			assert.Error(t, err, "Join(%q) must not be turned into a valid address", host)
		})
	}
}

func TestUnbracket(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"[::1]", "::1"},
		{"::1", "::1"},
		{"[fe80::1%eth0]", "fe80::1%eth0"},
		{"db", "db"},
		{"", ""},
		{"[]", ""},
		// One pair only, and only a whole pair.
		{"[[::1]]", "[::1]"},
		{"[::1", "[::1"},
		{"::1]", "::1]"},
		{"[", "["},
		{"]", "]"},
	}

	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			assert.Equal(t, test.want, Unbracket(test.host))
		})
	}
}

// TestJoin_ListensOnLoopback listens on the address Join builds, for each loopback spelling, and
// checks the socket is bound to that loopback address and not to every interface. The IPv6 rows
// are the case that failed with "too many colons in address" before #424.
func TestJoin_ListensOnLoopback(t *testing.T) {
	tests := []struct {
		host string
		want net.IP
	}{
		{"127.0.0.1", net.ParseIP("127.0.0.1")},
		{"::1", net.IPv6loopback},
		{"[::1]", net.IPv6loopback},
	}

	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			if test.want.To4() == nil {
				testutil.SkipWithoutIPv6Loopback(t)
			}

			ln, err := net.Listen("tcp", Join(test.host, 0))
			require.NoError(t, err)
			defer func() { _ = ln.Close() }()

			bound := ln.Addr().(*net.TCPAddr)
			assert.True(t, bound.IP.Equal(test.want), "bound to %s, want %s", bound.IP, test.want)
			assert.NotZero(t, bound.Port)
		})
	}
}

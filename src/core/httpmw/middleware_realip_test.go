package httpmw

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustCIDRs(t *testing.T, entries ...string) []*net.IPNet {
	t.Helper()
	ranges, err := ParseTrustedProxies(entries)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%q): %v", entries, err)
	}
	return ranges
}

// resolveClientIPCase is one row of the resolution table: the socket peer, the
// X-Forwarded-For and X-Real-IP values as one string each, the trust
// settings, and the client address they resolve to.
type resolveClientIPCase struct {
	name              string
	remoteAddr        string
	xff               string
	xRealIP           string
	trustProxyHeaders bool
	trusted           []string
	want              string
}

const (
	cdnRange = "198.51.100.0/24" // TEST-NET-2, stands in for a CDN egress range
	lbRange  = "10.0.0.0/8"      // internal load balancer range
)

var resolveClientIPCases = []resolveClientIPCase{
	{
		name:              "no trust: socket peer, headers ignored even if spoofed",
		remoteAddr:        "203.0.113.9:44321",
		xff:               "1.2.3.4, 5.6.7.8",
		xRealIP:           "9.9.9.9",
		trustProxyHeaders: false,
		want:              "203.0.113.9",
	},
	{
		name:              "trust + empty allowlist: single XFF entry is the client",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "203.0.113.9",
		trustProxyHeaders: true,
		want:              "203.0.113.9",
	},
	{
		name:              "trust + empty allowlist: spoofed-left, real-right -> rightmost wins",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "6.6.6.6, 203.0.113.9",
		trustProxyHeaders: true,
		want:              "203.0.113.9",
	},
	{
		name:              "trust + CDN allowlist: walk past trusted hop to real client",
		remoteAddr:        "10.0.0.5:5000", // our LB (peer)
		xff:               "6.6.6.6, 203.0.113.9, 198.51.100.7",
		trustProxyHeaders: true,
		trusted:           []string{lbRange, cdnRange},
		want:              "203.0.113.9",
	},
	{
		name:              "allowlist set + direct connection (peer not trusted): headers ignored",
		remoteAddr:        "203.0.113.9:44321",
		xff:               "6.6.6.6",
		xRealIP:           "9.9.9.9",
		trustProxyHeaders: true,
		trusted:           []string{lbRange, cdnRange},
		want:              "203.0.113.9",
	},
	{
		name:              "trust + trusted peer + empty XFF + X-Real-IP set",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "",
		xRealIP:           "203.0.113.9",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "203.0.113.9",
	},
	{
		name:              "trust + empty XFF + no X-Real-IP -> peer",
		remoteAddr:        "10.0.0.5:5000",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "10.0.0.5",
	},
	{
		name:              "IPv6 socket peer with port and no trust",
		remoteAddr:        "[2001:db8::1]:443",
		trustProxyHeaders: false,
		want:              "2001:db8::1",
	},
	{
		name:              "IPv6 client through trusted IPv4 hop",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "2001:db8::abcd, 198.51.100.7",
		trustProxyHeaders: true,
		trusted:           []string{lbRange, cdnRange},
		want:              "2001:db8::abcd",
	},
	{
		name:              "malformed / empty XFF segments are skipped, no panic",
		remoteAddr:        "10.0.0.5:5000",
		xff:               " , , 203.0.113.9 , ",
		trustProxyHeaders: true,
		want:              "203.0.113.9",
	},
	{
		name:              "all entries trusted (degenerate) -> leftmost",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "10.1.1.1, 10.2.2.2",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "10.1.1.1",
	},
	{
		name:              "CIDR range match (10.0.0.0/8 contains 10.9.9.9)",
		remoteAddr:        "10.9.9.9:5000",
		xff:               "203.0.113.9, 10.0.0.5",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "203.0.113.9",
	},
	{
		name:              "bare IP socket peer without port",
		remoteAddr:        "203.0.113.9",
		trustProxyHeaders: false,
		want:              "203.0.113.9",
	},
	// An entry that does not parse as an IP is dropped, not carried through: the
	// header is caller-controlled and the resolved value becomes a rate-limit
	// bucket, an audit field and a session record (#219). Dropping an entry is not
	// rejecting the header, so the rows below say which entries survive rather than
	// assuming the peer always wins.
	{
		name:              "non-IP XFF entry alone is dropped -> peer",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "<script>",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "10.0.0.5",
	},
	{
		name:              "every XFF entry is non-IP -> peer",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "<script>, ../../etc",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "10.0.0.5",
	},
	{
		name:              "non-IP X-Real-IP is refused -> peer",
		remoteAddr:        "10.0.0.5:5000",
		xRealIP:           "../../etc/passwd",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "10.0.0.5",
	},
	{
		name:              "non-IP entry dropped, surviving untrusted entry is the client",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "<script>, 203.0.113.9",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "203.0.113.9",
	},
	{
		name:              "non-IP entry dropped, surviving entry is trusted -> walk runs out there",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "<script>, 10.0.0.6",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "10.0.0.6",
	},
	{
		// Alone, so the drop is what decides the answer: with a real client to its
		// right the walk would stop there and the row would pass either way.
		name:              "IPv6 address with a zone is not a reachable client -> dropped",
		remoteAddr:        "10.0.0.5:5000",
		xff:               "fe80::1%eth0",
		trustProxyHeaders: true,
		trusted:           []string{lbRange},
		want:              "10.0.0.5",
	},
}

func TestResolveClientIP(t *testing.T) {
	for _, tt := range resolveClientIPCases {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveClientIP(tt.remoteAddr, tt.xff, tt.xRealIP, tt.trustProxyHeaders, mustCIDRs(t, tt.trusted...))
			if got != tt.want {
				t.Errorf("resolveClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The ten entries net.ParseCIDR refuses, whatever ParseTrustedProxies did to them first. Each
// was executed against the rule before being written here.
var refusedTrustedProxyEntries = []string{
	"10.0.0.0/33",
	"not-an-ip",
	"1.2.3",
	"10.0.0.256",
	"fe80::1%eth0",
	"*",
	"10.0.0.0/",
	"/8",
	"10.0.0.0/8/8",
	"10.0.0.0 /8",
}

func TestParseTrustedProxies(t *testing.T) {
	t.Run("accepted entries", func(t *testing.T) {
		tests := []struct {
			entry     string
			wantRange string
			inside    []string
			outside   []string
		}{
			{entry: "10.0.0.5", wantRange: "10.0.0.5/32", inside: []string{"10.0.0.5"}, outside: []string{"10.0.0.6"}},
			{entry: "2001:db8::1", wantRange: "2001:db8::1/128", inside: []string{"2001:db8::1"}, outside: []string{"2001:db8::2"}},
			{entry: "192.168.0.0/16", wantRange: "192.168.0.0/16", inside: []string{"192.168.42.1"}, outside: []string{"192.169.0.1"}},
			// Host bits are dropped: the entry stands for its network.
			{entry: "10.0.0.1/8", wantRange: "10.0.0.0/8", inside: []string{"10.9.9.9"}, outside: []string{"11.0.0.1"}},
			{entry: " 10.0.0.0/8 ", wantRange: "10.0.0.0/8", inside: []string{"10.9.9.9"}, outside: []string{"11.0.0.1"}},
			// The mapped spelling of an IPv4 proxy is that proxy's /32. Appending /32 to the IPv6
			// text, the rule this replaced, produced ::/32, which trusted IPv6 loopback and not
			// the proxy (#425).
			{entry: "::ffff:10.0.0.1", wantRange: "10.0.0.1/32", inside: []string{"10.0.0.1", "::ffff:10.0.0.1"}, outside: []string{"::1", "::2"}},
			{entry: "::ffff:a00:1", wantRange: "10.0.0.1/32", inside: []string{"10.0.0.1", "::ffff:10.0.0.1"}, outside: []string{"::1"}},
			// A mapped CIDR range is net.ParseCIDR's to decide, and it already means the IPv4 range.
			{entry: "::ffff:10.0.0.0/104", wantRange: "10.0.0.0/8", inside: []string{"10.9.9.9"}, outside: []string{"11.0.0.1"}},
			{entry: "0.0.0.0/0", wantRange: "0.0.0.0/0", inside: []string{"203.0.113.9"}, outside: []string{"2001:db8::1"}},
			{entry: "::/0", wantRange: "::/0", inside: []string{"2001:db8::1", "::1"}},
		}
		for _, tt := range tests {
			t.Run(tt.entry, func(t *testing.T) {
				got, err := ParseTrustedProxies([]string{tt.entry})
				require.NoError(t, err)
				require.Len(t, got, 1)
				assert.Equal(t, tt.wantRange, got[0].String())
				for _, ip := range tt.inside {
					assert.True(t, ipInAny(ip, got), "%s should be inside %s", ip, got[0])
				}
				for _, ip := range tt.outside {
					assert.False(t, ipInAny(ip, got), "%s should be outside %s", ip, got[0])
				}
			})
		}
	})

	t.Run("refused entries", func(t *testing.T) {
		// Each alone in its list, so that it is the only possible reason for the refusal.
		for _, entry := range refusedTrustedProxyEntries {
			t.Run(entry, func(t *testing.T) {
				got, err := ParseTrustedProxies([]string{entry})
				assert.Nil(t, got)
				require.Error(t, err)
				assert.Contains(t, err.Error(), strconv.Quote(entry))
			})
		}
	})

	t.Run("skipped entries", func(t *testing.T) {
		for name, entries := range map[string][]string{
			"empty":      {""},
			"blank":      {"   "},
			"nil list":   nil,
			"empty list": {},
		} {
			t.Run(name, func(t *testing.T) {
				got, err := ParseTrustedProxies(entries)
				require.NoError(t, err)
				assert.Nil(t, got)
			})
		}
	})

	t.Run("every entry malformed: the error names each of them", func(t *testing.T) {
		got, err := ParseTrustedProxies(refusedTrustedProxyEntries)
		assert.Nil(t, got)
		require.Error(t, err)
		for _, entry := range refusedTrustedProxyEntries {
			assert.Contains(t, err.Error(), strconv.Quote(entry))
		}
	})

	t.Run("one bad entry among good ones: no ranges at all", func(t *testing.T) {
		got, err := ParseTrustedProxies([]string{"10.0.0.0/8", "not-an-ip", "192.168.0.0/16"})
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"not-an-ip"`)
		assert.NotContains(t, err.Error(), "10.0.0.0/8")
		assert.NotContains(t, err.Error(), "192.168.0.0/16")
	})
}

func TestRealIP_RewritesRemoteAddr(t *testing.T) {
	var seen string
	handler := RealIP(true, mustCIDRs(t, "10.0.0.0/8"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:5000"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if seen != "203.0.113.9" {
		t.Errorf("middleware set RemoteAddr = %q, want %q", seen, "203.0.113.9")
	}
}

// serveRealIP passes a request from peer, carrying each header's field lines in the order
// given (one Header.Add per line), through RealIP, and returns the address the next handler
// sees.
func serveRealIP(t *testing.T, trustProxyHeaders bool, trusted []string, peer string, xffLines, xRealIPLines []string) string {
	t.Helper()
	var seen string
	handler := RealIP(trustProxyHeaders, mustCIDRs(t, trusted...))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = peer
	for _, line := range xffLines {
		req.Header.Add("X-Forwarded-For", line)
	}
	for _, line := range xRealIPLines {
		req.Header.Add("X-Real-IP", line)
	}
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return seen
}

// HAProxy's option forwardfor keeps the lines a client sent and adds its own line after
// them, so the proxy's observation is the rightmost entry only when every line is read, in
// order (#727). Peer and addresses are those of the issue's probe.
func TestRealIP_ReadsEveryXForwardedForLine(t *testing.T) {
	forgedThenProxy := []string{"6.6.6.6", "203.0.113.7"}

	t.Run("forged line before the proxy's own line, one hop", func(t *testing.T) {
		got := serveRealIP(t, true, nil, "10.0.0.2:5000", forgedThenProxy, nil)
		assert.Equal(t, "203.0.113.7", got)
	})

	t.Run("forged line before the proxy's own line, peer listed as trusted", func(t *testing.T) {
		got := serveRealIP(t, true, []string{"10.0.0.2"}, "10.0.0.2:5000", forgedThenProxy, nil)
		assert.Equal(t, "203.0.113.7", got)
	})

	t.Run("client entry on an earlier line than a trusted hop's", func(t *testing.T) {
		// A CDN appended its client to the client's own line; HAProxy then added the CDN's
		// edge address on a line of its own.
		got := serveRealIP(t, true, []string{lbRange, cdnRange}, "10.0.0.5:5000",
			[]string{"6.6.6.6, 203.0.113.9", "198.51.100.7"}, nil)
		assert.Equal(t, "203.0.113.9", got)
	})

	t.Run("client entry on an earlier line, a trusted hop on each later line", func(t *testing.T) {
		got := serveRealIP(t, true, []string{lbRange, cdnRange}, "10.0.0.5:5000",
			[]string{"203.0.113.9", "198.51.100.7", "10.0.0.6"}, nil)
		assert.Equal(t, "203.0.113.9", got)
	})
}

// A value split over several field lines resolves exactly as it does on one line (RFC 9110
// §5.3): each X-Forwarded-For row of the resolution table, sent with its value split at
// every comma, expects the row's own result.
func TestRealIP_SplitXForwardedForResolvesAsOneLine(t *testing.T) {
	for _, tt := range resolveClientIPCases {
		if tt.xff == "" {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			var xRealIPLines []string
			if tt.xRealIP != "" {
				xRealIPLines = []string{tt.xRealIP}
			}
			got := serveRealIP(t, tt.trustProxyHeaders, tt.trusted, tt.remoteAddr,
				strings.Split(tt.xff, ","), xRealIPLines)
			assert.Equal(t, tt.want, got)
		})
	}
}

// X-Real-IP holds one address and RFC 9110 §5.3 forbids repeating a field that is not a
// list, so two lines mean one of them did not come from the proxy: both are ignored and the
// peer is used, as for a value that is not an IP address.
func TestRealIP_RepeatedXRealIPIsIgnored(t *testing.T) {
	t.Run("two lines, no X-Forwarded-For, one hop", func(t *testing.T) {
		got := serveRealIP(t, true, nil, "10.0.0.5:5000", nil, []string{"6.6.6.6", "203.0.113.9"})
		assert.Equal(t, "10.0.0.5", got)
	})

	t.Run("two lines, no X-Forwarded-For, peer listed as trusted", func(t *testing.T) {
		got := serveRealIP(t, true, []string{lbRange}, "10.0.0.5:5000", nil, []string{"6.6.6.6", "203.0.113.9"})
		assert.Equal(t, "10.0.0.5", got)
	})

	t.Run("two identical lines are still two", func(t *testing.T) {
		got := serveRealIP(t, true, nil, "10.0.0.5:5000", nil, []string{"203.0.113.9", "203.0.113.9"})
		assert.Equal(t, "10.0.0.5", got)
	})

	t.Run("one line resolves to its address", func(t *testing.T) {
		got := serveRealIP(t, true, nil, "10.0.0.5:5000", nil, []string{"203.0.113.9"})
		assert.Equal(t, "203.0.113.9", got)
	})

	t.Run("a valid X-Forwarded-For wins over one X-Real-IP line", func(t *testing.T) {
		got := serveRealIP(t, true, nil, "10.0.0.5:5000", []string{"203.0.113.7"}, []string{"6.6.6.6"})
		assert.Equal(t, "203.0.113.7", got)
	})

	t.Run("a valid X-Forwarded-For wins over two X-Real-IP lines", func(t *testing.T) {
		got := serveRealIP(t, true, nil, "10.0.0.5:5000", []string{"203.0.113.7"}, []string{"6.6.6.6", "7.7.7.7"})
		assert.Equal(t, "203.0.113.7", got)
	})
}

// With TRUST_PROXY_HEADERS off no header is read, however many lines it comes on.
func TestRealIP_TrustOffIgnoresEveryLine(t *testing.T) {
	t.Run("several X-Forwarded-For lines", func(t *testing.T) {
		got := serveRealIP(t, false, nil, "203.0.113.9:44321", []string{"6.6.6.6", "7.7.7.7"}, nil)
		assert.Equal(t, "203.0.113.9", got)
	})

	t.Run("several X-Real-IP lines", func(t *testing.T) {
		got := serveRealIP(t, false, nil, "203.0.113.9:44321", nil, []string{"6.6.6.6", "7.7.7.7"})
		assert.Equal(t, "203.0.113.9", got)
	})

	t.Run("one X-Real-IP line", func(t *testing.T) {
		got := serveRealIP(t, false, nil, "203.0.113.9:44321", nil, []string{"6.6.6.6"})
		assert.Equal(t, "203.0.113.9", got)
	})
}

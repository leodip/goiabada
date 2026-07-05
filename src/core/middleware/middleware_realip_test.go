package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustCIDRs(t *testing.T, entries ...string) []*net.IPNet {
	t.Helper()
	return parseCIDRs(entries)
}

func TestResolveClientIP(t *testing.T) {
	const cdn = "198.51.100.0/24" // TEST-NET-2, stands in for a CDN egress range
	const lb = "10.0.0.0/8"       // internal load balancer range

	tests := []struct {
		name              string
		remoteAddr        string
		xff               string
		xRealIP           string
		trustProxyHeaders bool
		trusted           []string
		want              string
	}{
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
			trusted:           []string{lb, cdn},
			want:              "203.0.113.9",
		},
		{
			name:              "allowlist set + direct connection (peer not trusted): headers ignored",
			remoteAddr:        "203.0.113.9:44321",
			xff:               "6.6.6.6",
			xRealIP:           "9.9.9.9",
			trustProxyHeaders: true,
			trusted:           []string{lb, cdn},
			want:              "203.0.113.9",
		},
		{
			name:              "trust + trusted peer + empty XFF + X-Real-IP set",
			remoteAddr:        "10.0.0.5:5000",
			xff:               "",
			xRealIP:           "203.0.113.9",
			trustProxyHeaders: true,
			trusted:           []string{lb},
			want:              "203.0.113.9",
		},
		{
			name:              "trust + empty XFF + no X-Real-IP -> peer",
			remoteAddr:        "10.0.0.5:5000",
			trustProxyHeaders: true,
			trusted:           []string{lb},
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
			trusted:           []string{lb, cdn},
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
			trusted:           []string{lb},
			want:              "10.1.1.1",
		},
		{
			name:              "CIDR range match (10.0.0.0/8 contains 10.9.9.9)",
			remoteAddr:        "10.9.9.9:5000",
			xff:               "203.0.113.9, 10.0.0.5",
			trustProxyHeaders: true,
			trusted:           []string{lb},
			want:              "203.0.113.9",
		},
		{
			name:              "bare IP socket peer without port",
			remoteAddr:        "203.0.113.9",
			trustProxyHeaders: false,
			want:              "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveClientIP(tt.remoteAddr, tt.xff, tt.xRealIP, tt.trustProxyHeaders, mustCIDRs(t, tt.trusted...))
			if got != tt.want {
				t.Errorf("resolveClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseCIDRs(t *testing.T) {
	// Bare IPv4 -> /32, bare IPv6 -> /128, CIDR passthrough, invalid skipped.
	got := parseCIDRs([]string{"10.0.0.5", "2001:db8::1", "192.168.0.0/16", "not-an-ip", ""})
	if len(got) != 3 {
		t.Fatalf("parseCIDRs kept %d ranges, want 3 (invalid/empty skipped)", len(got))
	}
	if !ipInAny("10.0.0.5", got) {
		t.Error("expected bare IPv4 10.0.0.5 to match its /32")
	}
	if ipInAny("10.0.0.6", got) {
		t.Error("did not expect 10.0.0.6 to match a /32 of 10.0.0.5")
	}
	if !ipInAny("192.168.42.1", got) {
		t.Error("expected 192.168.42.1 to match 192.168.0.0/16")
	}
	if !ipInAny("2001:db8::1", got) {
		t.Error("expected bare IPv6 to match its /128")
	}
}

func TestMiddlewareRealIP_RewritesRemoteAddr(t *testing.T) {
	var seen string
	handler := MiddlewareRealIP(true, []string{"10.0.0.0/8"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

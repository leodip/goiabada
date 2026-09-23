package server

import (
	"net"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewHTTPServer_ServesOnEachLoopbackSpelling takes the server Start builds for a listener
// through the listen and one request, for each spelling of a loopback host an operator can set in
// GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP(S). The IPv6 rows are the ones a Sprintf'd `host:port`
// stopped at start with "too many colons in address"; `[::1]` is the spelling that worked around
// it and must keep working (#424).
func TestNewHTTPServer_ServesOnEachLoopbackSpelling(t *testing.T) {
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

			srv := newHTTPServer(test.host, 0, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))

			// ListenAndServe is net.Listen("tcp", srv.Addr) followed by Serve. The two halves are
			// called apart here only to learn which port 0 was given.
			ln, err := net.Listen("tcp", srv.Addr)
			require.NoError(t, err, "Start would stop here with this error")
			go func() { _ = srv.Serve(ln) }()
			t.Cleanup(func() { _ = srv.Close() })

			bound := ln.Addr().(*net.TCPAddr)
			assert.True(t, bound.IP.Equal(test.want), "bound to %s, want only %s", bound.IP, test.want)

			resp, err := http.Get("http://" + ln.Addr().String() + "/")
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusNoContent, resp.StatusCode, "the request must reach the handler passed in")
		})
	}
}

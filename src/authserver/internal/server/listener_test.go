package server

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/hostport/hostporttest"
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
				hostporttest.SkipWithoutIPv6Loopback(t)
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

// TestNewHTTPServer_SetsEveryTimeoutAndTheHeaderBound pins the five bounds every listener carries
// (#426). Each row checks the field against its constant, the constant against the value #426
// chose, so changing one is a deliberate edit here, and the field against zero, which is
// net/http's "no bound" (1 MB for the header block). A field dropped from newHTTPServer fails its
// own row and no other. The running server's behaviour under two of them is proved in the
// integration tier's listener_test.go.
func TestNewHTTPServer_SetsEveryTimeoutAndTheHeaderBound(t *testing.T) {
	srv := newHTTPServer("127.0.0.1", 0, nil)

	tests := []struct {
		field    string
		got      int64
		constant int64
		want     int64
	}{
		{"ReadHeaderTimeout", int64(srv.ReadHeaderTimeout), int64(readHeaderTimeout), int64(10 * time.Second)},
		{"ReadTimeout", int64(srv.ReadTimeout), int64(readTimeout), int64(60 * time.Second)},
		{"WriteTimeout", int64(srv.WriteTimeout), int64(writeTimeout), int64(60 * time.Second)},
		{"IdleTimeout", int64(srv.IdleTimeout), int64(idleTimeout), int64(120 * time.Second)},
		{"MaxHeaderBytes", int64(srv.MaxHeaderBytes), int64(maxHeaderBytes), 65536},
	}

	for _, test := range tests {
		t.Run(test.field, func(t *testing.T) {
			assert.NotZero(t, test.got, "a zero %s is net/http's default, which bounds nothing", test.field)
			assert.Equal(t, test.constant, test.got, "%s must be set from its constant", test.field)
			assert.Equal(t, test.want, test.constant, "%s's constant moved from the value #426 chose", test.field)
		})
	}

	// The TLS handshake's deadline is the smallest of the non-zero header, read and write timeouts
	// (net/http's tlsHandshakeTimeout; the idle timeout plays no part), so a client that never says
	// hello is dropped at readHeaderTimeout only while it stays the smallest of the three.
	assert.Less(t, readHeaderTimeout, readTimeout, "readHeaderTimeout must stay the handshake deadline")
	assert.Less(t, readHeaderTimeout, writeTimeout, "readHeaderTimeout must stay the handshake deadline")

	// net/http times readTimeout from when it begins reading a request, and writeTimeout from when it
	// has read the request's header block, which is no earlier. With writeTimeout no shorter, the
	// write deadline never falls before the read deadline, so a body the read timeout admits still
	// has time for its response.
	assert.GreaterOrEqual(t, writeTimeout, readTimeout, "writeTimeout must not end before readTimeout")
}

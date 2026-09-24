package server

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewHTTPServer_ServesOnEachLoopbackSpelling is the admin console's copy of the auth server's
// case, and owes its own for the same reason the TLS warning does: neither module imports the
// other, so each builds its listeners itself. It takes the server Start builds through the listen
// and one request, for each spelling of a loopback host an operator can set in
// GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP(S). The IPv6 rows are the ones a Sprintf'd `host:port`
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

// TestNewHTTPServer_SetsEveryTimeoutAndTheHeaderBound is the auth server's case again, over the
// console's own copy of the five bounds (#426). Each row checks the field against its constant, the constant
// against the value #426 chose, so changing one is a deliberate edit here, and the field against
// zero, which is net/http's "no bound" (1 MB for the header block). A field dropped from
// newHTTPServer fails its own row and no other.
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

	// The smallest non-zero timeout is the TLS handshake's deadline, so a client that never says
	// hello is dropped at readHeaderTimeout only while it stays the smallest.
	assert.Less(t, readHeaderTimeout, readTimeout, "readHeaderTimeout must stay the handshake deadline")
	assert.Less(t, readHeaderTimeout, writeTimeout, "readHeaderTimeout must stay the handshake deadline")
	assert.Less(t, readHeaderTimeout, idleTimeout, "readHeaderTimeout must stay the handshake deadline")

	// net/http starts the read deadline at the first header byte and the write deadline at the
	// last, so a write timeout shorter than the read timeout loses the response to a body the read
	// timeout admits.
	assert.GreaterOrEqual(t, writeTimeout, readTimeout, "writeTimeout must not end before readTimeout")
}

// TestNewHTTPServer_DropsAPartialHeaderBlock takes a real listener through the attack
// readHeaderTimeout exists for: a client that sends part of a header block and stops. The console
// has no integration tier, so this is the only proof that the bound holds a connection to it
// rather than only sitting in a struct field (#426). Without ReadHeaderTimeout net/http falls back
// to the 60s ReadTimeout, so the connection is still open when the client's own deadline passes;
// that deadline sits past the window so the case fails on the window rather than hanging.
func TestNewHTTPServer_DropsAPartialHeaderBlock(t *testing.T) {
	t.Parallel()

	var called atomic.Bool
	srv := newHTTPServer("127.0.0.1", 0, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	ln, err := net.Listen("tcp", srv.Addr)
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	start := time.Now()
	// No terminating blank line: the header block never ends.
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nX-A: b\r\n"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(start.Add(readHeaderTimeout+5*time.Second)))

	got, err := io.ReadAll(conn)
	elapsed := time.Since(start)

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("the server still held the connection after %s", elapsed)
	}
	require.NoError(t, err, "the server must close the connection, not reset it")
	assert.Empty(t, got, "a header block cut short gets no response, only a close")
	assert.False(t, called.Load(), "the handler must never see a request whose header block never ended")
	assert.GreaterOrEqual(t, elapsed, readHeaderTimeout-time.Second, "closed before readHeaderTimeout")
	assert.LessOrEqual(t, elapsed, readHeaderTimeout+2*time.Second, "closed well after readHeaderTimeout")
}

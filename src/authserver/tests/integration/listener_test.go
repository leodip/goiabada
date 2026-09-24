package integrationtests

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The running server's listener bounds (#426), reached over a raw connection to the host and port
// of the configured base URL, so what is tested is the listener main started and not a struct
// built for the test. The unit tier's TestNewHTTPServer_SetsEveryTimeoutAndTheHeaderBound owns the
// values; these cases own the proof that main reaches newHTTPServer and that net/http enforces
// them on it.

// listenerHeaderTimeout is the server's readHeaderTimeout, unexported in internal/server and
// pinned there by the unit tier.
const listenerHeaderTimeout = 10 * time.Second

// dialAuthServer opens a raw TCP connection to the running auth server.
func dialAuthServer(t *testing.T) net.Conn {
	t.Helper()
	base, err := url.Parse(config.GetAuthServer().BaseURL)
	require.NoError(t, err)
	require.Equal(t, "http", base.Scheme, "these cases write a raw HTTP/1.1 request, so the base URL must be plain http")

	conn, err := net.Dial("tcp", base.Host)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestListener_DropsAPartialHeaderBlock(t *testing.T) {
	t.Parallel()
	conn := dialAuthServer(t)

	start := time.Now()
	// No terminating blank line: the header block never ends.
	_, err := conn.Write([]byte("GET /health HTTP/1.1\r\nHost: x\r\nX-A: b\r\n"))
	require.NoError(t, err)
	// Past the window, so a listener without ReadHeaderTimeout fails on the window below rather
	// than hanging on the 60s ReadTimeout it would fall back to.
	require.NoError(t, conn.SetReadDeadline(start.Add(listenerHeaderTimeout+5*time.Second)))

	got, err := io.ReadAll(conn)
	elapsed := time.Since(start)

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("the server still held the connection after %s", elapsed)
	}
	require.NoError(t, err, "the server must close the connection, not reset it")
	assert.Empty(t, got, "a header block cut short gets no response, only a close")
	assert.GreaterOrEqual(t, elapsed, listenerHeaderTimeout-time.Second, "closed before readHeaderTimeout")
	assert.LessOrEqual(t, elapsed, listenerHeaderTimeout+2*time.Second, "closed well after readHeaderTimeout")
}

// headOfLength builds a GET /health request head exactly n bytes long, request line and
// terminating blank line included, padded through one X-Pad field.
func headOfLength(t *testing.T, n int) string {
	t.Helper()
	const prefix = "GET /health HTTP/1.1\r\nHost: localhost\r\nX-Pad: "
	const suffix = "\r\n\r\n"
	pad := n - len(prefix) - len(suffix)
	require.Positive(t, pad)
	head := prefix + strings.Repeat("a", pad) + suffix
	require.Len(t, head, n)
	return head
}

// sendHead writes a request head and reads the status the server answers it with.
func sendHead(t *testing.T, head string) int {
	t.Helper()
	conn := dialAuthServer(t)
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	_, err := conn.Write([]byte(head))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestListener_RefusesAHeaderBlockPastTheBound: maxHeaderBytes is 64 KiB and net/http admits 4096
// bytes beyond it, so 69632 is the largest head it reads. At net/http's 1 MB default this same
// request gets 200.
func TestListener_RefusesAHeaderBlockPastTheBound(t *testing.T) {
	t.Parallel()
	assert.Equal(t, http.StatusRequestHeaderFieldsTooLarge, sendHead(t, headOfLength(t, 69633)))
}

// TestListener_AdmitsAHeaderBlockAtTheBound is the same request with only the pad changed, to a
// head of exactly 64 KiB, so a bound set too low fails here.
func TestListener_AdmitsAHeaderBlockAtTheBound(t *testing.T) {
	t.Parallel()
	assert.Equal(t, http.StatusOK, sendHead(t, headOfLength(t, 65536)))
}

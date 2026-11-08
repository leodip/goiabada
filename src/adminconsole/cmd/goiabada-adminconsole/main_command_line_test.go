package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// healthcheckRefusal is the one line `healthcheck` given an argument, before or after it, writes.
const healthcheckRefusal = "healthcheck takes no arguments: it reads the listener from the environment, " +
	"so run goiabada-adminconsole healthcheck alone\n"

// unknownCommand is the refusal of a word that names no command, for word.
func unknownCommand(word string) string {
	return `unknown command "` + word + `": run goiabada-adminconsole [flags], with no command, to start ` +
		`the admin console, or goiabada-adminconsole healthcheck, alone, to check the running console's ` +
		"health\n"
}

// commandLineBound is how long a child of these cases may run. Each expects an exit well inside a
// second, or the health check's 3; a console that got past a refusal waits for the auth server's
// token, and the case should fail on that rather than wait for it.
const commandLineBound = 15 * time.Second

// unstartableEnvironment is an environment the console refuses at start, and the health check reads
// none of: a TZ naming no zone, a malformed number and a malformed boolean the check does not read,
// an internal CA file that is not there, and no session keys or client secret. A health check that
// resolved TZ or loaded the configuration would stop on the first of them with exit 2 (#808
// decision 2).
var unstartableEnvironment = []string{
	"TZ=Not/AZone",
	"GOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS=91x1",
	"GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS=yes",
	"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE=/nonexistent/internal-ca.pem",
}

// commandLineRun is what one `goiabada-adminconsole` process did.
type commandLineRun struct {
	code           int
	stdout, stderr string
}

// runMainExactly runs main in a fresh process with args over env and nothing else, and answers its
// exit code and both streams.
func runMainExactly(t *testing.T, env []string, args ...string) commandLineRun {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), commandLineBound)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append([]string{runMainMarker + "=1"}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	run := commandLineRun{stdout: stdout.String(), stderr: stderr.String()}
	if ctx.Err() != nil {
		t.Fatalf("main did not exit within %s\nstdout: %s\nstderr: %s", commandLineBound, run.stdout, run.stderr)
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		run.code = exitErr.ExitCode()
	default:
		t.Fatalf("running main: %v\nstdout: %s\nstderr: %s", err, run.stdout, run.stderr)
	}
	return run
}

// runHealthcheck runs main with args over the unstartable environment and then env, so a case's
// own variables win.
func runHealthcheck(t *testing.T, env []string, args ...string) commandLineRun {
	t.Helper()
	return runMainExactly(t, append(append([]string{}, unstartableEnvironment...), env...), args...)
}

// healthStub is a listener the test starts, recording the path of every request it receives.
type healthStub struct {
	server *httptest.Server
	mu     sync.Mutex
	paths  []string
}

// newHealthStub starts a loopback stub answering every request with status, over TLS with a
// self-signed certificate when tls is set.
func newHealthStub(t *testing.T, tls bool, status int) *healthStub {
	t.Helper()

	stub := &healthStub{}
	stub.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.paths = append(stub.paths, r.Method+" "+r.URL.Path)
		stub.mu.Unlock()
		w.WriteHeader(status)
	}))
	if tls {
		stub.server.StartTLS()
	} else {
		stub.server.Start()
	}
	t.Cleanup(stub.server.Close)
	return stub
}

// port is the port the stub listens on.
func (s *healthStub) port() string {
	return strconv.Itoa(s.server.Listener.Addr().(*net.TCPAddr).Port)
}

// requests is every request the stub received, as method and path.
func (s *healthStub) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.paths...)
}

// TestMain_HealthcheckAsksTheConsolesOwnListener is decision 2 over the console's own listener
// variables: its HTTP listener when on, its HTTPS listener only when HTTP is off, a wildcard host
// called on loopback, silent and exit 0, under an environment the console would refuse to start
// with. The HTTPS certificate and key are named by files that are not there.
func TestMain_HealthcheckAsksTheConsolesOwnListener(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		stub := newHealthStub(t, false, http.StatusOK)

		run := runHealthcheck(t, []string{
			"GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP=0.0.0.0",
			"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=" + stub.port(),
		}, "healthcheck")

		assert.Equal(t, 0, run.code, "stderr: %s", run.stderr)
		assert.Empty(t, run.stdout)
		assert.Empty(t, run.stderr)
		assert.Equal(t, []string{"GET /health"}, stub.requests())
	})

	t.Run("HTTPS, with HTTP off", func(t *testing.T) {
		stub := newHealthStub(t, true, http.StatusOK)

		run := runHealthcheck(t, []string{
			"GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP=",
			"GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS=0.0.0.0",
			"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS=" + stub.port(),
			"GOIABADA_ADMINCONSOLE_CERTFILE=/nonexistent/cert.pem",
			"GOIABADA_ADMINCONSOLE_KEYFILE=/nonexistent/key.pem",
		}, "healthcheck")

		assert.Equal(t, 0, run.code, "stderr: %s", run.stderr)
		assert.Empty(t, run.stdout)
		assert.Empty(t, run.stderr)
		assert.Equal(t, []string{"GET /health"}, stub.requests())
	})

	t.Run("HTTP answering other than 200, while HTTPS would answer", func(t *testing.T) {
		plain := newHealthStub(t, false, http.StatusServiceUnavailable)
		secure := newHealthStub(t, true, http.StatusOK)

		run := runHealthcheck(t, []string{
			"GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP=0.0.0.0",
			"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=" + plain.port(),
			"GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS=0.0.0.0",
			"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS=" + secure.port(),
			"GOIABADA_ADMINCONSOLE_CERTFILE=/nonexistent/cert.pem",
			"GOIABADA_ADMINCONSOLE_KEYFILE=/nonexistent/key.pem",
		}, "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, "GET http://127.0.0.1:"+plain.port()+"/health answered 503 Service Unavailable\n", run.stderr)
		assert.Empty(t, secure.requests())
	})

	t.Run("neither listener enabled", func(t *testing.T) {
		run := runHealthcheck(t, []string{"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=0"}, "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Equal(t, "neither the http nor the https listener is enabled, so there is no /health to check\n", run.stderr)
	})
}

// TestMain_HealthcheckRefusesAMalformedListenerVariable: a console listener setting that does not
// parse is one line on stderr and exit 2.
func TestMain_HealthcheckRefusesAMalformedListenerVariable(t *testing.T) {
	run := runHealthcheck(t, []string{
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS=94x4",
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=90x1",
	}, "healthcheck")

	assert.Equal(t, 2, run.code)
	assert.Empty(t, run.stdout)
	assert.Equal(t, `malformed configuration: GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS is "94x4", not an integer; `+
		`GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP is "90x1", not an integer`+"\n", run.stderr)
}

// TestMain_HealthcheckTakesNoArguments is decision 3 at the console: an argument after the command,
// or a flag before it, is refused with exit 2 in one line, and nothing is asked.
func TestMain_HealthcheckTakesNoArguments(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		args []string
	}{
		{"an argument after it", unstartableEnvironment, []string{"healthcheck", "extra"}},
		{"a flag after it", unstartableEnvironment, []string{"healthcheck", "--adminconsole-listen-port-http=9091"}},
		// Before it, the word is no longer the first argument, so it reaches the command line's own
		// parse, under an environment the parse accepts.
		{"a flag before it", nil, []string{"--adminconsole-log-level=debug", "healthcheck"}},
		{"-- before it", nil, []string{"--", "healthcheck"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newHealthStub(t, false, http.StatusOK)
			env := append(append([]string{}, tc.env...),
				"GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP=0.0.0.0",
				"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP="+stub.port())

			run := runMainExactly(t, env, tc.args...)

			assert.Equal(t, 2, run.code)
			assert.Empty(t, run.stdout)
			assert.Equal(t, healthcheckRefusal, run.stderr)
			assert.Empty(t, stub.requests())
		})
	}
}

// watchedListener is a listener counting every connection made to it, and closing each at once.
type watchedListener struct {
	url         string
	connections atomic.Int32
}

func newWatchedListener(t *testing.T) *watchedListener {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	watched := &watchedListener{url: "http://" + listener.Addr().String()}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			watched.connections.Add(1)
			_ = conn.Close()
		}
	}()
	return watched
}

// TestMain_RefusesAWordThatNamesNoCommand is decision 5: a positional argument the console does not
// know stops it with exit 2 and one line naming the word and listing the commands, before startup
// does anything else. The environment is one the console would start with, its auth server a
// listener the test watches, so a console that went on would connect to it.
func TestMain_RefusesAWordThatNamesNoCommand(t *testing.T) {
	cases := []struct {
		name string
		args []string
		word string
	}{
		{"a word", []string{"serve"}, "serve"},
		{"a word after the flags", []string{"--adminconsole-log-level=debug", "serve"}, "serve"},
		{"a flag after the word, refused with it", []string{"serve", "--adminconsole-log-level=debug"}, "serve"},
		{"a mistyped command", []string{"healthchek"}, "healthchek"},
		{"behind --", []string{"--", "-x"}, "-x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authServer := newWatchedListener(t)

			run := runMainExactly(t, []string{
				"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=" + strings.Repeat("b1", 64),
				"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=" + strings.Repeat("b2", 32),
				"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=process-test-secret",
				"GOIABADA_AUTHSERVER_BASEURL=" + authServer.url,
				"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=0",
			}, tc.args...)

			assert.Equal(t, 2, run.code)
			assert.Empty(t, run.stdout)
			assert.Equal(t, unknownCommand(tc.word), run.stderr)
			assert.Zero(t, authServer.connections.Load(), "no connection is made to the auth server")
		})
	}
}

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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/hostport/hostporttest"
)

// healthcheckRefusal is the one line `healthcheck` given an argument, before or after it, writes.
const healthcheckRefusal = "healthcheck takes no arguments: it reads the listener from the environment, " +
	"so run goiabada-authserver healthcheck alone\n"

// unstartableEnvironment is an environment the server refuses at start, and the health check reads
// none of: a TZ naming no zone, a malformed number the check does not read, a database CA file and
// an internal CA file that are not there, and no keys at all. A health check that resolved TZ or
// loaded the configuration would stop on the first of them with exit 2 (#808 decision 2).
var unstartableEnvironment = []string{
	"TZ=Not/AZone",
	"GOIABADA_DB_PORT=33o6",
	"GOIABADA_AUTHSERVER_LISTEN_PORT_METRICS=91x0",
	"GOIABADA_DB_TLS_CA_FILE=/nonexistent/db-ca.pem",
	"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE=/nonexistent/internal-ca.pem",
}

// healthcheckRun is what one `goiabada-authserver` process did.
type healthcheckRun struct {
	code           int
	stdout, stderr string
	elapsed        time.Duration
}

// runHealthcheck runs main in a fresh process with args over exactly env, the unstartable
// environment first, so a case's own variables win.
func runHealthcheck(t *testing.T, env []string, args ...string) healthcheckRun {
	t.Helper()
	return runMainExactly(t, append(append([]string{}, unstartableEnvironment...), env...), args...)
}

// runMainExactly runs main in a fresh process with args over env and nothing else, and answers its
// exit code, both streams and how long it ran.
func runMainExactly(t *testing.T, env []string, args ...string) healthcheckRun {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append([]string{runMainMarker + "=1"}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	started := time.Now()
	err := cmd.Run()
	run := healthcheckRun{stdout: stdout.String(), stderr: stderr.String(), elapsed: time.Since(started)}
	if ctx.Err() != nil {
		t.Fatalf("main did not exit within %s\nstdout: %s\nstderr: %s", mainProcessBound, run.stdout, run.stderr)
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

// healthStub is a listener the test starts, recording the path of every request it receives.
type healthStub struct {
	server *httptest.Server
	mu     sync.Mutex
	paths  []string
	hosts  []string
}

// newHealthStub starts a stub on network's loopback answering every request with handler, over TLS
// with a self-signed certificate when tls is set.
func newHealthStub(t *testing.T, network string, tls bool, handler http.HandlerFunc) *healthStub {
	t.Helper()

	stub := &healthStub{}
	stub.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.paths = append(stub.paths, r.Method+" "+r.URL.Path)
		stub.hosts = append(stub.hosts, r.Host)
		stub.mu.Unlock()
		handler(w, r)
	}))
	if network == "tcp6" {
		listener, err := net.Listen("tcp6", "[::1]:0")
		require.NoError(t, err)
		_ = stub.server.Listener.Close()
		stub.server.Listener = listener
	}
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

// called is the host every request named, the address the check called: a wildcard is reached
// on Linux whether or not it is replaced, so only this shows that it was.
func (s *healthStub) called() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.hosts...)
}

// healthy answers 200, as /health does.
func healthy(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// httpOnly is the environment of an HTTP listener on host and port, the HTTPS listener off because
// no certificate is named.
func httpOnly(host, port string) []string {
	return []string{
		"GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP=" + host,
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=" + port,
	}
}

// httpsNamed is the environment of an HTTPS listener on host and port, its certificate and key
// named by files that are not there: the check names no file it reads.
func httpsNamed(host, port string) []string {
	return []string{
		"GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS=" + host,
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS=" + port,
		"GOIABADA_AUTHSERVER_CERTFILE=/nonexistent/cert.pem",
		"GOIABADA_AUTHSERVER_KEYFILE=/nonexistent/key.pem",
	}
}

// TestMain_HealthcheckAsksTheHTTPListener is decision 2's healthy answer: one GET of /health on the
// HTTP listener, a wildcard host called on loopback and any other host as configured, silent and
// exit 0, under an environment the server itself would refuse to start with.
func TestMain_HealthcheckAsksTheHTTPListener(t *testing.T) {
	cases := []struct {
		name, network, host, called string
	}{
		{"the IPv4 wildcard, on 127.0.0.1", "tcp4", "0.0.0.0", "127.0.0.1"},
		{"a host as configured", "tcp4", "localhost", "localhost"},
		{"the IPv6 wildcard, on ::1", "tcp6", "::", "[::1]"},
		{"the IPv6 wildcard in brackets, on ::1", "tcp6", "[::]", "[::1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.network == "tcp6" {
				hostporttest.SkipWithoutIPv6Loopback(t)
			}
			stub := newHealthStub(t, tc.network, false, healthy)

			run := runHealthcheck(t, httpOnly(tc.host, stub.port()), "healthcheck")

			assert.Equal(t, 0, run.code, "stderr: %s", run.stderr)
			assert.Empty(t, run.stdout)
			assert.Empty(t, run.stderr)
			assert.Equal(t, []string{"GET /health"}, stub.requests())
			assert.Equal(t, []string{tc.called + ":" + stub.port()}, stub.called())
		})
	}
}

// TestMain_HealthcheckAsksTheHTTPSListenerWhenHTTPIsOff is the HTTPS listener, asked only when the
// HTTP one is off, by an empty host or a port of 0, its self-signed certificate unverified and its
// named files never read.
func TestMain_HealthcheckAsksTheHTTPSListenerWhenHTTPIsOff(t *testing.T) {
	cases := []struct {
		name string
		off  []string
	}{
		{"no HTTP host", []string{"GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP="}},
		{"an HTTP port of 0", []string{"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newHealthStub(t, "tcp4", true, healthy)

			run := runHealthcheck(t, append(tc.off, httpsNamed("0.0.0.0", stub.port())...), "healthcheck")

			assert.Equal(t, 0, run.code, "stderr: %s", run.stderr)
			assert.Empty(t, run.stdout)
			assert.Empty(t, run.stderr)
			assert.Equal(t, []string{"GET /health"}, stub.requests())
			assert.Equal(t, []string{"127.0.0.1:" + stub.port()}, stub.called())
		})
	}
}

// TestMain_HealthcheckAsksARedirectingHTTPListener: with an https base URL and both listeners on,
// the HTTP listener only redirects, and still answers /health, which is what the check asks it.
func TestMain_HealthcheckAsksARedirectingHTTPListener(t *testing.T) {
	stub := newHealthStub(t, "tcp4", false, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "https://auth.example.test"+r.URL.Path, http.StatusMovedPermanently)
	})
	env := append(httpOnly("0.0.0.0", stub.port()), httpsNamed("0.0.0.0", strconv.Itoa(freePort(t)))...)
	env = append(env, "GOIABADA_AUTHSERVER_BASEURL=https://auth.example.test")

	run := runHealthcheck(t, env, "healthcheck")

	assert.Equal(t, 0, run.code, "stderr: %s", run.stderr)
	assert.Empty(t, run.stdout)
	assert.Empty(t, run.stderr)
	assert.Equal(t, []string{"GET /health"}, stub.requests())
}

// TestMain_HealthcheckReportsAnUnhealthyListener is every way the one GET can fail: one line on
// stderr naming the URL and what it met, exit 1, and nothing on stdout.
func TestMain_HealthcheckReportsAnUnhealthyListener(t *testing.T) {
	t.Run("nothing listening", func(t *testing.T) {
		port := strconv.Itoa(freePort(t))

		run := runHealthcheck(t, httpOnly("0.0.0.0", port), "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, "GET http://127.0.0.1:"+port+"/health failed: dial tcp 127.0.0.1:"+port+
			": connect: connection refused\n", run.stderr)
	})

	t.Run("an answer other than 200", func(t *testing.T) {
		stub := newHealthStub(t, "tcp4", false, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})

		run := runHealthcheck(t, httpOnly("0.0.0.0", stub.port()), "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, "GET http://127.0.0.1:"+stub.port()+"/health answered 503 Service Unavailable\n", run.stderr)
	})

	t.Run("a 204 is not a 200", func(t *testing.T) {
		stub := newHealthStub(t, "tcp4", false, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		run := runHealthcheck(t, httpOnly("0.0.0.0", stub.port()), "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Equal(t, "GET http://127.0.0.1:"+stub.port()+"/health answered 204 No Content\n", run.stderr)
	})

	// The redirect points back at the stub itself, so a check that followed it would be seen.
	t.Run("a redirect, not followed", func(t *testing.T) {
		stub := newHealthStub(t, "tcp4", false, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				http.Redirect(w, r, "/elsewhere", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		})

		run := runHealthcheck(t, httpOnly("0.0.0.0", stub.port()), "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, "GET http://127.0.0.1:"+stub.port()+`/health answered 302 Found, a redirect to "/elsewhere"`+"\n", run.stderr)
		assert.Equal(t, []string{"GET /health"}, stub.requests())
	})

	t.Run("a server that accepts and never answers, bounded by 3 seconds", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			var held []net.Conn
			defer func() {
				for _, c := range held {
					_ = c.Close()
				}
			}()
			for {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				held = append(held, conn)
			}
		}()
		port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)

		run := runHealthcheck(t, httpOnly("0.0.0.0", port), "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, "GET http://127.0.0.1:"+port+"/health had no answer within 3s\n", run.stderr)
		assert.GreaterOrEqual(t, run.elapsed, 3*time.Second)
		assert.Less(t, run.elapsed, 10*time.Second)
	})

	// An HTTP failure is the answer: falling back to HTTPS would hide a broken HTTP listener.
	t.Run("HTTP failing while an HTTPS listener would answer", func(t *testing.T) {
		https := newHealthStub(t, "tcp4", true, healthy)
		port := strconv.Itoa(freePort(t))

		run := runHealthcheck(t, append(httpOnly("0.0.0.0", port), httpsNamed("0.0.0.0", https.port())...), "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Equal(t, "GET http://127.0.0.1:"+port+"/health failed: dial tcp 127.0.0.1:"+port+
			": connect: connection refused\n", run.stderr)
		assert.Empty(t, https.requests(), "the HTTPS listener is never asked")
	})

	t.Run("neither listener enabled", func(t *testing.T) {
		run := runHealthcheck(t, []string{"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=0"}, "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, "neither the http nor the https listener is enabled, so there is no /health to check\n", run.stderr)
	})

	// An HTTPS listener lacking only its key is off, as the server's own rule has it.
	t.Run("an HTTPS listener with no key named is off", func(t *testing.T) {
		https := newHealthStub(t, "tcp4", true, healthy)
		env := append([]string{"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=0"}, httpsNamed("0.0.0.0", https.port())...)
		env = append(env, "GOIABADA_AUTHSERVER_KEYFILE=")

		run := runHealthcheck(t, env, "healthcheck")

		assert.Equal(t, 1, run.code)
		assert.Equal(t, "neither the http nor the https listener is enabled, so there is no /health to check\n", run.stderr)
		assert.Empty(t, https.requests())
	})
}

// TestMain_HealthcheckRefusesAMalformedListenerVariable: a listener setting that does not parse is
// a malformed variable, one line on stderr naming each and exit 2, as at the server's start.
func TestMain_HealthcheckRefusesAMalformedListenerVariable(t *testing.T) {
	t.Run("one", func(t *testing.T) {
		run := runHealthcheck(t, []string{"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=90x0"}, "healthcheck")

		assert.Equal(t, 2, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, `malformed configuration: GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP is "90x0", not an integer`+"\n", run.stderr)
	})

	t.Run("both, the HTTPS one read though the HTTP listener would be used", func(t *testing.T) {
		stub := newHealthStub(t, "tcp4", false, healthy)
		env := append(httpOnly("0.0.0.0", stub.port()), "GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS=94x3",
			"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=90x0")

		run := runHealthcheck(t, env, "healthcheck")

		assert.Equal(t, 2, run.code)
		assert.Equal(t, `malformed configuration: GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS is "94x3", not an integer; `+
			`GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP is "90x0", not an integer`+"\n", run.stderr)
		assert.Empty(t, stub.requests())
	})
}

// TestMain_HealthcheckTakesNoArguments is decision 3: an argument after the command, or a flag
// before it, is refused with exit 2 in one line, and nothing is asked.
func TestMain_HealthcheckTakesNoArguments(t *testing.T) {
	t.Run("after it", func(t *testing.T) {
		for _, args := range [][]string{
			{"healthcheck", "extra"},
			{"healthcheck", "--authserver-listen-port-http=9090"},
		} {
			stub := newHealthStub(t, "tcp4", false, healthy)

			run := runHealthcheck(t, httpOnly("0.0.0.0", stub.port()), args...)

			assert.Equal(t, 2, run.code, "%v", args)
			assert.Empty(t, run.stdout)
			assert.Equal(t, healthcheckRefusal, run.stderr, "%v", args)
			assert.Empty(t, stub.requests())
		}
	})

	// Before it, the word is no longer the first argument, and the flag parse alone finds it,
	// under the environment the server refuses at start and a log level its handler cannot use:
	// neither TZ, the configuration nor the log handler answers for the misplaced command.
	t.Run("before it", func(t *testing.T) {
		for _, args := range [][]string{
			{"--authserver-log-level=debug", "healthcheck"},
			{"--authserver-log-sql", "healthcheck"},
			{"--", "healthcheck"},
		} {
			stub := newHealthStub(t, "tcp4", false, healthy)

			run := runHealthcheck(t, append(httpOnly("0.0.0.0", stub.port()),
				"GOIABADA_AUTHSERVER_LOG_LEVEL=not-a-level"), args...)

			assert.Equal(t, 2, run.code, "%v", args)
			assert.Empty(t, run.stdout)
			assert.Equal(t, healthcheckRefusal, run.stderr, "%v", args)
			assert.Empty(t, stub.requests())
		}
	})
}

// TestMain_RefusesAWordThatNamesNoCommandBeforeTheConfiguration: a word that names no command is
// refused by the flag parse alone, under the environment the server refuses at start, so the
// refusal names the word rather than a setting it has nothing to do with (#808 decision 3).
func TestMain_RefusesAWordThatNamesNoCommandBeforeTheConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"serve"},
		{"--authserver-log-level=debug", "serve"},
		{"--", "serve"},
	} {
		run := runHealthcheck(t, []string{"GOIABADA_AUTHSERVER_LOG_LEVEL=not-a-level"}, args...)

		assert.Equal(t, 2, run.code, "%v", args)
		assert.Empty(t, run.stdout)
		assert.Equal(t, `unknown command "serve": run goiabada-authserver [flags] with no command `+
			`to start the server, goiabada-authserver [flags] migrate version, or `+
			`goiabada-authserver [flags] migrate to <version>, to manage the schema, `+
			`goiabada-authserver [flags] recover --email <address> [flags], to restore sign-in for `+
			`one user, or goiabada-authserver healthcheck, alone, to check the running server's `+
			`health; the server's flags go before the command`+"\n", run.stderr, "%v", args)
	}
}

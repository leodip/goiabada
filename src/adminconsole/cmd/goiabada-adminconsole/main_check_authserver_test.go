package main

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkAuthServerRefusal is the one line `check-authserver` given an argument, before or after it,
// writes.
const checkAuthServerRefusal = "check-authserver takes no arguments: it reads the auth server's URLs and the " +
	"internal CA file from the environment, so run goiabada-adminconsole check-authserver alone\n"

// publicSettingsBody is the auth server's answer at /api/public/settings, as it writes it.
const publicSettingsBody = `{"appName":"Goiabada","uiTheme":"light","smtpEnabled":false,"issuer":"https://auth.example.test"}`

// uncheckableEnvironment is an environment the console refuses at start and check-authserver
// reads none of: a TZ naming no zone, a malformed number and a malformed boolean, no session keys
// and no client secret. A check that resolved TZ, loaded the whole configuration or wanted the
// console's credentials would stop on one of them (#808 decision 6).
var uncheckableEnvironment = []string{
	"TZ=Not/AZone",
	"GOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS=91x1",
	"GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS=yes",
}

// runCheckAuthServer runs main with args over the uncheckable environment and then env.
func runCheckAuthServer(t *testing.T, env []string, args ...string) commandLineRun {
	t.Helper()
	return runMainExactly(t, append(append([]string{}, uncheckableEnvironment...), env...), args...)
}

// settingsStub is an auth server the test starts, answering every request with handler and
// recording each one's method and path.
type settingsStub struct {
	server *httptest.Server
	mu     sync.Mutex
	seen   []string
}

func (s *settingsStub) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, r.Method+" "+r.URL.Path)
}

func (s *settingsStub) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.seen...)
}

// newSettingsStub starts a plain HTTP auth server answering every request with handler.
func newSettingsStub(t *testing.T, handler http.HandlerFunc) *settingsStub {
	t.Helper()
	stub := &settingsStub{}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.record(r)
		handler(w, r)
	}))
	t.Cleanup(stub.server.Close)
	return stub
}

// answering is a handler writing status and body as JSON.
func answering(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// TestMain_CheckAuthServerFetchesThePublicSettings is decision 6's success: the console's settings
// call, once, to the internal URL when one is set and the base URL otherwise, one line on stdout
// naming the URL that answered and exit 0, under an environment the console would refuse to start
// with and without its session keys or client secret.
func TestMain_CheckAuthServerFetchesThePublicSettings(t *testing.T) {
	t.Run("the internal URL, when set", func(t *testing.T) {
		stub := newSettingsStub(t, answering(http.StatusOK, publicSettingsBody))
		public := newWatchedListener(t)

		run := runCheckAuthServer(t, []string{
			"GOIABADA_AUTHSERVER_BASEURL=" + public.url,
			"GOIABADA_AUTHSERVER_INTERNALBASEURL=" + stub.server.URL,
		}, "check-authserver")

		assert.Equal(t, 0, run.code, "stderr: %s", run.stderr)
		assert.Equal(t, "GET "+stub.server.URL+"/api/public/settings answered with the auth server's public settings\n", run.stdout)
		assert.Empty(t, run.stderr)
		assert.Equal(t, []string{"GET /api/public/settings"}, stub.requests())
		assert.Zero(t, public.connections.Load(), "the base URL is not called while the internal URL is set")
	})

	t.Run("the base URL, when the internal URL is blank", func(t *testing.T) {
		stub := newSettingsStub(t, answering(http.StatusOK, publicSettingsBody))

		run := runCheckAuthServer(t, []string{
			"GOIABADA_AUTHSERVER_BASEURL=" + stub.server.URL,
			"GOIABADA_AUTHSERVER_INTERNALBASEURL=  ",
		}, "check-authserver")

		assert.Equal(t, 0, run.code, "stderr: %s", run.stderr)
		assert.Equal(t, "GET "+stub.server.URL+"/api/public/settings answered with the auth server's public settings\n", run.stdout)
		assert.Empty(t, run.stderr)
		assert.Equal(t, []string{"GET /api/public/settings"}, stub.requests())
	})
}

// TestMain_CheckAuthServerReportsWhatItMet is decision 6's failures: anything but settings fetched
// and decoded prints the client's error on stderr, nothing on stdout, and exits 1.
func TestMain_CheckAuthServerReportsWhatItMet(t *testing.T) {
	t.Run("a 200 whose body does not decode", func(t *testing.T) {
		stub := newSettingsStub(t, answering(http.StatusOK, "<html>a proxy's page</html>"))

		run := runCheckAuthServer(t, []string{"GOIABADA_AUTHSERVER_INTERNALBASEURL=" + stub.server.URL}, "check-authserver")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, "failed to decode public settings response: invalid character '<' looking for beginning of value\n", run.stderr)
	})

	t.Run("an answer other than 200", func(t *testing.T) {
		stub := newSettingsStub(t, answering(http.StatusBadGateway, "bad gateway"))

		run := runCheckAuthServer(t, []string{"GOIABADA_AUTHSERVER_INTERNALBASEURL=" + stub.server.URL}, "check-authserver")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, "authserver returned status 502: bad gateway\n", run.stderr)
	})

	t.Run("a redirect, not followed", func(t *testing.T) {
		var followed atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Add(1) }))
		t.Cleanup(target.Close)
		stub := newSettingsStub(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/api/public/settings", http.StatusMovedPermanently)
		})

		run := runCheckAuthServer(t, []string{"GOIABADA_AUTHSERVER_INTERNALBASEURL=" + stub.server.URL}, "check-authserver")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, `failed to fetch public settings from authserver: Get "`+stub.server.URL+`/api/public/settings": `+
			"the auth server answered 301, a redirect to "+target.URL+", which the admin console does not follow: "+
			"set GOIABADA_AUTHSERVER_INTERNALBASEURL to an address of the auth server that answers directly\n", run.stderr)
		assert.Zero(t, followed.Load())
	})

	t.Run("nothing listening", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		address := listener.Addr().String()
		require.NoError(t, listener.Close())

		run := runCheckAuthServer(t, []string{"GOIABADA_AUTHSERVER_INTERNALBASEURL=http://" + address}, "check-authserver")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, `failed to fetch public settings from authserver: Get "http://`+address+`/api/public/settings": `+
			"dial tcp "+address+": connect: connection refused\n", run.stderr)
	})
}

// TestMain_CheckAuthServerVerifiesTheCertificate is decision 6's TLS: an https internal URL a
// private CA signed answers once GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE names that CA, as the
// console's own calls do, and without it is refused as untrusted before anything is asked.
func TestMain_CheckAuthServerVerifiesTheCertificate(t *testing.T) {
	ca, caKey := newTestCA(t, "the internal CA check-authserver is told of")
	var seen []string
	var mu sync.Mutex
	peer := newRecordingTLSAuthServer(t, newTestLeaf(t, ca, caKey), func(path string) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, path)
	})
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600))
	requests := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, seen...)
	}

	t.Run("without the CA file", func(t *testing.T) {
		run := runCheckAuthServer(t, []string{"GOIABADA_AUTHSERVER_INTERNALBASEURL=" + peer.URL}, "check-authserver")

		assert.Equal(t, 1, run.code)
		assert.Empty(t, run.stdout)
		assert.Equal(t, `failed to fetch public settings from authserver: Get "`+peer.URL+`/api/public/settings": `+
			"tls: failed to verify certificate: x509: certificate signed by unknown authority\n", run.stderr)
		assert.Empty(t, requests(), "nothing is asked of a peer whose certificate does not verify")
	})

	t.Run("with the CA file naming its CA", func(t *testing.T) {
		run := runCheckAuthServer(t, []string{
			"GOIABADA_AUTHSERVER_INTERNALBASEURL=" + peer.URL,
			"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE=" + caFile,
		}, "check-authserver")

		assert.Equal(t, 0, run.code, "stderr: %s", run.stderr)
		assert.Equal(t, "GET "+peer.URL+"/api/public/settings answered with the auth server's public settings\n", run.stdout)
		assert.Empty(t, run.stderr)
		assert.Equal(t, []string{"/api/public/settings"}, requests())
	})
}

// TestMain_CheckAuthServerRefusesAnInternalCAFileItCannotUse: a CA file that cannot be read, or
// holds no certificate, is a malformed value, refused with the console's own start-up line and
// exit 2 before the auth server is called (#808 decision 6, #525).
func TestMain_CheckAuthServerRefusesAnInternalCAFileItCannotUse(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.pem")
	notPEM := filepath.Join(dir, "not-a-certificate.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600))
	const setting = "malformed configuration: GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE (--adminconsole-internal-ca-file) is "

	cases := []struct {
		name, file, want string
	}{
		{"a file that is not there", missing, setting + `"` + missing + `", which cannot be read: no such file or directory` + "\n"},
		{"a file holding no certificate", notPEM, setting + `"` + notPEM + `", which holds no PEM certificate` + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authServer := newWatchedListener(t)

			run := runCheckAuthServer(t, []string{
				"GOIABADA_AUTHSERVER_INTERNALBASEURL=" + authServer.url,
				"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE=" + tc.file,
			}, "check-authserver")

			assert.Equal(t, 2, run.code)
			assert.Empty(t, run.stdout)
			assert.Equal(t, tc.want, run.stderr)
			assert.Zero(t, authServer.connections.Load(), "no connection is made to the auth server")
		})
	}
}

// TestMain_CheckAuthServerTakesNoArguments: an argument after the command, or a flag before it, is
// refused with exit 2 in one line, and the auth server is not called (#808 decisions 3, 5 and 6).
func TestMain_CheckAuthServerTakesNoArguments(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		args []string
	}{
		{"an argument after it", uncheckableEnvironment, []string{"check-authserver", "extra"}},
		{"a flag after it", uncheckableEnvironment, []string{"check-authserver", "--authserver-internalbaseurl=http://127.0.0.1:1"}},
		// Before it, the word is no longer the first argument, so it reaches the command line's own
		// parse, under an environment the parse accepts.
		{"a flag before it", nil, []string{"--adminconsole-log-level=debug", "check-authserver"}},
		{"-- before it", nil, []string{"--", "check-authserver"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authServer := newWatchedListener(t)
			env := append(append([]string{}, tc.env...), "GOIABADA_AUTHSERVER_INTERNALBASEURL="+authServer.url)

			run := runMainExactly(t, env, tc.args...)

			assert.Equal(t, 2, run.code)
			assert.Empty(t, run.stdout)
			assert.Equal(t, checkAuthServerRefusal, run.stderr)
			assert.Zero(t, authServer.connections.Load(), "no connection is made to the auth server")
		})
	}
}

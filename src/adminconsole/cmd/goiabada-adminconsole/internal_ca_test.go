package main

// #525's done-when, both halves. In process: with GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE naming
// the CA that signed an https internal URL, every client the console composes reaches it, with no
// SSL_CERT_FILE in the environment, and the console still refuses a server whose CA it was not
// told of before sending a byte. Across processes: the named CA is appended to the system roots
// rather than left in their place, which is the difference from SSL_CERT_FILE and SSL_CERT_DIR
// the issue turns on -- the child's system roots are one CA through SSL_CERT_FILE, the setting
// adds a second beside it, and a server under each must answer.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/internal/sessionbackend"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// TestInternalBaseURL_HTTPS_TrustsAPrivateCATheConsoleNames is the issue as a test: the console
// names the private CA through the setting, and every call it makes to the internal URL reaches
// the peer the CA signed. No SSL_CERT_FILE or SSL_CERT_DIR is set, so nothing but the setting
// can have made the certificate verify. The clients are the ones main and the routes compose,
// against a configuration Load read, so the test covers the setting from its variable to the
// wire: the token client, the session backend, the public settings client and the admin API
// client. The session backend is handed a token rather than a token source over the token client,
// so its write is its own transport's request, in the refusal as much as the reach: over the token
// client, the refused token grant would stop it before its own transport dialled.
func TestInternalBaseURL_HTTPS_TrustsAPrivateCATheConsoleNames(t *testing.T) {
	ca, caKey := newTestCA(t, "the named internal CA")
	var requests atomic.Int32
	peer := newTLSAuthServer(t, newTestLeaf(t, ca, caKey), &requests)
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600))

	t.Setenv("GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE", caFile)
	t.Setenv("GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET", "the-secret")

	// loadFor reads the configuration the way main does, with the internal URL in the
	// environment, and answers it beside the roots it read the CA file into.
	loadFor := func(t *testing.T, internalURL string) (*config.Config, *x509.CertPool) {
		t.Setenv("GOIABADA_AUTHSERVER_INTERNALBASEURL", internalURL)
		fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		cfg, loadErr := config.Load(fs, nil)
		require.NoError(t, loadErr, "the load must accept a CA file it can read")
		require.NotNil(t, cfg.AdminConsole.InternalRoots, "a CA file the load accepted must answer a pool")
		return cfg, cfg.AdminConsole.InternalRoots
	}

	// call makes the four calls the console's page load makes, with the clients main and the
	// routes compose, and answers their errors in the order the peer sees them.
	call := func(cfg *config.Config, roots *x509.CertPool) []error {
		upstream := upstreammetrics.Register(metrics.NewRegistry())
		authBase := cfg.AuthServer.GetEffectiveBaseURL()

		tokenClient := newTokenClient(cfg, oauthclient.NewAuthServerHTTPClient(roots), upstream)
		_, tokenErr := tokenClient.ClientCredentials(context.Background(), "authserver:manage")
		_, sessionErr := sessionbackend.New(authBase, staticTokens{}, roots, upstream).
			Create(context.Background(), "a-session", []byte("ciphertext"), false)
		_, settingsErr := publicsettings.NewClient(authBase, roots, upstream).GetPublicSettings(context.Background())
		_, adminErr := apiclient.NewAuthServerClient(authBase, roots, upstream).
			GetSettingsGeneral(context.Background(), "an-access-token")
		return []error{tokenErr, sessionErr, settingsErr, adminErr}
	}

	t.Run("the CA the console names", func(t *testing.T) {
		cfg, roots := loadFor(t, peer.URL)

		for i, err := range call(cfg, roots) {
			require.NoError(t, err, "call %d to the private-CA auth server answered %v, want the console to reach it once it names the CA", i, err)
		}
		// Four: the token grant, the session backend's write, the public settings read and the
		// admin API read.
		assert.Equal(t, int32(4), requests.Load(), "the peer whose CA the console names saw these calls")
	})

	t.Run("a CA the console was not told of", func(t *testing.T) {
		otherCA, otherCAKey := newTestCA(t, "a CA the console was not told of")
		var untrustedRequests atomic.Int32
		untrusted := newTLSAuthServer(t, newTestLeaf(t, otherCA, otherCAKey), &untrustedRequests)

		cfg, roots := loadFor(t, untrusted.URL)

		for i, err := range call(cfg, roots) {
			var unknownAuthority x509.UnknownAuthorityError
			require.ErrorAs(t, err, &unknownAuthority, "call %d to the auth server answered %v, want its certificate refused", i, err)
		}
		assert.Equal(t, int32(0), untrustedRequests.Load(), "the peer whose certificate the console refuses saw these calls")
	})
}

// staticTokens is a session token source that always has a token, so the session backend's
// request is its own transport's from the first byte.
type staticTokens struct{}

func (staticTokens) Token(context.Context) (string, error) { return "a-session-token", nil }
func (staticTokens) Invalidate()                           {}

// The environment the parent hands the child half of the append test: the marker that makes the
// test the child, and the two servers' URLs.
const (
	internalCAChildMarker   = "GOIABADA_TEST_INTERNAL_CA_CHILD"
	internalCASystemURL     = "GOIABADA_TEST_INTERNAL_CA_SYSTEM_URL"
	internalCAAppendedURL   = "GOIABADA_TEST_INTERNAL_CA_APPENDED_URL"
	internalCAChildTestName = "TestInternalCAFile_KeepsTheSystemRootsBesideTheNamedCA"
)

// TestInternalCAFile_AppendsTheNamedCAToTheSystemRoots is the difference from SSL_CERT_FILE the
// issue turns on, proven over the wire. The child's system roots are one CA, through SSL_CERT_FILE
// and an empty SSL_CERT_DIR, and the setting names a second CA. Both servers must answer: the
// one the system roots alone trust, and the one the named CA signed. A setting that replaced the
// system roots would have refused the first, which is what makes the append rather than the
// handshake the thing this pins. The child is a fresh process because the system roots load once
// per process.
func TestInternalCAFile_AppendsTheNamedCAToTheSystemRoots(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "ios", "windows", "android", "plan9":
		t.Skipf("SSL_CERT_FILE does not replace the system roots on %s", runtime.GOOS)
	}

	dir := t.TempDir()
	systemCA, systemKey := newTestCA(t, "the CA the child's system roots hold")
	appendedCA, appendedKey := newTestCA(t, "the CA the setting names")
	systemFile := filepath.Join(dir, "system-ca.pem")
	require.NoError(t, os.WriteFile(systemFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: systemCA.Raw}), 0o600))
	appendedFile := filepath.Join(dir, "appended-ca.pem")
	require.NoError(t, os.WriteFile(appendedFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: appendedCA.Raw}), 0o600))
	// An empty directory, so the child's system roots are the one CA and nothing the host happens to hold.
	certDir := filepath.Join(dir, "certs")
	require.NoError(t, os.Mkdir(certDir, 0o700))

	var systemRequests, appendedRequests atomic.Int32
	system := newTLSAuthServer(t, newTestLeaf(t, systemCA, systemKey), &systemRequests)
	appended := newTLSAuthServer(t, newTestLeaf(t, appendedCA, appendedKey), &appendedRequests)

	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+internalCAChildTestName+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(),
		internalCAChildMarker+"=1",
		"SSL_CERT_FILE="+systemFile,
		"SSL_CERT_DIR="+certDir,
		"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE="+appendedFile,
		internalCASystemURL+"="+system.URL,
		internalCAAppendedURL+"="+appended.URL,
	)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	require.NoError(t, err, "the child failed:\n%s", output.String())
	// A -test.run that matched nothing exits 0 too.
	require.Contains(t, output.String(), "--- PASS: "+internalCAChildTestName, "the child ran no test:\n%s", output.String())

	assert.Equal(t, int32(1), systemRequests.Load(), "the server the system roots alone trust saw these calls, which the named CA must not have replaced")
	assert.Equal(t, int32(1), appendedRequests.Load(), "the server the named CA signed saw these calls")
}

// TestInternalCAFile_KeepsTheSystemRootsBesideTheNamedCA is the child half of the test above,
// and skips unless that test started it. Its system roots are the one CA SSL_CERT_FILE names, so
// a request that verifies says which pool it verified against.
func TestInternalCAFile_KeepsTheSystemRootsBesideTheNamedCA(t *testing.T) {
	if os.Getenv(internalCAChildMarker) != "1" {
		t.Skip("the child half of TestInternalCAFile_AppendsTheNamedCAToTheSystemRoots")
	}

	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg, loadErr := config.Load(fs, nil)
	require.NoError(t, loadErr)
	roots := cfg.AdminConsole.InternalRoots
	require.NotNil(t, roots)

	client := oauthclient.NewAuthServerHTTPClient(roots)
	for name, url := range map[string]string{
		"the system roots hold": internalCASystemURL,
		"the named CA signed":   internalCAAppendedURL,
	} {
		resp, err := client.Get(os.Getenv(url))
		require.NoError(t, err, "the request to the server %s must verify, so the named CA joined the system roots beside them rather than in their place", name)
		_ = resp.Body.Close()
	}
}

// TestMain_HandsTheInternalRootsToEveryClientItBuilds is the wiring between the pool Load reads
// and the clients main composes, at the process: the internal URL is served under a private CA
// that only GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE names, with no SSL_CERT_FILE in the child's
// environment. main's own token grant must reach it, or the console never listens; and a page
// that reads the settings and saves a session, the sign-in redirect, must reach the settings
// endpoint and the session endpoint. A main handing any of the three clients nil instead of the
// pool sends that request under the system roots alone, and the peer never sees it.
func TestMain_HandsTheInternalRootsToEveryClientItBuilds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	ca, caKey := newTestCA(t, "the CA only the setting names")
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600))
	var mu sync.Mutex
	arrived := map[string]int{}
	peer := newRecordingTLSAuthServer(t, newTestLeaf(t, ca, caKey), func(path string) {
		mu.Lock()
		defer mu.Unlock()
		arrived[path]++
	})

	ports := freePorts(t, 2)
	httpPort := ports[0]
	child := startMetricsChild(t, ctx, "https://auth.example.test", httpPort, ports[1], "",
		"GOIABADA_AUTHSERVER_INTERNALBASEURL="+peer.URL,
		"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE="+caFile)

	// A child whose token grant was refused never listens, so its exit ends the wait at once.
	up, upCancel := context.WithCancel(ctx)
	defer upCancel()
	go func() {
		select {
		case <-child.done:
		case <-up.Done():
		}
		upCancel()
	}()
	status, _, body := getWhenUp(t, up, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/admin/users")
	assert.Equal(t, http.StatusFound, status, "the sign-in redirect: %s", body)

	require.NoError(t, child.cmd.Process.Signal(syscall.SIGTERM))
	code, records := child.wait(t, ctx)
	require.Equalf(t, 0, code, "a drained stop exits 0\n%s", dumpRecords(records))

	mu.Lock()
	defer mu.Unlock()
	for path, client := range map[string]string{
		"/auth/token":             "the token client, over main's HTTP client",
		"/api/public/settings":    "the public settings client",
		"/api/v1/sessions/create": "the session backend",
	} {
		assert.Positivef(t, arrived[path], "%s never reached the peer at %s, so it was not handed the internal roots; arrived: %v\n%s",
			client, path, arrived, dumpRecords(records))
	}
}

// TestMain_HandsTheInternalRootsToTheServer is the last of main's hand-offs: the pool it gives
// NewServer, which the route table builds the admin API client from. Only a signed-in page calls
// the admin API, so the auth server here keeps the console's browser sessions for real, in memory,
// and the test seals a signed-in administrator's session into it under the child's own session
// keys, as the console would have after a sign-in. The child then serves /account/sessions to that
// session: the JWT middleware verifies the session's ID token against the JWKS it fetches, and the
// page asks the admin API for the account's sessions. Both must reach the auth server, which only
// the CA GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE names signed, and the page must render. A main
// handing NewServer nil leaves the admin API client on the system roots alone: the page answers
// 500 and the admin API request never arrives.
func TestMain_HandsTheInternalRootsToTheServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	ca, caKey := newTestCA(t, "the CA only the setting names")
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600))

	signing, _ := oauthclienttest.Keys(t)
	sessions := sessiontest.NewMemoryBackend()
	var mu sync.Mutex
	arrived := map[string]int{}
	peer := newTLSServer(t, newTestLeaf(t, ca, caKey), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrived[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/token":
			_, _ = w.Write([]byte(`{"access_token":"a-session-token","token_type":"Bearer","expires_in":3600}`))
		case "/api/public/settings":
			_, _ = w.Write([]byte(`{"appName":"Goiabada","issuer":"` + oauthclienttest.Issuer + `"}`))
		case "/certs":
			assert.NoError(t, json.NewEncoder(w).Encode(oauth.Jwks{
				Keys: []oauth.Jwk{oauthclienttest.JwkFromPublicKey("key-1", &signing.PublicKey)}}))
		case "/api/v1/account/sessions":
			_, _ = w.Write([]byte(`{}`))
		default:
			serveSessionEndpoint(t, sessions, w, r)
		}
	}))

	// The session a sign-in leaves: a signed ID token for the console's client and a token set
	// granting the account scope, sealed under the keys the child is started with.
	authenticationKey, err := hex.DecodeString(strings.Repeat("b1", 64))
	require.NoError(t, err)
	encryptionKey, err := hex.DecodeString(strings.Repeat("b2", 32))
	require.NoError(t, err)
	store, err := newSessionStore(sessions, false, sessionstore.KeyPair{
		AuthenticationKey: authenticationKey, EncryptionKey: encryptionKey}, nil)
	require.NoError(t, err)
	claims := oauthclienttest.ValidClaims()
	claims["aud"] = builtin.AdminConsoleClientIdentifier
	gob.Register(oauth.TokenResponse{})
	seed := httptest.NewRequest(http.MethodGet, "/", nil)
	session, err := store.Get(seed, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	session.Values[sessionkeys.JWT] = oauth.TokenResponse{
		AccessToken: "an-access-token",
		IdToken:     oauthclienttest.SignRS256(t, signing, "key-1", claims),
		TokenType:   "Bearer",
		Scope:       "openid authserver:manage-account",
	}
	session.Values[sessionkeys.JWTExpiresAt] = time.Now().Add(time.Hour).Unix()
	saved := httptest.NewRecorder()
	require.NoError(t, store.Save(seed, saved, session))

	ports := freePorts(t, 2)
	httpPort := ports[0]
	child := startMetricsChild(t, ctx, "https://auth.example.test", httpPort, ports[1], "",
		"GOIABADA_AUTHSERVER_INTERNALBASEURL="+peer.URL,
		"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE="+caFile)

	// A child whose token grant was refused never listens, so its exit ends the wait at once.
	up, upCancel := context.WithCancel(ctx)
	defer upCancel()
	go func() {
		select {
		case <-child.done:
		case <-up.Done():
		}
		upCancel()
	}()
	consoleURL := "http://127.0.0.1:" + strconv.Itoa(httpPort)
	status, _, body := getWhenUp(t, up, consoleURL+"/health")
	require.Equal(t, http.StatusOK, status, "the console answers: %s", body)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, consoleURL+"/account/sessions", nil)
	require.NoError(t, err)
	for _, cookie := range saved.Result().Cookies() {
		req.AddCookie(cookie)
	}
	noRedirects := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirects.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.NoError(t, child.cmd.Process.Signal(syscall.SIGTERM))
	code, records := child.wait(t, ctx)
	require.Equalf(t, 0, code, "a drained stop exits 0\n%s", dumpRecords(records))

	mu.Lock()
	defer mu.Unlock()
	assert.Positivef(t, arrived["/certs"], "the JWKS fetch never reached the peer; arrived: %v\n%s", arrived, dumpRecords(records))
	assert.Positivef(t, arrived["/api/v1/account/sessions"],
		"the admin API client never reached the peer, so main did not hand NewServer the internal roots; arrived: %v\n%s",
		arrived, dumpRecords(records))
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the signed-in page renders from the admin API's answer")
}

// serveSessionEndpoint answers the auth server's browser-session endpoint, /api/v1/sessions/<op>,
// over backend, with the statuses the console's session backend reads: 404 for a session that is
// gone, 204 for a delete.
func serveSessionEndpoint(t *testing.T, backend sessionstore.Backend, w http.ResponseWriter, r *http.Request) {
	operation, found := strings.CutPrefix(r.URL.Path, "/api/v1/sessions/")
	if !found {
		http.NotFound(w, r)
		return
	}
	var request api.SessionWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var (
		answer any
		err    error
	)
	switch operation {
	case "load":
		var record *sessionstore.Record
		if record, err = backend.Load(r.Context(), request.Id); err == nil {
			answer = api.SessionLoadResponse{Data: string(record.Data), LastAccessed: record.LastAccessed, ExpiresAt: record.ExpiresAt}
		}
	case "create", "update", "touch":
		var expiresAt time.Time
		switch operation {
		case "create":
			expiresAt, err = backend.Create(r.Context(), request.Id, []byte(request.Data), request.Authenticated)
		case "update":
			expiresAt, err = backend.Update(r.Context(), request.Id, []byte(request.Data), request.Authenticated)
		default:
			expiresAt, err = backend.Touch(r.Context(), request.Id, request.Authenticated)
		}
		answer = api.SessionWriteResponse{ExpiresAt: expiresAt}
	case "delete":
		if err = backend.Delete(r.Context(), request.Id); err == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	switch {
	case errors.Is(err, sessionstore.ErrNotFound):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		assert.NoError(t, json.NewEncoder(w).Encode(answer))
	}
}

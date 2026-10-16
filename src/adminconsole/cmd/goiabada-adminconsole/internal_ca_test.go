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
	"encoding/pem"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/internal/sessionbackend"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/metrics"
)

// TestInternalBaseURL_HTTPS_TrustsAPrivateCATheConsoleNames is the issue as a test: the console
// names the private CA through the setting, and every call it makes to the internal URL reaches
// the peer the CA signed. No SSL_CERT_FILE or SSL_CERT_DIR is set, so nothing but the setting
// can have made the certificate verify. The clients are the ones main and the routes compose,
// against a configuration Load read, so the test covers the setting from its variable to the
// wire: the token client, the session backend (its token grant and its write, which is why the
// peer sees five requests), the public settings client and the admin API client.
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
		roots, rootsErr := cfg.AdminConsole.InternalRoots()
		require.NoError(t, rootsErr)
		require.NotNil(t, roots, "a CA file the load accepted must answer a pool")
		return cfg, roots
	}

	// call makes the four calls the console's page load makes, with the clients main and the
	// routes compose, and answers their errors in the order the peer sees them.
	call := func(cfg *config.Config, roots *x509.CertPool) []error {
		upstream := upstreammetrics.Register(metrics.NewRegistry())
		authBase := cfg.AuthServer.GetEffectiveBaseURL()

		tokenClient := newTokenClient(cfg, oauthclient.NewAuthServerHTTPClient(roots), upstream)
		tokenSource := oauthclient.NewSessionTokenSource(tokenClient)
		_, tokenErr := tokenClient.ClientCredentials(context.Background(), "authserver:manage")
		_, sessionErr := sessionbackend.New(authBase, tokenSource, roots, upstream).
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
		// Five: the token grant above, the session backend's own token grant and its write,
		// the public settings read and the admin API read.
		assert.Equal(t, int32(5), requests.Load(), "the peer whose CA the console names saw these calls")
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
	roots, rootsErr := cfg.AdminConsole.InternalRoots()
	require.NoError(t, rootsErr)
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

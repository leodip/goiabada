package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/metrics"
)

// The environment the parent hands the child half of the https internal URL test: the marker that
// makes the test the child, and the two auth servers' URLs.
const (
	httpsChildMarker   = "GOIABADA_TEST_INTERNAL_HTTPS_CHILD"
	httpsTrustedURL    = "GOIABADA_TEST_INTERNAL_HTTPS_TRUSTED_URL"
	httpsUntrustedURL  = "GOIABADA_TEST_INTERNAL_HTTPS_UNTRUSTED_URL"
	httpsChildTestName = "TestInternalBaseURL_HTTPS_TrustsWhatTheSystemRootsTrust"
)

// An https internal URL is a configuration the console supports with no setting of its own (#505):
// its clients send through Go's default transport, which verifies the auth server's certificate
// against the system roots, and on Linux SSL_CERT_FILE and SSL_CERT_DIR replace those roots. The
// parent serves two auth servers over TLS, one under a CA the child's SSL_CERT_FILE names and one
// under a CA it does not, and runs the child with only that CA trusted: the system roots load once
// per process, so the child is a fresh one. The child makes the calls with the clients main and
// the routes compose, through the internal URL; the first server must see every call arrive, and
// the second none, since the console refuses its certificate before sending a byte of a request.
func TestInternalBaseURL_HTTPS_ReachesATrustedAuthServerAndRefusesAnUntrustedOne(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "ios", "windows", "android", "plan9":
		t.Skipf("SSL_CERT_FILE does not replace the system roots on %s", runtime.GOOS)
	}

	dir := t.TempDir()
	trustedCA, trustedKey := newTestCA(t, "trusted test CA")
	untrustedCA, untrustedKey := newTestCA(t, "untrusted test CA")
	caFile := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedCA.Raw}), 0o600))
	// An empty directory, so the child's roots are the one CA and nothing the host happens to hold.
	certDir := filepath.Join(dir, "certs")
	require.NoError(t, os.Mkdir(certDir, 0o700))

	var trustedRequests, untrustedRequests atomic.Int32
	trusted := newTLSAuthServer(t, newTestLeaf(t, trustedCA, trustedKey), &trustedRequests)
	untrusted := newTLSAuthServer(t, newTestLeaf(t, untrustedCA, untrustedKey), &untrustedRequests)

	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+httpsChildTestName+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(),
		httpsChildMarker+"=1",
		"SSL_CERT_FILE="+caFile,
		"SSL_CERT_DIR="+certDir,
		httpsTrustedURL+"="+trusted.URL,
		httpsUntrustedURL+"="+untrusted.URL,
	)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	require.NoError(t, err, "the child failed:\n%s", output.String())
	// A -test.run that matched nothing exits 0 too.
	require.Contains(t, output.String(), "--- PASS: "+httpsChildTestName, "the child ran no test:\n%s", output.String())

	assert.Equal(t, int32(3), trustedRequests.Load(), "the auth server whose certificate the console trusts received these calls")
	assert.Equal(t, int32(0), untrustedRequests.Load(), "the auth server whose certificate the console does not trust received these calls")
}

// TestInternalBaseURL_HTTPS_TrustsWhatTheSystemRootsTrust is the child half of the test above, and
// skips unless that test started it. It builds the token client as main does, and the admin API and
// public settings clients as main and the routes do, from a configuration whose internal URL is
// https, records them as main does, and calls each.
func TestInternalBaseURL_HTTPS_TrustsWhatTheSystemRootsTrust(t *testing.T) {
	if os.Getenv(httpsChildMarker) != "1" {
		t.Skip("the child half of TestInternalBaseURL_HTTPS_ReachesATrustedAuthServerAndRefusesAnUntrustedOne")
	}

	call := func(internalURL string) []error {
		cfg := &config.Config{
			AdminConsole: config.AdminConsoleConfig{OAuthClientSecret: "the-secret"},
			AuthServer: config.AuthServerConfig{
				BaseURL:         "https://auth.example.test",
				InternalBaseURL: internalURL,
			},
		}
		upstream := upstreammetrics.Register(metrics.NewRegistry())
		authBase := cfg.AuthServer.GetEffectiveBaseURL()

		_, tokenErr := newTokenClient(cfg, oauthclient.NewAuthServerHTTPClient(), upstream).ClientCredentials(context.Background(), "authserver:manage")
		_, settingsErr := publicsettings.NewClient(authBase, upstream).GetPublicSettings(context.Background())
		_, adminErr := apiclient.NewAuthServerClient(authBase, upstream).GetSettingsGeneral(context.Background(), "an-access-token")
		return []error{tokenErr, settingsErr, adminErr}
	}

	for i, err := range call(os.Getenv(httpsTrustedURL)) {
		assert.NoError(t, err, "call %d to the trusted auth server", i)
	}
	for i, err := range call(os.Getenv(httpsUntrustedURL)) {
		var unknownAuthority x509.UnknownAuthorityError
		assert.True(t, errors.As(err, &unknownAuthority), "call %d to the untrusted auth server answered %v, want its certificate refused", i, err)
	}
}

// newTLSAuthServer serves the three answers the child's calls expect over TLS with leaf, counting
// every request that reaches it.
func newTLSAuthServer(t *testing.T, leaf tls.Certificate, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/token":
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`))
		case "/api/public/settings":
			_, _ = w.Write([]byte(`{"appName":"Goiabada","uiTheme":"","smtpEnabled":false,"issuer":"https://auth.example.test"}`))
		case "/api/v1/admin/settings/general":
			_, _ = w.Write([]byte(`{"appName":"Goiabada","issuer":"https://auth.example.test"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	// The refused handshakes are the point of the test; the server's log of them is noise.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	if !strings.HasPrefix(server.URL, "https://127.0.0.1:") {
		t.Fatalf("the test auth server is at %s, which the leaf does not name", server.URL)
	}
	return server
}

// newTestCA is a self-signed CA certificate and its key.
func newTestCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// newTestLeaf is a server certificate for 127.0.0.1 that ca signs.
func newTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "goiabada-authserver"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

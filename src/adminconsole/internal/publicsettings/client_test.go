package publicsettings

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/boundedread"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The client is the admin console's second caller of the auth server, so the same two rules that
// hold apiclient's executor reach it: the body is bounded on both arms, and the request carries the
// caller's context. These cases moved here from apiclient with the client in #441.

// publicSettingsBodyOf returns a valid PublicSettingsResponse whose encoding is exactly size bytes,
// by padding the one field the case reads.
func publicSettingsBodyOf(t *testing.T, size int) string {
	t.Helper()

	const envelope = `{"appName":""}`
	require.Greater(t, size, len(envelope), "the body cannot be shorter than its own envelope")

	return `{"appName":"` + strings.Repeat("a", size-len(envelope)) + `"}`
}

func serveBody(t *testing.T, body string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return server
}

func TestClient_ABodyExactlyAtTheCeilingIsAccepted(t *testing.T) {
	body := publicSettingsBodyOf(t, 1<<20)
	require.Len(t, body, 1<<20)

	settings, err := NewClient(serveBody(t, body).URL, nil).GetPublicSettings(context.Background())
	require.NoError(t, err, "the ceiling is inclusive: a body of exactly 1 MiB is answered")
	assert.Len(t, settings.AppName, 1<<20-len(`{"appName":""}`))
}

func TestClient_RefusesAnOversizedAnswerRatherThanDecodingAPrefix(t *testing.T) {
	// Deliberately not an appName: a decoder over the body would stop at the first complete value
	// and accept this truncated-looking document with the issuer missing, which is the shape
	// #386 decision 4 calls unsound.
	settings, err := NewClient(serveBody(t, publicSettingsBodyOf(t, 1<<20+1)).URL, nil).
		GetPublicSettings(context.Background())
	require.Error(t, err)
	assert.Nil(t, settings)
	assert.True(t, errors.Is(err, boundedread.ErrResponseTooLarge), "got %v", err)
}

func TestClient_CarriesTheCallersContext(t *testing.T) {
	released := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-released
	}))
	t.Cleanup(func() {
		close(released)
		server.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewClient(server.URL, nil).GetPublicSettings(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
}

// The deadline is read off the client rather than waited out, as apiclient's executor test does:
// waiting out ten seconds proves a contract net/http already holds, at a cost on every run. It is
// the only bound on the cache's shared fetch, which no caller's cancellation ends.
func TestNewClient_CarriesADeadline(t *testing.T) {
	client := NewClient("http://auth.example.com", nil)

	assert.Equal(t, 10*time.Second, client.httpClient.Timeout,
		"the value every client on the console's page-load path carries (#386 decision 6)")
}

func TestClient_ReadsTheSettingsItIsGiven(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/public/settings", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"appName":"Goiabada","issuer":"https://auth.example.com","uiTheme":"dark"}`))
	}))
	t.Cleanup(server.Close)

	settings, err := NewClient(server.URL, nil).GetPublicSettings(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "Goiabada", settings.AppName)
	assert.Equal(t, "https://auth.example.com", settings.Issuer)
	assert.Equal(t, "dark", settings.UITheme)
}

// The failure arm keeps the status and whatever the auth server said, which is what the middleware
// logs when the console cannot start a page.
func TestClient_ANonOKAnswerNamesItsStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("the settings row is missing"))
	}))
	t.Cleanup(server.Close)

	_, err := NewClient(server.URL, nil).GetPublicSettings(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
	assert.Contains(t, err.Error(), "the settings row is missing")
}

package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 3 for the executor itself (#386).
//
// The 106 wire rows next door own what each method says about itself. This file owns what the
// executor does with it: the ceiling, the deadline, the cancellation and the decode. Every case
// drives a real method rather than the unexported executor, so what is asserted is what a handler
// would see.

// settingsGeneralBodyOf returns a valid SettingsGeneralResponse whose encoding is exactly size
// bytes, by padding the one field the case reads.
func settingsGeneralBodyOf(t *testing.T, size int) string {
	t.Helper()

	const envelope = `{"appName":""}`
	require.Greater(t, size, len(envelope), "the body cannot be shorter than its own envelope")

	return `{"appName":"` + strings.Repeat("a", size-len(envelope)) + `"}`
}

func TestExecutor_ABodyExactlyAtTheCeilingIsAccepted(t *testing.T) {
	body := settingsGeneralBodyOf(t, maxAPIResponseBytes)
	require.Len(t, body, maxAPIResponseBytes)

	client, _ := charServer(t, http.StatusOK, body)

	got, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.NoError(t, err, "the ceiling is inclusive: a body of exactly that many bytes is answered")
	assert.Len(t, got.AppName, maxAPIResponseBytes-len(`{"appName":""}`))
}

// Decision 4: the answer is refused rather than cut, so the overrun is its own classified failure
// and no prefix reaches a decoder. One byte is the whole difference, which is why the case above
// exists beside this one.
func TestExecutor_ABodyOneByteOverTheCeilingIsRefusedAndNeverDecoded(t *testing.T) {
	body := settingsGeneralBodyOf(t, maxAPIResponseBytes+1)
	require.Len(t, body, maxAPIResponseBytes+1)

	client, _ := charServer(t, http.StatusOK, body)

	got, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.Error(t, err)
	assert.Nil(t, got, "nothing decoded out of an oversized answer")
	assert.True(t, errors.Is(err, boundedread.ErrResponseTooLarge),
		"an overrun is its own failure, not a parse failure: got %v", err)
}

// The oversized answer must not arrive looking like the auth server's own refusal, because the
// console routes on *APIError and would otherwise show the administrator a status the auth server
// never sent.
func TestExecutor_AnOversizedAnswerIsNotAnAPIError(t *testing.T) {
	client, _ := charServer(t, http.StatusOK, settingsGeneralBodyOf(t, maxAPIResponseBytes+1))

	_, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.Error(t, err)

	var apiErr *APIError
	assert.False(t, errors.As(err, &apiErr), "it falls through to the console's generic 500")
}

// An oversized *failure* body is refused on the same terms: parseAPIError never sees a prefix
// either, so a 500 with a megabyte of text behind it cannot become a plausible-looking error.
func TestExecutor_AnOversizedFailureBodyIsRefusedBeforeClassification(t *testing.T) {
	client, _ := charServer(t, http.StatusInternalServerError,
		settingsGeneralBodyOf(t, maxAPIResponseBytes+1))

	_, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.Error(t, err)
	assert.True(t, errors.Is(err, boundedread.ErrResponseTooLarge))
}

func TestExecutor_MalformedJSONOnASuccessStatusIsADecodeFailure(t *testing.T) {
	client, _ := charServer(t, http.StatusOK, `{"appName":`)

	got, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.Error(t, err)
	assert.Nil(t, got)

	var apiErr *APIError
	assert.False(t, errors.As(err, &apiErr), "a 200 that will not parse is not the auth server's refusal")
	assert.False(t, errors.Is(err, boundedread.ErrResponseTooLarge))
}

// The request's cancellation reaches the transport. This is the whole point of carrying a context
// down from the handler: an administrator who navigates away must not leave a goroutine waiting on
// an auth server that has stopped answering.
func TestExecutor_ACancelledRequestContextStopsTheCall(t *testing.T) {
	released := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-released
	}))
	t.Cleanup(func() {
		close(released)
		server.Close()
	})

	client := NewAuthServerClient(server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetSettingsGeneral(ctx, charAccessToken)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
}

func TestExecutor_ARequestDeadlineStopsACallTheAuthServerNeverAnswers(t *testing.T) {
	released := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-released
	}))
	t.Cleanup(func() {
		close(released)
		server.Close()
	})

	client := NewAuthServerClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := client.GetSettingsGeneral(ctx, charAccessToken)
	require.Error(t, err)

	assert.True(t, errors.Is(err, context.DeadlineExceeded), "got %v", err)
	assert.Less(t, time.Since(started), 5*time.Second, "the call returned on its deadline")
}

// client/no-timeout closed. The general client was a bare &http.Client{}, with no deadline of any
// kind, so a request the auth server accepted and then stopped answering held an admin console
// handler goroutine for as long as the connection stayed open.
//
// The deadline is read off the client rather than waited out: the case above already shows that a
// deadline of this kind cuts a request the server never answers, and proving the same thing again
// at the real value would cost the suite ten seconds of sleeping on every run, forever, to observe
// a contract net/http already holds.
func TestNewAuthServerClient_CarriesADeadline(t *testing.T) {
	client := NewAuthServerClient("http://auth.example.com")

	assert.Equal(t, generalAPITimeout, client.httpClient.Timeout,
		"every request this client makes is bounded")
	assert.Equal(t, 10*time.Second, generalAPITimeout,
		"decision 6's value, matching the three request-path clients already in the tree")
}

// SettingsClient is the admin console's second caller of the auth server, so the same two rules
// reach it: the body is bounded on both arms, and the request carries the caller's context.
func TestSettingsClient_RefusesAnOversizedAnswerRatherThanDecodingAPrefix(t *testing.T) {
	// Deliberately not an appName: a decoder over the body would stop at the first complete value
	// and accept this truncated-looking document with the issuer missing, which is the shape
	// decision 4 calls unsound.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(settingsGeneralBodyOf(t, maxAPIResponseBytes+1)))
	}))
	t.Cleanup(server.Close)

	settings, err := NewSettingsClient(server.URL).GetPublicSettings(context.Background())
	require.Error(t, err)
	assert.Nil(t, settings)
	assert.True(t, errors.Is(err, boundedread.ErrResponseTooLarge), "got %v", err)
}

func TestSettingsClient_CarriesTheCallersContext(t *testing.T) {
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

	_, err := NewSettingsClient(server.URL).GetPublicSettings(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
}

func TestSettingsClient_ReadsTheSettingsItIsGiven(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/public/settings", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"appName":"Goiabada","issuer":"https://auth.example.com","uiTheme":"dark"}`))
	}))
	t.Cleanup(server.Close)

	settings, err := NewSettingsClient(server.URL).GetPublicSettings(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "Goiabada", settings.AppName)
	assert.Equal(t, "https://auth.example.com", settings.Issuer)
	assert.Equal(t, "dark", settings.UITheme)
}

// The failure arm keeps the status and whatever the auth server said, which is what the middleware
// logs when the console cannot start a page.
func TestSettingsClient_ANonOKAnswerNamesItsStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("the settings row is missing"))
	}))
	t.Cleanup(server.Close)

	_, err := NewSettingsClient(server.URL).GetPublicSettings(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
	assert.Contains(t, err.Error(), "the settings row is missing")
}

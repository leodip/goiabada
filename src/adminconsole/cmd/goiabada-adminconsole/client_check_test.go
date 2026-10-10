package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin console's start-up check of its own client (#542): it asks the auth server for the
// token every page needs before it listens, stops on a refusal, and waits for an auth server that
// is not answering yet.

// scriptedTokens answers Token with each error of script in turn, then with a token.
type scriptedTokens struct {
	script []error
	calls  int
}

func (s *scriptedTokens) Token(context.Context) (string, error) {
	s.calls++
	if s.calls <= len(s.script) {
		return "", s.script[s.calls-1]
	}
	return "a-token", nil
}

func refusal(status int, code string) error {
	return errs.WithStack(&oauthclient.TokenEndpointError{StatusCode: status, ErrorCode: code})
}

// recordDelays is a retryDelay that waits nothing and keeps the attempts it was asked about.
func recordDelays(attempts *[]int) func(int) time.Duration {
	return func(attempt int) time.Duration {
		*attempts = append(*attempts, attempt)
		return 0
	}
}

func TestAwaitAuthServerAcceptsClient_WaitsForAnAuthServerNotAnsweringYet(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	tokens := &scriptedTokens{script: []error{
		errs.New("dial tcp 10.0.0.7:9090: connect: connection refused"),
		refusal(http.StatusServiceUnavailable, ""),
		refusal(http.StatusBadGateway, ""),
		refusal(http.StatusInternalServerError, "server_error"),
		refusal(http.StatusTooManyRequests, ""),
		refusal(http.StatusRequestTimeout, ""),
		errs.New("error parsing response: invalid character '<' looking for beginning of value"),
	}}
	var attempts []int

	err := awaitAuthServerAcceptsClient(context.Background(), tokens, recordDelays(&attempts))

	require.NoError(t, err)
	assert.Equal(t, 8, tokens.calls, "asked again after each of the seven, and the eighth was issued")
	assert.Equal(t, []int{1, 2, 3, 4, 5, 6, 7}, attempts)

	records := logs.Records()
	require.Len(t, records, 7, "one record per attempt that did not get a token")
	for i, record := range records {
		assert.Equal(t, slog.LevelInfo, record.Level, "waiting for a dependency at start is lifecycle, not a fault")
		assert.Equal(t, "waiting for the auth server to issue the admin console's token", record.Message)
		assert.EqualValues(t, i+1, record.Attrs["attempt"])
		assert.Equal(t, tokens.script[i], record.Attrs["error"], "the record says what the attempt met")
	}
}

func TestAwaitAuthServerAcceptsClient_StopsAtARefusal(t *testing.T) {
	for name, refused := range map[string]error{
		"a secret the database does not hold": refusal(http.StatusUnauthorized, "invalid_client"),
		"client credentials switched off":     refusal(http.StatusBadRequest, "unauthorized_client"),
		"the session permission taken away":   refusal(http.StatusBadRequest, "invalid_scope"),
		"an address answering for another":    refusal(http.StatusNotFound, ""),
		"a proxy refusing it":                 refusal(http.StatusForbidden, ""),
	} {
		t.Run(name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			tokens := &scriptedTokens{script: []error{refusal(http.StatusServiceUnavailable, ""), refused}}
			var attempts []int

			err := awaitAuthServerAcceptsClient(context.Background(), tokens, recordDelays(&attempts))

			require.ErrorIs(t, err, refused, "the refusal itself, which logClientRefused reads")
			assert.Equal(t, 2, tokens.calls, "asking again changes nothing, so it does not ask again")
			assert.Len(t, logs.Records(), 1, "the one wait before the refusal, and nothing for the refusal: main writes that")
		})
	}
}

func TestAwaitAuthServerAcceptsClient_EndsTheWaitWhenTheProcessIsStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tokens := &scriptedTokens{script: []error{errs.New("connection refused"), errs.New("connection refused")}}
	waiting := make(chan struct{})
	retryDelay := func(int) time.Duration {
		close(waiting)
		return time.Hour
	}

	done := make(chan error, 1)
	go func() { done <- awaitAuthServerAcceptsClient(ctx, tokens, retryDelay) }()
	<-waiting
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, tokens.calls)
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled context did not end the wait")
	}
}

// The check runs the session store's token source over the real token client, so a refusal
// arrives in the shape both of them give it, and the token it obtains is the one the first page
// uses: a second Token sends nothing.
func TestAwaitAuthServerAcceptsClient_OverTheRealTokenClient(t *testing.T) {
	t.Run("issued, and cached for the first page", func(t *testing.T) {
		var requests atomic.Int32
		authServer := tokenEndpoint(t, &requests, http.StatusServiceUnavailable, http.StatusOK)
		source := oauthclient.NewSessionTokenSource(tokenClientFor(authServer.URL))
		var attempts []int

		require.NoError(t, awaitAuthServerAcceptsClient(context.Background(), source, recordDelays(&attempts)))
		require.Equal(t, int32(2), requests.Load())

		token, err := source.Token(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "a-session-token", token)
		assert.Equal(t, int32(2), requests.Load(), "the first page asks nothing more of the auth server")
	})

	t.Run("refused", func(t *testing.T) {
		var requests atomic.Int32
		authServer := tokenEndpoint(t, &requests, http.StatusBadGateway, http.StatusUnauthorized)
		var attempts []int

		err := awaitAuthServerAcceptsClient(context.Background(),
			oauthclient.NewSessionTokenSource(tokenClientFor(authServer.URL)), recordDelays(&attempts))

		var refused *oauthclient.TokenEndpointError
		require.ErrorAs(t, err, &refused)
		assert.Equal(t, "invalid_client", refused.ErrorCode)
		assert.Equal(t, int32(2), requests.Load())
	})
}

// tokenEndpoint answers the token endpoint with each status of statuses in turn, the last one for
// every request after: 200 with a token, 401 with invalid_client, anything else with no body.
func tokenEndpoint(t *testing.T, requests *atomic.Int32, statuses ...int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(requests.Add(1))
		status := statuses[min(n, len(statuses))-1]
		w.Header().Set("Content-Type", "application/json")
		switch status {
		case http.StatusOK:
			_, _ = w.Write([]byte(`{"access_token":"a-session-token","token_type":"Bearer","expires_in":300}`))
		case http.StatusUnauthorized:
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"Client authentication failed. Please review your client_secret."}`))
		default:
			w.WriteHeader(status)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func tokenClientFor(authServerURL string) *oauthclient.TokenClient {
	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{OAuthClientSecret: "the-secret"},
		AuthServer:   config.AuthServerConfig{BaseURL: authServerURL},
	}
	return newTokenClient(cfg, oauthclient.NewAuthServerHTTPClient(), upstreammetrics.Register(metrics.NewRegistry()))
}

func TestAuthServerRetryDelay_DoublesFromOneSecondToTen(t *testing.T) {
	var delays []time.Duration
	for attempt := 1; attempt <= 7; attempt++ {
		delays = append(delays, authServerRetryDelay(attempt))
	}
	assert.Equal(t, []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		10 * time.Second, 10 * time.Second, 10 * time.Second,
	}, delays)
	assert.Equal(t, 10*time.Second, authServerRetryDelay(1000), "no shift overflows into a short or negative wait")
}

// The refusal a deployment's own secrets cause has a record of its own naming the variable to fix
// and where its value comes from; the others carry the error, which names what is wrong.
func TestLogClientRefused_NamesTheSecretWhenTheAuthServerRefusesIt(t *testing.T) {
	t.Run("invalid_client", func(t *testing.T) {
		logs := logtest.CaptureSlog(t)
		refused := refusal(http.StatusUnauthorized, "invalid_client")

		logClientRefused(refused)

		records := logs.Records()
		require.Len(t, records, 1)
		assert.Equal(t, slog.LevelError, records[0].Level, "the console does not start, and somebody has to act")
		assert.Equal(t, "the auth server does not accept the admin console's client secret, so the admin console cannot start", records[0].Message)
		assert.Equal(t, refused, records[0].Attrs["error"])
		assert.Contains(t, records[0].Attrs["remedy"], "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET")
		assert.Contains(t, records[0].Attrs["remedy"], "backup")
	})

	t.Run("another refusal", func(t *testing.T) {
		logs := logtest.CaptureSlog(t)
		refused := refusal(http.StatusBadRequest, "invalid_scope")

		logClientRefused(refused)

		records := logs.Records()
		require.Len(t, records, 1)
		assert.Equal(t, slog.LevelError, records[0].Level)
		assert.Equal(t, "the auth server refused the admin console's token request, so the admin console cannot start", records[0].Message)
		assert.Equal(t, refused, records[0].Attrs["error"])
		assert.NotContains(t, records[0].Attrs, "remedy", "the secret is not what this refusal is about")
	})

	t.Run("a refusal wrapped on its way up", func(t *testing.T) {
		logs := logtest.CaptureSlog(t)

		logClientRefused(errs.Wrap(refusal(http.StatusUnauthorized, "invalid_client"), "the token request"))

		require.Len(t, logs.Records(), 1)
		assert.Contains(t, logs.Records()[0].Message, "client secret", "matched with errors.As, not by type assertion")
	})
}

// refusedForGood reads the status the token client parsed, whatever wraps it.
func TestRefusedForGood(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{refusal(http.StatusUnauthorized, "invalid_client"), true},
		{refusal(http.StatusBadRequest, "invalid_scope"), true},
		{refusal(http.StatusNotFound, ""), true},
		{errs.Wrap(refusal(http.StatusForbidden, ""), "wrapped"), true},
		{refusal(http.StatusTooManyRequests, ""), false},
		{refusal(http.StatusRequestTimeout, ""), false},
		{refusal(http.StatusServiceUnavailable, ""), false},
		{refusal(http.StatusGatewayTimeout, ""), false},
		{errs.New("connection refused"), false},
		{errors.New("an error from outside this tree"), false},
	} {
		assert.Equal(t, tc.want, refusedForGood(tc.err), "%v", tc.err)
	}
}

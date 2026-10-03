package oauthclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// The bounds, goal 9 of #338.
//
// Two facts are under test here and neither is observable through the
// httptest.Server seam token_client_test.go uses: how much of the peer's answer
// is read, and what context the request carries -- its deadline, its
// cancellation and its values. A RoundTripper is the seam that shows both, and it
// needs no socket, so an oversized body costs a counter rather than a megabyte on
// the wire.
// =============================================================================

// countingBody serves a fixed body and records how much of it was actually read.
// The body is deliberately larger than the cap but finite: an unbounded read
// consumes all of it and succeeds, while the bound stops one byte past the cap
// and refuses the answer. Endless would prove the same thing by hanging, which
// is not a failure anyone can read.
type countingBody struct {
	remaining []byte
	read      atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	if len(b.remaining) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.remaining)
	b.remaining = b.remaining[n:]
	b.read.Add(int64(n))
	return n, nil
}

func (b *countingBody) Close() error { return nil }

// oversizedTokenResponse is a valid token response whose scope claim pads it
// past the cap. Valid matters: it is what makes an unbounded read succeed, so
// the case below fails on both the count and the outcome when the cap goes.
func oversizedTokenResponse() *countingBody {
	prefix := `{"access_token":"at","scope":"`
	suffix := `"}`
	padding := MaxTokenResponseBytes + 1024 - len(prefix) - len(suffix)
	return &countingBody{remaining: []byte(prefix + strings.Repeat("x", padding) + suffix)}
}

// roundTripperFunc adapts a function to http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func clientReturning(status int, body io.ReadCloser) *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       body,
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}
}

// testTokenURL is where the RoundTripper cases post. Nothing listens there: the
// transport answers before any socket would be opened.
const testTokenURL = "https://authserver.example/auth/token"

// -----------------------------------------------------------------------------
// The read bound
// -----------------------------------------------------------------------------

// Two assertions, and the pair is the point. With the cap removed this body is
// read whole and parses cleanly, so the call succeeds and the count runs past
// MaxTokenResponseBytes; both flip together. The refresh grant's read was a
// bounded read of its own inside the middleware until #441, and is this one now.
func TestTokenClient_RefusesAnAnswerOverTheCap(t *testing.T) {
	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			body := oversizedTokenResponse()

			tokenResponse, err := g.send(context.Background(),
				NewTokenClient(testTokenURL, "ci", "cs", clientReturning(http.StatusOK, body)))

			require.Error(t, err)
			assert.True(t, errors.Is(err, boundedread.ErrResponseTooLarge),
				"the answer is refused as oversized rather than reaching the decoder truncated: %v", err)
			assert.Nil(t, tokenResponse, "nothing is decoded out of an answer that was refused")

			assert.Equal(t, int64(MaxTokenResponseBytes)+1, body.read.Load(),
				"one byte past the cap is read, which is what makes the overrun detectable, and no more")
		})
	}
}

// The answer exactly at the cap is accepted, so the case above is the overrun and
// not the size. The case below it pads to half the cap, which leaves the boundary
// itself untested without this.
func TestTokenClient_AcceptsABodyOfExactlyTheCap(t *testing.T) {
	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			prefix := `{"access_token":"at","scope":"`
			suffix := `"}`
			padding := MaxTokenResponseBytes - len(prefix) - len(suffix)
			body := io.NopCloser(strings.NewReader(prefix + strings.Repeat("x", padding) + suffix))

			tokenResponse, err := g.send(context.Background(),
				NewTokenClient(testTokenURL, "ci", "cs", clientReturning(http.StatusOK, body)))

			require.NoError(t, err)
			require.NotNil(t, tokenResponse)
			assert.Equal(t, "at", tokenResponse.AccessToken)
			assert.Len(t, tokenResponse.Scope, padding)
		})
	}
}

// The benign member of the class: an answer under the cap is unaffected, so the
// case above cannot be read as "large answers are refused".
func TestTokenClient_AcceptsABodyUnderTheCap(t *testing.T) {
	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			// Well over any realistic token response and still short of the cap: the
			// padding rides in the scope claim, which is a string of unbounded length.
			padding := strings.Repeat("x", MaxTokenResponseBytes/2)
			body := io.NopCloser(strings.NewReader(`{"access_token":"at","scope":"` + padding + `"}`))

			tokenResponse, err := g.send(context.Background(),
				NewTokenClient(testTokenURL, "ci", "cs", clientReturning(http.StatusOK, body)))

			require.NoError(t, err)
			require.NotNil(t, tokenResponse)
			assert.Equal(t, "at", tokenResponse.AccessToken)
			assert.Len(t, tokenResponse.Scope, len(padding))
		})
	}
}

// -----------------------------------------------------------------------------
// The detachment and the deadline
// -----------------------------------------------------------------------------

// outboundContext records what the context of the one outbound request looked like
// while it was in flight, then fails the call. It records the facts rather than the
// context, because the client cancels its own timeout context on return, which is
// correct and means the context is done by the time the assertions run.
type outboundContext struct {
	called    atomic.Bool
	ctxErr    error
	deadline  time.Time
	hasLimit  bool
	requestID string
}

func (o *outboundContext) client() *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		o.called.Store(true)
		o.ctxErr = r.Context().Err()
		o.deadline, o.hasLimit = r.Context().Deadline()
		o.requestID = chimiddleware.GetReqID(r.Context())
		return nil, errs.New("the transport stops here")
	})}
}

// Both grants are single use. The code is burned by the time the auth server answers,
// and the refresh token is revoked as part of issuing its replacement, so a browser
// that goes away mid-call must not take the call with it: it would be abandoned with
// the grant spent and the answer unread, and for the refresh the administrator would
// be left holding a revoked token and signed out on their next page load. The client
// owns that rule, so no caller can forget it (#338, #441 decision 2).
//
// The caller's context here is already cancelled, which is exactly that. What reaches
// the request has to be live anyway, bounded by TokenExchangeTimeout, which is what
// replaces the cancellation, and still carrying the caller's values: chi's RequestID
// puts the id on every inbound request and the installed slog handler lifts it off the
// context onto every record, so context.Background() would silence this grant in the
// operator's log. Passing ctx straight through is the one-token change this case
// exists to catch.
func TestTokenClient_TheSingleUseGrantsSurviveACancelledCallerAndKeepItsRequestId(t *testing.T) {
	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			const wantRequestID = "the-inbound-request-id"
			ctx, cancel := context.WithCancel(
				context.WithValue(context.Background(), chimiddleware.RequestIDKey, wantRequestID))
			cancel()

			outbound := &outboundContext{}
			tokenResponse, err := g.send(ctx, NewTokenClient(testTokenURL, "ci", "cs", outbound.client()))

			require.Error(t, err)
			assert.Nil(t, tokenResponse)
			require.True(t, outbound.called.Load(), "the request was sent, cancelled caller or not")
			assert.NoError(t, outbound.ctxErr,
				"the request runs on a context detached from the caller's, which is already cancelled")

			require.True(t, outbound.hasLimit, "detached, but not unbounded")
			assert.LessOrEqual(t, time.Until(outbound.deadline), TokenExchangeTimeout,
				"bounded by TokenExchangeTimeout, which is what replaces the cancellation")
			// The tolerance is what the client spends between taking the deadline and the
			// transport reading it, which is microseconds; a second is generous for a loaded
			// machine and still refuses any value that is not the ten seconds chosen in #338.
			assert.Greater(t, time.Until(outbound.deadline), TokenExchangeTimeout-time.Second,
				"and by that value rather than by something shorter")

			assert.Equal(t, wantRequestID, outbound.requestID,
				"the detached request keeps the caller's values, so request_id still reaches its records")
		})
	}
}

// -----------------------------------------------------------------------------
// The record
// -----------------------------------------------------------------------------

// One Debug record on every administrator sign-in, naming where the code is
// exchanged: per-request tracing, which #320 keeps out of Info, and the one reader
// who needs it is debugging the exchange against an address they suspect. The URL
// is an attribute rather than concatenated into the message, so a query can find it.
// The request id is not named here or in the client; it reaches the record because
// it rode on the context and the installed handler read it off there.
func TestExchangeCode_TheExchangeIsDebugAndCarriesTheTokenUrlAndTheRequestId(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	ctx := context.WithValue(context.Background(), chimiddleware.RequestIDKey, "req-admin-callback")

	_, err := NewTokenClient("https://authserver.internal.example/auth/token", "ci", "cs",
		clientReturning(http.StatusOK, io.NopCloser(strings.NewReader(`{}`)))).
		ExchangeCode(ctx, "c", "r", "cv")
	require.NoError(t, err)

	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelDebug, records[0].Level)
	assert.Equal(t, "exchanging the code for tokens", records[0].Message)
	assert.Equal(t, "https://authserver.internal.example/auth/token", records[0].Attrs["token_url"])
	assert.Equal(t, "req-admin-callback", records[0].Attrs["request_id"])
}

// A refresh writes no record of its own. It runs whenever a signed-in administrator's
// access token is due, and the middleware records each way one can fail; a successful
// refresh has never been logged, and moving it into the client did not start (#441).
func TestRefresh_WritesNoRecord(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	_, err := NewTokenClient(testTokenURL, "ci", "cs",
		clientReturning(http.StatusOK, io.NopCloser(strings.NewReader(`{}`)))).
		Refresh(context.Background(), "rt")
	require.NoError(t, err)

	assert.Empty(t, logs.Records())
}

// -----------------------------------------------------------------------------
// The HTTP client
// -----------------------------------------------------------------------------

// The JWKS fetch is the reason the shared client's timeout is worth a case of its
// own. The token grants build their own deadline, so the client's timeout is
// redundant defence for them; the JWKS fetch keeps the browser's context on purpose,
// being an idempotent read, and a browser context carries no deadline at all. This
// client's timeout is therefore the only thing standing between a peer that accepts
// the connection and never answers and a handler held open for as long as the
// browser waits (#338).
func TestNewAuthServerHTTPClient_CarriesTheConfiguredTimeout(t *testing.T) {
	client := NewAuthServerHTTPClient()

	require.NotNil(t, client)
	assert.Equal(t, TokenExchangeTimeout, client.Timeout,
		"the one client this process uses against the auth server is bounded")
}

// routes.go builds one client for every call, so the nil arm is not what
// production takes. It is here because a nil client used to mean an unbounded
// one, and this is the whole of what stops that being true again.
func TestNewTokenClient_DefaultsANilClientToTheConfiguredTimeout(t *testing.T) {
	assert.Equal(t, TokenExchangeTimeout, NewTokenClient(testTokenURL, "ci", "cs", nil).httpClient.Timeout,
		"a nil client gets the deadline rather than no deadline")

	injected := &http.Client{Timeout: 3 * time.Second}
	assert.Same(t, injected, NewTokenClient(testTokenURL, "ci", "cs", injected).httpClient,
		"an injected client is used as given, so the composition root sets the deadline")
}

package oauthclient

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// The bounds, goal 9 of #338.
//
// Two facts are under test here and neither is observable through the
// httptest.Server seam token_exchanger_test.go uses: how much of the peer's
// answer is read, and whether the caller's deadline reaches the request. A
// RoundTripper is the seam that shows both, and it needs no socket, so an
// oversized body costs a counter rather than a megabyte on the wire.
// =============================================================================

// countingBody serves a fixed body and records how much of it was actually read.
// The body is deliberately larger than the cap but finite: an unbounded read
// consumes all of it and succeeds, a bounded one stops at the cap and hands the
// decoder a truncated object. Endless would prove the same thing by hanging,
// which is not a failure anyone can read.
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

// -----------------------------------------------------------------------------
// The read bound
// -----------------------------------------------------------------------------

// Two assertions, and the pair is the point. With the cap removed this body is
// read whole and parses cleanly, so the call succeeds and the count runs past
// MaxTokenResponseBytes; both flip together.
func TestExchangeCodeForTokens_ReadsAtMostTheCap(t *testing.T) {
	body := oversizedTokenResponse()

	tokenResponse, err := NewTokenExchanger(clientReturning(http.StatusOK, body)).
		ExchangeCodeForTokens(context.Background(), "c", "r", "ci", "cs", "cv",
			"https://authserver.example/auth/token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing response",
		"the answer reaches the decoder truncated rather than being refused outright")
	assert.Nil(t, tokenResponse)

	assert.Equal(t, int64(MaxTokenResponseBytes), body.read.Load(),
		"exactly the cap is read from a peer answering with more than it")
}

// The benign member of the class: an answer under the cap is unaffected, so the
// case above cannot be read as "large answers are refused".
func TestExchangeCodeForTokens_AcceptsABodyUnderTheCap(t *testing.T) {
	// Well over any realistic token response and still short of the cap: the
	// padding rides in the scope claim, which is a string of unbounded length.
	padding := strings.Repeat("x", MaxTokenResponseBytes/2)
	body := io.NopCloser(strings.NewReader(`{"access_token":"at","scope":"` + padding + `"}`))

	tokenResponse, err := NewTokenExchanger(clientReturning(http.StatusOK, body)).
		ExchangeCodeForTokens(context.Background(), "c", "r", "ci", "cs", "cv",
			"https://authserver.example/auth/token")

	require.NoError(t, err)
	require.NotNil(t, tokenResponse)
	assert.Equal(t, "at", tokenResponse.AccessToken)
	assert.Len(t, tokenResponse.Scope, len(padding))
}

// -----------------------------------------------------------------------------
// The deadline
// -----------------------------------------------------------------------------

// What this pins is that the caller's context reaches the request at all, which
// is what makes the ten second deadline handler_auth_callback.go builds mean
// anything. The deadline it drives with is the test's own, so the case costs
// milliseconds rather than TokenExchangeTimeout.
func TestExchangeCodeForTokens_CarriesTheCallersDeadline(t *testing.T) {
	var sawDeadline atomic.Bool

	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if _, ok := r.Context().Deadline(); ok {
			sawDeadline.Store(true)
		}
		// A peer that accepted the connection and never answers. Before the
		// context reached the request this blocked forever; now it ends when
		// the deadline does.
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	tokenResponse, err := NewTokenExchanger(client).
		ExchangeCodeForTokens(ctx, "c", "r", "ci", "cs", "cv",
			"https://authserver.example/auth/token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error sending request")
	assert.Nil(t, tokenResponse)
	assert.True(t, sawDeadline.Load(), "the outbound request carries the caller's deadline")
}

// -----------------------------------------------------------------------------
// The injected client
// -----------------------------------------------------------------------------

// routes.go builds one client for all three calls, so the nil arm is not what
// production takes. It is here because a nil client used to mean an unbounded
// one, and this is the whole of what stops that being true again.
func TestNewTokenExchanger_DefaultsANilClientToTheConfiguredTimeout(t *testing.T) {
	assert.Equal(t, TokenExchangeTimeout, NewTokenExchanger(nil).httpClient.Timeout,
		"a nil client gets the deadline rather than no deadline")

	injected := &http.Client{Timeout: 3 * time.Second}
	assert.Same(t, injected, NewTokenExchanger(injected).httpClient,
		"an injected client is used as given, so the composition root sets the deadline")
}

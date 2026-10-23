package requestid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The request ids both servers carry, made as chi's RequestID middleware made them (#462 decision
// 6): an incoming X-Request-Id adopted verbatim, otherwise <hostname>/<10 base62>-<6-digit
// counter>, and never written to the response.

// idOf sends one request through the middleware and answers the id the handler saw and the
// response's headers.
func idOf(t *testing.T, header string) (string, http.Header) {
	t.Helper()

	var seen string
	handler := Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = FromContext(r.Context())
	}))
	request := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	if header != "" {
		request.Header.Set("X-Request-Id", header)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return seen, recorder.Header()
}

func TestMiddleware_AnIncomingIdIsAdoptedVerbatim(t *testing.T) {
	for _, incoming := range []string{
		"req-from-the-edge",
		"a proxy's id, with spaces/slashes and ✓",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-past-128",
	} {
		seen, headers := idOf(t, incoming)

		assert.Equal(t, incoming, seen)
		assert.Empty(t, headers.Values("X-Request-Id"), "no response header carries the id")
	}
}

// The header is the one chi read, spelled as the docs spell it, and Go's header lookup is
// case-insensitive, so a proxy writing it in lower case is adopted too.
func TestMiddleware_TheHeaderIsXRequestId(t *testing.T) {
	assert.Equal(t, "X-Request-Id", Header)

	var seen string
	handler := Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = FromContext(r.Context())
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("x-request-id", "lower")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	assert.Equal(t, "lower", seen)
}

func TestMiddleware_WithoutAnIncomingIdOneIsMinted(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "localhost"
	}
	shape := regexp.MustCompile(`^` + regexp.QuoteMeta(hostname) + `/([A-Za-z0-9]{10})-([0-9]{6,})$`)

	first, headers := idOf(t, "")
	second, _ := idOf(t, "")

	firstParts := shape.FindStringSubmatch(first)
	require.NotNil(t, firstParts, "minted id %q is not <hostname>/<10 base62>-<6-digit counter>", first)
	secondParts := shape.FindStringSubmatch(second)
	require.NotNil(t, secondParts, "minted id %q is not <hostname>/<10 base62>-<6-digit counter>", second)
	assert.Empty(t, headers.Values("X-Request-Id"), "no response header carries the id")

	// One prefix per process, and a counter that advances by one per id minted.
	assert.Equal(t, firstParts[1], secondParts[1], "the random part is the process's, not the request's")
	firstCount, err := strconv.Atoi(firstParts[2])
	require.NoError(t, err)
	secondCount, err := strconv.Atoi(secondParts[2])
	require.NoError(t, err)
	assert.Equal(t, firstCount+1, secondCount)
}

func TestFromContext_AContextWithNoIdReadsEmpty(t *testing.T) {
	assert.Empty(t, FromContext(context.Background()))
	assert.Equal(t, "planted", FromContext(NewContext(context.Background(), "planted")))
}

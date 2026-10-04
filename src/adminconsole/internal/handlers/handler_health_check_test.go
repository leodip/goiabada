package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/logging/logtest"
)

// healthBodyRefused records the status and headers the handler commits and refuses every body
// write, which is a probe that hung up after the status went out.
type healthBodyRefused struct {
	*httptest.ResponseRecorder
}

var errHealthBodyRefused = errors.New("connection reset by peer")

func (h healthBodyRefused) Write([]byte) (int, error) {
	return 0, errHealthBodyRefused
}

func TestHandleHealthCheckGet(t *testing.T) {
	t.Run("answers 200 healthy, uncached", func(t *testing.T) {
		rr := httptest.NewRecorder()

		HandleHealthCheckGet().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "healthy", rr.Body.String())
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	// The 200 is committed before the body, so a failed write has nothing left to answer, and it
	// answers before the settings middleware, so there would be no settings to render a page with.
	// It is recorded at Debug: per-request tracing, not a fault an operator acts on.
	t.Run("a failed write after the committed 200 is a Debug record", func(t *testing.T) {
		logs := logtest.CaptureSlog(t)
		rr := healthBodyRefused{httptest.NewRecorder()}

		HandleHealthCheckGet().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

		assert.Equal(t, http.StatusOK, rr.Code)

		records := logs.Records()
		require.Len(t, records, 1)
		assert.Equal(t, slog.LevelDebug, records[0].Level)
		assert.Equal(t, "unable to write the health check response", records[0].Message)
		logged, isError := records[0].Attrs["error"].(error)
		require.True(t, isError, "the error attribute must carry the error value itself")
		assert.ErrorIs(t, logged, errHealthBodyRefused)
	})
}

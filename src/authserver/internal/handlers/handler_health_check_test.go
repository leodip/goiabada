package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingBodyRecorder records the status and headers a handler commits and refuses every body
// write, which is a client that hung up after the status went out.
type failingBodyRecorder struct {
	*httptest.ResponseRecorder
}

var errBodyWriteRefused = errors.New("connection reset by peer")

func (f failingBodyRecorder) Write([]byte) (int, error) {
	return 0, errBodyWriteRefused
}

func TestHandleHealthCheckGet(t *testing.T) {
	t.Run("Successful health check", func(t *testing.T) {
		handler := HandleHealthCheckGet()

		req, err := http.NewRequest("GET", "/health", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "healthy", rr.Body.String())
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	// The 200 is committed before the body, so a failed write has nothing left to answer and is
	// recorded at Debug: per-request tracing, not a fault an operator acts on (#435).
	t.Run("A failed write after the committed 200 is a Debug record", func(t *testing.T) {
		logs := logtest.CaptureSlog(t)
		rr := failingBodyRecorder{httptest.NewRecorder()}

		HandleHealthCheckGet().ServeHTTP(rr, httptest.NewRequest("GET", "/health", nil))

		assert.Equal(t, http.StatusOK, rr.Code)

		records := logs.Records()
		require.Len(t, records, 1)
		assert.Equal(t, slog.LevelDebug, records[0].Level)
		assert.Equal(t, "unable to write the health check response", records[0].Message)
		logged, isError := records[0].Attrs["error"].(error)
		require.True(t, isError, "the error attribute must carry the error value itself")
		assert.ErrorIs(t, logged, errBodyWriteRefused)
	})
}

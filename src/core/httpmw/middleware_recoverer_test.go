package httpmw

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/requestid"
)

// A panic beneath Recoverer answers an empty 500, as chi's Recoverer did, and leaves one ERROR
// record through the process's handler carrying the request id, the panic value and the stack,
// where chi wrote a coloured trace to standard error outside the log stream (#462).

// panicsWith is a handler that panics with value, from a function whose name the stack must carry.
func panicsWith(value any) http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		aHandlerThatPanics(value)
	})
}

func aHandlerThatPanics(value any) {
	panic(value)
}

func TestRecoverer_APanicIsAnEmpty500AndOneErrorRecord(t *testing.T) {
	capture := logtest.CaptureSlog(t)

	handler := requestid.Middleware(Recoverer(panicsWith("a handler panicked")))
	request := httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=c", nil)
	request.Header.Set(requestid.Header, "req-panic-1")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Empty(t, recorder.Body.String())
	assert.Empty(t, recorder.Header().Get("Content-Type"))

	require.Len(t, capture.Records(), 1, "one record per panic:\n%s", capture.Text())
	record := capture.Records()[0]
	assert.Equal(t, slog.LevelError, record.Level)
	assert.Equal(t, "req-panic-1", record.Attrs["request_id"])
	assert.Equal(t, "a handler panicked", record.Attrs["panic"])
	assert.Contains(t, record.Attrs["stack"], "aHandlerThatPanics",
		"the stack is the panicking goroutine's, taken before it unwound")
}

// An error value is rendered as the error it is.
func TestRecoverer_APanicWithAnErrorRecordsItsText(t *testing.T) {
	capture := logtest.CaptureSlog(t)

	Recoverer(panicsWith(http.ErrBodyNotAllowed)).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.Len(t, capture.Records(), 1)
	assert.Equal(t, http.ErrBodyNotAllowed.Error(), capture.Records()[0].Attrs["panic"])
}

// http.ErrAbortHandler is how a handler aborts its response on purpose; net/http recovers it
// silently, so it passes through, unanswered and unrecorded.
func TestRecoverer_ErrAbortHandlerPassesThrough(t *testing.T) {
	capture := logtest.CaptureSlog(t)

	recorder := httptest.NewRecorder()
	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		Recoverer(panicsWith(http.ErrAbortHandler)).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	})
	assert.Empty(t, capture.Records())
	assert.False(t, recorder.Flushed)
	assert.Equal(t, http.StatusOK, recorder.Code, "nothing was written: the recorder's default")
}

// A request asking to upgrade its connection is recorded but not answered 500, as chi's Recoverer
// did: the connection may already belong to the handler.
func TestRecoverer_AnUpgradeIsRecordedButNotAnswered(t *testing.T) {
	capture := logtest.CaptureSlog(t)

	written := false
	writer := headerSpy{ResponseWriter: httptest.NewRecorder(), wrote: &written}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Connection", "Upgrade")
	Recoverer(panicsWith("boom")).ServeHTTP(writer, request)

	assert.False(t, written, "no status is written on a connection asking to upgrade")
	assert.Len(t, capture.Records(), 1)
}

// A handler that does not panic is untouched.
func TestRecoverer_ARequestThatDoesNotPanicIsUntouched(t *testing.T) {
	capture := logtest.CaptureSlog(t)

	recorder := httptest.NewRecorder()
	Recoverer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusTeapot, recorder.Code)
	assert.Empty(t, capture.Records())
}

type headerSpy struct {
	http.ResponseWriter
	wrote *bool
}

func (s headerSpy) WriteHeader(code int) {
	*s.wrote = true
	s.ResponseWriter.WriteHeader(code)
}

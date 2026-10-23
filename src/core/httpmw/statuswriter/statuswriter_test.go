package statuswriter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The writer the request logger and the HTTP metrics read a response's status and size through,
// answering as chi's WrapResponseWriter did: the first final status written, 200 for a body
// written with none, 0 for a handler that wrote nothing, and the bytes of the body.

func TestWriter_ReportsTheStatusAndTheBytesWritten(t *testing.T) {
	recorder := httptest.NewRecorder()
	w := Wrap(recorder)

	w.WriteHeader(http.StatusCreated)
	n, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	_, err = w.Write([]byte(", world"))
	require.NoError(t, err)

	assert.Equal(t, 5, n)
	assert.Equal(t, http.StatusCreated, w.Status())
	assert.Equal(t, 12, w.BytesWritten())
	assert.Equal(t, http.StatusCreated, recorder.Code)
	assert.Equal(t, "hello, world", recorder.Body.String())
}

func TestWriter_ABodyWithNoStatusIs200(t *testing.T) {
	w := Wrap(httptest.NewRecorder())

	_, err := w.Write([]byte("x"))
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Status())
}

// Nothing written is 0, not 200: the metrics and the logger tell a handler that returned without
// answering, and one that panicked past them, from one that answered 200.
func TestWriter_NothingWrittenIsZero(t *testing.T) {
	w := Wrap(httptest.NewRecorder())

	assert.Equal(t, 0, w.Status())
	assert.Equal(t, 0, w.BytesWritten())
}

// The first final status is the one the client received; a later WriteHeader is neither recorded
// nor passed on, so net/http logs no superfluous call for it.
func TestWriter_TheFirstStatusWins(t *testing.T) {
	spy := &statusSpy{ResponseWriter: httptest.NewRecorder()}
	w := Wrap(spy)

	w.WriteHeader(http.StatusNotFound)
	w.WriteHeader(http.StatusInternalServerError)
	_, err := w.Write([]byte("x"))
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, w.Status())
	assert.Equal(t, []int{http.StatusNotFound}, spy.codes)
}

// An informational status goes to the client and is not the response's status; 101 is final,
// because the connection is the handler's after it.
func TestWriter_AnInformationalStatusIsPassedOnNotRecorded(t *testing.T) {
	spy := &statusSpy{ResponseWriter: httptest.NewRecorder()}
	w := Wrap(spy)

	w.WriteHeader(http.StatusEarlyHints)
	w.WriteHeader(http.StatusNoContent)

	assert.Equal(t, http.StatusNoContent, w.Status())
	assert.Equal(t, []int{http.StatusEarlyHints, http.StatusNoContent}, spy.codes)

	switching := Wrap(httptest.NewRecorder())
	switching.WriteHeader(http.StatusSwitchingProtocols)
	assert.Equal(t, http.StatusSwitchingProtocols, switching.Status())
}

// Unwrap hands http.ResponseController the writer beneath, so a handler can still flush or set a
// deadline through the wrapper.
func TestWriter_UnwrapsToTheWriterBeneath(t *testing.T) {
	recorder := httptest.NewRecorder()
	w := Wrap(recorder)

	assert.Same(t, recorder, w.Unwrap())
	require.NoError(t, http.NewResponseController(w).Flush())
	assert.True(t, recorder.Flushed)
}

type statusSpy struct {
	http.ResponseWriter
	codes []int
}

func (s *statusSpy) WriteHeader(code int) {
	s.codes = append(s.codes, code)
	s.ResponseWriter.WriteHeader(code)
}

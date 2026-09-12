package apiresponse

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file owns the API's response seam: the envelope, the buffered write, and the one log record
// every 500 on that surface produces. The handlers get a thin case each; the table is here, so the
// properties are stated once (#279 seam 4).

const requestId = "req-abc-123"

// requestWithId builds a request carrying chi's request id, which is the attribute the request
// logger already writes and therefore the one the body and the log record have to agree on.
func requestWithId(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/anything", nil)
	return r.WithContext(context.WithValue(r.Context(), middleware.RequestIDKey, requestId))
}

func decodeEnvelope(t *testing.T, rr *httptest.ResponseRecorder) (code, description string) {
	t.Helper()
	var body struct {
		ErrorCode        string `json:"error_code"`
		ErrorDescription string `json:"error_description"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	return body.ErrorCode, body.ErrorDescription
}

// Every case below holds slog's default logger through testutil.CaptureSlog, which installs the
// same handler both servers run, and asserts on the record and on the wire together: "answered
// once and logged once" is one property and not two. Text() renders a record the way the servers'
// text handler does, with an error value printed by %+v, so the stack rides inside the attribute
// and the two stack cases can read it.
//
// loggedError reads the error attribute as an error value, which is the contract: the handlers
// print a stack from an error value and nothing from its text.
func loggedError(t *testing.T, record testutil.CapturedRecord) error {
	t.Helper()
	logged, ok := record.Attrs["error"].(error)
	require.True(t, ok, "the error attribute must carry the error value itself, not its text")
	return logged
}

func TestWriteJSON_WritesStatusContentTypeAndBody(t *testing.T) {
	rr := httptest.NewRecorder()
	capture := testutil.CaptureSlog(t)

	WriteJSON(rr, requestWithId(t), http.StatusCreated, map[string]string{"hello": "world"})

	records := capture.Records()

	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.JSONEq(t, "{\"hello\":\"world\"}", rr.Body.String())
	assert.Empty(t, records, "a successful write logs nothing")
}

// The property decision 8 exists for. The 113 sites this replaced committed the status first, so a
// failing encoder left a half-written body under a 200 that could not be taken back, and the 34
// that then called a 500 writer could only add a superfluous WriteHeader. Buffering first means the
// caller gets a real 500 and no partial body.
func TestWriteJSON_AnUnencodableValueIsARealFiveHundred(t *testing.T) {
	rr := httptest.NewRecorder()
	capture := testutil.CaptureSlog(t)

	WriteJSON(rr, requestWithId(t), http.StatusOK, map[string]any{"broken": math.Inf(1)})

	records := capture.Records()

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	code, description := decodeEnvelope(t, rr)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", code)
	assert.Contains(t, description, requestId)
	require.Len(t, records, 1)
	assert.ErrorContains(t, loggedError(t, records[0]), "unable to encode the API response")
}

func TestWriteError_WritesTheEnvelope(t *testing.T) {
	rr := httptest.NewRecorder()
	capture := testutil.CaptureSlog(t)

	WriteError(rr, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)

	records := capture.Records()

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	code, description := decodeEnvelope(t, rr)
	assert.Equal(t, "VALIDATION_ERROR", code)
	assert.Equal(t, "Client ID is required", description)
	assert.Empty(t, records, "a 4xx envelope is not a server fault and logs nothing")
}

// The whole of decision 7 in one case: one code, one sentence, the request id on the wire, and
// exactly one structured record carrying the error, the request id and the caller's attributes.
func TestWriteInternalServerError_AnswersOneCodeAndLogsOnce(t *testing.T) {
	rr := httptest.NewRecorder()
	capture := testutil.CaptureSlog(t)

	WriteInternalServerError(rr, requestWithId(t),
		errs.Wrap(errors.New("connection refused"), "failed to load the client"),
		"client_id", int64(7))

	records := capture.Records()

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	code, description := decodeEnvelope(t, rr)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", code)
	assert.Equal(t, "An unexpected server error has occurred. For additional information, "+
		"refer to the server logs. Request Id: "+requestId, description)

	require.Len(t, records, 1, "exactly one record, which is the point of the primitive")
	// The level is pinned rather than merely observed. Nothing in the text of a call holds a
	// level, and this is the one record that means the server failed at something it can do
	// and somebody has to look: lowered to Warn it would sit among the refusals an auth
	// server produces all day and nobody would find it again (#320 decision 5).
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, "internal server error", records[0].Message)
	assert.Equal(t, requestId, records[0].Attrs["request_id"])
	// snake_case, like every other key in the tree. The caller's attributes reach the record
	// through a variadic parameter, so this key is written at the call site and read nowhere
	// else: until the slog lint read through the wrapper, 179 of the 328 calls that pass
	// through here still spelled it clientId. sloglint reads them now, through the custom-funcs
	// registration in .golangci.yml (#320 decision 3).
	assert.Equal(t, int64(7), records[0].Attrs["client_id"])
	assert.ErrorContains(t, loggedError(t, records[0]), "failed to load the client: connection refused")
}

// The sentence is HttpHelper.JsonError's own, so the API and the web surface read alike. If either
// moves, this fails rather than the two drifting apart unnoticed.
func TestWriteInternalServerError_RepeatsTheWebSurfaceSentence(t *testing.T) {
	rr := httptest.NewRecorder()
	// Held so the record does not reach the test's own output; nothing here asserts on it.
	testutil.CaptureSlog(t)

	WriteInternalServerError(rr, requestWithId(t), errors.New("boom"))

	_, description := decodeEnvelope(t, rr)
	assert.Equal(t, "An unexpected server error has occurred. For additional information, "+
		"refer to the server logs. Request Id: "+requestId, description)
}

// errs.WithStack is applied inside the primitive, not at the call sites, which is what lets all 344
// of them pass err bare. A bare error from the standard library or a driver is the only value it
// changes, and it is the one that would otherwise log with no frames at all (#279 decision 10).
func TestWriteInternalServerError_ABareStdlibErrorStillLogsAStack(t *testing.T) {
	rr := httptest.NewRecorder()
	capture := testutil.CaptureSlog(t)

	WriteInternalServerError(rr, requestWithId(t), errors.New("a bare stdlib error"))

	logged := capture.Text()

	assert.Contains(t, logged, "a bare stdlib error")
	assert.Contains(t, logged, "apiresponse_test.go:", "the stack is the caller's, and it is present")
}

// An error this tree constructed already owns a stack, and the primitive must not add a second one:
// one stack per error tree is goal 2.
func TestWriteInternalServerError_DoesNotAddASecondStack(t *testing.T) {
	rr := httptest.NewRecorder()
	origin := errs.New("the origin")

	capture := testutil.CaptureSlog(t)

	WriteInternalServerError(rr, requestWithId(t), errs.Wrap(origin, "on the way up"))

	logged := capture.Text()

	assert.Equal(t, 1, strings.Count(logged, "apiresponse_test.go:"),
		"one frame set from this file means one stack, the origin's")
}

// The DCR surface takes the log half alone: RFC 7591 section 3.2.2 fixes its body, so the record
// has to exist without anything being written to the wire.
func TestLogInternalServerError_LogsAndWritesNothing(t *testing.T) {
	rr := httptest.NewRecorder()

	var returned string
	capture := testutil.CaptureSlog(t)

	returned = LogInternalServerError(requestWithId(t), errs.New("DCR: could not register"),
		"uri", "https://a.example.com")

	records := capture.Records()

	assert.Equal(t, requestId, returned)
	assert.Equal(t, 200, rr.Code, "nothing was written")
	assert.Empty(t, rr.Body.String())
	require.Len(t, records, 1)
	assert.Equal(t, requestId, records[0].Attrs["request_id"])
	assert.Equal(t, "https://a.example.com", records[0].Attrs["uri"])
}

// A request outside the request-id middleware still answers and still logs. The attribute is
// absent rather than empty: the writer stopped naming it at #320 decision 2, and the handler that
// injects it writes nothing when chi's helper returns the empty string, so an empty request_id can
// no longer reach a record and be mistaken for a correlated one.
func TestWriteInternalServerError_WithoutARequestId(t *testing.T) {
	rr := httptest.NewRecorder()
	capture := testutil.CaptureSlog(t)

	WriteInternalServerError(rr, httptest.NewRequest(http.MethodGet, "/api/v1/admin/anything", nil),
		errs.New("boom"))

	records := capture.Records()

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Len(t, records, 1)
	assert.NotContains(t, records[0].Attrs, "request_id")
}

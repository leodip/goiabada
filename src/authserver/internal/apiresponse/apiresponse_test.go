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

// captureOne runs fn with slog's default logger redirected, which is the logger both servers run,
// and returns the records it produced. Every case below asserts on the record and on the wire
// together, because "answered once and logged once" is one property and not two.
func captureOne(t *testing.T, fn func()) []map[string]any {
	t.Helper()
	var buf strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(previous)

	fn()

	records := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		records = append(records, rec)
	}
	return records
}

// captureText redirects the default logger to slog's TEXT handler, which is what both servers
// actually run: it formats an error value with %+v, so the stack rides inside the error attribute.
// The JSON handler above prints the message alone, which is slog's convention and decision 3's
// stated consequence, so the two stack cases below have to read this one.
func captureText(t *testing.T, fn func()) string {
	t.Helper()
	var buf strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(previous)

	fn()
	return buf.String()
}

func TestWriteJSON_WritesStatusContentTypeAndBody(t *testing.T) {
	rr := httptest.NewRecorder()

	records := captureOne(t, func() {
		WriteJSON(rr, requestWithId(t), http.StatusCreated, map[string]string{"hello": "world"})
	})

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

	records := captureOne(t, func() {
		WriteJSON(rr, requestWithId(t), http.StatusOK, map[string]any{"broken": math.Inf(1)})
	})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	code, description := decodeEnvelope(t, rr)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", code)
	assert.Contains(t, description, requestId)
	require.Len(t, records, 1)
	assert.Contains(t, records[0]["error"], "unable to encode the API response")
}

func TestWriteError_WritesTheEnvelope(t *testing.T) {
	rr := httptest.NewRecorder()

	records := captureOne(t, func() {
		WriteError(rr, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
	})

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

	records := captureOne(t, func() {
		WriteInternalServerError(rr, requestWithId(t),
			errs.Wrap(errors.New("connection refused"), "failed to load the client"),
			"clientId", int64(7))
	})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	code, description := decodeEnvelope(t, rr)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", code)
	assert.Equal(t, "An unexpected server error has occurred. For additional information, "+
		"refer to the server logs. Request Id: "+requestId, description)

	require.Len(t, records, 1, "exactly one record, which is the point of the primitive")
	assert.Equal(t, "internal server error", records[0]["msg"])
	assert.Equal(t, requestId, records[0]["request_id"])
	assert.Equal(t, float64(7), records[0]["clientId"])
	assert.Contains(t, records[0]["error"], "failed to load the client: connection refused")
}

// The sentence is HttpHelper.JsonError's own, so the API and the web surface read alike. If either
// moves, this fails rather than the two drifting apart unnoticed.
func TestWriteInternalServerError_RepeatsTheWebSurfaceSentence(t *testing.T) {
	rr := httptest.NewRecorder()
	captureOne(t, func() {
		WriteInternalServerError(rr, requestWithId(t), errors.New("boom"))
	})
	_, description := decodeEnvelope(t, rr)
	assert.Equal(t, "An unexpected server error has occurred. For additional information, "+
		"refer to the server logs. Request Id: "+requestId, description)
}

// errs.WithStack is applied inside the primitive, not at the call sites, which is what lets all 344
// of them pass err bare. A bare error from the standard library or a driver is the only value it
// changes, and it is the one that would otherwise log with no frames at all (#279 decision 10).
func TestWriteInternalServerError_ABareStdlibErrorStillLogsAStack(t *testing.T) {
	rr := httptest.NewRecorder()

	logged := captureText(t, func() {
		WriteInternalServerError(rr, requestWithId(t), errors.New("a bare stdlib error"))
	})

	assert.Contains(t, logged, "a bare stdlib error")
	assert.Contains(t, logged, "apiresponse_test.go:", "the stack is the caller's, and it is present")
}

// An error this tree constructed already owns a stack, and the primitive must not add a second one:
// one stack per error tree is goal 2.
func TestWriteInternalServerError_DoesNotAddASecondStack(t *testing.T) {
	rr := httptest.NewRecorder()
	origin := errs.New("the origin")

	logged := captureText(t, func() {
		WriteInternalServerError(rr, requestWithId(t), errs.Wrap(origin, "on the way up"))
	})

	assert.Equal(t, 1, strings.Count(logged, "apiresponse_test.go:"),
		"one frame set from this file means one stack, the origin's")
}

// The DCR surface takes the log half alone: RFC 7591 section 3.2.2 fixes its body, so the record
// has to exist without anything being written to the wire.
func TestLogInternalServerError_LogsAndWritesNothing(t *testing.T) {
	rr := httptest.NewRecorder()

	var returned string
	records := captureOne(t, func() {
		returned = LogInternalServerError(requestWithId(t), errs.New("DCR: could not register"),
			"uri", "https://a.example.com")
	})

	assert.Equal(t, requestId, returned)
	assert.Equal(t, 200, rr.Code, "nothing was written")
	assert.Empty(t, rr.Body.String())
	require.Len(t, records, 1)
	assert.Equal(t, requestId, records[0]["request_id"])
	assert.Equal(t, "https://a.example.com", records[0]["uri"])
}

// A request outside the request-id middleware still answers and still logs; chi's helper returns
// the empty string there, so the attribute is present and empty rather than missing.
func TestWriteInternalServerError_WithoutARequestId(t *testing.T) {
	rr := httptest.NewRecorder()

	records := captureOne(t, func() {
		WriteInternalServerError(rr, httptest.NewRequest(http.MethodGet, "/api/v1/admin/anything", nil),
			errs.New("boom"))
	})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Len(t, records, 1)
	assert.Equal(t, "", records[0]["request_id"])
}

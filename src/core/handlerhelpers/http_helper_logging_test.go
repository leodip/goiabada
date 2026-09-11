package handlerhelpers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file owns seam 3's logging contract. InternalServerError and JsonError are the only place a
// 500 is recorded, so what they log is observable nowhere else and no handler test can stand in for
// these rows: a handler proves it called the writer, and the writer proves what the operator reads
// (#279 decisions 6, 9 and 10).

// capturedLogs collects the records the writers emit while a test holds the default logger.
type capturedLogs struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *capturedLogs) add(record slog.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record)
}

func (c *capturedLogs) all() []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]slog.Record(nil), c.records...)
}

// recordingHandler is the slog.Handler side of capturedLogs. Nothing under test builds a logger
// through slog.With or opens a group, so WithAttrs and WithGroup are the identity.
type recordingHandler struct{ logs *capturedLogs }

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	// Clone before keeping it: a Record's attributes may share backing storage with the caller's.
	h.logs.add(record.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

func captureLogs(t *testing.T) *capturedLogs {
	t.Helper()
	logs := &capturedLogs{}
	previous := slog.Default()
	slog.SetDefault(slog.New(&recordingHandler{logs: logs}))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logs
}

// theOneErrorRecord requires exactly one ERROR record and returns it. Exactly one is the assertion,
// not at least one: decision 9's claim is that a 500 is logged once, so a writer that logged twice,
// or that logged at a level an operator filters out, has to fail here.
func theOneErrorRecord(t *testing.T, logs *capturedLogs) (slog.Record, bool) {
	t.Helper()
	captured := logs.all()
	var matched []slog.Record
	for _, record := range captured {
		if record.Level == slog.LevelError {
			matched = append(matched, record)
		}
	}
	if !assert.Len(t, matched, 1, "want exactly one ERROR record, out of %d captured", len(captured)) {
		return slog.Record{}, false
	}
	return matched[0], true
}

// attrsOf flattens ONE record's attributes. Taking a record rather than the whole capture is the
// point: two unrelated records must not be able to satisfy one assertion between them.
func attrsOf(record slog.Record) map[string]any {
	attrs := make(map[string]any)
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Resolve().Any()
		return true
	})
	return attrs
}

// frameCount counts the "\n\tfile:line" pairs %+v printed, which is how many stack frames the error
// carries. Counted rather than matched: frame text is file paths and line numbers, and those drift
// with every edit made above them.
func frameCount(err error) int {
	return strings.Count(fmt.Sprintf("%+v", err), "\n\t")
}

// loggedErrorOf reads the error attribute as an error value. The type assertion is itself an
// assertion about the contract: slog's default handler is what prints the stack, and it can only do
// that from an error value, so a writer that logged err.Error() would satisfy every text check
// while silently dropping every frame.
func loggedErrorOf(t *testing.T, record slog.Record) (error, bool) {
	t.Helper()
	logged, ok := attrsOf(record)["error"].(error)
	if !assert.True(t, ok, "the error attribute must carry the error value itself, not its text") {
		return nil, false
	}
	return logged, true
}

// errorRouter is the harness these rows share: a chi router carrying the request id middleware and
// the settings the renderer reads, calling handle for GET /.
func errorRouter(handle http.HandlerFunc) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), constants.ContextKeySettings, &models.Settings{})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	r.Get("/", handle)
	return r
}

func errorPageHelper() *HttpHelper {
	return NewHttpHelper(&mocks.TestFS{
		FileContents: map[string]string{
			"layouts/no_menu_layout.html": "<html>{{template \"content\" .}}</html>",
			"error.html":                  "{{define \"content\"}}Error: {{.requestId}}{{end}}",
		},
	})
}

func notFoundPageHelper() *HttpHelper {
	return NewHttpHelper(&mocks.TestFS{
		FileContents: map[string]string{
			"layouts/no_menu_layout.html": "<html>{{template \"content\" .}}</html>",
			"not_found.html":              "{{define \"content\"}}Not found{{end}}",
			"error.html":                  "{{define \"content\"}}Error: {{.requestId}}{{end}}",
		},
	})
}

// Decision 11's other half, and the half no status assertion can see. The console reaches NotFound
// from 203 sites that used to answer 500, and every one of them wrote a log record with a stack: if
// this method logged, the change would trade one page for the same volume of noise, and an operator
// grepping for ERROR would still be reading other people's stale bookmarks. Empty rather than "no
// ERROR record": a warn or an info line at this volume is the same defect (#279 decision 11).
func TestNotFound_LogsNothing(t *testing.T) {
	logs := captureLogs(t)
	httpHelper := notFoundPageHelper()

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.NotFound(w, r)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	require.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	assert.Empty(t, logs.all(), "a stale or malformed URL is not an event an operator has to read")
}

// The silence is scoped to the 404. A render failure inside NotFound is a server fault reaching
// InternalServerError, and it keeps the whole of decision 9's record: one line, the error value, and
// the request id the page shows. errorPageHelper has no not_found.html, so ParseFS fails for its own
// reason.
func TestNotFound_RenderFailureStillLogsOnce(t *testing.T) {
	logs := captureLogs(t)
	httpHelper := errorPageHelper()

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.NotFound(w, r)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)

	record, ok := theOneErrorRecord(t, logs)
	if !ok {
		return
	}
	assert.Equal(t, "internal server error", record.Message)

	logged, isError := loggedErrorOf(t, record)
	if !isError {
		return
	}
	assert.Contains(t, logged.Error(), "unable to render template")

	requestId, isString := attrsOf(record)["request_id"].(string)
	assert.True(t, isString, "request_id must be a string attribute")
	assert.Contains(t, w.Body.String(), "Error: "+requestId)
}

func TestInternalServerError_LogsOnceWithErrorAndRequestId(t *testing.T) {
	logs := captureLogs(t)
	httpHelper := errorPageHelper()

	failure := errs.New("the database went away")
	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.InternalServerError(w, r, failure)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	record, ok := theOneErrorRecord(t, logs)
	if !ok {
		return
	}
	assert.Equal(t, "internal server error", record.Message)

	logged, isError := loggedErrorOf(t, record)
	if !isError {
		return
	}
	assert.Equal(t, failure.Error(), logged.Error())

	// The request id on the log line and the one on the page the visitor is looking at have to be
	// the same string, or the line cannot be found from a user's report, which is the only reason
	// either of them is written down at all.
	requestId, isString := attrsOf(record)["request_id"].(string)
	assert.True(t, isString, "request_id must be a string attribute")
	assert.NotEmpty(t, requestId)
	assert.Contains(t, w.Body.String(), "Error: "+requestId)
}

// The stack is why decision 10 moved WithStack off the call sites and into the writer: a caller
// that passes a bare error still gets frames, so nothing is lost by asking all 1,007 sites to pass
// err bare.
func TestInternalServerError_StacksAnUnstackedError(t *testing.T) {
	logs := captureLogs(t)
	httpHelper := errorPageHelper()

	// Deliberately a stdlib error with no frames anywhere in its tree, which is what a dependency
	// hands back and what the constructor sweep cannot reach.
	bare := errors.New("a bare error from somewhere else")
	require.Equal(t, 0, frameCount(bare), "the fixture must start with no frames or this proves nothing")

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.InternalServerError(w, r, bare)
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	record, ok := theOneErrorRecord(t, logs)
	if !ok {
		return
	}
	logged, isError := loggedErrorOf(t, record)
	if !isError {
		return
	}
	assert.Equal(t, bare.Error(), logged.Error(), "attaching a stack must not change the message")
	assert.Positive(t, frameCount(logged), "the writer must attach a stack to an error that has none")
}

// One stack, not two. The writer's WithStack is the identity on anything this tree constructed, so
// an error arriving already stacked must not collect the writer's frames on top of its own. That is
// rule 3, and this writer is the one place in the tree that could break it for every error at once.
func TestInternalServerError_KeepsTheOriginsSingleStack(t *testing.T) {
	logs := captureLogs(t)
	httpHelper := errorPageHelper()

	origin := errs.New("the origin")
	wanted := frameCount(origin)
	require.Positive(t, wanted)

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.InternalServerError(w, r, errs.Wrap(origin, "and a layer above it"))
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	record, ok := theOneErrorRecord(t, logs)
	if !ok {
		return
	}
	logged, isError := loggedErrorOf(t, record)
	if !isError {
		return
	}
	assert.Equal(t, wanted, frameCount(logged), "the tree must still carry exactly the origin's frames")
}

func TestJsonError_LogsOnceOnTheGenericBranch(t *testing.T) {
	logs := captureLogs(t)
	httpHelper := NewHttpHelper(&mocks.TestFS{})

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.JsonError(w, r, errs.New("not a wire error"))
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	record, ok := theOneErrorRecord(t, logs)
	if !ok {
		return
	}
	assert.Equal(t, "internal server error", record.Message)

	if _, isError := loggedErrorOf(t, record); !isError {
		return
	}
	requestId, isString := attrsOf(record)["request_id"].(string)
	assert.True(t, isString, "request_id must be a string attribute")
	assert.NotEmpty(t, requestId)

	// The same id reaches the client, in the sentence this branch writes.
	var response map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "server_error", response["error"])
	assert.Contains(t, response["error_description"], requestId)
}

// The branch between the two: an *ErrorDetail carrying no status at all. It is answered 500, and a
// 500 is a server fault whichever branch produced it, so it owes the same single record and the
// same request id on the wire. It did neither, which made this the one 500 in the tree an operator
// could not join to a log line, and the silence was invisible because TestJsonError pinned the
// status and the code and never looked at the record (#279 decisions 9 and 12).
func TestJsonError_ADetailWithNoStatusIsA500ThatStillLogsAndCorrelates(t *testing.T) {
	logs := captureLogs(t)
	httpHelper := NewHttpHelper(&mocks.TestFS{})

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.JsonError(w, r, customerrors.NewErrorDetail("server_error", "The operation failed."))
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	record, ok := theOneErrorRecord(t, logs)
	if !ok {
		return
	}
	assert.Equal(t, "internal server error", record.Message)
	if _, isError := loggedErrorOf(t, record); !isError {
		return
	}

	requestId, isString := attrsOf(record)["request_id"].(string)
	require.True(t, isString, "request_id must be a string attribute")
	require.NotEmpty(t, requestId)

	var response map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "server_error", response["error"], "the detail's own code still reaches the wire")
	assert.Contains(t, response["error_description"], "The operation failed.",
		"and so does its own sentence")
	assert.Contains(t, response["error_description"], requestId,
		"the id on the wire and the id on the log line have to be the same string")
}

// The silence is scoped to a status somebody chose. A 4xx detail is a client's mistake and stays
// silent, which is the row below; an explicit 500 stays silent too, because its one production
// builder is handler_token.go's jsonErrorConformed, which writes the record and puts the request id
// in the description before it ever reaches here. Logging it a second time here is the defect this
// row exists to catch.
func TestJsonError_AnExplicit500DetailIsNotLoggedTwice(t *testing.T) {
	logs := captureLogs(t)
	httpHelper := NewHttpHelper(&mocks.TestFS{})

	detail := customerrors.NewErrorDetailWithHttpStatusCode("server_error",
		"An unexpected server error has occurred. Request Id: already-in-the-sentence",
		http.StatusInternalServerError)

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.JsonError(w, r, detail)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, logs.all(), "the caller that chose this status owns the record")

	var response map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "An unexpected server error has occurred. Request Id: already-in-the-sentence",
		response["error_description"], "and owns the sentence, so nothing is appended to it")
}

// Decision 6's regression guard at this writer. An *ErrorDetail that something wrapped on the way
// up still decides the status, the code and the description; under the bare type assertion this
// replaced, one wrap turned a validator's 400 into a 500 and sent the sentence to the log instead
// of to the client.
func TestJsonError_ReadsAWrappedErrorDetail(t *testing.T) {
	logs := captureLogs(t)
	httpHelper := NewHttpHelper(&mocks.TestFS{})

	detail := customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
		"The redirect URI is not registered.", http.StatusBadRequest)

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.JsonError(w, r, errs.Wrap(detail, "unable to validate the request"))
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "invalid_request", response["error"])
	assert.Equal(t, "The redirect URI is not registered.", response["error_description"],
		"the wrapper's own message must not reach the wire")

	assert.Empty(t, logs.all(), "a client's mistake answered as a client's mistake is not a server fault")
}

// The WWW-Authenticate header travels with the detail through a wrapper too, and it is the half of
// RFC 6749 section 5.2 a bare assertion would have dropped in silence: the status would have become
// 500 and the header simply would not be written.
func TestJsonError_ReadsAWrappedErrorDetailsWWWAuthenticate(t *testing.T) {
	httpHelper := NewHttpHelper(&mocks.TestFS{})

	detail := customerrors.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_token",
		"The access token is invalid.", http.StatusUnauthorized, "Bearer error=\"invalid_token\"")

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.JsonError(w, r, errs.Wrap(detail, "unable to read the token"))
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	assert.Equal(t, "Bearer error=\"invalid_token\"", res.Header.Get("WWW-Authenticate"))
}

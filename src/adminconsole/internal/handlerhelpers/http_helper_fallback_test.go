package handlerhelpers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/mocks"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These rows own InternalServerError's last resort: the body written when the error page itself
// will not render. It used to be "unable to render the error page: " followed by the render
// error, which named template files and internal state to anybody who could make a page fail. It
// is now fixed catalog text and the request id, and the render error goes to the log (#414 item 3,
// #425 decision 11).

// failingErrorPageHelper's error.html parses and then fails to execute: it calls a template nothing
// defines, which html/template reports only when it runs. That is the one way to reach the last
// resort, because RenderTemplate buffers the page before it touches the response.
func failingErrorPageHelper() *HttpHelper {
	return NewHttpHelper(&mocks.TestFS{
		FileContents: map[string]string{
			"layouts/no_menu_layout.html": "<html>{{template \"content\" .}}</html>",
			"error.html":                  "{{define \"content\"}}{{template \"never_defined\" .}}{{end}}",
		},
	}, stubSettingsReader{})
}

func errorLevelRecords(logs *testutil.SlogCapture) []testutil.CapturedRecord {
	var matched []testutil.CapturedRecord
	for _, record := range logs.Records() {
		if record.Level == slog.LevelError {
			matched = append(matched, record)
		}
	}
	return matched
}

// catalogText resolves a key and refuses one that resolved to itself, which is what every key
// renders as when the catalog is absent: an expectation built from that would agree with a writer
// that wrote the key names.
func catalogText(t *testing.T, key string) string {
	t.Helper()
	text := i18n.T(context.Background(), key)
	require.NotEqual(t, key, text, "the catalog must be loaded, or this row compares key names")
	return text
}

func TestInternalServerError_RenderFailureWritesCatalogTextAndLogsTheRenderError(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	httpHelper := failingErrorPageHelper()

	failure := errs.New("the database went away")
	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.InternalServerError(w, r, failure)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusInternalServerError, res.StatusCode)
	assert.Equal(t, "text/plain; charset=utf-8", res.Header.Get("Content-Type"))

	// Two records: the fault the caller reported, and the render failure, which nothing else
	// would ever show an operator.
	records := errorLevelRecords(logs)
	require.Len(t, records, 2)
	assert.Equal(t, "internal server error", records[0].Message)
	assert.Equal(t, "unable to render the error page", records[1].Message)
	renderErr, isError := loggedErrorOf(t, records[1])
	require.True(t, isError)
	assert.Contains(t, renderErr.Error(), "never_defined", "the record carries what the body must not")

	requestId, isString := records[1].Attrs["request_id"].(string)
	require.True(t, isString, "request_id must be a string attribute")
	require.NotEmpty(t, requestId)

	body := w.Body.String()
	assert.Equal(t, catalogText(t, "adminconsole.error.body")+" "+catalogText(t, "adminconsole.error.request_id_label")+" "+
		requestId+"\n", body)
	assert.NotContains(t, body, "never_defined")
	assert.NotContains(t, body, "template")
	assert.NotContains(t, body, failure.Error())
}

// chi's RequestID adopts an inbound X-Request-Id verbatim, so the one variable in the body is the
// caller's to choose. A megabyte of it, led by control bytes, comes back escaped and clipped.
func TestInternalServerError_RenderFailureBoundsAClientChosenRequestId(t *testing.T) {
	_ = testutil.CaptureSlog(t)
	httpHelper := failingErrorPageHelper()

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		httpHelper.InternalServerError(w, r, errs.New("the database went away"))
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-Id", "\x01\r\n"+strings.Repeat("a", 1<<20))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	body := w.Body.String()
	assert.Less(t, len(body), 512, "the echoed id must be clipped, not a megabyte long")
	assert.Contains(t, body, "%01%0D%0A")
	assert.Contains(t, body, "[truncated,")
	assert.NotContains(t, strings.TrimSuffix(body, "\n"), "\n")
	assert.NotContains(t, body, "\x01")
}

// The body is localized the way the page it stands in for is.
func TestInternalServerError_RenderFailureSpeaksTheRequestsLocale(t *testing.T) {
	_ = testutil.CaptureSlog(t)
	httpHelper := failingErrorPageHelper()

	router := errorRouter(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(i18n.WithLocale(r.Context(), true, "pt-BR"))
		httpHelper.InternalServerError(w, r, errs.New("the database went away"))
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.True(t, strings.HasPrefix(w.Body.String(), "Pedimos desculpas"), "got %q", w.Body.String())
	assert.Contains(t, w.Body.String(), "ID da requisição:")
}

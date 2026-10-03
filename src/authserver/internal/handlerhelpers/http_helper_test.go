package handlerhelpers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRequest is httptest.NewRequest with settings on its context, as middleware.Settings puts them
// on every application request, so a render reaches its template.
func newRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	return req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{}))
}

// assertNoStore requires the two cache header fields every rendered page carries. Read off
// http.Response.Header, which is the snapshot the client receives, rather than the recorder's
// live map (#247).
func assertNoStore(t *testing.T, header http.Header) {
	t.Helper()

	assert.Equal(t, "no-store", header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", header.Get("Pragma"))
}

func TestInternalServerError(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/no_menu_layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"error.html":                  {Data: []byte("{{define \"content\"}}Error: {{.requestId}}{{end}}")},
	}
	httpHelper := NewHttpHelper(templateFS)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		httpHelper.InternalServerError(w, r, errors.New("test error"))
	})

	req := newRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Every header assertion here reads the snapshot taken at WriteHeader, never the recorder's
	// live map. The two disagree in exactly the case this test used to be blind to: a header set
	// after the status is committed is dropped from the wire but still visible in w.Header(), so
	// the Content-Type assertion below was green for a header the 500 page never sent (#247).
	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	assert.Contains(t, w.Body.String(), "Error:")

	// Check if the response contains a request ID
	assert.Regexp(t, `Error: [a-zA-Z0-9/-]+`, w.Body.String(), "Response should contain a request ID")

	// Check if the content type is set correctly
	assert.Equal(t, "text/html; charset=UTF-8", res.Header.Get("Content-Type"))

	assertNoStore(t, res.Header)

	// Ensure the response body is not empty
	assert.NotEmpty(t, w.Body.String())

	// Check if the response contains expected HTML structure
	assert.True(t, strings.HasPrefix(w.Body.String(), "<html>"))
	assert.True(t, strings.HasSuffix(w.Body.String(), "</html>"))
}

// NotFound owns the answer to a stale or malformed URL, so this row owns the status, the page and
// the headers it carries; its silence is pinned in http_helper_logging_test.go (#279 decision 11).
func TestNotFound(t *testing.T) {
	httpHelper := NewHttpHelper(fstest.MapFS{
		"layouts/no_menu_layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"not_found.html":              {Data: []byte("{{define \"content\"}}Not found{{end}}")},
	})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/admin/clients/{clientId}/settings", func(w http.ResponseWriter, r *http.Request) {
		httpHelper.NotFound(w, r)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, newRequest("GET", "/admin/clients/not-a-number/settings", nil))

	// Read the snapshot the client receives rather than the recorder's live header map, for the
	// reason TestInternalServerError states (#247).
	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Equal(t, "<html>Not found</html>", w.Body.String())
	assert.Equal(t, "text/html; charset=UTF-8", res.Header.Get("Content-Type"))
	assertNoStore(t, res.Header)

	// Nothing of the request survives onto the page: no request id, because there is no log line to
	// join it to, and no echo of the id that was rejected.
	assert.NotContains(t, w.Body.String(), "not-a-number")
}

// A render failure is a real server fault, and it is the one path out of NotFound that is not a
// 404. The template FS here has the layout the error page needs and no not_found.html at all, so
// ParseFS fails and the fallback is exercised for its own reason rather than by a stub.
func TestNotFound_RenderFailureAnswers500(t *testing.T) {
	httpHelper := NewHttpHelper(fstest.MapFS{
		"layouts/no_menu_layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"error.html":                  {Data: []byte("{{define \"content\"}}Error: {{.requestId}}{{end}}")},
	})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		httpHelper.NotFound(w, r)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, newRequest("GET", "/", nil))

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	assert.Contains(t, w.Body.String(), "Error:")
}

func TestRenderTemplate(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"page.html":           {Data: []byte("{{define \"content\"}}Hello, {{.Name}}! Status: {{._httpStatus}}{{end}}")},
	}
	httpHelper := NewHttpHelper(templateFS)

	t.Run("Without _httpStatus", func(t *testing.T) {
		req := newRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		data := map[string]interface{}{
			"Name": "John",
		}

		err := httpHelper.RenderTemplate(w, req, "layouts/layout.html", "page.html", data)

		res := w.Result()
		defer func() { _ = res.Body.Close() }()

		assert.NoError(t, err)
		assert.Equal(t, "text/html; charset=UTF-8", res.Header.Get("Content-Type"))
		assertNoStore(t, res.Header)
		assert.Contains(t, w.Body.String(), "Hello, John!")
		assert.Contains(t, w.Body.String(), "Status:")
		assert.Equal(t, http.StatusOK, res.StatusCode) // Default status should be 200 OK
	})

	t.Run("With _httpStatus", func(t *testing.T) {
		req := newRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		data := map[string]interface{}{
			"Name":        "Jane",
			"_httpStatus": http.StatusCreated,
		}

		err := httpHelper.RenderTemplate(w, req, "layouts/layout.html", "page.html", data)

		res := w.Result()
		defer func() { _ = res.Body.Close() }()

		assert.NoError(t, err)
		assert.Equal(t, "text/html; charset=UTF-8", res.Header.Get("Content-Type"))
		assertNoStore(t, res.Header)
		assert.Contains(t, w.Body.String(), "Hello, Jane!")
		assert.Contains(t, w.Body.String(), "Status: 201")
		assert.Equal(t, http.StatusCreated, res.StatusCode)
	})

	// A failed render must leave the response completely untouched, so the caller's
	// InternalServerError owns every header as well as the status. That is the property the
	// placement of the Cache-Control write depends on: it sits after RenderTemplateToBuffer has
	// returned successfully, and moving it above the error return would put a directive on a
	// response this function never wrote a body for (#247).
	t.Run("A failed render writes no headers at all", func(t *testing.T) {
		emptyFS := fstest.MapFS{}
		failing := NewHttpHelper(emptyFS)

		req := newRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		err := failing.RenderTemplate(w, req, "layouts/layout.html", "page.html", map[string]interface{}{})

		res := w.Result()
		defer func() { _ = res.Body.Close() }()

		assert.Error(t, err)
		assert.Empty(t, res.Header.Get("Content-Type"))
		assert.Empty(t, res.Header.Get("Cache-Control"))
		assert.Empty(t, res.Header.Get("Pragma"))
		assert.Empty(t, w.Body.String())
	})
}

func TestRenderTemplateToBuffer(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"page.html":           {Data: []byte("{{define \"content\"}}Hello, {{if .loggedInUser}}{{.loggedInUser.Username}}{{else}}Guest{{end}}!{{end}}")},
	}
	httpHelper := NewHttpHelper(templateFS)

	// This renderer binds no loggedInUser and no isAdmin. Both were admin console page data
	// living in the one core renderer both binaries used, and no auth server template binds
	// either; #385 moved the enrichment that produced them into the console's own renderer. A
	// template naming loggedInUser here takes the empty branch.
	t.Run("No admin console page data is bound", func(t *testing.T) {
		req := newRequest("GET", "/", nil)
		data := map[string]interface{}{}

		buf, err := httpHelper.RenderTemplateToBuffer(req, "layouts/layout.html", "page.html", data)

		require.NoError(t, err)
		assert.Contains(t, buf.String(), "Hello, Guest!")
		assert.NotContains(t, data, "loggedInUser")
		assert.NotContains(t, data, "isAdmin")
	})

	t.Run("Layout settings reach the template", func(t *testing.T) {
		layoutFS := fstest.MapFS{
			"layouts/layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
			"page.html":           {Data: []byte("{{define \"content\"}}{{.appName}}|{{.uiTheme}}|{{.smtpEnabled}}{{end}}")},
		}
		layoutHelper := NewHttpHelper(layoutFS)
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{
			AppName:     "sentinel app",
			UITheme:     "sentinel theme",
			SMTPEnabled: true,
		}))

		buf, err := layoutHelper.RenderTemplateToBuffer(req, "layouts/layout.html", "page.html", map[string]interface{}{})

		require.NoError(t, err)
		assert.Equal(t, "<html>sentinel app|sentinel theme|true</html>", buf.String())
	})

	// Every application route runs under middleware.Settings, so a render without settings is a
	// wiring defect. It is refused with the one sentinel, for the caller's 500 path to answer, and
	// binds nothing into the page data (#433 decision 7).
	t.Run("Without settings the render is refused", func(t *testing.T) {
		data := map[string]interface{}{}

		buf, err := httpHelper.RenderTemplateToBuffer(
			httptest.NewRequest("GET", "/", nil), "layouts/layout.html", "page.html", data)

		require.ErrorIs(t, err, reqctx.ErrNoSettings)
		assert.Nil(t, buf)
		assert.Empty(t, data)
	})
}

// A nil bind map is allocated rather than written into, which would panic. The render still binds
// the layout's values, so the page sees the settings as it would through a caller's own map (#435).
func TestRenderTemplateToBuffer_NilDataMap(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"page.html":           {Data: []byte("{{define \"content\"}}{{.appName}}|{{.urlPath}}{{end}}")},
	}
	req := httptest.NewRequest("GET", "/some/page", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{AppName: "sentinel app"}))

	buf, err := NewHttpHelper(templateFS).RenderTemplateToBuffer(req, "layouts/layout.html", "page.html", nil)

	require.NoError(t, err)
	assert.Equal(t, "<html>sentinel app|/some/page</html>", buf.String())
}

// Every file under partials/ is parsed beside the layout and the page, which is how a page calls a
// fragment it does not define. The second case is the first one's tree without the fragment, so a
// pass there cannot come from anything but the partials branch (#431).
func TestRenderTemplateToBuffer_Partials(t *testing.T) {
	layout := []byte(`<html>{{template "content" .}}</html>`)
	page := []byte(`{{define "content"}}[{{template "badge" .}}]{{end}}`)
	render := func(templateFS fstest.MapFS) (*bytes.Buffer, error) {
		return NewHttpHelper(templateFS).RenderTemplateToBuffer(
			newRequest("GET", "/", nil), "layouts/layout.html", "page.html", map[string]interface{}{})
	}

	t.Run("A template defined under partials is parsed with the page", func(t *testing.T) {
		buf, err := render(fstest.MapFS{
			"layouts/layout.html": {Data: layout},
			"page.html":           {Data: page},
			"partials/badge.html": {Data: []byte(`{{define "badge"}}the badge{{end}}`)},
		})

		require.NoError(t, err)
		assert.Equal(t, "<html>[the badge]</html>", buf.String())
	})

	t.Run("Without the partial the page does not render", func(t *testing.T) {
		_, err := render(fstest.MapFS{
			"layouts/layout.html": {Data: layout},
			"page.html":           {Data: page},
		})

		require.Error(t, err)
		assert.ErrorContains(t, err, `no such template "badge"`)
	})

	t.Run("An empty partials directory renders as if absent", func(t *testing.T) {
		buf, err := render(fstest.MapFS{
			"layouts/layout.html": {Data: layout},
			"page.html":           {Data: []byte(`{{define "content"}}no fragments{{end}}`)},
			"partials":            {Mode: fs.ModeDir},
		})

		require.NoError(t, err)
		assert.Equal(t, "<html>no fragments</html>", buf.String())
	})
}

func TestJsonError(t *testing.T) {
	templateFS := fstest.MapFS{}
	httpHelper := NewHttpHelper(templateFS)

	req := newRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := oauth.NewErrorDetail("test_error", "Test error description")
	httpHelper.JsonError(w, req, err)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err2 := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err2)

	assert.Equal(t, "test_error", response["error"])
	// The detail names no status, so it defaults to 500 and the description picks up the request
	// id the way every other 500 on this surface does. There is no request id middleware on this
	// bare request, so the id is empty; http_helper_logging_test.go owns the row that pins the
	// correlation itself.
	assert.Contains(t, response["error_description"], "Test error description")
}

func TestEncodeJson(t *testing.T) {
	templateFS := fstest.MapFS{}
	httpHelper := NewHttpHelper(templateFS)

	req := newRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	data := map[string]string{"key": "value"}
	httpHelper.EncodeJson(w, req, data)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, "value", response["key"])
}

func TestGetFromUrlQueryOrFormPost(t *testing.T) {
	t.Run("Get from URL query", func(t *testing.T) {
		req := newRequest("GET", "/?key=value", nil)
		value := GetFromUrlQueryOrFormPost(req, "key")
		assert.Equal(t, "value", value)
	})

	t.Run("Get from form post", func(t *testing.T) {
		req := newRequest("POST", "/", bytes.NewBufferString("key=value"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		err := req.ParseForm()
		assert.NoError(t, err)
		value := GetFromUrlQueryOrFormPost(req, "key")
		assert.Equal(t, "value", value)
	})
}

func TestLookupFromUrlQueryOrFormPost(t *testing.T) {
	// postForm builds a form-encoded POST, optionally with a query string of its own.
	postForm := func(target string, body string) *http.Request {
		req := newRequest("POST", target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}

	tests := []struct {
		name          string
		request       *http.Request
		expectValue   string
		expectPresent bool
	}{
		{"Absent from the query", newRequest("GET", "/?other=1", nil), "", false},
		{"Empty in the query is present", newRequest("GET", "/?state=", nil), "", true},
		{"Present in the query", newRequest("GET", "/?state=abc", nil), "abc", true},
		{"Whitespace in the query is untrimmed", newRequest("GET", "/?state=%20%20%20", nil), "   ", true},
		{"Present in the body", postForm("/", "state=abc"), "abc", true},
		{"Empty in the body is present", postForm("/", "state="), "", true},
		{"A non-empty query beats the body", postForm("/?state=abc", "state=xyz"), "abc", true},
		{"An empty query falls through to the body", postForm("/?state=", "state=xyz"), "xyz", true},
		{"Absent from the body", postForm("/", "other=1"), "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value, present := LookupFromUrlQueryOrFormPost(tc.request, "state")
			assert.Equal(t, tc.expectValue, value)
			assert.Equal(t, tc.expectPresent, present)
		})
	}
}

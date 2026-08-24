package handlerhelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// assertNoStore requires the two cache header fields every rendered page carries. Read off
// http.Response.Header, which is the snapshot the client receives, rather than the recorder's
// live map (#247).
func assertNoStore(t *testing.T, header http.Header) {
	t.Helper()

	assert.Equal(t, "no-store", header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", header.Get("Pragma"))
}

func TestInternalServerError(t *testing.T) {
	templateFS := &mocks.TestFS{
		FileContents: map[string]string{
			"layouts/no_menu_layout.html": "<html>{{template \"content\" .}}</html>",
			"error.html":                  "{{define \"content\"}}Error: {{.requestId}}{{end}}",
		},
	}
	httpHelper := NewHttpHelper(templateFS)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, constants.ContextKeySettings, &models.Settings{})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		httpHelper.InternalServerError(w, r, errors.New("test error"))
	})

	req := httptest.NewRequest("GET", "/", nil)
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

func TestRenderTemplate(t *testing.T) {
	templateFS := &mocks.TestFS{
		FileContents: map[string]string{
			"layouts/layout.html": "<html>{{template \"content\" .}}</html>",
			"page.html":           "{{define \"content\"}}Hello, {{.Name}}! Status: {{._httpStatus}}{{end}}",
		},
	}
	httpHelper := NewHttpHelper(templateFS)

	t.Run("Without _httpStatus", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, &models.Settings{AppName: "TestApp", UITheme: "light"})
		req = req.WithContext(ctx)

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
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, &models.Settings{AppName: "TestApp", UITheme: "light"})
		req = req.WithContext(ctx)

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
		emptyFS := &mocks.TestFS{FileContents: map[string]string{}}
		failing := NewHttpHelper(emptyFS)

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, &models.Settings{AppName: "TestApp", UITheme: "light"})
		req = req.WithContext(ctx)

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
	templateFS := &mocks.TestFS{
		FileContents: map[string]string{
			"layouts/layout.html": "<html>{{template \"content\" .}}</html>",
			"page.html":           "{{define \"content\"}}Hello, {{if .loggedInUser}}{{.loggedInUser.Username}}{{else}}Guest{{end}}!{{end}}",
		},
	}
	httpHelper := NewHttpHelper(templateFS)

	t.Run("Without ID Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, &models.Settings{AppName: "TestApp", UITheme: "light"})
		req = req.WithContext(ctx)

		data := map[string]interface{}{}

		buf, err := httpHelper.RenderTemplateToBuffer(req, "layouts/layout.html", "page.html", data)

		assert.NoError(t, err)
		assert.NotNil(t, buf)
		assert.Contains(t, buf.String(), "Hello, Guest!")
	})

	t.Run("With ID Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, &models.Settings{AppName: "TestApp", UITheme: "light"})

		// Mock JwtInfo with ID Token
		jwtInfo := oauth.JwtInfo{
			IdToken: &oauth.JwtToken{
				Claims: map[string]interface{}{
					"sub":  "user123",
					"name": "Guest",
				},
			},
		}
		ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, jwtInfo)
		req = req.WithContext(ctx)

		data := map[string]interface{}{}

		buf, err := httpHelper.RenderTemplateToBuffer(req, "layouts/layout.html", "page.html", data)

		assert.NoError(t, err)
		assert.NotNil(t, buf)
		// With ID token containing "name" claim, it should render that name
		assert.Contains(t, buf.String(), "Hello, Guest!")
	})
}

func TestJsonError(t *testing.T) {
	templateFS := &mocks.TestFS{}
	httpHelper := NewHttpHelper(templateFS)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := customerrors.NewErrorDetail("test_error", "Test error description")
	httpHelper.JsonError(w, req, err)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err2 := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err2)

	assert.Equal(t, "test_error", response["error"])
	assert.Equal(t, "Test error description", response["error_description"])
}

func TestEncodeJson(t *testing.T) {
	templateFS := &mocks.TestFS{}
	httpHelper := NewHttpHelper(templateFS)

	req := httptest.NewRequest("GET", "/", nil)
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
	templateFS := &mocks.TestFS{}
	httpHelper := NewHttpHelper(templateFS)

	t.Run("Get from URL query", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/?key=value", nil)
		value := httpHelper.GetFromUrlQueryOrFormPost(req, "key")
		assert.Equal(t, "value", value)
	})

	t.Run("Get from form post", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", bytes.NewBufferString("key=value"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		err := req.ParseForm()
		assert.NoError(t, err)
		value := httpHelper.GetFromUrlQueryOrFormPost(req, "key")
		assert.Equal(t, "value", value)
	})
}

func TestLookupFromUrlQueryOrFormPost(t *testing.T) {
	templateFS := &mocks.TestFS{}
	httpHelper := NewHttpHelper(templateFS)

	// postForm builds a form-encoded POST, optionally with a query string of its own.
	postForm := func(target string, body string) *http.Request {
		req := httptest.NewRequest("POST", target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}

	tests := []struct {
		name          string
		request       *http.Request
		expectValue   string
		expectPresent bool
	}{
		{"Absent from the query", httptest.NewRequest("GET", "/?other=1", nil), "", false},
		{"Empty in the query is present", httptest.NewRequest("GET", "/?state=", nil), "", true},
		{"Present in the query", httptest.NewRequest("GET", "/?state=abc", nil), "abc", true},
		{"Whitespace in the query is untrimmed", httptest.NewRequest("GET", "/?state=%20%20%20", nil), "   ", true},
		{"Present in the body", postForm("/", "state=abc"), "abc", true},
		{"Empty in the body is present", postForm("/", "state="), "", true},
		{"A non-empty query beats the body", postForm("/?state=abc", "state=xyz"), "abc", true},
		{"An empty query falls through to the body", postForm("/?state=", "state=xyz"), "xyz", true},
		{"Absent from the body", postForm("/", "other=1"), "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value, present := httpHelper.LookupFromUrlQueryOrFormPost(tc.request, "state")
			assert.Equal(t, tc.expectValue, value)
			assert.Equal(t, tc.expectPresent, present)
		})
	}
}

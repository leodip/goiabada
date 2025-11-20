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

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Error:")

	// Check if the response contains a request ID
	assert.Regexp(t, `Error: [a-zA-Z0-9/-]+`, w.Body.String(), "Response should contain a request ID")

	// Check if the content type is set correctly
	assert.Equal(t, "text/html; charset=UTF-8", w.Header().Get("Content-Type"))

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

		assert.NoError(t, err)
		assert.Equal(t, "text/html; charset=UTF-8", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), "Hello, John!")
		assert.Contains(t, w.Body.String(), "Status:")
		assert.Equal(t, http.StatusOK, w.Code) // Default status should be 200 OK
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

		assert.NoError(t, err)
		assert.Equal(t, "text/html; charset=UTF-8", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), "Hello, Jane!")
		assert.Contains(t, w.Body.String(), "Status: 201")
		assert.Equal(t, http.StatusCreated, w.Code)
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

package handlerhelpers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"errors"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/mocks"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubSettingsReader struct {
	settings LayoutSettings
	panic    bool
}

func (s stubSettingsReader) LayoutSettings(context.Context) LayoutSettings {
	if s.panic {
		panic("settings are absent")
	}
	return s.settings
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
	templateFS := &mocks.TestFS{
		FileContents: map[string]string{
			"layouts/no_menu_layout.html": "<html>{{template \"content\" .}}</html>",
			"error.html":                  "{{define \"content\"}}Error: {{.requestId}}{{end}}",
		},
	}
	httpHelper := NewHttpHelper(templateFS, stubSettingsReader{})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
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

// NotFound owns the answer to a stale or malformed URL, so this row owns the status, the page and
// the headers it carries; its silence is pinned in http_helper_logging_test.go (#279 decision 11).
func TestNotFound(t *testing.T) {
	httpHelper := NewHttpHelper(&mocks.TestFS{
		FileContents: map[string]string{
			"layouts/no_menu_layout.html": "<html>{{template \"content\" .}}</html>",
			"not_found.html":              "{{define \"content\"}}Not found{{end}}",
		},
	}, stubSettingsReader{})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/admin/clients/{clientId}/settings", func(w http.ResponseWriter, r *http.Request) {
		httpHelper.NotFound(w, r)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/admin/clients/not-a-number/settings", nil))

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
	httpHelper := NewHttpHelper(&mocks.TestFS{
		FileContents: map[string]string{
			"layouts/no_menu_layout.html": "<html>{{template \"content\" .}}</html>",
			"error.html":                  "{{define \"content\"}}Error: {{.requestId}}{{end}}",
		},
	}, stubSettingsReader{})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		httpHelper.NotFound(w, r)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	assert.Contains(t, w.Body.String(), "Error:")
}

func TestRenderTemplate(t *testing.T) {
	templateFS := &mocks.TestFS{
		FileContents: map[string]string{
			"layouts/layout.html": "<html>{{template \"content\" .}}</html>",
			"page.html":           "{{define \"content\"}}Hello, {{.Name}}! Status: {{._httpStatus}}{{end}}",
		},
	}
	httpHelper := NewHttpHelper(templateFS, stubSettingsReader{})

	t.Run("Without _httpStatus", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
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
		req := httptest.NewRequest("GET", "/", nil)
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
		emptyFS := &mocks.TestFS{FileContents: map[string]string{}}
		failing := NewHttpHelper(emptyFS, stubSettingsReader{})

		req := httptest.NewRequest("GET", "/", nil)
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
	templateFS := &mocks.TestFS{
		FileContents: map[string]string{
			"layouts/layout.html": "<html>{{template \"content\" .}}</html>",
			"page.html":           "{{define \"content\"}}Hello, {{if .loggedInUser}}{{.loggedInUser.Username}}{{else}}Guest{{end}}!{{end}}",
		},
	}
	httpHelper := NewHttpHelper(templateFS, stubSettingsReader{})

	t.Run("Without ID Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		data := map[string]interface{}{}

		buf, err := httpHelper.RenderTemplateToBuffer(req, "layouts/layout.html", "page.html", data)

		assert.NoError(t, err)
		assert.NotNil(t, buf)
		assert.Contains(t, buf.String(), "Hello, Guest!")
	})

	t.Run("With ID Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := req.Context()

		// Mock JwtInfo with ID Token
		jwtInfo := oauthclient.JwtInfo{
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

	// The isAdmin bind is the other half of the enrichment #385 moved here out of core, and
	// the console's layouts gate the admin menu on it. It is true only for a token carrying the
	// auth server's manage scope, which is why both arms are here: the scope string is assembled
	// from two core constants and a token holding a different scope must not light the menu.
	t.Run("isAdmin follows the access token's scope", func(t *testing.T) {
		withAccessToken := func(scope string) *http.Request {
			req := httptest.NewRequest("GET", "/", nil)
			jwtInfo := oauthclient.JwtInfo{
				AccessToken: &oauth.JwtToken{Claims: map[string]interface{}{"scope": scope}},
			}
			return req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo))
		}
		manageScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManagePermissionIdentifier

		data := map[string]interface{}{}
		_, err := httpHelper.RenderTemplateToBuffer(
			withAccessToken(manageScope), "layouts/layout.html", "page.html", data)
		require.NoError(t, err)
		assert.Equal(t, true, data["isAdmin"])

		other := map[string]interface{}{}
		_, err = httpHelper.RenderTemplateToBuffer(
			withAccessToken(coreconstants.AuthServerResourceIdentifier+":"+coreconstants.ManageAccountPermissionIdentifier),
			"layouts/layout.html", "page.html", other)
		require.NoError(t, err)
		assert.NotContains(t, other, "isAdmin")
	})

	t.Run("Layout settings reach the template", func(t *testing.T) {
		templateFS := &mocks.TestFS{FileContents: map[string]string{
			"layouts/layout.html": "<html>{{template \"content\" .}}</html>",
			"page.html":           "{{define \"content\"}}{{.appName}}|{{.uiTheme}}|{{.smtpEnabled}}{{end}}",
		}}
		httpHelper := NewHttpHelper(templateFS, stubSettingsReader{settings: LayoutSettings{
			AppName:     "sentinel app",
			UITheme:     "sentinel theme",
			SMTPEnabled: true,
		}})

		buf, err := httpHelper.RenderTemplateToBuffer(
			httptest.NewRequest("GET", "/", nil), "layouts/layout.html", "page.html", map[string]interface{}{})

		require.NoError(t, err)
		assert.Equal(t, "<html>sentinel app|sentinel theme|true</html>", buf.String())
	})

	t.Run("A settings reader panic is propagated", func(t *testing.T) {
		httpHelper := NewHttpHelper(templateFS, stubSettingsReader{panic: true})

		require.Panics(t, func() {
			_, _ = httpHelper.RenderTemplateToBuffer(
				httptest.NewRequest("GET", "/", nil), "layouts/layout.html", "page.html", map[string]interface{}{})
		})
	})
}

func TestJsonError(t *testing.T) {
	templateFS := &mocks.TestFS{}
	httpHelper := NewHttpHelper(templateFS, stubSettingsReader{})

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
	// The detail names no status, so it defaults to 500 and the description picks up the request
	// id the way every other 500 on this surface does. There is no request id middleware on this
	// bare request, so the id is empty; http_helper_logging_test.go owns the row that pins the
	// correlation itself.
	assert.Contains(t, response["error_description"], "Test error description")
}

func TestEncodeJson(t *testing.T) {
	templateFS := &mocks.TestFS{}
	httpHelper := NewHttpHelper(templateFS, stubSettingsReader{})

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

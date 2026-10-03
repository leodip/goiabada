package handlerhelpers

import (
	"context"
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
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRequest is httptest.NewRequest with settings on its context, as MiddlewareSettingsCache puts
// them there for every application route. A row about a render without settings builds its request
// with httptest.NewRequest instead.
func newRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	return req.WithContext(reqctx.WithSettings(req.Context(), &api.PublicSettingsResponse{}))
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
	// placement of the Cache-Control write depends on: it sits after renderToBuffer has
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

// renderPage renders through RenderTemplate, the renderer's one way to a page, and answers what the
// response carries. A render RenderTemplate refuses writes nothing, so the body is empty then.
func renderPage(h *HttpHelper, r *http.Request, layoutName, templateName string,
	data map[string]interface{}) (string, error) {

	w := httptest.NewRecorder()
	err := h.RenderTemplate(w, r, layoutName, templateName, data)
	return w.Body.String(), err
}

func TestRenderTemplate_Binds(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"page.html":           {Data: []byte("{{define \"content\"}}Hello, {{if .loggedInUser}}{{.loggedInUser.Username}}{{else}}Guest{{end}}!{{end}}")},
	}
	httpHelper := NewHttpHelper(templateFS)

	t.Run("Without ID Token", func(t *testing.T) {
		req := newRequest("GET", "/", nil)
		data := map[string]interface{}{}

		body, err := renderPage(httpHelper, req, "layouts/layout.html", "page.html", data)

		assert.NoError(t, err)
		assert.Contains(t, body, "Hello, Guest!")
	})

	t.Run("With ID Token", func(t *testing.T) {
		req := newRequest("GET", "/", nil)
		ctx := req.Context()

		jwtInfo := oauthclient.JwtInfo{
			IdToken: &oauth.JwtToken{
				Claims: map[string]interface{}{
					"sub":  "user123",
					"name": "Alice",
				},
			},
		}
		ctx = reqctx.WithJwtInfo(ctx, jwtInfo)
		req = req.WithContext(ctx)

		data := map[string]interface{}{}

		body, err := renderPage(httpHelper, req, "layouts/layout.html", "page.html", data)

		assert.NoError(t, err)
		// With ID token containing "name" claim, it should render that name
		assert.Contains(t, body, "Hello, Alice!")
	})

	// The isAdmin bind is the other half of the enrichment #385 moved here out of core, and
	// the console's layouts gate the admin menu on it. It is true only for a grant carrying the
	// auth server's manage scope, which is why both arms are here: the scope string is assembled
	// from two core constants and a grant holding a different scope must not light the menu. The
	// grant is the token response's scope, not anything inside the access token, which the console
	// carries without decoding (#427).
	t.Run("isAdmin follows the granted scope", func(t *testing.T) {
		withAccessToken := func(scope string) *http.Request {
			req := newRequest("GET", "/", nil)
			jwtInfo := oauthclient.JwtInfo{
				TokenResponse: oauth.TokenResponse{AccessToken: "opaque", Scope: "openid " + scope},
				IdToken:       &oauth.JwtToken{TokenBase64: "i"},
			}
			return req.WithContext(reqctx.WithJwtInfo(req.Context(), jwtInfo))
		}
		manageScope := coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManagePermissionIdentifier

		data := map[string]interface{}{}
		_, err := renderPage(httpHelper,
			withAccessToken(manageScope), "layouts/layout.html", "page.html", data)
		require.NoError(t, err)
		assert.Equal(t, true, data["isAdmin"])

		other := map[string]interface{}{}
		_, err = renderPage(httpHelper,
			withAccessToken(coreconstants.AuthServerResourceIdentifier+":"+coreconstants.ManageAccountPermissionIdentifier),
			"layouts/layout.html", "page.html", other)
		require.NoError(t, err)
		assert.NotContains(t, other, "isAdmin")
	})

	t.Run("Layout settings reach the template", func(t *testing.T) {
		layoutFS := fstest.MapFS{
			"layouts/layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
			"page.html":           {Data: []byte("{{define \"content\"}}{{.appName}}|{{.uiTheme}}|{{.smtpEnabled}}{{end}}")},
		}
		httpHelper := NewHttpHelper(layoutFS)
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(reqctx.WithSettings(req.Context(), &api.PublicSettingsResponse{
			AppName:     "sentinel app",
			UITheme:     "sentinel theme",
			SMTPEnabled: true,
		}))

		body, err := renderPage(httpHelper, req, "layouts/layout.html", "page.html", map[string]interface{}{})

		require.NoError(t, err)
		assert.Equal(t, "<html>sentinel app|sentinel theme|true</html>", body)
	})

	// Every application route runs under MiddlewareSettingsCache, so a render without settings is
	// a wiring defect. It is refused with the one sentinel, for the caller's 500 path to answer,
	// writes nothing, and binds nothing into the page data. The page would otherwise render under
	// an invented blank app name and theme (#440 decision 3).
	t.Run("Without settings the render is refused", func(t *testing.T) {
		for name, req := range map[string]*http.Request{
			"nothing written":       httptest.NewRequest("GET", "/", nil),
			"a nil pointer written": httptest.NewRequest("GET", "/", nil).WithContext(reqctx.WithSettings(context.Background(), nil)),
		} {
			t.Run(name, func(t *testing.T) {
				data := map[string]interface{}{}
				w := httptest.NewRecorder()

				err := httpHelper.RenderTemplate(w, req, "layouts/layout.html", "page.html", data)

				require.ErrorIs(t, err, reqctx.ErrNoSettings)
				assert.Empty(t, data)
				assert.Empty(t, w.Body.String())
				assert.Empty(t, w.Result().Header.Get("Content-Type"))
			})
		}
	})
}

// The page named is the page rendered, in every locale. The per-locale lookup copied from the auth
// server tried <name>.<locale>.html first for anything under emails/, which this binary has no
// template under and never sends; the case is a tree that has both files, so a locale variant
// served here could only come from that lookup (#440).
func TestRenderTemplate_RendersTheTemplateNamedWhateverTheLocale(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/layout.html":        {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"emails/note.html":           {Data: []byte("{{define \"content\"}}the page named{{end}}")},
		"emails/note.pt-BR.html":     {Data: []byte("{{define \"content\"}}a locale variant{{end}}")},
		"account_profile.html":       {Data: []byte("{{define \"content\"}}the profile{{end}}")},
		"account_profile.pt-BR.html": {Data: []byte("{{define \"content\"}}a locale variant{{end}}")},
	}
	httpHelper := NewHttpHelper(templateFS)

	for _, templateName := range []string{"/emails/note.html", "emails/note.html"} {
		t.Run(templateName, func(t *testing.T) {
			req := newRequest("GET", "/", nil)
			req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))
			require.Equal(t, "pt-BR", i18n.LocaleTag(req.Context()), "the request is in the variant's locale")

			body, err := renderPage(httpHelper, req, "/layouts/layout.html", templateName, map[string]interface{}{})

			require.NoError(t, err)
			assert.Equal(t, "<html>the page named</html>", body)
		})
	}

	t.Run("a page outside emails/", func(t *testing.T) {
		req := newRequest("GET", "/", nil)
		req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))

		body, err := renderPage(httpHelper, req, "/layouts/layout.html", "/account_profile.html", map[string]interface{}{})

		require.NoError(t, err)
		assert.Equal(t, "<html>the profile</html>", body)
	})
}

// A nil bind map is allocated rather than written into, which would panic. The render still binds
// the layout's values, so the page sees the settings as it would through a caller's own map (#435).
func TestRenderTemplate_NilDataMap(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"page.html":           {Data: []byte("{{define \"content\"}}{{.appName}}|{{.urlPath}}{{end}}")},
	}
	httpHelper := NewHttpHelper(templateFS)
	req := httptest.NewRequest("GET", "/some/page", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &api.PublicSettingsResponse{AppName: "sentinel app"}))

	body, err := renderPage(httpHelper, req, "layouts/layout.html", "page.html", nil)

	require.NoError(t, err)
	assert.Equal(t, "<html>sentinel app|/some/page</html>", body)
}

// The menu's full name is joined from the ID token's three name claims by the same rule
// UserFullName applies to a user response, and the rows are TestFullNames_JoinTheSamePartsFromBothShapes'
// own: the one that would expose a separate join is a missing part, where a hand-written
// concatenation leaves a doubled or a dangling space (#373, #440).
func TestRenderTemplate_MenuNameJoinsTheNameClaims(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/layout.html": {Data: []byte("<html>{{template \"content\" .}}</html>")},
		"page.html":           {Data: []byte("{{define \"content\"}}[{{.loggedInUser.GetFullName}}]{{end}}")},
	}
	httpHelper := NewHttpHelper(templateFS)

	for _, tc := range []struct {
		name                              string
		givenName, middleName, familyName string
		want                              string
	}{
		{"all three", "Jane", "Q", "Doe", "Jane Q Doe"},
		{"no middle name", "Jane", "", "Doe", "Jane Doe"},
		{"given name only", "Jane", "", "", "Jane"},
		{"family name only", "", "", "Doe", "Doe"},
		{"middle name only", "", "Q", "", "Q"},
		{"nothing at all", "", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest("GET", "/", nil)
			req = req.WithContext(reqctx.WithJwtInfo(req.Context(), oauthclient.JwtInfo{
				IdToken: &oauth.JwtToken{Claims: map[string]interface{}{
					"sub":         "user123",
					"given_name":  tc.givenName,
					"middle_name": tc.middleName,
					"family_name": tc.familyName,
				}},
			}))

			body, err := renderPage(httpHelper, req, "layouts/layout.html", "page.html", map[string]interface{}{})

			require.NoError(t, err)
			assert.Equal(t, "<html>["+tc.want+"]</html>", body)
		})
	}
}

// Every file under partials/ is parsed beside the layout and the page, which is how a page calls a
// fragment it does not define. The second case is the first one's tree without the fragment, so a
// pass there cannot come from anything but the partials branch (#431).
func TestRenderTemplate_Partials(t *testing.T) {
	layout := []byte(`<html>{{template "content" .}}</html>`)
	page := []byte(`{{define "content"}}[{{template "badge" .}}]{{end}}`)
	render := func(templateFS fstest.MapFS) (string, error) {
		return renderPage(NewHttpHelper(templateFS),
			newRequest("GET", "/", nil), "layouts/layout.html", "page.html", map[string]interface{}{})
	}

	t.Run("A template defined under partials is parsed with the page", func(t *testing.T) {
		body, err := render(fstest.MapFS{
			"layouts/layout.html": {Data: layout},
			"page.html":           {Data: page},
			"partials/badge.html": {Data: []byte(`{{define "badge"}}the badge{{end}}`)},
		})

		require.NoError(t, err)
		assert.Equal(t, "<html>[the badge]</html>", body)
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
		body, err := render(fstest.MapFS{
			"layouts/layout.html": {Data: layout},
			"page.html":           {Data: []byte(`{{define "content"}}no fragments{{end}}`)},
			"partials":            {Mode: fs.ModeDir},
		})

		require.NoError(t, err)
		assert.Equal(t, "<html>no fragments</html>", body)
	})
}

func TestJsonError(t *testing.T) {
	templateFS := fstest.MapFS{}
	httpHelper := NewHttpHelper(templateFS)

	req := newRequest("GET", "/", nil)
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

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mock_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mock_oauth "github.com/leodip/goiabada/core/oauth/mocks"
	mock_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

// recordingErrorRenderer captures what the middleware handed the error page. It
// answers the way *handlerhelpers.HttpHelper does once the page is rendered: 500,
// with a body that carries the generic localized message and nothing about the
// cause.
type recordingErrorRenderer struct {
	calls int
	err   error
}

func (rec *recordingErrorRenderer) InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	rec.calls++
	rec.err = err
	http.Error(w, i18n.T(r.Context(), "error.body"), http.StatusInternalServerError)
}

// TestMiddlewareJwt_ServerErrorsRenderThePageAndKeepTheCauseOutOfTheResponse covers
// every site in this middleware that used to answer with http.Error and the Go
// error text.
//
// Two claims per site, and the second is the one that matters. That the response is
// a 500 was already true and is asserted by the older tests in
// middleware_jwt_test.go, which is why it cannot stand alone here: a middleware
// that kept calling http.Error with the raw message would satisfy it. So each row
// also requires that the cause reached the renderer, where it is logged against the
// request id, and did not reach the response body, where it was an untranslatable
// internal detail in front of whoever was refused.
func TestMiddlewareJwt_ServerErrorsRenderThePageAndKeepTheCauseOutOfTheResponse(t *testing.T) {
	const sessionName = "test-session"

	// A phrase from the message the site logs. Asserting it present in the error and
	// absent from the body is what distinguishes rendering the page from writing the
	// cause out, which is the whole of this change.
	tests := []struct {
		name      string
		wantCause string
		build     func(t *testing.T, rec *recordingErrorRenderer) (http.Handler, *http.Request)
	}{
		{
			name:      "the session cannot be read",
			wantCause: "unable to get the session",
			build: func(t *testing.T, rec *recordingErrorRenderer) (http.Handler, *http.Request) {
				store := new(mock_sessionstore.Store)
				store.On("Get", mock.Anything, sessionName).Return(nil, assert.AnError)

				m := NewMiddlewareJwt(store, sessionName, new(mock_oauth.TokenParser),
					new(mock_handler_helpers.AuthHelper), rec, nil,
					"http://localhost:9090", "http://localhost:9091", "", "")

				return m.JwtSessionHandler()(mustNotRun(t)), httptest.NewRequest(http.MethodGet, "/", nil)
			},
		},
		{
			name:      "the session holds something that is not a TokenResponse",
			wantCause: "unable to cast the session value to TokenResponse",
			build: func(t *testing.T, rec *recordingErrorRenderer) (http.Handler, *http.Request) {
				store := new(mock_sessionstore.Store)
				store.On("Get", mock.Anything, sessionName).Return(&sessions.Session{
					Values: map[interface{}]interface{}{constants.SessionKeyJwt: "not a token response"},
				}, nil)

				m := NewMiddlewareJwt(store, sessionName, new(mock_oauth.TokenParser),
					new(mock_handler_helpers.AuthHelper), rec, nil,
					"http://localhost:9090", "http://localhost:9091", "", "")

				return m.JwtSessionHandler()(mustNotRun(t)), httptest.NewRequest(http.MethodGet, "/", nil)
			},
		},
		{
			name:      "clearing an unrefreshable session cannot be saved",
			wantCause: "unable to save the session",
			build: func(t *testing.T, rec *recordingErrorRenderer) (http.Handler, *http.Request) {
				store := new(mock_sessionstore.Store)
				// No refresh token, so refreshToken reports "not refreshed" without a
				// network call and the middleware falls through to clearing the session.
				store.On("Get", mock.Anything, sessionName).Return(&sessions.Session{
					Values: map[interface{}]interface{}{
						constants.SessionKeyJwt: oauth.TokenResponse{AccessToken: "expired"},
					},
				}, nil)
				store.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError)

				parser := new(mock_oauth.TokenParser)
				parser.On("DecodeAndValidateTokenString", "expired", mock.Anything, true).
					Return(nil, assert.AnError)

				m := NewMiddlewareJwt(store, sessionName, parser,
					new(mock_handler_helpers.AuthHelper), rec, nil,
					"http://localhost:9090", "http://localhost:9091", "", "")

				return m.JwtSessionHandler()(mustNotRun(t)), httptest.NewRequest(http.MethodGet, "/", nil)
			},
		},
		{
			name:      "clearing a session whose tokens carry a foreign issuer cannot be saved",
			wantCause: "unable to save the session",
			build: func(t *testing.T, rec *recordingErrorRenderer) (http.Handler, *http.Request) {
				token := &oauth.JwtToken{
					TokenBase64: "valid",
					Claims:      map[string]interface{}{"iss": "https://someone-else.example"},
				}

				store := new(mock_sessionstore.Store)
				store.On("Get", mock.Anything, sessionName).Return(&sessions.Session{
					Values: map[interface{}]interface{}{
						constants.SessionKeyJwt: oauth.TokenResponse{AccessToken: "valid"},
					},
				}, nil)
				store.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError)

				parser := new(mock_oauth.TokenParser)
				parser.On("DecodeAndValidateTokenString", "valid", mock.Anything, true).Return(token, nil)
				parser.On("DecodeAndValidateTokenResponse", mock.AnythingOfType("*oauth.TokenResponse")).
					Return(&oauth.JwtInfo{
						TokenResponse: oauth.TokenResponse{AccessToken: "valid"},
						AccessToken:   token,
					}, nil)

				m := NewMiddlewareJwt(store, sessionName, parser,
					new(mock_handler_helpers.AuthHelper), rec, nil,
					"http://localhost:9090", "http://localhost:9091", "", "")

				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
					&models.Settings{Issuer: "https://this-deployment.example"}))

				return m.JwtSessionHandler()(mustNotRun(t)), req
			},
		},
		{
			name:      "the context holds something that is not a JwtInfo",
			wantCause: "unable to cast the context value to JwtInfo",
			build: func(t *testing.T, rec *recordingErrorRenderer) (http.Handler, *http.Request) {
				m := NewMiddlewareJwt(new(mock_sessionstore.Store), sessionName,
					new(mock_oauth.TokenParser), new(mock_handler_helpers.AuthHelper), rec, nil,
					"http://localhost:9090", "http://localhost:9091", "", "")

				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req = req.WithContext(context.WithValue(req.Context(),
					constants.ContextKeyJwtInfo, "not a JwtInfo"))

				return m.RequiresScope([]string{"required:scope"})(mustNotRun(t)), req
			},
		},
		{
			name:      "the redirect to the authorize endpoint fails",
			wantCause: "unable to redirect to authorize",
			build: func(t *testing.T, rec *recordingErrorRenderer) (http.Handler, *http.Request) {
				jwtInfo := oauth.JwtInfo{}

				helper := new(mock_handler_helpers.AuthHelper)
				helper.On("IsAuthorizedToAccessResource", jwtInfo, []string{"required:scope"}).Return(false)
				helper.On("IsAuthenticated", jwtInfo).Return(false)
				helper.On("RedirToAuthorize", mock.Anything, mock.Anything,
					constants.AdminConsoleClientIdentifier, mock.AnythingOfType("string"),
					mock.AnythingOfType("string")).Return(assert.AnError)

				m := NewMiddlewareJwt(new(mock_sessionstore.Store), sessionName,
					new(mock_oauth.TokenParser), helper, rec, nil,
					"http://localhost:9090", "http://localhost:9091",
					constants.AdminConsoleClientIdentifier, "")

				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req = req.WithContext(context.WithValue(req.Context(),
					constants.ContextKeyJwtInfo, jwtInfo))

				return m.RequiresScope([]string{"required:scope"})(mustNotRun(t)), req
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingErrorRenderer{}
			handler, req := tt.build(t, rec)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			assert.Equal(t, http.StatusInternalServerError, recorder.Code)

			require.Equal(t, 1, rec.calls,
				"the site must answer through the error page, not through http.Error")
			require.Error(t, rec.err)
			assert.Contains(t, rec.err.Error(), tt.wantCause,
				"the cause must reach the renderer, which logs it against the request id")

			body := recorder.Body.String()
			assert.NotContains(t, body, tt.wantCause,
				"the cause must not reach the response: it is an internal detail and has no translation")
			assert.Equal(t, i18n.T(context.Background(), "error.body"), strings.TrimSpace(body))
		})
	}
}

// mustNotRun is the next handler for a chain that must stop at the middleware.
func mustNotRun(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the next handler ran, want the request refused by the middleware")
	})
}

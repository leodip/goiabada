package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// TestHandleAuthorizeGet_MaxAge covers what /auth/authorize does with max_age itself: the raw value
// goes to ValidateRequest, a malformed one is treated as absent when deciding whether the browser
// holds a valid session, and whoever is at the browser is answered as #213 answers any other
// validation failure. The validator is mocked here; the parse and the refusal are
// oidc.ParseMaxAge's and ValidateRequest's own tables (#243).
func TestHandleAuthorizeGet_MaxAge(t *testing.T) {
	const redirectURI = "https://legit.example/cb"
	const sessionIdentifier = "session-243"

	maxAgeRefusal := customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
		"The max_age parameter must be a non-negative integer.", http.StatusBadRequest)

	type fixture struct {
		pageRenderer       *mocks_handlers.PageRenderer
		authHelper         *mocks_handlers.AuthHelper
		userSessionManager *mocks_handlers.UserSessionManager
		database           *mocks_data.Database
		authorizeValidator *mocks_handlers.AuthorizeValidator
		handler            http.HandlerFunc
		req                *http.Request
		rr                 *httptest.ResponseRecorder
		saved              *ceremony.AuthContext
	}

	// arrange builds the request with the settings and the browser's session identifier on it,
	// and the stubs every row shares up to the session predicate.
	arrange := func(t *testing.T, query string) *fixture {
		f := &fixture{
			pageRenderer:       mocks_handlers.NewPageRenderer(t),
			authHelper:         mocks_handlers.NewAuthHelper(t),
			userSessionManager: mocks_handlers.NewUserSessionManager(t),
			database:           mocks_data.NewDatabase(t),
			authorizeValidator: mocks_handlers.NewAuthorizeValidator(t),
		}
		f.handler = HandleAuthorizeGet(f.pageRenderer, f.authHelper, f.userSessionManager, f.database, nil,
			f.authorizeValidator, mocks_handlers.NewAuditLogger(t), mocks_handlers.NewPermissionChecker(t),
			mocks_handlers.NewTokenParser(t), testBaseURL)

		target := "/authorize?client_id=test-client&redirect_uri=" + url.QueryEscape(redirectURI) +
			"&response_type=code&scope=openid&state=s1&" + query
		f.req = withSessionSettings(httptest.NewRequest("GET", target, nil))
		f.req = f.req.WithContext(reqctx.WithSessionIdentifier(f.req.Context(), sessionIdentifier))
		f.rr = httptest.NewRecorder()

		f.authHelper.On("SaveAuthContext", f.rr, f.req, mock.AnythingOfType("*ceremony.AuthContext")).
			Run(func(args mock.Arguments) {
				saved := *args.Get(2).(*ceremony.AuthContext)
				f.saved = &saved
			}).Return(nil)
		f.authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything,
			mock.AnythingOfType("*protocolvalidation.ValidateClientAndRedirectURIInput")).Return(nil)
		f.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
			&models.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: models.AcrLevel1}, nil)
		f.authorizeValidator.On("ValidateUnsupportedRequestParameters",
			mock.AnythingOfType("*protocolvalidation.ValidateUnsupportedRequestParametersInput")).Return(nil)
		stubRegisteredRedirectURI(f.database, redirectURI)
		return f
	}

	// refuseMaxAge makes ValidateRequest refuse, and only when it was handed the raw value.
	refuseMaxAge := func(f *fixture, raw string) {
		f.authorizeValidator.On("ValidateRequest", mock.MatchedBy(func(input *protocolvalidation.ValidateRequestInput) bool {
			return input.MaxAge == raw
		})).Return(maxAgeRefusal)
	}

	t.Run("a session holder's malformed max_age is refused at once, the session judged without it", func(t *testing.T) {
		f := arrange(t, "max_age=abc")

		userSession := &models.UserSession{Id: 7, UserId: 1}
		f.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).
			Return(userSession, nil)
		// nil, not 0: a value ValidateRequest is about to refuse must not decide the session, and
		// read as 0 it would call every session invalid and send a signed-in user to log in for a
		// request that is refused anyway. The two lifetimes are the request's settings, idle first.
		f.userSessionManager.On("HasValidUserSession", userSession,
			testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, (*int64)(nil)).Return(true)
		refuseMaxAge(f, "abc")
		f.authHelper.On("ClearAuthContext", f.rr, f.req).Return(nil)

		f.handler.ServeHTTP(f.rr, f.req)

		require.Equal(t, http.StatusFound, f.rr.Code)
		location, err := url.Parse(f.rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "legit.example", location.Host)
		assert.Equal(t, "invalid_request", location.Query().Get("error"))
		assert.Equal(t, maxAgeRefusal.GetDescription(), location.Query().Get("error_description"))
		assert.Equal(t, "s1", location.Query().Get("state"))
	})

	t.Run("a silent request's malformed max_age is refused at once, with no session read", func(t *testing.T) {
		f := arrange(t, "max_age=abc&prompt=none")
		refuseMaxAge(f, "abc")
		f.authHelper.On("ClearAuthContext", f.rr, f.req).Return(nil)

		f.handler.ServeHTTP(f.rr, f.req)

		require.Equal(t, http.StatusFound, f.rr.Code)
		location, err := url.Parse(f.rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "legit.example", location.Host)
		assert.Equal(t, "invalid_request", location.Query().Get("error"))
		f.database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("an anonymous browser's malformed max_age is parked and the visitor sent to log in", func(t *testing.T) {
		f := arrange(t, "max_age=abc")
		f.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).
			Return((*models.UserSession)(nil), nil)
		f.userSessionManager.On("HasValidUserSession", (*models.UserSession)(nil),
			testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, (*int64)(nil)).Return(false)
		refuseMaxAge(f, "abc")

		f.handler.ServeHTTP(f.rr, f.req)

		require.Equal(t, http.StatusFound, f.rr.Code)
		assert.Equal(t, testBaseURL+"/auth/level1", f.rr.Header().Get("Location"))
		require.NotNil(t, f.saved)
		assert.Equal(t, ceremony.AuthStateRequiresLevel1, f.saved.AuthState)
		assert.Equal(t, "invalid_request", f.saved.DeferredErrorCode)
		assert.Equal(t, maxAgeRefusal.GetDescription(), f.saved.DeferredErrorDescription)
		assert.Equal(t, "abc", f.saved.MaxAge, "the raw value stays on the context, as its wire shape requires")
	})

	t.Run("prompt=none judges the session with max_age, then without it to name the cause", func(t *testing.T) {
		f := arrange(t, "max_age=600&prompt=none")
		f.authorizeValidator.On("ValidateRequest", mock.MatchedBy(func(input *protocolvalidation.ValidateRequestInput) bool {
			return input.MaxAge == "600"
		})).Return(nil)
		f.authorizeValidator.On("ValidateScopes", mock.Anything, "openid").Return(nil)
		f.authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

		userSession := &models.UserSession{Id: 7, UserId: 1, AcrLevel: models.AcrLevel1,
			User: models.User{Id: 1, Enabled: true}}
		f.database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).
			Return(userSession, nil)
		f.database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)
		f.userSessionManager.On("HasValidUserSession", userSession,
			testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, mock.MatchedBy(func(maxAge *int64) bool {
				return maxAge != nil && *maxAge == 600
			})).Return(false)
		f.userSessionManager.On("HasValidUserSession", userSession,
			testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, (*int64)(nil)).Return(true)
		f.authHelper.On("ClearAuthContext", f.rr, f.req).Return(nil)

		f.handler.ServeHTTP(f.rr, f.req)

		require.Equal(t, http.StatusFound, f.rr.Code)
		location, err := url.Parse(f.rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "login_required", location.Query().Get("error"))
		assert.Equal(t, "Session age exceeds max_age", location.Query().Get("error_description"))
	})
}

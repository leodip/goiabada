package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// A request /auth/authorize answers at once with an error stores nothing and removes nothing (#246
// decision 1). The browser below holds a sign-in in progress, at its password page, and the request
// arrives from another tab or another site in the same browser: the client is answered, the sign-in
// is still held as it was, and no cookie is written. Driven over the real ceremony store, so what
// the browser holds afterwards is what the store reads, not what a mock was told.
func TestHandleAuthorizeGet_AnErrorAnsweredAtOnceLeavesTheSignInInProgress(t *testing.T) {
	inProgress := &ceremony.AuthContext{
		CeremonyId: testCeremonyId,
		AuthState:  ceremony.AuthStateLevel1Password,
		ClientId:   "other-client",
		State:      "the-first-request",
	}

	testCases := []struct {
		name    string
		query   url.Values
		arrange func(database *datamocks.Database, validator *handlersmocks.AuthorizeValidator,
			sessions *handlersmocks.UserSessionManager)
		wantError string
	}{
		{
			// A browser with a valid user session is answered at once, by redirect, whoever is at it.
			name: "an interactive request refused over a valid session",
			query: url.Values{"client_id": {"test-client"}, "redirect_uri": {"https://example.com"},
				"response_type": {"code"}, "scope": {"openid"}},
			arrange: func(database *datamocks.Database, validator *handlersmocks.AuthorizeValidator,
				sessions *handlersmocks.UserSessionManager) {
				stubAuthenticatedBrowser(database, sessions)
				validator.On("ValidateRequest", mock.AnythingOfType("*protocolvalidation.ValidateRequestInput")).Return(
					oauth.NewErrorDetailWithHTTPStatus("invalid_request", "The request is refused.", http.StatusBadRequest))
			},
			wantError: "invalid_request",
		},
		{
			// The browser holds no user session, so a silent request is answered login_required.
			name: "a prompt=none request answered login_required",
			query: url.Values{"client_id": {"test-client"}, "redirect_uri": {"https://example.com"},
				"response_type": {"code"}, "scope": {"openid"}, "prompt": {"none"}},
			arrange: func(database *datamocks.Database, validator *handlersmocks.AuthorizeValidator,
				sessions *handlersmocks.UserSessionManager) {
				validator.On("ValidateRequest", mock.AnythingOfType("*protocolvalidation.ValidateRequestInput")).Return(nil)
				validator.On("ValidateScopes", mock.Anything, "openid").Return(nil)
				validator.On("ValidatePrompt", "none").Return("none", nil)
				database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, nil)
				sessions.On("HasValidUserSession", mock.Anything, mock.AnythingOfType("int"), mock.AnythingOfType("int"),
					mock.Anything).Return(false).Maybe()
			},
			wantError: "login_required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ceremonyStore, cookies := holdingCeremony(t, inProgress)

			pageRenderer := handlersmocks.NewPageRenderer(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			database := datamocks.NewDatabase(t)
			stubRegisteredRedirectURI(database, "https://example.com")
			authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
			handler := buildAuthorizeGet(authorizeGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      ceremonyStore,
				userSessionManager: userSessionManager,
				database:           database,
				authorizeValidator: authorizeValidator,
				auditLogger:        handlersmocks.NewAuditLogger(t),
				permissionChecker:  handlersmocks.NewPermissionChecker(t),
				tokenParser:        handlersmocks.NewTokenParser(t),
			})

			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything,
				mock.AnythingOfType("*protocolvalidation.ValidateClientAndRedirectURIInput")).Return(nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters",
				mock.AnythingOfType("*protocolvalidation.ValidateUnsupportedRequestParametersInput")).Return(nil)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
				&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1}, nil)
			tc.arrange(database, authorizeValidator, userSessionManager)

			req := withCookies(httptest.NewRequest(http.MethodGet, "/auth/authorize?"+tc.query.Encode(), nil), cookies)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Issuer: testResponseIssuer}))
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusFound, rr.Code)
			location, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, "https", location.Scheme)
			assert.Equal(t, "example.com", location.Host, "the client is answered at its redirect URI")
			assert.Equal(t, tc.wantError, location.Query().Get("error"))

			assert.Empty(t, rr.Result().Cookies(), "an error answered at once writes no cookie")
			assertStillHeld(t, ceremonyStore, cookies, inProgress)
		})
	}
}

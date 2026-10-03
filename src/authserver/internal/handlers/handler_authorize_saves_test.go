package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// A request /auth/authorize refuses before it has assigned a state writes no auth context (#436).
// It used to save the context twice before any state was set, as `initial`, which no gate accepts,
// so a malformed link opened in the middle of a sign-in replaced that sign-in with a record nothing
// could continue. Each row reaches a different refusal, and the mocks are strict: the store has no
// expectation at all, and the two AssertNotCalled lines say so in terms of the calls that matter,
// because a refusal that cleared the context would lose the sign-in just as surely as one that saved.
func TestHandleAuthorizeGet_ARefusalWritesNoAuthContext(t *testing.T) {
	validatorFault := errors.New("the clients table is unreachable")

	for _, tc := range []struct {
		name         string
		query        string
		validatorErr error
		expect       func(pageRenderer *handlersmocks.PageRenderer, rr *httptest.ResponseRecorder, req *http.Request)
	}{
		{
			name:         "an unknown client_id is refused on a page",
			query:        "client_id=no-such-client&redirect_uri=https://example.com&response_type=code&scope=openid",
			validatorErr: i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientNotFound, nil),
			expect: func(pageRenderer *handlersmocks.PageRenderer, rr *httptest.ResponseRecorder, req *http.Request) {
				pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
					mock.MatchedBy(func(data map[string]interface{}) bool {
						return data["_httpStatus"] == http.StatusOK
					})).Return(nil).Once()
			},
		},
		{
			name:         "an unregistered redirect_uri is refused on a page",
			query:        "client_id=test-client&redirect_uri=https://elsewhere.example&response_type=code&scope=openid",
			validatorErr: i18n.NewLocalizedError(i18n.ErrCodeAuthorizeRedirectURINotRegistered, nil),
			expect: func(pageRenderer *handlersmocks.PageRenderer, rr *httptest.ResponseRecorder, req *http.Request) {
				pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
					mock.MatchedBy(func(data map[string]interface{}) bool {
						return data["_httpStatus"] == http.StatusOK
					})).Return(nil).Once()
			},
		},
		{
			name:         "a validator fault answers 500",
			query:        "client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid",
			validatorErr: validatorFault,
			expect: func(pageRenderer *handlersmocks.PageRenderer, rr *httptest.ResponseRecorder, req *http.Request) {
				pageRenderer.On("InternalServerError", rr, req, validatorFault).Return().Once()
			},
		},
		{
			name:  "response_mode=jwt is refused 400 on a page",
			query: "client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&response_mode=jwt",
			expect: func(pageRenderer *handlersmocks.PageRenderer, rr *httptest.ResponseRecorder, req *http.Request) {
				pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
					mock.MatchedBy(func(data map[string]interface{}) bool {
						return data["_httpStatus"] == http.StatusBadRequest
					})).Return(nil).Once()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			database := datamocks.NewDatabase(t)
			authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			permissionChecker := handlersmocks.NewPermissionChecker(t)
			tokenParser := handlersmocks.NewTokenParser(t)

			handler := HandleAuthorizeGet(pageRenderer, ceremonyStore, userSessionManager, database, nil,
				authorizeValidator, auditLogger, permissionChecker, tokenParser, testBaseURL)

			req := httptest.NewRequest("GET", "/authorize?"+tc.query, nil)
			rr := httptest.NewRecorder()

			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything,
				mock.AnythingOfType("*protocolvalidation.ValidateClientAndRedirectURIInput")).Return(tc.validatorErr).Once()
			tc.expect(pageRenderer, rr, req)

			handler.ServeHTTP(rr, req)

			assert.Empty(t, rr.Header().Get("Location"), "a refusal sends the browser nowhere")
			ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
			ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything)
			pageRenderer.AssertExpectations(t)
			authorizeValidator.AssertExpectations(t)
		})
	}
}

// Every exit of /auth/authorize that saves the auth context saves it once, with the state that exit
// declares (#436). Before this change each of them was the third save of the request, after two that
// stored `initial`. The prompt=none exit, the sixth that saves, is pinned by the prompt=none cases in
// TestHandleAuthorizeGet_IdTokenHint, which hold it to one save carrying ready_to_issue_code.
//
// Every save is recorded rather than matched, so a second save of any shape fails the count, and
// the one save is asserted to carry the whole request as well as its state: the request fields are
// written once, in the literal, and now reach the store only through this save.
func TestHandleAuthorizeGet_EverySaveCarriesADeclaredState(t *testing.T) {
	const sessionSubject = "subject-of-the-session"

	for _, tc := range []struct {
		name         string
		extraQuery   string
		prompt       string
		hint         string // the sub of the id_token_hint, or none
		hasSession   bool
		scopeInvalid bool
		wantState    ceremony.AuthState
		wantDeferred string
		wantLocation string
	}{
		{
			name:         "no session",
			wantState:    ceremony.AuthStateRequiresLevel1,
			wantLocation: "/auth/level1",
		},
		{
			name:         "a valid session is reused",
			hasSession:   true,
			wantState:    ceremony.AuthStateLevel1ExistingSession,
			wantLocation: "/auth/level1completed",
		},
		{
			name:         "prompt=login",
			prompt:       "login",
			hasSession:   true,
			wantState:    ceremony.AuthStateRequiresLevel1,
			wantLocation: "/auth/level1",
		},
		{
			name:         "an id_token_hint naming another user",
			hint:         "subject-of-someone-else",
			hasSession:   true,
			wantState:    ceremony.AuthStateRequiresLevel1,
			wantLocation: "/auth/level1",
		},
		{
			name:         "a parked deferred error",
			scopeInvalid: true,
			wantState:    ceremony.AuthStateRequiresLevel1,
			wantDeferred: "invalid_scope",
			wantLocation: "/auth/level1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			database := datamocks.NewDatabase(t)
			stubRegisteredRedirectURI(database, "https://example.com")
			authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			permissionChecker := handlersmocks.NewPermissionChecker(t)
			tokenParser := handlersmocks.NewTokenParser(t)

			handler := HandleAuthorizeGet(pageRenderer, ceremonyStore, userSessionManager, database, nil,
				authorizeValidator, auditLogger, permissionChecker, tokenParser, testBaseURL)

			target := "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code" +
				"&scope=openid&state=the-state&nonce=the-nonce"
			if tc.prompt != "" {
				target += "&prompt=" + url.QueryEscape(tc.prompt)
			}
			if tc.hint != "" {
				target += "&id_token_hint=the-hint"
				tokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-hint", false).Return(
					&oauth.JwtToken{Claims: jwt.MapClaims{"iss": "https://issuer.example", "sub": tc.hint}}, nil)
			}

			req := httptest.NewRequest("GET", target, nil)
			ctx := reqctx.WithSettings(req.Context(), &record.Settings{Issuer: "https://issuer.example"})
			req = req.WithContext(reqctx.WithSessionIdentifier(ctx, "session-123"))
			rr := httptest.NewRecorder()

			client := &record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1}
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.Anything).Return(nil)
			authorizeValidator.On("ValidateRequest", mock.Anything).Return(nil)
			if tc.scopeInvalid {
				authorizeValidator.On("ValidateScopes", mock.Anything, "openid").Return(
					oauth.NewErrorDetailWithHTTPStatus("invalid_scope", "Invalid scope.", http.StatusBadRequest))
			} else {
				authorizeValidator.On("ValidateScopes", mock.Anything, "openid").Return(nil)
				authorizeValidator.On("ValidatePrompt", tc.prompt).Return(tc.prompt, nil)
			}

			// Maybe, because which exits look the session up is not what this table is about: the
			// prompt=login exit never does, and TestHandleAuthorizeGet_SessionLookupIsLazyAndFailsClosed
			// owns that.
			var userSession *record.UserSession
			if tc.hasSession {
				userSession = &record.UserSession{Id: 1, UserId: 123, AcrLevel: record.AcrLevel1, AuthMethods: "pwd",
					User: record.User{Id: 123, Enabled: true, Subject: sessionSubject}}
			}
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-123").
				Return(userSession, nil).Maybe()
			database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil).Maybe()
			userSessionManager.On("HasValidUserSession", userSession, mock.AnythingOfType("int"), mock.AnythingOfType("int"), mock.Anything).
				Return(tc.hasSession).Maybe()

			var saves []ceremony.AuthContext
			ceremonyStore.On("SaveAuthContext", rr, req, mock.AnythingOfType("*ceremony.AuthContext")).
				Run(func(args mock.Arguments) {
					saves = append(saves, *args.Get(2).(*ceremony.AuthContext))
				}).Return(nil)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code)
			require.Len(t, saves, 1, "each exit saves the auth context exactly once")
			saved := saves[0]
			assert.Equal(t, saved.CeremonyId, assertStepLocation(t, rr.Header().Get("Location"), tc.wantLocation),
				"the redirect names the ceremony this request just saved")
			assert.Equal(t, tc.wantState, saved.AuthState)
			assert.Equal(t, tc.wantDeferred, saved.DeferredErrorCode)

			assert.Len(t, saved.CeremonyId, ceremony.IdLength)
			assert.Equal(t, "test-client", saved.ClientId)
			assert.Equal(t, "https://example.com", saved.RedirectURI)
			assert.Equal(t, "code", saved.ResponseType)
			assert.Equal(t, "openid", saved.Scope)
			assert.Equal(t, "openid", saved.RequestedScope, "what a restart puts Scope back to")
			assert.Equal(t, "the-state", saved.State)
			assert.Equal(t, "the-nonce", saved.Nonce)
			assert.Equal(t, tc.hint, saved.IdTokenHintSub)
			if !tc.scopeInvalid {
				assert.Equal(t, record.AcrLevel1.String(), saved.TargetAcrLevel,
					"the target is fixed before the exit saves")
			}

			ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything)
			authorizeValidator.AssertExpectations(t)
		})
	}
}

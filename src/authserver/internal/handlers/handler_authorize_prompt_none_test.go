package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// handlePromptNone's steps 4 to 6 through the handler: each answer the step-up rule gives reaches
// its own description, and the rule's two answers keep step 5 between them. Which answer a session
// gets is ceremony.StepUpOwed's table; this is the thin seam showing prompt=none consults it and in
// what order (#437 seam 4).
func TestHandlePromptNone_StepUpAnswers(t *testing.T) {
	testCases := []struct {
		name            string
		target          record.AcrLevel
		sessionAcr      record.AcrLevel
		sessionOtpGen   int64
		userOtpGen      int64
		userOTPEnabled  bool
		wantDescription string
	}{
		{
			// Step 5 would refuse too; step 4 is asked first.
			name:            "a target above the session's level, before the missing authenticator",
			target:          record.AcrLevel2Mandatory,
			sessionAcr:      record.AcrLevel1,
			userOTPEnabled:  false,
			wantDescription: "Higher authentication level required",
		},
		{
			name:            "an unknown session level is insufficient",
			target:          record.AcrLevel1,
			sessionAcr:      "urn:goiabada:pwd",
			userOTPEnabled:  true,
			wantDescription: "Higher authentication level required",
		},
		{
			// Step 6 would refuse too; step 5 is asked first.
			name:            "a mandatory target with no authenticator, before the changed configuration",
			target:          record.AcrLevel2Mandatory,
			sessionAcr:      record.AcrLevel2Mandatory,
			sessionOtpGen:   2,
			userOtpGen:      3,
			userOTPEnabled:  false,
			wantDescription: "Additional authentication setup required",
		},
		{
			name:            "the authenticator changed since the session answered level 2",
			target:          record.AcrLevel2Optional,
			sessionAcr:      record.AcrLevel2Optional,
			sessionOtpGen:   2,
			userOtpGen:      3,
			userOTPEnabled:  true,
			wantDescription: "Authentication configuration has changed",
		},
	}

	for _, tc := range testCases {
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

			req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&prompt=none", nil)
			require.NoError(t, err)
			ctx := reqctx.WithSettings(req.Context(), &record.Settings{PKCERequired: true, Issuer: "https://test-issuer.com"})
			ctx = reqctx.WithSessionIdentifier(ctx, "session-1")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()

			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateClientAndRedirectURIInput")).Return(nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*protocolvalidation.ValidateUnsupportedRequestParametersInput")).Return(nil)
			authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*protocolvalidation.ValidateRequestInput")).Return(nil)
			authorizeValidator.On("ValidateScopes", mock.Anything, "openid").Return(nil)
			authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

			client := &record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: tc.target}
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

			userSession := &record.UserSession{
				Id:                  1,
				UserId:              7,
				AcrLevel:            tc.sessionAcr,
				AuthMethods:         "pwd",
				OtpConfigGeneration: tc.sessionOtpGen,
				User: record.User{
					Id:                  7,
					Enabled:             true,
					OTPEnabled:          tc.userOTPEnabled,
					OtpConfigGeneration: tc.userOtpGen,
				},
			}
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").Return(userSession, nil)
			database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)
			userSessionManager.On("HasValidUserSession", userSession, mock.AnythingOfType("int"), mock.AnythingOfType("int"), mock.AnythingOfType("*int64")).Return(true)
			ceremonyStore.On("ClearAuthContext", rr, req).Return(nil)

			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusFound, rr.Code)
			location, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, "interaction_required", location.Query().Get("error"))
			assert.Equal(t, tc.wantDescription, location.Query().Get("error_description"))
		})
	}
}

// Every read and write prompt=none makes, failing. Each answers 500 and nothing else: the client is
// not answered, because a read that failed is no answer, and taking it for "no session" or "no
// consent" would tell a signed-in user's client login_required or consent_required for a database
// fault. Which reads a request makes is decideSilentAuthentication's table; this is that each load
// stops on its fault (#437 seam 4).
func TestHandlePromptNone_LoadFaultsAnswer500(t *testing.T) {
	fault := errors.New("the database is unavailable")

	testCases := []struct {
		name  string
		fails string
	}{
		{"the session lookup", "GetUserSessionBySessionIdentifier"},
		{"the session's user", "UserSessionLoadUser"},
		{"the effective scope", "FilterOutScopesWhereUserIsNotAuthorized"},
		{"the consent", "GetConsentByUserIdAndClientId"},
		{"the session bump", "BumpUserSession"},
		{"the save", "SaveAuthContext"},
	}

	for _, tc := range testCases {
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

			req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&prompt=none", nil)
			require.NoError(t, err)
			ctx := reqctx.WithSettings(req.Context(), &record.Settings{Issuer: "https://test-issuer.com"})
			ctx = reqctx.WithSessionIdentifier(ctx, "session-1")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()

			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateClientAndRedirectURIInput")).Return(nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*protocolvalidation.ValidateUnsupportedRequestParametersInput")).Return(nil)
			authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*protocolvalidation.ValidateRequestInput")).Return(nil)
			authorizeValidator.On("ValidateScopes", mock.Anything, "openid").Return(nil)
			authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

			// ConsentRequired, so the consent is read and every load is reached.
			client := &record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1, ConsentRequired: true}
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

			userSession := &record.UserSession{
				Id:          1,
				UserId:      7,
				AcrLevel:    record.AcrLevel1,
				AuthMethods: "pwd",
				User:        record.User{Id: 7, Enabled: true},
			}

			// Each load answers until the one this row fails, and nothing after it is stubbed, so
			// a load made past the fault fails the test on the mock.
			steps := []struct {
				method string
				stub   func(fail bool)
			}{
				{"GetUserSessionBySessionIdentifier", func(fail bool) {
					if fail {
						database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").Return(nil, fault)
						return
					}
					database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").Return(userSession, nil)
				}},
				{"UserSessionLoadUser", func(fail bool) {
					if fail {
						database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(fault)
						return
					}
					database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)
					userSessionManager.On("HasValidUserSession", userSession, mock.AnythingOfType("int"), mock.AnythingOfType("int"), mock.AnythingOfType("*int64")).Return(true)
				}},
				{"FilterOutScopesWhereUserIsNotAuthorized", func(fail bool) {
					if fail {
						permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, "openid", &userSession.User).Return("", fault)
						return
					}
					permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, "openid", &userSession.User).Return("openid", nil)
				}},
				{"GetConsentByUserIdAndClientId", func(fail bool) {
					if fail {
						database.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(7), int64(1)).Return(nil, fault)
						return
					}
					database.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(7), int64(1)).Return(&record.UserConsent{Scope: "openid"}, nil)
				}},
				{"BumpUserSession", func(fail bool) {
					if fail {
						userSessionManager.On("BumpUserSession", mock.Anything, "session-1", int64(1), "", record.AcrLevel(""), mock.Anything).Return(nil, fault)
						return
					}
					userSessionManager.On("BumpUserSession", mock.Anything, "session-1", int64(1), "", record.AcrLevel(""), mock.Anything).Return(userSession, nil)
					auditLogger.On("Log", mock.Anything, audit.EventBumpedUserSession, mock.Anything).Return()
				}},
				{"SaveAuthContext", func(fail bool) {
					ceremonyStore.On("SaveAuthContext", rr, req, mock.AnythingOfType("*ceremony.AuthContext")).Return(fault)
				}},
			}
			for _, step := range steps {
				step.stub(step.method == tc.fails)
				if step.method == tc.fails {
					break
				}
			}

			pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
				return errors.Is(err, fault)
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			assert.Empty(t, rr.Header().Get("Location"), "a fault answers the client nothing")
			ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything)
		})
	}
}

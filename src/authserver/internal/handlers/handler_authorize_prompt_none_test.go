package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// authflow.decideSilentAuthentication's steps 5 to 7 through the handler: each answer the step-up
// rule gives reaches its own description, and the rule's two answers keep step 6 between them. Which
// answer a session gets is ceremony.StepUpOwed's table; this is the thin seam showing prompt=none
// consults it and in what order (#437 seam 4).
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
			// Step 6 would refuse too; step 5 is asked first.
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
			// Step 7 would refuse too; step 6 is asked first.
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

			handler := buildAuthorizeGet(authorizeGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      ceremonyStore,
				userSessionManager: userSessionManager,
				database:           database,
				authorizeValidator: authorizeValidator,
				auditLogger:        auditLogger,
				permissionChecker:  permissionChecker,
				tokenParser:        tokenParser,
			})

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
// fault. Which reads a request makes is authflow.decideSilentAuthentication's table; this is that
// each load stops on its fault (#437 seam 4).
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
		{"the save", "AddAuthContext"},
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

			handler := buildAuthorizeGet(authorizeGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      ceremonyStore,
				userSessionManager: userSessionManager,
				database:           database,
				authorizeValidator: authorizeValidator,
				auditLogger:        auditLogger,
				permissionChecker:  permissionChecker,
				tokenParser:        tokenParser,
			})

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
				AuthTime:    time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC),
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
				{"AddAuthContext", func(fail bool) {
					ceremonyStore.On("AddAuthContext", rr, req, mock.AnythingOfType("*ceremony.AuthContext")).Return(fault)
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
		})
	}
}

// prompt=none from a consent-off client asking for authserver:manage-account through the handler:
// an ordinary client's request reads the user's consent to that client and, with none stored, is
// answered consent_required, and the admin console's client reads no consent and goes on to issue.
// Which answer each fact gets is authflow.decideSilentAuthentication's table; this is that the
// handler hands it the client and loads the consent it asks for (#509 decisions 2 and 3).
func TestHandlePromptNone_ManageAccountConsent(t *testing.T) {
	const scope = "openid authserver:manage-account"

	testCases := []struct {
		name             string
		clientIdentifier string
		wantIssue        bool
	}{
		{name: "an ordinary client with no stored consent is answered consent_required",
			clientIdentifier: "test-client"},
		{name: "the admin console's client reads no consent and goes on to issue",
			clientIdentifier: "admin-console-client", wantIssue: true},
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

			handler := buildAuthorizeGet(authorizeGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      ceremonyStore,
				userSessionManager: userSessionManager,
				database:           database,
				authorizeValidator: authorizeValidator,
				auditLogger:        auditLogger,
				permissionChecker:  permissionChecker,
				tokenParser:        tokenParser,
			})

			req, err := http.NewRequest("GET", "/authorize?"+url.Values{
				"client_id":     {tc.clientIdentifier},
				"redirect_uri":  {"https://example.com"},
				"response_type": {"code"},
				"scope":         {scope},
				"prompt":        {"none"},
			}.Encode(), nil)
			require.NoError(t, err)
			ctx := reqctx.WithSettings(req.Context(), &record.Settings{Issuer: "https://test-issuer.com"})
			ctx = reqctx.WithSessionIdentifier(ctx, "session-1")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()

			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateClientAndRedirectURIInput")).Return(nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*protocolvalidation.ValidateUnsupportedRequestParametersInput")).Return(nil)
			authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*protocolvalidation.ValidateRequestInput")).Return(nil)
			authorizeValidator.On("ValidateScopes", mock.Anything, scope).Return(nil)
			authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

			// Consent required off, as every client an administrator creates starts.
			client := &record.Client{Id: 1, ClientIdentifier: tc.clientIdentifier, DefaultAcrLevel: record.AcrLevel1}
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, tc.clientIdentifier).Return(client, nil)

			userSession := &record.UserSession{
				Id:          1,
				UserId:      7,
				AcrLevel:    record.AcrLevel1,
				AuthMethods: "pwd",
				AuthTime:    time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC),
				User:        record.User{Id: 7, Enabled: true},
			}
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").Return(userSession, nil)
			database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)
			userSessionManager.On("HasValidUserSession", userSession, mock.AnythingOfType("int"), mock.AnythingOfType("int"), mock.AnythingOfType("*int64")).Return(true)
			permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, scope, &userSession.User).Return(scope, nil)

			if tc.wantIssue {
				userSessionManager.On("BumpUserSession", mock.Anything, "session-1", int64(1), "", record.AcrLevel(""), mock.Anything).Return(userSession, nil)
				auditLogger.On("Log", mock.Anything, audit.EventBumpedUserSession, mock.Anything).Return()
				ceremonyStore.On("AddAuthContext", rr, req, mock.AnythingOfType("*ceremony.AuthContext")).Return(nil)
			} else {
				database.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(7), int64(1)).Return(nil, nil).Once()
				stubRegisteredRedirectURI(database, "https://example.com")
			}

			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusFound, rr.Code)
			location, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			if tc.wantIssue {
				assert.Equal(t, "/auth/issue", location.Path)
				database.AssertNotCalled(t, "GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				return
			}
			assert.Equal(t, "consent_required", location.Query().Get("error"))
			assert.Equal(t, "User consent is required", location.Query().Get("error_description"))
		})
	}
}

// silentSessionFixture is a prompt=none request from a level 1 client asking for openid, over a valid
// session of an enabled user whose AuthTime is authTime. expectScopeFiltered answers the last load
// the request makes before it adopts the session.
type silentSessionFixture struct {
	pageRenderer       *handlersmocks.PageRenderer
	ceremonyStore      *handlersmocks.CeremonyStore
	userSessionManager *handlersmocks.UserSessionManager
	auditLogger        *handlersmocks.AuditLogger
	permissionChecker  *handlersmocks.PermissionChecker
	database           *datamocks.Database
	userSession        *record.UserSession
	handler            http.HandlerFunc
	rr                 *httptest.ResponseRecorder
	req                *http.Request
}

func newSilentSessionFixture(t *testing.T, authTime time.Time) *silentSessionFixture {
	t.Helper()
	f := &silentSessionFixture{
		pageRenderer:       handlersmocks.NewPageRenderer(t),
		ceremonyStore:      handlersmocks.NewCeremonyStore(t),
		userSessionManager: handlersmocks.NewUserSessionManager(t),
		auditLogger:        handlersmocks.NewAuditLogger(t),
		permissionChecker:  handlersmocks.NewPermissionChecker(t),
		database:           datamocks.NewDatabase(t),
	}
	database := f.database
	authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
	f.handler = buildAuthorizeGet(authorizeGetDeps{
		pageRenderer:       f.pageRenderer,
		ceremonyStore:      f.ceremonyStore,
		userSessionManager: f.userSessionManager,
		database:           database,
		authorizeValidator: authorizeValidator,
		auditLogger:        f.auditLogger,
		permissionChecker:  f.permissionChecker,
		tokenParser:        handlersmocks.NewTokenParser(t),
	})

	req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&prompt=none", nil)
	require.NoError(t, err)
	ctx := reqctx.WithSettings(req.Context(), &record.Settings{Issuer: "https://test-issuer.com"})
	ctx = reqctx.WithSessionIdentifier(ctx, "session-1")
	ctx = context.WithValue(ctx, chimiddleware.RequestIDKey, propagatedRequestId)
	f.req = req.WithContext(ctx)
	f.rr = httptest.NewRecorder()

	authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateClientAndRedirectURIInput")).Return(nil)
	authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*protocolvalidation.ValidateUnsupportedRequestParametersInput")).Return(nil)
	authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*protocolvalidation.ValidateRequestInput")).Return(nil)
	authorizeValidator.On("ValidateScopes", mock.Anything, "openid").Return(nil)
	authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

	client := &record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1}
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

	f.userSession = &record.UserSession{
		Id:          1,
		UserId:      7,
		AcrLevel:    record.AcrLevel1,
		AuthMethods: "pwd",
		Started:     time.Date(2026, 10, 14, 7, 0, 0, 0, time.UTC),
		AuthTime:    authTime,
		User:        record.User{Id: 7, Enabled: true},
	}
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").Return(f.userSession, nil)
	database.On("UserSessionLoadUser", mock.Anything, mock.Anything, f.userSession).Return(nil)
	f.userSessionManager.On("HasValidUserSession", f.userSession, mock.AnythingOfType("int"), mock.AnythingOfType("int"), mock.AnythingOfType("*int64")).Return(true)
	return f
}

func (f *silentSessionFixture) expectScopeFiltered() {
	f.permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, "openid", &f.userSession.User).
		Return("openid", nil).Once()
}

// The ceremony a silent request adopts the session into is issued with the session's auth_time,
// the instant its user last entered a credential, not the time of this request (OIDC Core 1.0
// section 2).
func TestHandlePromptNone_TheCeremonyCarriesTheSessionsAuthTime(t *testing.T) {
	authTime := time.Date(2026, 10, 14, 8, 15, 0, 0, time.UTC)
	f := newSilentSessionFixture(t, authTime)
	f.expectScopeFiltered()
	f.userSessionManager.On("BumpUserSession", mock.Anything, "session-1", int64(1), "", record.AcrLevel(""), mock.Anything).Return(f.userSession, nil)
	f.auditLogger.On("Log", mock.Anything, audit.EventBumpedUserSession, mock.Anything).Return()
	var saved *ceremony.AuthContext
	f.ceremonyStore.On("AddAuthContext", f.rr, f.req, mock.AnythingOfType("*ceremony.AuthContext")).
		Run(func(args mock.Arguments) { saved = args.Get(2).(*ceremony.AuthContext) }).Return(nil).Once()

	f.handler.ServeHTTP(f.rr, f.req)

	require.Equal(t, http.StatusFound, f.rr.Code)
	assert.Equal(t, saved.CeremonyId, assertStepLocation(t, f.rr.Header().Get("Location"), "/auth/issue"))
	require.NotNil(t, saved.AuthenticatedAt)
	assert.Equal(t, authTime, *saved.AuthenticatedAt)
	assert.Equal(t, ceremony.AuthStateReadyToIssueCode, saved.AuthState)
}

// A session with a zero AuthTime has no auth_time to give the ceremony that adopts it. That cannot
// be stored: StartNewUserSession refuses a zero instant and migration 000062 ended every older
// session. If it ever is, the silent request answers 500 and goes no further: the session is not
// bumped, the ceremony not saved and the client not answered, so nothing is issued with a zero
// auth_time or one invented from the session's start (#580 decision 5, as #252 decision 8 refuses a
// missing credential instant).
func TestHandlePromptNone_ASessionWithNoAuthTimeIsRefused(t *testing.T) {
	f := newSilentSessionFixture(t, time.Time{})
	f.expectScopeFiltered()
	f.pageRenderer.On("InternalServerError", f.rr, f.req, mock.MatchedBy(hasNoAuthTime)).Return().Once()

	f.handler.ServeHTTP(f.rr, f.req)

	f.pageRenderer.AssertExpectations(t)
	assert.Empty(t, f.rr.Header().Get("Location"), "the client is answered nothing")
	f.userSessionManager.AssertNotCalled(t, "BumpUserSession", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything)
	f.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	f.ceremonyStore.AssertNotCalled(t, "AddAuthContext", mock.Anything, mock.Anything, mock.Anything)
}

// A silent request over a disabled user's session records user_disabled against the session's user
// and answers the client access_denied, reading nothing past the check, bumping nothing and storing
// nothing.
func TestHandlePromptNone_ADisabledUserIsAuditedAndRefused(t *testing.T) {
	f := newSilentSessionFixture(t, time.Date(2026, 10, 14, 8, 15, 0, 0, time.UTC))
	f.userSession.User.Enabled = false
	stubRegisteredRedirectURI(f.database, "https://example.com")
	var audited bool
	f.auditLogger.On("Log", theRequestsContext(), audit.EventUserDisabled, map[string]interface{}{"user_id": int64(7)}).
		Run(func(mock.Arguments) { audited = true }).Return().Once()

	f.handler.ServeHTTP(f.rr, f.req)

	require.Equal(t, http.StatusFound, f.rr.Code)
	location, err := url.Parse(f.rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "access_denied", location.Query().Get("error"))
	assert.Equal(t, "The user account is disabled", location.Query().Get("error_description"))
	assert.True(t, audited)
	f.permissionChecker.AssertNotCalled(t, "FilterOutScopesWhereUserIsNotAuthorized", mock.Anything, mock.Anything,
		mock.Anything)
	f.userSessionManager.AssertNotCalled(t, "BumpUserSession", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything)
	f.ceremonyStore.AssertNotCalled(t, "AddAuthContext", mock.Anything, mock.Anything, mock.Anything)
}

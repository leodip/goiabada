package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/useragent"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// Every rotation of the browser session's identifier a ceremony step makes lands only while the
// browser session still holds the ceremony the step loaded, and a step whose rotation found its
// ceremony replaced, or its session gone, answers the "no longer active" page at 400 and goes no
// further (#579 decisions 2 and 3). The rotations are the password's, the code's and
// /auth/completed's reuse arm's and its create arm's, which binds the session it started; the create
// arm first confirms the browser session still holds its ceremony before it ends or creates anything
// (decision 4). The cases arm the CeremonyStore mock; the last is the issue's interleaving at the
// password step, with the real ceremony store.

// expectCeremonyConfirmed arms /auth/completed's create arm to find the browser session still
// holding its ceremony, which it asks before it ends or creates anything (#579 decision 4).
func expectCeremonyConfirmed(ceremonyStore *handlersmocks.CeremonyStore, rr *httptest.ResponseRecorder, req *http.Request) {
	ceremonyStore.On("ConfirmCeremony", rr, req, testCeremonyId).Return(nil).Once()
}

// expectRotationReplaced arms a step's rotation to find the browser session holding another
// ceremony.
func expectRotationReplaced(ceremonyStore *handlersmocks.CeremonyStore, rr *httptest.ResponseRecorder, req interface{}) {
	ceremonyStore.On("RegenerateSession", rr, req, testCeremonyId).Return(ceremony.ErrCeremonyReplaced).Once()
}

func TestHandleAuthPwdPost_ARotationFindingItsCeremonyReplacedAnswersNoLongerActive(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := buildAuthPwdPost(authPwdPostDeps{
		pageRenderer:  pageRenderer,
		ceremonyStore: ceremonyStore,
		database:      database,
		auditLogger:   auditLogger,
	})

	passwordHash, err := passwordhash.Hash("testpassword")
	require.NoError(t, err)
	form := url.Values{}
	form.Add(ceremony.IdField, testCeremonyId)
	form.Add("email", "test@example.com")
	form.Add("password", "testpassword")
	req, _ := http.NewRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
	rr := httptest.NewRecorder()

	ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
		AuthState:  ceremony.AuthStateLevel1Password,
		CeremonyId: testCeremonyId,
		ClientId:   "test-client",
	}, nil)
	database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(&record.User{
		Id: 1, Email: "test@example.com", PasswordHash: passwordHash, Enabled: true,
	}, nil)
	auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessPwd, mock.Anything).Return().Once()
	// mock.Anything for the request: the handler refines the localizer onto a fresh *http.Request
	// after the password verifies.
	expectRotationReplaced(ceremonyStore, rr, mock.Anything)
	expectCeremonyNoLongerActiveOnAnyRequest(pageRenderer, rr, req)

	handler.ServeHTTP(rr, req)

	assertAnsweredNoLongerActive(t, rr)
	ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertExpectations(t)
}

func TestHandleAuthOtpPost_ARotationFindingItsCeremonyReplacedAnswersNoLongerActive(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := buildAuthOtpPost(authOtpPostDeps{
		pageRenderer:  pageRenderer,
		ceremonyStore: ceremonyStore,
		database:      database,
		auditLogger:   auditLogger,
	})

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "TestApp", AccountName: "test@test.com"})
	require.NoError(t, err)
	otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	form := url.Values{}
	form.Add(ceremony.IdField, testCeremonyId)
	form.Add("otp", otpCode)
	req, _ := http.NewRequest(http.MethodPost, "/auth/otp", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
	rr := httptest.NewRecorder()

	ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
		AuthState:  ceremony.AuthStateLevel2OTP,
		CeremonyId: testCeremonyId,
		UserId:     1,
		ClientId:   "test-client",
	}, nil)
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{
		Id: 1, Enabled: true, OTPEnabled: true, OTPSecretEncrypted: encryptOTPForTest(t, key.Secret()), OtpConfigGeneration: 3,
	}, nil)
	database.On("TryConsumeEnrolledUserOTPStep", mock.Anything, mock.Anything, int64(1), mock.Anything, int64(3)).
		Return(true, nil)
	auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessOtp, mock.Anything).Return().Once()
	expectRotationReplaced(ceremonyStore, rr, req)
	expectCeremonyNoLongerActive(t, pageRenderer, rr, req)

	handler.ServeHTTP(rr, req)

	assertAnsweredNoLongerActive(t, rr)
	ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertExpectations(t)
}

// The reuse arm rotates before it binds when the bind raises a privilege. A rotation that finds the
// ceremony replaced binds nothing: the session the browser holds is not raised for a ceremony the
// browser has abandoned.
func TestHandleAuthCompletedGet_AReuseArmRotationFindingItsCeremonyReplacedAnswersNoLongerActive(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	userSessionManager := handlersmocks.NewUserSessionManager(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	permissionChecker := handlersmocks.NewPermissionChecker(t)
	handler := buildAuthCompletedGet(authCompletedGetDeps{
		pageRenderer:       pageRenderer,
		ceremonyStore:      ceremonyStore,
		userSessionManager: userSessionManager,
		database:           database,
		templateFS:         fstest.MapFS{},
		auditLogger:        auditLogger,
		permissionChecker:  permissionChecker,
	})

	sessionIdentifier := "test-session"
	req, _ := http.NewRequest(http.MethodGet, "/auth/completed?ceremony="+testCeremonyId, nil)
	req = withSessionSettings(req)
	req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier))
	rr := httptest.NewRecorder()

	captured := int64(4)
	authenticatedAt := time.Now().UTC().Add(-time.Minute)
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
		CeremonyId:          testCeremonyId,
		AuthState:           ceremony.AuthStateAuthenticationCompleted,
		ClientId:            "test-client",
		UserId:              1,
		Scope:               "openid",
		AuthMethods:         "pwd otp",
		AuthenticatedAt:     &authenticatedAt,
		OtpConfigGeneration: &captured,
		OtpClaimGeneration:  &captured,
	}, nil)
	userSession := &record.UserSession{Id: 9, UserId: 1, AcrLevel: record.AcrLevel1, AuthMethods: "pwd"}
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(userSession, nil)
	database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
		&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel2Optional}, nil)
	userSessionManager.On("HasValidUserSession", userSession, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds,
		mock.AnythingOfType("*int64")).Return(true)
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).
		Return(&record.User{Id: 1, Enabled: true, OTPEnabled: true, OtpConfigGeneration: 4}, nil).Once()
	userSessionManager.On("AuthenticationIsStale", mock.Anything, sessionIdentifier,
		boundWith("pwd otp", record.AcrLevel2Optional)).Return(false, nil).Once()
	expectRotationReplaced(ceremonyStore, rr, req)
	expectCeremonyNoLongerActive(t, pageRenderer, rr, req)

	handler.ServeHTTP(rr, req)

	assertAnsweredNoLongerActive(t, rr)
	userSessionManager.AssertNotCalled(t, "BindUserSession", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertExpectations(t)
}

// createArmCase is a ceremony that completed its password on a browser whose session, if any, it may
// not reuse, so /auth/completed takes the create arm: the session the browser carries is another
// user's, this user's own but no longer valid, or there is none.
type createArmCase struct {
	name    string
	session *record.UserSession
	valid   bool
}

var createArmCases = []createArmCase{
	{name: "over another user's session", session: &record.UserSession{Id: 7, UserId: 2, SessionIdentifier: "the-browser-session"}, valid: true},
	{name: "over this user's expired session", session: &record.UserSession{Id: 7, UserId: 1, SessionIdentifier: "the-browser-session"}},
	{name: "with no session", session: nil},
}

// armCreateArm registers what /auth/completed reads before its create arm runs, for tc.
func armCreateArm(t *testing.T, tc createArmCase, ceremonyStore *handlersmocks.CeremonyStore,
	userSessionManager *handlersmocks.UserSessionManager, database *datamocks.Database) (*http.Request, *time.Time) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "/auth/completed?ceremony="+testCeremonyId, nil)
	req = withSessionSettings(req)
	req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), "the-browser-session"))

	pwdAuthTime := time.Now().UTC().Add(-time.Minute)
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
		CeremonyId:          testCeremonyId,
		AuthState:           ceremony.AuthStateAuthenticationCompleted,
		ClientId:            "test-client",
		UserId:              1,
		Scope:               "openid",
		AuthMethods:         "pwd",
		AuthStateGeneration: 7,
		AuthenticatedAt:     &pwdAuthTime,
		PasswordVerifiedAt:  &pwdAuthTime,
		Level1AuthCompleted: true,
	}, nil)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "the-browser-session").Return(tc.session, nil)
	database.On("UserSessionLoadUser", mock.Anything, mock.Anything, tc.session).Return(nil)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
		&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1, AuthorizationCodeEnabled: true}, nil)
	userSessionManager.On("HasValidUserSession", tc.session, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds,
		mock.AnythingOfType("*int64")).Return(tc.valid)
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).
		Return(&record.User{Id: 1, Enabled: true, AuthStateGeneration: 7}, nil)
	return req, &pwdAuthTime
}

// The create arm asks whether the browser session still holds its ceremony before anything else:
// before it ends another user's session, revoking that session's codes and refresh tokens, and
// before the transaction that creates the new session and deletes the browser's own previous one
// and the user's others. A ceremony the browser has abandoned answers the page having ended,
// deleted and created nothing (#579 decision 4).
func TestHandleAuthCompletedGet_TheCreateArmEndsAndCreatesNothingForAReplacedCeremony(t *testing.T) {
	for _, tc := range createArmCases {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			// Strict: a termination, which opens a transaction, fails the case.
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			handler := buildAuthCompletedGet(authCompletedGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      ceremonyStore,
				userSessionManager: userSessionManager,
				database:           database,
				templateFS:         fstest.MapFS{},
				auditLogger:        auditLogger,
				permissionChecker:  handlersmocks.NewPermissionChecker(t),
			})
			req, _ := armCreateArm(t, tc, ceremonyStore, userSessionManager, database)
			rr := httptest.NewRecorder()

			ceremonyStore.On("ConfirmCeremony", rr, req, testCeremonyId).Return(ceremony.ErrCeremonyReplaced).Once()
			expectCeremonyNoLongerActive(t, pageRenderer, rr, req)

			handler.ServeHTTP(rr, req)

			assertAnsweredNoLongerActive(t, rr)
			database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
			userSessionManager.AssertNotCalled(t, "StartNewUserSession", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertExpectations(t)
		})
	}
}

// A newer sign-in can land between the create arm's check and its rotation, after the start's
// commit. The rotation then refuses, or finds the session gone, and the new session is abandoned as a
// failed rotation abandons it. /auth/completed answers the page rather than a 500, audits the rows the
// committed sweep removed as it does for any failed rotation, records no new session and writes no
// device cookie (#579 decisions 3 and 4).
func TestHandleAuthCompletedGet_ACreateArmRotationFindingItsCeremonyReplacedAnswersNoLongerActive(t *testing.T) {
	for _, failure := range []struct {
		name string
		err  error
	}{
		{name: "another ceremony", err: errs.WithStack(ceremony.ErrCeremonyReplaced)},
		// What ceremony.Store answers for a session gone since the request read it.
		{name: "the session gone", err: errs.Wrap(ceremony.ErrCeremonyReplaced, "the browser session is gone")},
	} {
		t.Run(failure.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			handler := buildAuthCompletedGet(authCompletedGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      ceremonyStore,
				userSessionManager: userSessionManager,
				database:           database,
				templateFS:         fstest.MapFS{},
				auditLogger:        auditLogger,
				permissionChecker:  handlersmocks.NewPermissionChecker(t),
			})
			req, pwdAuthTime := armCreateArm(t, createArmCases[2], ceremonyStore, userSessionManager, database)
			rr := httptest.NewRecorder()

			ceremonyStore.On("ConfirmCeremony", rr, req, testCeremonyId).Return(nil).Once()
			removed := []usersession.Removal{{Session: record.UserSession{Id: 42}, Reason: audit.DeletedUserSessionSameDevice}}
			started := &record.UserSession{Id: 43, SessionIdentifier: "the-new-user-session", UserId: 1}
			var minted string
			userSessionManager.On("StartNewUserSession", theContextOf(req), int64(1),
				signedInAs(int64(1), "pwd", record.AcrLevel1, pwdAuthTime), int64(7), (*int64)(nil), aNewDeviceOf(req, &minted), "",
				(*record.UserSession)(nil), testSessionLimits).Return(started, removed, nil).Once()
			ceremonyStore.On("RegenerateSessionAndBind", rr, req, testCeremonyId, "the-new-user-session").
				Return(failure.err).Once()
			userSessionManager.On("AbandonUserSession", theContextOf(req), started, mock.MatchedBy(func(cause error) bool {
				return errors.Is(cause, failure.err)
			})).Return(func(_ context.Context, _ *record.UserSession, cause error) error { return cause }).Once()
			auditLogger.On("Log", mock.Anything, audit.EventDeletedUserSession, mock.MatchedBy(func(details map[string]interface{}) bool {
				return details["user_session_id"] == int64(42) && details["reason"] == audit.DeletedUserSessionSameDevice
			})).Return().Once()
			expectCeremonyNoLongerActive(t, pageRenderer, rr, req)

			handler.ServeHTTP(rr, req)

			assertAnsweredNoLongerActive(t, rr)
			noDeviceCookieIn(t, rr)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventStartedNewUserSession, mock.Anything)
			ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
			pageRenderer.AssertExpectations(t)
			auditLogger.AssertExpectations(t)
			userSessionManager.AssertExpectations(t)
		})
	}
}

// The issue's interleaving at the password step, with the real ceremony store: tab A's password
// submission has loaded ceremony A and is held in its read of the user, tab B's /auth/authorize runs
// to its save in the same browser session, and tab A resumes. Its rotation used to write ceremony A
// under a new identifier and delete the row holding ceremony B. Now tab A answers the "no longer
// active" page, and the browser's identifier still names its session, which keeps ceremony B.
func TestHandleAuthPwdPost_ARotationResumingAfterANewerAuthorizeLeavesItsCeremonyAlone(t *testing.T) {
	ceremonyStore, _ := newRealCeremonyStore(t)

	seed := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.ReplaceAuthContext(seed, httptest.NewRequest(http.MethodGet, "/auth/authorize", nil),
		&ceremony.AuthContext{
			CeremonyId: testCeremonyId,
			AuthState:  ceremony.AuthStateLevel1Password,
			ClientId:   "test-client",
		}))
	cookies := seed.Result().Cookies()
	require.Len(t, cookies, 1)

	passwordHash, err := passwordhash.Hash("testpassword")
	require.NoError(t, err)

	pageRendererA := handlersmocks.NewPageRenderer(t)
	databaseA := datamocks.NewDatabase(t)
	auditLoggerA := handlersmocks.NewAuditLogger(t)
	reached := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	databaseA.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Run(func(mock.Arguments) {
		close(reached)
		<-release
	}).Return(&record.User{Id: 1, Email: "test@example.com", PasswordHash: passwordHash, Enabled: true}, nil)
	auditLoggerA.On("Log", mock.Anything, audit.EventAuthSuccessPwd, mock.Anything).Return().Once()

	form := url.Values{}
	form.Add(ceremony.IdField, testCeremonyId)
	form.Add("email", "test@example.com")
	form.Add("password", "testpassword")
	reqA := withCookies(httptest.NewRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode())), cookies)
	reqA.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	reqA = reqA.WithContext(reqctx.WithSettings(reqA.Context(), &record.Settings{}))
	rrA := httptest.NewRecorder()
	expectCeremonyNoLongerActiveOnAnyRequest(pageRendererA, rrA, reqA)

	tabADone := make(chan struct{})
	go func() {
		defer close(tabADone)
		buildAuthPwdPost(authPwdPostDeps{
			pageRenderer:  pageRendererA,
			ceremonyStore: ceremonyStore,
			database:      databaseA,
			auditLogger:   auditLoggerA,
		}).ServeHTTP(rrA, reqA)
	}()
	select {
	case <-reached:
	case <-tabADone:
		t.Fatal("tab A's step returned before it reached its read of the user")
	case <-time.After(10 * time.Second):
		t.Fatal("tab A's step never reached its read of the user")
	}

	// Tab B's /auth/authorize, carrying the same cookie, through to its save.
	e := newSyntaxAuthorizeEndpoint(t)
	e.stubLoggedOutBrowser()
	tabB := buildAuthorizeGet(authorizeGetDeps{
		pageRenderer:       e.pageRenderer,
		ceremonyStore:      ceremonyStore,
		userSessionManager: e.userSessionManager,
		database:           e.database,
		authorizeValidator: protocolvalidation.NewAuthorizeValidator(e.database),
		auditLogger:        handlersmocks.NewAuditLogger(t),
		permissionChecker:  handlersmocks.NewPermissionChecker(t),
		tokenParser:        handlersmocks.NewTokenParser(t),
	})
	reqB := withCookies(withSessionSettings(httptest.NewRequest(http.MethodGet,
		"/auth/authorize?"+syntaxQuery(nil), nil)), cookies)
	rrB := httptest.NewRecorder()
	tabB.ServeHTTP(rrB, reqB)

	require.Equal(t, http.StatusFound, rrB.Code)
	locationB, err := url.Parse(rrB.Header().Get("Location"))
	require.NoError(t, err)
	ceremonyB := locationB.Query().Get(ceremony.QueryParameter)
	require.NotEmpty(t, ceremonyB)
	require.NotEqual(t, testCeremonyId, ceremonyB)

	close(release)
	select {
	case <-tabADone:
	case <-time.After(10 * time.Second):
		t.Fatal("tab A's step never returned")
	}

	assertAnsweredNoLongerActive(t, rrA)
	assert.Empty(t, rrA.Result().Cookies(), "tab A rotated nothing, so it tells the browser nothing")
	pageRendererA.AssertExpectations(t)

	stored, err := ceremonyStore.LatestAuthContext(withCookies(httptest.NewRequest(http.MethodGet, "/auth/level1", nil), cookies))
	require.NoError(t, err, "the browser's identifier still names its session")
	assert.Equal(t, ceremonyB, stored.CeremonyId, "the browser session keeps the newer ceremony")
	assert.Equal(t, ceremony.AuthStateRequiresLevel1, stored.AuthState)
}

// theContextOf matches req's own context, which /auth/completed's operation runs under.
func theContextOf(req *http.Request) interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool { return ctx == req.Context() })
}

// aNewDeviceOf matches the device /auth/completed's create arm reads from req, which carries no
// device cookie: a new identifier as this server mints one, with req's display labels and header. It
// records the identifier in minted, which the device cookie the response sets must then hold.
func aNewDeviceOf(req *http.Request, minted *string) interface{} {
	return mock.MatchedBy(func(device usersession.Device) bool {
		name, deviceType, deviceOS := useragent.Labels(req)
		if !device.New || !lowerHex64.MatchString(device.Identifier) || device.Name != name ||
			device.Type != deviceType || device.OS != deviceOS || device.UserAgent != req.UserAgent() {
			return false
		}
		*minted = device.Identifier
		return true
	})
}

// expectNewSessionBound arms /auth/completed's create arm's rotation, which binds the user session it
// started to the browser session on condition it still holds this ceremony (#266, #579 decision 4).
func expectNewSessionBound(ceremonyStore *handlersmocks.CeremonyStore, rr *httptest.ResponseRecorder, req *http.Request,
	userSessionIdentifier string) {
	ceremonyStore.On("RegenerateSessionAndBind", rr, req, testCeremonyId, userSessionIdentifier).Return(nil).Once()
}

// expectCeremonyNoLongerActiveOnAnyRequest is expectCeremonyNoLongerActive for a handler that renders
// on a request of its own, as the password step does once it refines the localizer; req is the one
// the test sent, whose locale the page's text is in.
func expectCeremonyNoLongerActiveOnAnyRequest(pageRenderer *handlersmocks.PageRenderer, rr *httptest.ResponseRecorder,
	req *http.Request) {
	pageRenderer.On("RenderTemplate", rr, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["_httpStatus"] == http.StatusBadRequest &&
				data["title"] == i18n.T(req.Context(), "auth_error.ceremony_mismatch.title") &&
				data["error"] == i18n.T(req.Context(), "auth_error.ceremony_mismatch.message")
		})).Return(nil).Once()
}

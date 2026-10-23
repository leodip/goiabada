package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// Every step after /auth/authorize saves its auth context only while the browser session still holds
// the ceremony the step loaded, and a step whose ceremony was replaced answers the "no longer
// active" page at 400 and goes no further (#579). The cases at each save site are beside that
// site's other tests and arm the CeremonyStore mock with expectStepSaveReplaced; the case here is
// the issue's interleaving at one step, with the real ceremony store, where a ceremony is no longer
// held because newer sign-ins pushed it out (#246).

// expectStepSaveReplaced arms a step's save to find the browser session no longer holding its
// ceremony, and the one page that answers it. The save is matched on its request and recorder, so a save made
// anywhere else does not satisfy it.
func expectStepSaveReplaced(t *testing.T, ceremonyStore *handlersmocks.CeremonyStore,
	pageRenderer *handlersmocks.PageRenderer, rr *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()
	ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(ceremony.ErrCeremonyReplaced).Once()
	expectCeremonyNoLongerActive(t, pageRenderer, rr, req)
}

// assertAnsweredNoLongerActive is what a step whose save found its ceremony replaced leaves on the
// wire besides the page: no redirect to a next step or to the client.
func assertAnsweredNoLongerActive(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	assert.Empty(t, rr.Header().Get("Location"), "a replaced ceremony is sent nowhere")
}

const stepSaveSessionName = "goiabada-auth-test"

// newRealCeremonyStore is the ceremony store as the auth server builds it, over an in-memory
// backend, with the session store under it.
func newRealCeremonyStore(t *testing.T) (*ceremony.Store, *sessionstore.ServerSideStore) {
	t.Helper()
	backend := sessiontest.NewMemoryBackend()
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.SessionIdentifier, false,
		sessionstore.PersistentCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			EncryptionKey:     []byte("0123456789abcdef0123456789abcdef"),
		}, nil)
	require.NoError(t, err)
	conditional, err := sessionstore.NewConditionalStore(store, backend)
	require.NoError(t, err)
	return ceremony.NewStore(conditional, stepSaveSessionName), store
}

func withCookies(req *http.Request, cookies []*http.Cookie) *http.Request {
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// newerAuthorizes runs /auth/authorize n times in the browser cookies name, as n other tabs starting
// a sign-in would, each through to its save, and answers the ceremonies they started.
func newerAuthorizes(t *testing.T, ceremonyStore *ceremony.Store, cookies []*http.Cookie, n int) []string {
	t.Helper()
	e := newSyntaxAuthorizeEndpoint(t)
	e.stubLoggedOutBrowser()
	authorize := buildAuthorizeGet(authorizeGetDeps{
		pageRenderer:       e.pageRenderer,
		ceremonyStore:      ceremonyStore,
		userSessionManager: e.userSessionManager,
		database:           e.database,
		authorizeValidator: protocolvalidation.NewAuthorizeValidator(e.database),
		auditLogger:        handlersmocks.NewAuditLogger(t),
		permissionChecker:  handlersmocks.NewPermissionChecker(t),
		tokenParser:        handlersmocks.NewTokenParser(t),
	})

	var started []string
	for i := 0; i < n; i++ {
		req := withCookies(withSessionSettings(httptest.NewRequest(http.MethodGet,
			"/auth/authorize?"+syntaxQuery(nil), nil)), cookies)
		rr := httptest.NewRecorder()
		authorize.ServeHTTP(rr, req)

		require.Equal(t, http.StatusFound, rr.Code)
		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "/auth/level1", location.Path)
		id := location.Query().Get(ceremony.QueryParameter)
		require.NotEmpty(t, id)
		started = append(started, id)
	}
	return started
}

// heldCeremony reads the ceremony id names from the browser cookies name, as that ceremony's next
// step would.
func heldCeremony(ceremonyStore *ceremony.Store, cookies []*http.Cookie, id string) (*ceremony.AuthContext, error) {
	return ceremonyStore.GetAuthContext(withCookies(httptest.NewRequest(http.MethodGet,
		"/auth/level1?"+url.Values{ceremony.QueryParameter: {id}}.Encode(), nil), cookies))
}

// The issue's interleaving at /auth/level2: tab A's step has loaded ceremony A and is held inside
// its read of the user, other tabs' /auth/authorize run to their saves in the same browser session,
// and tab A resumes. After one newer sign-in, both carry on: tab A goes to its next step and the
// newer one is still held (#246). After five, ceremony A has been pushed out: tab A answers the "no
// longer active" page, logged at warn and audited nowhere, and the browser session keeps the five
// newer ones, so each of their next steps finds the sign-in it started.
func TestHandleAuthLevel2Get_AStepResumingAfterANewerAuthorize(t *testing.T) {
	for _, tc := range []struct {
		name      string
		newer     int
		carriesOn bool
	}{
		{name: "one newer sign-in leaves it to carry on", newer: 1, carriesOn: true},
		{name: "five newer sign-ins push it out", newer: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ceremonyStore, _ := newRealCeremonyStore(t)

			// Ceremony A, as /auth/authorize left it when it reached /auth/level2.
			seed := httptest.NewRecorder()
			require.NoError(t, ceremonyStore.AddAuthContext(seed, httptest.NewRequest(http.MethodGet, "/auth/authorize", nil),
				&ceremony.AuthContext{
					CeremonyId: testCeremonyId,
					AuthState:  ceremony.AuthStateRequiresLevel2,
					ClientId:   "test-client",
					UserId:     1,
				}))
			cookies := seed.Result().Cookies()
			require.Len(t, cookies, 1)

			// Tab A, held in GetUserById until the other tabs have saved.
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
			databaseA.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
				&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel2Optional}, nil).Maybe()
			databaseA.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Run(func(mock.Arguments) {
				close(reached)
				<-release
			}).Return(&record.User{Id: 1, Enabled: true, OTPEnabled: true, OtpConfigGeneration: 4}, nil)

			reqA := withCookies(withSessionSettings(httptest.NewRequest(http.MethodGet,
				"/auth/level2?ceremony="+testCeremonyId, nil)), cookies)
			rrA := httptest.NewRecorder()
			if !tc.carriesOn {
				expectCeremonyNoLongerActive(t, pageRendererA, rrA, reqA)
			}

			logged := logtest.CaptureSlog(t)
			tabADone := make(chan struct{})
			go func() {
				defer close(tabADone)
				buildAuthLevel2Get(authLevel2GetDeps{
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

			newer := newerAuthorizes(t, ceremonyStore, cookies, tc.newer)

			close(release)
			select {
			case <-tabADone:
			case <-time.After(10 * time.Second):
				t.Fatal("tab A's step never returned")
			}

			// Each newer tab's next step finds the ceremony it started.
			for _, id := range newer {
				stored, err := heldCeremony(ceremonyStore, cookies, id)
				require.NoError(t, err, "the newer ceremony %s is held", id)
				assert.Equal(t, ceremony.AuthStateRequiresLevel1, stored.AuthState, "tab A's state did not land on it")
			}

			if tc.carriesOn {
				require.Equal(t, http.StatusFound, rrA.Code, rrA.Body.String())
				assertStepLocation(t, rrA.Header().Get("Location"), "/auth/otp")
				storedA, err := heldCeremony(ceremonyStore, cookies, testCeremonyId)
				require.NoError(t, err, "tab A's ceremony is still held")
				assert.Equal(t, ceremony.AuthStateLevel2OTP, storedA.AuthState, "and tab A's save landed on it")
				return
			}

			assertAnsweredNoLongerActive(t, rrA)
			assert.Empty(t, rrA.Result().Cookies(), "tab A wrote nothing, so it tells the browser nothing")
			pageRendererA.AssertExpectations(t)

			var warned bool
			for _, r := range logged.Records() {
				if r.Message == "the browser session no longer holds this ceremony, answering it as no longer active" {
					assert.Equal(t, slog.LevelWarn, r.Level)
					warned = true
				}
			}
			assert.True(t, warned, "the pushed-out step is logged at warn:\n%s", logged.Text())
			_, err := heldCeremony(ceremonyStore, cookies, testCeremonyId)
			require.ErrorIs(t, err, ceremony.ErrCeremonyNotHeld, "ceremony A is not put back")
		})
	}
}

// The cases below arm each of these handlers' saves to find the ceremony replaced, one per save
// site. Every mock is strict, so a step that went on to redirect, render its own page, answer 500
// or record an audit event fails the case.

func TestHandleAuthLevel1Get_AReplacedCeremonyAnswersNoLongerActive(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	handler := buildAuthLevel1Get(authLevel1GetDeps{
		pageRenderer:  pageRenderer,
		ceremonyStore: ceremonyStore,
		auditLogger:   handlersmocks.NewAuditLogger(t),
	})

	req := withSessionSettings(httptest.NewRequest(http.MethodGet, "/auth/level1?ceremony="+testCeremonyId, nil))
	rr := httptest.NewRecorder()
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
		CeremonyId: testCeremonyId,
		AuthState:  ceremony.AuthStateRequiresLevel1,
	}, nil)
	expectStepSaveReplaced(t, ceremonyStore, pageRenderer, rr, req)

	handler.ServeHTTP(rr, req)

	assertAnsweredNoLongerActive(t, rr)
	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertExpectations(t)
}

// /auth/level1completed saves on both of its arms: towards level 2, and towards /auth/completed.
// A ceremony that verified its password itself counts no session, so the client's level alone
// decides which arm runs.
func TestHandleAuthLevel1CompletedGet_AReplacedCeremonyAnswersNoLongerActive(t *testing.T) {
	for _, tc := range []struct {
		name        string
		clientLevel record.AcrLevel
	}{
		{name: "on the way to level 2", clientLevel: record.AcrLevel2Optional},
		{name: "on the way to completed", clientLevel: record.AcrLevel1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			database := datamocks.NewDatabase(t)
			handler := buildAuthLevel1CompletedGet(authLevel1CompletedGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      ceremonyStore,
				userSessionManager: userSessionManager,
				database:           database,
				auditLogger:        handlersmocks.NewAuditLogger(t),
			})

			req := withSessionSettings(httptest.NewRequest(http.MethodGet,
				"/auth/level1completed?ceremony="+testCeremonyId, nil))
			rr := httptest.NewRecorder()
			ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
				CeremonyId:          testCeremonyId,
				AuthState:           ceremony.AuthStateLevel1PasswordCompleted,
				ClientId:            "test-client",
				UserId:              1,
				Level1AuthCompleted: true,
			}, nil)
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
			database.On("UserSessionLoadUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
				&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: tc.clientLevel}, nil)
			expectStepSaveReplaced(t, ceremonyStore, pageRenderer, rr, req)

			handler.ServeHTTP(rr, req)

			assertAnsweredNoLongerActive(t, rr)
			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertExpectations(t)
		})
	}
}

func TestHandleAuthLevel2Get_AReplacedCeremonyAnswersNoLongerActive(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)
	handler := buildAuthLevel2Get(authLevel2GetDeps{
		pageRenderer:  pageRenderer,
		ceremonyStore: ceremonyStore,
		database:      database,
		auditLogger:   handlersmocks.NewAuditLogger(t),
	})

	req := withSessionSettings(httptest.NewRequest(http.MethodGet, "/auth/level2?ceremony="+testCeremonyId, nil))
	rr := httptest.NewRecorder()
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
		CeremonyId: testCeremonyId,
		AuthState:  ceremony.AuthStateRequiresLevel2,
		ClientId:   "test-client",
		UserId:     1,
	}, nil)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
		&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel2Optional}, nil)
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(
		&record.User{Id: 1, OTPEnabled: true, OtpConfigGeneration: 4}, nil)
	expectStepSaveReplaced(t, ceremonyStore, pageRenderer, rr, req)

	handler.ServeHTTP(rr, req)

	assertAnsweredNoLongerActive(t, rr)
	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertExpectations(t)
}

// /auth/otp's page saves before it renders, on both arms: the code form for a user with an
// authenticator, and the enrolment form for one without. A replaced ceremony renders neither.
func TestHandleAuthOtpGet_AReplacedCeremonyAnswersNoLongerActive(t *testing.T) {
	for _, tc := range []struct {
		name       string
		otpEnabled bool
	}{
		{name: "the code form", otpEnabled: true},
		{name: "the enrolment form", otpEnabled: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			handler := buildAuthOtpGet(authOtpGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      ceremonyStore,
				database:           database,
				otpSecretGenerator: handlersmocks.NewOtpSecretGenerator(t),
				auditLogger:        handlersmocks.NewAuditLogger(t),
			})

			req := withSettings(httptest.NewRequest(http.MethodGet, "/auth/otp?ceremony="+testCeremonyId, nil),
				&record.Settings{AppName: "TestApp"})
			rr := httptest.NewRecorder()
			ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
				CeremonyId: testCeremonyId,
				AuthState:  ceremony.AuthStateLevel2OTP,
				ClientId:   "test-client",
				UserId:     1,
				// A key this ceremony already generated, so the enrolment arm draws no new one.
				OTPKeyURL: otpTestKeyURL("JBSWY3DPEHPK3PXP"),
			}, nil)
			database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(
				&record.User{Id: 1, Email: "test@example.com", OTPEnabled: tc.otpEnabled}, nil)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
				&record.Client{ClientIdentifier: "test-client"}, nil)
			expectStepSaveReplaced(t, ceremonyStore, pageRenderer, rr, req)

			handler.ServeHTTP(rr, req)

			assertAnsweredNoLongerActive(t, rr)
			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertExpectations(t)
		})
	}
}

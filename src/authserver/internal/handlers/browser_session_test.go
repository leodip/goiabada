package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usersession"
)

// The browser adapter is the one path from an authflow operation to the browser session, so every
// call it delegates has to reach the ceremony store with the response writer and the request the
// handler built it for, and through that request, the request's own context. The matchers compare
// identity: two fresh recorders, or two requests to the same URL, are equal as values, and a match on
// equality would pass an adapter that built a request of its own.

func theWriter(rr *httptest.ResponseRecorder) interface{} {
	return mock.MatchedBy(func(w http.ResponseWriter) bool {
		recorder, ok := w.(*httptest.ResponseRecorder)
		return ok && recorder == rr
	})
}

func theRequest(req *http.Request) interface{} {
	return mock.MatchedBy(func(r *http.Request) bool { return r == req })
}

// adapterRequest is a request whose context carries a value no other request has, so a delegated
// call that reached the store on a derived or a background context would be told apart by
// requestKeyValue.
func adapterRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth/level2?ceremony="+testCeremonyId, nil)
	return req.WithContext(context.WithValue(req.Context(), adapterContextKey{}, "this request"))
}

type adapterContextKey struct{}

func requestKeyValue(r *http.Request) interface{} {
	return r.Context().Value(adapterContextKey{})
}

func TestBrowserSession_SaveAuthContextCarriesTheHandlersWriterAndRequest(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()
	authContext := &ceremony.AuthContext{CeremonyId: testCeremonyId, AuthState: ceremony.AuthStateLevel2OTP}

	ceremonyStore.On("SaveAuthContext", theWriter(rr), theRequest(req), authContext).
		Run(func(args mock.Arguments) {
			assert.Equal(t, "this request", requestKeyValue(args.Get(1).(*http.Request)))
		}).Return(nil).Once()

	err := newBrowserSession(rr, req, ceremonyStore).SaveAuthContext(authContext)

	require.NoError(t, err)
	ceremonyStore.AssertExpectations(t)
}

func TestBrowserSession_SaveAuthContextReturnsTheStoresRefusal(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()
	authContext := &ceremony.AuthContext{CeremonyId: testCeremonyId}

	ceremonyStore.On("SaveAuthContext", theWriter(rr), theRequest(req), authContext).
		Return(ceremony.ErrCeremonyReplaced).Once()

	err := newBrowserSession(rr, req, ceremonyStore).SaveAuthContext(authContext)

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
}

func TestBrowserSession_ClearAuthContextCarriesTheHandlersWriterAndRequest(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()

	ceremonyStore.On("ClearAuthContext", theWriter(rr), theRequest(req), testCeremonyId).
		Run(func(args mock.Arguments) {
			assert.Equal(t, "this request", requestKeyValue(args.Get(1).(*http.Request)))
		}).Return(nil).Once()

	err := newBrowserSession(rr, req, ceremonyStore).ClearAuthContext(testCeremonyId)

	require.NoError(t, err)
	ceremonyStore.AssertExpectations(t)
}

func TestBrowserSession_ClearAuthContextReturnsTheStoresRefusal(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()

	ceremonyStore.On("ClearAuthContext", theWriter(rr), theRequest(req), testCeremonyId).
		Return(assert.AnError).Once()

	err := newBrowserSession(rr, req, ceremonyStore).ClearAuthContext(testCeremonyId)

	require.ErrorIs(t, err, assert.AnError)
}

// Two adapters built for two requests each reach the store with their own pair: an adapter holds
// nothing shared, so one request's writes never land on another's response.
func TestBrowserSession_TwoRequestsKeepTheirOwnWritersAndRequests(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rrA, reqA := httptest.NewRecorder(), adapterRequest()
	rrB, reqB := httptest.NewRecorder(), adapterRequest()
	contextA := &ceremony.AuthContext{CeremonyId: "A"}
	contextB := &ceremony.AuthContext{CeremonyId: "B"}

	ceremonyStore.On("SaveAuthContext", theWriter(rrA), theRequest(reqA), contextA).Return(nil).Once()
	ceremonyStore.On("SaveAuthContext", theWriter(rrB), theRequest(reqB), contextB).Return(nil).Once()

	browserA := newBrowserSession(rrA, reqA, ceremonyStore)
	browserB := newBrowserSession(rrB, reqB, ceremonyStore)
	require.NoError(t, browserB.SaveAuthContext(contextB))
	require.NoError(t, browserA.SaveAuthContext(contextA))

	ceremonyStore.AssertExpectations(t)
}

func TestBrowserSession_RegenerateSessionCarriesTheHandlersWriterAndRequest(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()

	ceremonyStore.On("RegenerateSession", theWriter(rr), theRequest(req), testCeremonyId).
		Run(func(args mock.Arguments) {
			assert.Equal(t, "this request", requestKeyValue(args.Get(1).(*http.Request)))
		}).Return(nil).Once()

	err := newBrowserSession(rr, req, ceremonyStore).RegenerateSession(testCeremonyId)

	require.NoError(t, err)
	ceremonyStore.AssertExpectations(t)
}

func TestBrowserSession_RegenerateSessionReturnsTheStoresRefusal(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()

	ceremonyStore.On("RegenerateSession", theWriter(rr), theRequest(req), testCeremonyId).
		Return(ceremony.ErrCeremonyReplaced).Once()

	err := newBrowserSession(rr, req, ceremonyStore).RegenerateSession(testCeremonyId)

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
}

func TestBrowserSession_ConfirmCeremonyCarriesTheHandlersWriterAndRequest(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()

	ceremonyStore.On("ConfirmCeremony", theWriter(rr), theRequest(req), testCeremonyId).
		Run(func(args mock.Arguments) {
			assert.Equal(t, "this request", requestKeyValue(args.Get(1).(*http.Request)))
		}).Return(nil).Once()

	err := newBrowserSession(rr, req, ceremonyStore).ConfirmCeremony(testCeremonyId)

	require.NoError(t, err)
	ceremonyStore.AssertExpectations(t)
}

func TestBrowserSession_ConfirmCeremonyReturnsTheStoresRefusal(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()

	ceremonyStore.On("ConfirmCeremony", theWriter(rr), theRequest(req), testCeremonyId).
		Return(ceremony.ErrCeremonyReplaced).Once()

	err := newBrowserSession(rr, req, ceremonyStore).ConfirmCeremony(testCeremonyId)

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
}

// The session start rotates the browser session's identifier onto the new session and writes the
// device cookie, so it is reached with the handler's own writer and request, and every value the
// operation hands it arrives unchanged, the removals and the error it answers included.
func TestBrowserSession_StartNewUserSessionCarriesTheHandlersWriterAndRequest(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	userSessionManager := handlersmocks.NewUserSessionManager(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()

	authTime := time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
	authentication := usersession.Authentication{UserId: 7, AuthMethods: "pwd", AcrLevel: record.AcrLevel1,
		AuthTime: &authTime}
	otpConfigGeneration := int64(4)
	replacing := &record.UserSession{Id: 11, UserId: 7}
	limits := usersession.SessionLimits{IdleTimeoutInSeconds: 1, MaxLifetimeInSeconds: 2, MaxSessionsPerUser: 3}
	started := &record.UserSession{Id: 12, UserId: 7}
	removals := []usersession.Removal{{Session: *replacing, Reason: "replaced"}}

	userSessionManager.On("StartNewUserSession", theWriter(rr), theRequest(req), int64(5), authentication,
		int64(9), &otpConfigGeneration, "198.51.100.4", replacing, limits).
		Run(func(args mock.Arguments) {
			assert.Equal(t, "this request", requestKeyValue(args.Get(1).(*http.Request)))
		}).Return(started, removals, assert.AnError).Once()

	gotSession, gotRemovals, err := newSessionStartingBrowserSession(rr, req, ceremonyStore, userSessionManager).
		StartNewUserSession(5, authentication, 9, &otpConfigGeneration, "198.51.100.4", replacing, limits)

	require.ErrorIs(t, err, assert.AnError)
	assert.Same(t, started, gotSession)
	assert.Equal(t, removals, gotRemovals)
	userSessionManager.AssertExpectations(t)
}

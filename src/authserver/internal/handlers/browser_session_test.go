package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
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

func TestBrowserSession_AddAuthContextCarriesTheHandlersWriterAndRequest(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()
	authContext := &ceremony.AuthContext{CeremonyId: testCeremonyId, AuthState: ceremony.AuthStateReadyToIssueCode}

	ceremonyStore.On("AddAuthContext", theWriter(rr), theRequest(req), authContext).
		Run(func(args mock.Arguments) {
			assert.Equal(t, "this request", requestKeyValue(args.Get(1).(*http.Request)))
		}).Return(nil).Once()

	err := newBrowserSession(rr, req, ceremonyStore).AddAuthContext(authContext)

	require.NoError(t, err)
	ceremonyStore.AssertExpectations(t)
}

func TestBrowserSession_AddAuthContextReturnsTheStoresFailure(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()
	authContext := &ceremony.AuthContext{CeremonyId: testCeremonyId}

	ceremonyStore.On("AddAuthContext", theWriter(rr), theRequest(req), authContext).
		Return(assert.AnError).Once()

	err := newBrowserSession(rr, req, ceremonyStore).AddAuthContext(authContext)

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

// The create arm's rotation binds the new user session to the browser session, so it reaches the
// ceremony store with the handler's own writer and request, the ceremony and the user session named,
// and answers what the store answered.
func TestBrowserSession_RegenerateSessionAndBindCarriesTheHandlersWriterAndRequest(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := adapterRequest()

	ceremonyStore.On("RegenerateSessionAndBind", theWriter(rr), theRequest(req), testCeremonyId, "the-new-user-session").
		Run(func(args mock.Arguments) {
			assert.Equal(t, "this request", requestKeyValue(args.Get(1).(*http.Request)))
		}).Return(ceremony.ErrCeremonyReplaced).Once()

	err := newSessionStartingBrowserSession(rr, req, ceremonyStore, NewDeviceCookie(false)).
		RegenerateSessionAndBind(testCeremonyId, "the-new-user-session")

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
	ceremonyStore.AssertExpectations(t)
}

// The device is read from the handler's own request: its device cookie and its headers.
func TestBrowserSession_DeviceIsTheHandlersRequests(t *testing.T) {
	req := adapterRequest()
	req.Header.Set("User-Agent", chromeUserAgent)
	req.AddCookie(&http.Cookie{Name: "authserver_device", Value: thisDevice})

	device := newSessionStartingBrowserSession(httptest.NewRecorder(), req, handlersmocks.NewCeremonyStore(t),
		NewDeviceCookie(false)).Device()

	assert.Equal(t, thisDevice, device.Identifier)
	assert.False(t, device.New)
	assert.Equal(t, chromeUserAgent, device.UserAgent)
}

// The device cookie is written on the handler's own response.
func TestBrowserSession_WriteDeviceCookieLandsOnTheHandlersWriter(t *testing.T) {
	rr := httptest.NewRecorder()

	newSessionStartingBrowserSession(rr, adapterRequest(), handlersmocks.NewCeremonyStore(t), NewDeviceCookie(false)).
		WriteDeviceCookie(thisDevice)

	assert.Equal(t, thisDevice, deviceCookieOf(t, rr).Value)
}

// credentialFailureSpy records the requests the rate limiter's port is reached with. A spy here and
// nowhere else: what the adapter owes is to hand the limiter this request, and the limiter's own
// accounting is driven for real by TestHandleAuthPwdPost_SpendsTheLimiterBudgetOnFailuresOnly.
type credentialFailureSpy struct {
	requests []*http.Request
}

func (s *credentialFailureSpy) RecordCredentialFailure(r *http.Request) {
	s.requests = append(s.requests, r)
}

// A failed credential check charges the reservation the limiter placed on this request's context,
// so the adapter has to hand the limiter the handler's own request: a derived or another request
// carries no reservation, and the failure would cost nothing (#219).
func TestBrowserSession_RecordCredentialFailureCarriesTheHandlersRequest(t *testing.T) {
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	spy := &credentialFailureSpy{}
	rr := httptest.NewRecorder()
	req := adapterRequest()

	newCredentialCheckingBrowserSession(rr, req, ceremonyStore, spy).RecordCredentialFailure()

	require.Len(t, spy.requests, 1)
	assert.Same(t, req, spy.requests[0])
	assert.Equal(t, "this request", requestKeyValue(spy.requests[0]))
}

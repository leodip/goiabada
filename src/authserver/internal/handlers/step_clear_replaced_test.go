package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// A step's clear ends the ceremony only while the browser session still holds it, and a step whose
// clear found the ceremony replaced answers the "no longer active" page at 400 in place of whatever
// it would have answered, sending nothing to the client (#579 decision 2). The cases here arm the
// CeremonyStore mock to answer ceremony.ErrCeremonyReplaced at each clear: the shared error answer,
// the two issuance refusals that answer on a page of their own, the clear after a code or the
// implicit tokens are minted, and the lost enrolment.

// expectStepClearReplaced arms a step's clear of the test ceremony to find the browser session
// holding another, and the one page that answers it.
func expectStepClearReplaced(t *testing.T, ceremonyStore *handlersmocks.CeremonyStore,
	pageRenderer *handlersmocks.PageRenderer, rr *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()
	ceremonyStore.On("ClearAuthContext", rr, req, testCeremonyId).Return(ceremony.ErrCeremonyReplaced).Once()
	expectCeremonyNoLongerActive(t, pageRenderer, rr, req)
}

// assertReplacedAnsweredAtWarn is the record a replaced clear leaves: one warn line, and no error,
// since the browser moving on is no fault.
func assertReplacedAnsweredAtWarn(t *testing.T, logged *logtest.SlogCapture) {
	t.Helper()
	var warned bool
	for _, logRecord := range logged.Records() {
		assert.NotEqual(t, "ERROR", logRecord.Level.String(), "a replaced ceremony is no fault: %s", logRecord.Message)
		warned = warned || (logRecord.Level.String() == "WARN" &&
			logRecord.Message == "the browser session no longer holds this ceremony, answering it as no longer active")
	}
	assert.True(t, warned, "the replaced ceremony is a warn record")
}

// The shared error answer, at a step: the clear found another ceremony, so the error and its state
// are not sent into a browser where a newer sign-in is in progress. The database mock has no
// expectation, so the redirect gate's registration read, which only an emitted error makes, fails
// the case on its own.
func TestAnswerClientWithError_AReplacedCeremonyAnswersNoLongerActive(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/consent?ceremony="+testCeremonyId, nil)
	expectStepClearReplaced(t, ceremonyStore, pageRenderer, rr, req)
	logged := logtest.CaptureSlog(t)

	answerClientWithError(rr, req, datamocks.NewDatabase(t), pageRenderer, ceremonyStore, nil, testCeremonyId,
		testRedirectError("access_denied", "The user did not provide consent", "query",
			"https://legit.example/cb", "abc123", "code"))

	assertAnsweredNoLongerActive(t, rr)
	assertReplacedAnsweredAtWarn(t, logged)
	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertExpectations(t)
}

// lastComparisonBackend is the in-memory backend with a turn for the test before every conditional
// write, which is where another request of the browser can land between a clear's fresh read and
// its write.
type lastComparisonBackend struct {
	*sessiontest.MemoryBackend
	beforeConditional func()
}

func (b *lastComparisonBackend) UpdateIfUnchanged(ctx context.Context, id string, expected, data []byte, authenticated bool) (time.Time, error) {
	b.beforeConditional()
	return b.MemoryBackend.UpdateIfUnchanged(ctx, id, expected, data, authenticated)
}

// The shared error answer over the real ceremony store, when the clear loses its first two
// comparisons to unrelated writes of the browser and its last to another tab's /auth/authorize. It
// is the same replaced ceremony as on a first attempt, and answered the same: the page, with
// neither the error nor its state sent to the client, and ceremony B kept. Read as a clear that ran
// out of attempts, it answered server_error by redirect (#579 decision 2).
func TestAnswerClientWithError_ACeremonyReplacedAtTheLastAttemptAnswersNoLongerActive(t *testing.T) {
	backend := &lastComparisonBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.SessionIdentifier, false,
		sessionstore.PersistentCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			EncryptionKey:     []byte("0123456789abcdef0123456789abcdef"),
		}, nil)
	require.NoError(t, err)
	conditional, err := sessionstore.NewConditionalStore(store, backend)
	require.NoError(t, err)
	ceremonyStore := ceremony.NewStore(conditional, stepSaveSessionName)

	seed := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.ReplaceAuthContext(seed, httptest.NewRequest(http.MethodGet, "/auth/authorize", nil),
		&ceremony.AuthContext{CeremonyId: testCeremonyId, AuthState: ceremony.AuthStateRequiresConsent}))
	cookies := seed.Result().Cookies()
	req := withCookies(httptest.NewRequest(http.MethodGet, "/auth/consent?ceremony="+testCeremonyId, nil), cookies)
	_, err = ceremonyStore.GetAuthContext(req)
	require.NoError(t, err)

	comparisons := 0
	backend.beforeConditional = func() {
		comparisons++
		other := withCookies(httptest.NewRequest(http.MethodGet, "/auth/authorize", nil), cookies)
		if comparisons == 3 {
			require.NoError(t, ceremonyStore.ReplaceAuthContext(httptest.NewRecorder(), other,
				&ceremony.AuthContext{CeremonyId: "ceremony-b", AuthState: ceremony.AuthStateRequiresLevel1}))
			return
		}
		sess, getErr := store.Get(other, stepSaveSessionName)
		require.NoError(t, getErr)
		sess.Values["unrelated"] = comparisons
		require.NoError(t, store.Save(other, httptest.NewRecorder(), sess))
	}

	pageRenderer := handlersmocks.NewPageRenderer(t)
	rr := httptest.NewRecorder()
	expectCeremonyNoLongerActive(t, pageRenderer, rr, req)
	logged := logtest.CaptureSlog(t)

	answerClientWithError(rr, req, datamocks.NewDatabase(t), pageRenderer, ceremonyStore, nil, testCeremonyId,
		testRedirectError("access_denied", "The user did not provide consent", "query",
			"https://legit.example/cb", "state-a", "code"))

	assert.Equal(t, 3, comparisons)
	assertAnsweredNoLongerActive(t, rr)
	assertReplacedAnsweredAtWarn(t, logged)
	assert.Empty(t, rr.Result().Cookies())
	stored, err := ceremonyStore.GetAuthContext(withCookies(httptest.NewRequest(http.MethodGet, "/auth/level1", nil), cookies))
	require.NoError(t, err)
	assert.Equal(t, "ceremony-b", stored.CeremonyId)
	pageRenderer.AssertExpectations(t)
}

// The same answer through a step's handler: /auth/issue refusing a user disabled since
// /auth/completed answers access_denied by redirect, and a replaced ceremony gets the page instead.
func TestHandleIssueGet_ARefusalOfAReplacedCeremonyAnswersNoLongerActive(t *testing.T) {
	f := newRecheckFixture(t, "code", "")
	f.user.Enabled = false
	f.auditLogger.On("Log", mock.Anything, audit.EventUserDisabled, mock.Anything).Return().Once()
	expectStepClearReplaced(t, f.ceremonyStore, f.pageRenderer, f.rr, f.req)

	f.serve()

	assertAnsweredNoLongerActive(t, f.rr)
	f.assertNothingIssued(t)
	f.pageRenderer.AssertExpectations(t)
	f.ceremonyStore.AssertExpectations(t)
}

// The two issuance refusals that answer on a page of their own render the "no longer active" page
// instead, so one condition keeps one page wherever it fires.
func TestHandleIssueGet_AReplacedCeremonyIsNotRefusedOnItsOwnPage(t *testing.T) {
	t.Run("a disabled client", func(t *testing.T) {
		f := newRecheckFixture(t, "code", "")
		f.client.Enabled = false
		expectStepClearReplaced(t, f.ceremonyStore, f.pageRenderer, f.rr, f.req)
		logged := logtest.CaptureSlog(t)

		f.serve()

		assertAnsweredNoLongerActive(t, f.rr)
		assertReplacedAnsweredAtWarn(t, logged)
		f.assertNothingIssued(t)
		f.pageRenderer.AssertExpectations(t)
		f.ceremonyStore.AssertExpectations(t)
	})

	t.Run("a redirect URI no longer registered", func(t *testing.T) {
		f := newRecheckFixture(t, "code", "")
		f.authContext.RedirectURI = "https://example.com/deregistered"
		f.auditLogger.On("Log", mock.Anything, audit.EventIssuanceRefusedRedirectURI, mock.Anything).Return().Once()
		expectStepClearReplaced(t, f.ceremonyStore, f.pageRenderer, f.rr, f.req)
		logged := logtest.CaptureSlog(t)

		f.serve()

		assertAnsweredNoLongerActive(t, f.rr)
		assertReplacedAnsweredAtWarn(t, logged)
		f.assertNothingIssued(t)
		f.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
			"/auth_redirect_blocked.html", mock.Anything)
		f.pageRenderer.AssertExpectations(t)
		f.ceremonyStore.AssertExpectations(t)
	})
}

// /auth/issue mints before it clears, so a clear that finds the ceremony replaced comes after a code
// or tokens exist. They are not delivered: the page is answered, and the code, of which only the
// digest is stored, reaches nobody until the worker sweeps it.
func TestHandleIssueGet_WhatIsMintedForAReplacedCeremonyIsNotDelivered(t *testing.T) {
	t.Run("a code", func(t *testing.T) {
		f := newRecheckFixture(t, "code", "")
		f.codeIssuer.On("IssueAuthCodeTx", mock.Anything, mock.Anything).
			Return(&record.Code{Id: 1, Code: "the-code", ClientId: 1, RedirectURI: "https://example.com/callback",
				State: "test-state"}, nil).Once()
		f.auditLogger.On("Log", mock.Anything, audit.EventCreatedAuthCode, mock.Anything).Return().Once()
		expectStepClearReplaced(t, f.ceremonyStore, f.pageRenderer, f.rr, f.req)

		f.serve()

		assertAnsweredNoLongerActive(t, f.rr)
		assert.NotContains(t, f.rr.Body.String(), "the-code")
		f.pageRenderer.AssertExpectations(t)
		f.ceremonyStore.AssertExpectations(t)
	})

	t.Run("implicit tokens", func(t *testing.T) {
		f := newRecheckFixture(t, "token", "")
		f.implicitIssuer.On("IssueImplicitTx", mock.Anything, mock.Anything, mock.Anything, true, false).
			Return(&issuance.ImplicitGrantResponse{AccessToken: "the-token", TokenType: "Bearer", ExpiresIn: 60,
				Scope: "openid"}, nil).Once()
		f.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedImplicitResponse, mock.Anything).Return().Once()
		expectStepClearReplaced(t, f.ceremonyStore, f.pageRenderer, f.rr, f.req)

		f.serve()

		assertAnsweredNoLongerActive(t, f.rr)
		assert.NotContains(t, f.rr.Body.String(), "the-token")
		f.pageRenderer.AssertExpectations(t)
		f.ceremonyStore.AssertExpectations(t)
	})
}

// The lost-enrolment ending answers the "no longer active" page, not its own 409, when the browser
// has moved on to another ceremony: the sign-in the user is in is not the one whose authenticator
// changed.
func TestHandleAuthOtpPost_AnEnrolmentEndingForAReplacedCeremonyAnswersNoLongerActive(t *testing.T) {
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
	form.Add(ceremonyIdField, testCeremonyId)
	form.Add("otp", otpCode)
	req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
		AuthState:  ceremony.AuthStateLevel2OTP,
		CeremonyId: testCeremonyId,
		UserId:     1,
		ClientId:   "test-client",
		OTPKeyURL:  otpTestKeyURL(key.Secret()),
	}, nil)
	// The account has an authenticator now, set up after this ceremony rendered its enrolment.
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).
		Return(&record.User{Id: 1, Enabled: true, OTPEnabled: true, OtpConfigGeneration: 4}, nil)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(&record.Client{ClientIdentifier: "test-client"}, nil)
	expectStepClearReplaced(t, ceremonyStore, pageRenderer, rr, req)

	handler.ServeHTTP(rr, req)

	assertAnsweredNoLongerActive(t, rr)
	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertExpectations(t)
}

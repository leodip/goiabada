package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// The sign-in setup's recovery-codes step (#257 decision 14). An accepted setup code leaves the set
// the new authenticator came with on the ceremony, in level2_recovery_codes, and GET
// /auth/recovery-codes shows it: the save that takes the codes off the ceremony lands before the
// page renders, so the set is shown once, and a reload draws the page that says they were already
// shown. Both pages carry the same Continue, POST /auth/recovery-codes, which moves the ceremony to
// authentication_completed and answers 303 to /auth/completed.

// setupRecoveryCodes is a set as the setup step holds it, as shown.
var setupRecoveryCodes = []string{
	"7kq2-m9xh-4trw-b3np-j6vd-egac", "0123-4567-89ab-cdef-ghjk-mnpq", "rstv-wxyz-0123-4567-89ab-cdef",
	"ghjk-mnpq-rstv-wxyz-0123-4567", "89ab-cdef-ghjk-mnpq-rstv-wxyz", "a1b2-c3d4-e5f6-g7h8-j9k0-mnpq",
	"zzzz-yyyy-xxxx-wwww-vvvv-tttt", "0000-1111-2222-3333-4444-5555", "6666-7777-8888-9999-aaaa-bbbb",
	"cccc-dddd-eeee-ffff-gggg-hhhh",
}

type recoveryCodesStepMocks struct {
	pageRenderer  *handlersmocks.PageRenderer
	ceremonyStore *handlersmocks.CeremonyStore
	database      *datamocks.Database
	auditLogger   *handlersmocks.AuditLogger
}

func newRecoveryCodesStepMocks(t *testing.T) recoveryCodesStepMocks {
	return recoveryCodesStepMocks{
		pageRenderer:  handlersmocks.NewPageRenderer(t),
		ceremonyStore: handlersmocks.NewCeremonyStore(t),
		database:      datamocks.NewDatabase(t),
		auditLogger:   handlersmocks.NewAuditLogger(t),
	}
}

func (m recoveryCodesStepMocks) get() http.HandlerFunc {
	return buildAuthRecoveryCodesGet(authRecoveryCodesGetDeps{pageRenderer: m.pageRenderer,
		ceremonyStore: m.ceremonyStore, database: m.database, auditLogger: m.auditLogger})
}

func (m recoveryCodesStepMocks) post() http.HandlerFunc {
	return buildAuthRecoveryCodesPost(authRecoveryCodesPostDeps{pageRenderer: m.pageRenderer,
		ceremonyStore: m.ceremonyStore, auditLogger: m.auditLogger})
}

// armRecoveryCodesCeremony stores a ceremony in level2_recovery_codes for user 1 at "test-client",
// which set up an authenticator and verified its code, holding codes (nil for none).
func (m recoveryCodesStepMocks) armRecoveryCodesCeremony(codes []string) *ceremony.AuthContext {
	authContext := &ceremony.AuthContext{
		AuthState:   ceremony.AuthStateLevel2RecoveryCodes,
		CeremonyId:  testCeremonyId,
		UserId:      1,
		ClientId:    "test-client",
		AuthMethods: "pwd otp",
	}
	if codes != nil {
		authContext.RecoveryCodes = append([]string(nil), codes...)
	}
	m.ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)
	return authContext
}

func (m recoveryCodesStepMocks) armClient() {
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(&record.Client{ClientIdentifier: "test-client", ShowDisplayName: true, DisplayName: "Test Client"}, nil).Once()
}

func recoveryCodesGetRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth/recovery-codes?ceremony="+testCeremonyId, nil)
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "TestApp"}))
}

func recoveryCodesContinueRequest() *http.Request {
	form := url.Values{}
	form.Add(ceremony.IdField, testCeremonyId)
	req := httptest.NewRequest(http.MethodPost, "/auth/recovery-codes", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
}

// The first render shows the ten codes the ceremony holds, in the order they were drawn, beside the
// client block, naming the ceremony for the Continue form. The codes leave the ceremony in a save
// that lands before the page renders, and the ceremony stays in level2_recovery_codes, so the
// reload's page is this step's and its Continue still works. No log record carries a code.
func TestHandleAuthRecoveryCodesGet_TheFirstRenderShowsTheSetOnce(t *testing.T) {
	logged := logtest.CaptureSlog(t)
	m := newRecoveryCodesStepMocks(t)
	authContext := m.armRecoveryCodesCeremony(setupRecoveryCodes)
	m.armClient()

	req := recoveryCodesGetRequest()
	rr := httptest.NewRecorder()

	saved := false
	m.ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
		return len(ac.RecoveryCodes) == 0 && ac.AuthState == ceremony.AuthStateLevel2RecoveryCodes
	})).Return(nil).Once().Run(func(mock.Arguments) { saved = true })
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_recovery_codes.html",
		mock.MatchedBy(func(bind map[string]interface{}) bool {
			return assert.Equal(t, setupRecoveryCodes, bind["recoveryCodes"]) &&
				bind["ceremonyId"] == testCeremonyId &&
				bind["layoutShowClientSection"] == true &&
				bind["layoutClientName"] == "Test Client"
		})).Return(nil).Once().Run(func(mock.Arguments) {
		assert.True(t, saved, "the codes must leave the ceremony before the page that shows them renders")
	})

	m.get().ServeHTTP(rr, req)

	m.pageRenderer.AssertExpectations(t)
	m.ceremonyStore.AssertExpectations(t)
	assert.Empty(t, authContext.RecoveryCodes)
	for _, code := range setupRecoveryCodes {
		assert.NotContains(t, logged.Text(), code)
	}
}

// A reload finds no codes on the ceremony, so it draws the page that says they were already shown,
// with the same Continue, and writes nothing.
func TestHandleAuthRecoveryCodesGet_AReloadDoesNotShowTheCodesAgain(t *testing.T) {
	m := newRecoveryCodesStepMocks(t)
	m.armRecoveryCodesCeremony(nil)
	m.armClient()

	req := recoveryCodesGetRequest()
	rr := httptest.NewRecorder()

	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_recovery_codes.html",
		mock.MatchedBy(func(bind map[string]interface{}) bool {
			codes, _ := bind["recoveryCodes"].([]string)
			return len(codes) == 0 && bind["ceremonyId"] == testCeremonyId
		})).Return(nil).Once()

	m.get().ServeHTTP(rr, req)

	m.pageRenderer.AssertExpectations(t)
	m.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
}

// A save that finds the ceremony no longer held shows nothing: the codes are drawn only once the
// write taking them off the ceremony has landed, so no failure can show a set twice.
func TestHandleAuthRecoveryCodesGet_AReplacedCeremonyShowsNoCodes(t *testing.T) {
	m := newRecoveryCodesStepMocks(t)
	m.armRecoveryCodesCeremony(setupRecoveryCodes)
	m.armClient()

	req := recoveryCodesGetRequest()
	rr := httptest.NewRecorder()
	expectStepSaveReplaced(t, m.ceremonyStore, m.pageRenderer, rr, req)

	m.get().ServeHTTP(rr, req)

	assertAnsweredNoLongerActive(t, rr)
	m.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/auth_layout.html", "/auth_recovery_codes.html", mock.Anything)
}

// A save that fails otherwise is the 500 page, and shows no codes either.
func TestHandleAuthRecoveryCodesGet_AFailedSaveShowsNoCodes(t *testing.T) {
	m := newRecoveryCodesStepMocks(t)
	m.armRecoveryCodesCeremony(setupRecoveryCodes)
	m.armClient()

	req := recoveryCodesGetRequest()
	rr := httptest.NewRecorder()
	saveErr := errors.New("session store down")
	m.ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(saveErr).Once()
	m.pageRenderer.On("InternalServerError", rr, req, saveErr).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.pageRenderer.AssertExpectations(t)
	m.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/auth_layout.html", "/auth_recovery_codes.html", mock.Anything)
}

// A client that cannot be read is the 500 page, before the codes leave the ceremony: a reload can
// still show them.
func TestHandleAuthRecoveryCodesGet_AFailedClientReadKeepsTheCodes(t *testing.T) {
	m := newRecoveryCodesStepMocks(t)
	authContext := m.armRecoveryCodesCeremony(setupRecoveryCodes)
	readErr := errors.New("database down")
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(nil, readErr).Once()

	req := recoveryCodesGetRequest()
	rr := httptest.NewRecorder()
	m.pageRenderer.On("InternalServerError", rr, req, mock.Anything).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.pageRenderer.AssertExpectations(t)
	m.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	assert.Equal(t, setupRecoveryCodes, authContext.RecoveryCodes)
}

// Continue moves the ceremony to authentication_completed, holding no codes, and answers 303 to
// /auth/completed naming the ceremony, as every sign-in POST answers (RFC 9700 section 4.12).
func TestHandleAuthRecoveryCodesPost_ContinueGoesOnToCompleted(t *testing.T) {
	m := newRecoveryCodesStepMocks(t)
	m.armRecoveryCodesCeremony(setupRecoveryCodes)

	req := recoveryCodesContinueRequest()
	rr := httptest.NewRecorder()
	m.ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
		return ac.AuthState == ceremony.AuthStateAuthenticationCompleted && len(ac.RecoveryCodes) == 0 &&
			ac.AuthMethods == "pwd otp"
	})).Return(nil).Once()

	m.post().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, testBaseURL+"/auth/completed?ceremony="+testCeremonyId, rr.Header().Get("Location"))
	m.ceremonyStore.AssertExpectations(t)
}

// A Continue whose save finds the ceremony no longer held goes nowhere.
func TestHandleAuthRecoveryCodesPost_AReplacedCeremonyGoesNowhere(t *testing.T) {
	m := newRecoveryCodesStepMocks(t)
	m.armRecoveryCodesCeremony(nil)

	req := recoveryCodesContinueRequest()
	rr := httptest.NewRecorder()
	expectStepSaveReplaced(t, m.ceremonyStore, m.pageRenderer, rr, req)

	m.post().ServeHTTP(rr, req)

	assertAnsweredNoLongerActive(t, rr)
	m.pageRenderer.AssertExpectations(t)
}

// The step is reachable only in level2_recovery_codes: a ceremony still at the code, or one already
// past this step, is the state-mismatch page on either method, and nothing is read or written.
func TestHandleAuthRecoveryCodes_OnlyLevel2RecoveryCodesIsAccepted(t *testing.T) {
	for _, state := range []ceremony.AuthState{ceremony.AuthStateLevel2OTP, ceremony.AuthStateAuthenticationCompleted} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(string(state)+" "+method, func(t *testing.T) {
				m := newRecoveryCodesStepMocks(t)
				authContext := m.armRecoveryCodesCeremony(setupRecoveryCodes)
				authContext.AuthState = state

				req := recoveryCodesGetRequest()
				handler := m.get()
				if method == http.MethodPost {
					req = recoveryCodesContinueRequest()
					handler = m.post()
				}
				rr := httptest.NewRecorder()
				expectAuthStateMismatch(t, m.pageRenderer, rr, req)

				handler.ServeHTTP(rr, req)

				m.pageRenderer.AssertExpectations(t)
				m.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
				assert.Equal(t, setupRecoveryCodes, authContext.RecoveryCodes)
			})
		}
	}
}

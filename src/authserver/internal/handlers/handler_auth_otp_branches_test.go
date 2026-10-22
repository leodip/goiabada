package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The branches of the OTP step that no other case reaches: settings that are missing, a user or a
// client that cannot be read, an enrolment key that cannot be generated, parsed or drawn, a page
// that cannot render, and a lost enrolment whose clear or page fails. Each 500 answers with the
// error it met and goes no further: no save, no rotation, no verification. The POST reads the
// client only for a form it shows again, so a client that cannot be read fails a refusal after what
// the refusal did, and an accepted code or a lost enrolment reads none.

// otpStepMocks is one OTP step's doubles, strict, so a read or a write a case does not arm fails it.
type otpStepMocks struct {
	pageRenderer       *handlersmocks.PageRenderer
	ceremonyStore      *handlersmocks.CeremonyStore
	database           *datamocks.Database
	auditLogger        *handlersmocks.AuditLogger
	otpSecretGenerator *handlersmocks.OtpSecretGenerator
}

func newOtpStepMocks(t *testing.T) otpStepMocks {
	return otpStepMocks{
		pageRenderer:       handlersmocks.NewPageRenderer(t),
		ceremonyStore:      handlersmocks.NewCeremonyStore(t),
		database:           datamocks.NewDatabase(t),
		auditLogger:        handlersmocks.NewAuditLogger(t),
		otpSecretGenerator: handlersmocks.NewOtpSecretGenerator(t),
	}
}

func (m otpStepMocks) get() http.HandlerFunc {
	return buildAuthOtpGet(authOtpGetDeps{pageRenderer: m.pageRenderer, ceremonyStore: m.ceremonyStore,
		database: m.database, otpSecretGenerator: m.otpSecretGenerator, auditLogger: m.auditLogger})
}

func (m otpStepMocks) post() http.HandlerFunc {
	return buildAuthOtpPost(authOtpPostDeps{pageRenderer: m.pageRenderer, ceremonyStore: m.ceremonyStore,
		database: m.database, auditLogger: m.auditLogger})
}

// armOtpCeremony stores a ceremony in level2_otp for user 1 at the client "test-client", carrying
// keyURL as its enrolment key ("" for none).
func (m otpStepMocks) armOtpCeremony(keyURL string) *ceremony.AuthContext {
	authContext := &ceremony.AuthContext{
		AuthState:  ceremony.AuthStateLevel2OTP,
		CeremonyId: testCeremonyId,
		UserId:     1,
		ClientId:   "test-client",
		OTPKeyURL:  keyURL,
	}
	m.ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)
	return authContext
}

func (m otpStepMocks) armUser(user *record.User) {
	m.database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil).Once()
}

func (m otpStepMocks) armClient() {
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(&record.Client{ClientIdentifier: "test-client"}, nil).Once()
}

// assertNothingSaved is what a 500 of the OTP step leaves: the ceremony neither saved nor rotated,
// and no form rendered.
func (m otpStepMocks) assertNothingSaved(t *testing.T) {
	t.Helper()
	m.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	m.ceremonyStore.AssertNotCalled(t, "RegenerateSession", mock.Anything, mock.Anything, mock.Anything)
	m.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/auth_layout.html", mock.Anything, mock.Anything)
}

func otpGetRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth/otp?ceremony="+testCeremonyId, nil)
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "TestApp"}))
}

func otpPostRequest(code string) *http.Request {
	form := url.Values{}
	form.Add(ceremonyIdField, testCeremonyId)
	form.Add("otp", code)
	req := httptest.NewRequest(http.MethodPost, "/auth/otp", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
}

// otpUndrawableKeyURL is a well-formed TOTP key URL too long for any QR code: its secret parses,
// and drawing it fails.
func otpUndrawableKeyURL() string {
	return otpTestKeyURL(strings.Repeat("A", 3000))
}

// Both OTP routes read their settings at the route boundary before anything else, so a request
// reaching either without them answers the 500 page carrying reqctx.ErrNoSettings and reads nothing,
// not even its ceremony (#580 decision 5).
func TestMissingSettings_TheOTPStepAnswersBeforeReadingItsCeremony(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			m := newOtpStepMocks(t)
			var req *http.Request
			var handler http.Handler
			if method == http.MethodPost {
				form := url.Values{}
				form.Add(ceremonyIdField, testCeremonyId)
				form.Add("otp", "123456")
				req = httptest.NewRequest(http.MethodPost, "/auth/otp", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				handler = m.post()
			} else {
				req = httptest.NewRequest(http.MethodGet, "/auth/otp?ceremony="+testCeremonyId, nil)
				handler = m.get()
			}
			rr := httptest.NewRecorder()
			m.pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

			handler.ServeHTTP(rr, req)

			m.ceremonyStore.AssertNotCalled(t, "GetAuthContext", req)
			m.database.AssertNotCalled(t, "GetUserById", mock.Anything, mock.Anything, mock.Anything)
			m.otpSecretGenerator.AssertNotCalled(t, "GenerateKeyURL", mock.Anything, mock.Anything)
			m.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			m.assertNothingSaved(t)
		})
	}
}

func TestHandleAuthOtpGet_AUserReadFailingAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	m.armOtpCeremony("")
	m.database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
	m.assertNothingSaved(t)
}

func TestHandleAuthOtpGet_AUserNotFoundAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	m.armOtpCeremony("")
	m.database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, nil).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheMessage("user not found")).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
	m.assertNothingSaved(t)
}

func TestHandleAuthOtpGet_AClientReadFailingAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	m.armOtpCeremony("")
	m.armUser(&record.User{Id: 1, Email: "test@example.com"})
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(nil, assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.otpSecretGenerator.AssertNotCalled(t, "GenerateKeyURL", mock.Anything, mock.Anything)
	m.assertNothingSaved(t)
}

func TestHandleAuthOtpGet_AClientNotFoundAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	m.armOtpCeremony("")
	m.armUser(&record.User{Id: 1, Email: "test@example.com"})
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(nil, nil).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheMessage("client not found")).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.otpSecretGenerator.AssertNotCalled(t, "GenerateKeyURL", mock.Anything, mock.Anything)
	m.assertNothingSaved(t)
}

// The code form is rendered after its save, so a form that cannot render answers 500 with the
// ceremony already saved without its stale enrolment key.
func TestHandleAuthOtpGet_ACodeFormThatCannotRenderAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	m.armOtpCeremony(otpTestKeyURL("STALESECRETSTALE"))
	m.armUser(&record.User{Id: 1, OTPEnabled: true})
	m.armClient()
	m.ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
		return ac.OTPKeyURL == ""
	})).Return(nil).Once()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).
		Return(assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.get().ServeHTTP(rr, req)
}

// A save that fails other than by finding its ceremony replaced answers 500 and renders no form.
func TestHandleAuthOtpGet_ASaveFailingAnswers500(t *testing.T) {
	for _, tc := range []struct {
		name       string
		otpEnabled bool
	}{
		{name: "the code form", otpEnabled: true},
		{name: "the enrolment form", otpEnabled: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newOtpStepMocks(t)
			req := otpGetRequest()
			rr := httptest.NewRecorder()
			m.armOtpCeremony(otpTestKeyURL("JBSWY3DPEHPK3PXP"))
			m.armUser(&record.User{Id: 1, Email: "test@example.com", OTPEnabled: tc.otpEnabled})
			m.armClient()
			m.ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(assert.AnError).Once()
			m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

			m.get().ServeHTTP(rr, req)

			m.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything,
				"/layouts/auth_layout.html", mock.Anything, mock.Anything)
		})
	}
}

// The generator is handed the settings' application name, which the boundary read before anything
// else; a generator that fails answers 500 and nothing is saved.
func TestHandleAuthOtpGet_AKeyThatCannotBeGeneratedAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	m.armOtpCeremony("")
	m.armUser(&record.User{Id: 1, Email: "test@example.com"})
	m.armClient()
	m.otpSecretGenerator.On("GenerateKeyURL", "test@example.com", "TestApp").Return("", assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.assertNothingSaved(t)
}

func TestHandleAuthOtpGet_AGeneratedKeyThatDoesNotParseAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	authContext := m.armOtpCeremony("")
	m.armUser(&record.User{Id: 1, Email: "test@example.com"})
	m.armClient()
	m.otpSecretGenerator.On("GenerateKeyURL", "test@example.com", "TestApp").Return("not a key url", nil).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheMessage("otp key url is not a totp key")).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.assertNothingSaved(t)
	assert.Equal(t, "not a key url", authContext.OTPKeyURL, "the generated key is what failed to parse")
}

// The QR code is drawn before the save, so a key that cannot be drawn answers 500 and the ceremony
// is not saved with it.
func TestHandleAuthOtpGet_AKeyThatCannotBeDrawnAnswers500AndSavesNothing(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	m.armOtpCeremony(otpUndrawableKeyURL())
	m.armUser(&record.User{Id: 1, Email: "test@example.com"})
	m.armClient()
	m.pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "unable to generate otp png image")
	})).Return().Once()

	m.get().ServeHTTP(rr, req)

	m.otpSecretGenerator.AssertNotCalled(t, "GenerateKeyURL", mock.Anything, mock.Anything)
	m.assertNothingSaved(t)
}

// A stored key that does not parse counts as none: a fresh key is generated, saved and rendered,
// rather than the ceremony wedged on a 500 every reload repeats (#247).
func TestHandleAuthOtpGet_AStoredKeyThatDoesNotParseIsReplaced(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	authContext := m.armOtpCeremony("not a key url")
	m.armUser(&record.User{Id: 1, Email: "test@example.com"})
	m.armClient()
	generated := otpTestKeyURL("JBSWY3DPEHPK3PXP")
	m.otpSecretGenerator.On("GenerateKeyURL", "test@example.com", "TestApp").Return(generated, nil).Once()
	m.ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
		return ac.OTPKeyURL == generated
	})).Return(nil).Once()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_enrollment.html",
		mock.MatchedBy(func(bind map[string]interface{}) bool {
			return bind["secretKey"] == "JBSWY3DPEHPK3PXP" &&
				bind["base64Image"] == otpTestRenderedQR(t, generated) &&
				bind["ceremonyId"] == testCeremonyId
		})).Return(nil).Once()

	m.get().ServeHTTP(rr, req)

	assert.Equal(t, generated, authContext.OTPKeyURL)
}

func TestHandleAuthOtpGet_AnEnrolmentFormThatCannotRenderAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpGetRequest()
	rr := httptest.NewRecorder()
	m.armOtpCeremony(otpTestKeyURL("JBSWY3DPEHPK3PXP"))
	m.armUser(&record.User{Id: 1, Email: "test@example.com"})
	m.armClient()
	m.ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_enrollment.html",
		mock.Anything).Return(assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.get().ServeHTTP(rr, req)
}

// The enrolment key is parsed before anything is read, so a key that does not parse answers 500
// with no user read and no code looked at.
func TestHandleAuthOtpPost_AnEnrolmentKeyThatDoesNotParseAnswers500BeforeAnyRead(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpPostRequest("123456")
	rr := httptest.NewRecorder()
	m.armOtpCeremony("not a key url")
	m.pageRenderer.On("InternalServerError", rr, req, isTheMessage("otp key url is not a totp key")).Return().Once()

	m.post().ServeHTTP(rr, req)

	m.database.AssertNotCalled(t, "GetUserById", mock.Anything, mock.Anything, mock.Anything)
	m.database.AssertNotCalled(t, "TryConsumeUserOTPStep", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	m.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	m.assertNothingSaved(t)
}

func TestHandleAuthOtpPost_AUserReadFailingAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpPostRequest("123456")
	rr := httptest.NewRecorder()
	m.armOtpCeremony("")
	m.database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.post().ServeHTTP(rr, req)

	m.database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
	m.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	m.assertNothingSaved(t)
}

// A wrong code whose form cannot be shown again, because the client cannot be read, answers 500
// once the code is refused: it is charged to the rate limiter and audited first, as every wrong
// code is.
func TestHandleAuthOtpPost_AClientReadFailingOnARefusalAnswers500AfterTheCodeIsChecked(t *testing.T) {
	m := newOtpStepMocks(t)
	failures := &credentialFailureSpy{}
	handler := buildAuthOtpPost(authOtpPostDeps{pageRenderer: m.pageRenderer, ceremonyStore: m.ceremonyStore,
		database: m.database, auditLogger: m.auditLogger, credentialFailures: failures})
	req := otpPostRequest("123456")
	rr := httptest.NewRecorder()
	m.armOtpCeremony("")
	m.armUser(&record.User{Id: 1, Enabled: true, OTPEnabled: true,
		OTPSecretEncrypted: encryptOTPForTest(t, "test-secret")})
	// A refused code against the enrolled authenticator advances the consecutive count (#489).
	m.database.On("IncrementUserOtpConsecutiveFailures", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Once()
	m.auditLogger.On("Log", mock.Anything, audit.EventAuthFailedOtp, map[string]interface{}{"user_id": int64(1)}).
		Return().Once()
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(nil, assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	handler.ServeHTTP(rr, req)

	assert.Len(t, failures.requests, 1, "the refused code is charged before the client is read")
	m.assertNothingSaved(t)
}

// A submission with no code whose client is gone answers 500 as the GET does, and checks no code.
func TestHandleAuthOtpPost_AClientNotFoundOnARefusalAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpPostRequest("")
	rr := httptest.NewRecorder()
	m.armOtpCeremony("")
	m.armUser(&record.User{Id: 1, Enabled: true, OTPEnabled: true})
	m.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(nil, nil).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheMessage("client not found")).Return().Once()

	m.post().ServeHTTP(rr, req)

	m.database.AssertNotCalled(t, "TryConsumeEnrolledUserOTPStep", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
	m.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	m.assertNothingSaved(t)
}

// The enrolment form shown again beside a refusal redraws its QR code; a key that cannot be drawn
// answers 500 in place of the form. The disabled account is the refusal, so no code is checked.
func TestHandleAuthOtpPost_AnEnrolmentFormWhoseKeyCannotBeDrawnAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpPostRequest("123456")
	rr := httptest.NewRecorder()
	m.armOtpCeremony(otpUndrawableKeyURL())
	m.armUser(&record.User{Id: 1, Enabled: false})
	m.armClient()
	m.auditLogger.On("Log", mock.Anything, audit.EventUserDisabled, map[string]interface{}{"user_id": int64(1)}).
		Return().Once()
	m.pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "unable to generate otp png image")
	})).Return().Once()

	m.post().ServeHTTP(rr, req)

	m.assertNothingSaved(t)
}

func TestHandleAuthOtpPost_AFormThatCannotRenderAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpPostRequest("")
	rr := httptest.NewRecorder()
	m.armOtpCeremony("")
	m.armUser(&record.User{Id: 1, Enabled: true, OTPEnabled: true})
	m.armClient()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html",
		mock.MatchedBy(func(bind map[string]interface{}) bool {
			return bind["error"] == "Enter the 6-digit code from your authenticator app." && bind["ceremonyId"] == testCeremonyId
		})).Return(assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.post().ServeHTTP(rr, req)

	m.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	m.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
}

// A lost enrolment whose clear fails other than by finding the ceremony replaced still answers its
// own page, at 409, after an error record: a replay of the context left behind meets the same
// refusal or a state gate.
func TestHandleAuthOtpPost_ALostEnrolmentWhoseClearFailsStillAnswersItsPage(t *testing.T) {
	logged := logtest.CaptureSlog(t)
	m := newOtpStepMocks(t)
	req := otpPostRequest("123456")
	rr := httptest.NewRecorder()
	m.armOtpCeremony(otpTestKeyURL("JBSWY3DPEHPK3PXP"))
	// The account has an authenticator now, set up after this ceremony rendered its enrolment.
	m.armUser(&record.User{Id: 1, Enabled: true, OTPEnabled: true, OtpConfigGeneration: 4})
	m.ceremonyStore.On("ClearAuthContext", rr, req, testCeremonyId).Return(assert.AnError).Once()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["_httpStatus"] == http.StatusConflict &&
				data["title"] == "Your two-factor authentication settings changed"
		})).Return(nil).Once()

	m.post().ServeHTTP(rr, req)

	records := logged.Records()
	require.Len(t, records, 2)
	assert.Equal(t, slog.LevelWarn, records[0].Level)
	assert.Equal(t, "the account's authenticator changed during the enrolment, so nothing was stored and the sign-in ends",
		records[0].Message)
	assert.Equal(t, int64(1), records[0].Attrs["user_id"])
	assert.Equal(t, slog.LevelError, records[1].Level)
	assert.Equal(t, "unable to clear the auth context while ending a lost enrolment, rendering the page anyway",
		records[1].Message)
	assert.Equal(t, assert.AnError, records[1].Attrs["error"])
	m.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	m.pageRenderer.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleAuthOtpPost_ALostEnrolmentWhosePageCannotRenderAnswers500(t *testing.T) {
	m := newOtpStepMocks(t)
	req := otpPostRequest("123456")
	rr := httptest.NewRecorder()
	m.armOtpCeremony(otpTestKeyURL("JBSWY3DPEHPK3PXP"))
	m.armUser(&record.User{Id: 1, Enabled: true, OTPEnabled: true, OtpConfigGeneration: 4})
	m.ceremonyStore.On("ClearAuthContext", rr, req, testCeremonyId).Return(nil).Once()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.Anything).Return(assert.AnError).Once()
	m.pageRenderer.On("InternalServerError", rr, req, isTheError(assert.AnError)).Return().Once()

	m.post().ServeHTTP(rr, req)
}

package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	accounthandlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/requestid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The set-up notice from a sign-in (#724): a user who sets up an authenticator on the sign-in
// code step is told, as on the Account pages, once the step has committed and after its response.
// The step's operation reports what happened as a plain value, and the handler hands the notice
// off. A code checked against an authenticator the user already had, a lost enrolment and a
// rolled-back one tell nobody.

const (
	signInNoticeAddress   = "joana.reis@example.com"
	signInNoticeRequestId = "req-sign-in-otp-0001"
)

// signInNoticeJobs holds every job handed to it rather than starting it, so a case asserts what
// the request did before its response, and then runs the jobs.
type signInNoticeJobs struct {
	ctxs    []context.Context
	classes []afterresponse.Class
	jobs    []func(ctx context.Context)
}

func (h *signInNoticeJobs) Go(ctx context.Context, class afterresponse.Class, job func(ctx context.Context)) {
	h.ctxs = append(h.ctxs, ctx)
	h.classes = append(h.classes, class)
	h.jobs = append(h.jobs, job)
}

// signInNoticeSettings are the request's settings with SMTP on.
func signInNoticeSettings() *record.Settings {
	return &record.Settings{
		AppName:       "Goiabada",
		SMTPEnabled:   true,
		SMTPHost:      "smtp.example.com",
		SMTPPort:      587,
		SMTPFromEmail: "noreply@example.com",
	}
}

// signInNoticeUser is the user signing in, with a verified address and a name, and no
// authenticator yet.
func signInNoticeUser() *record.User {
	return &record.User{
		Id:            1,
		Enabled:       true,
		GivenName:     "Joana",
		FamilyName:    "Reis",
		Email:         signInNoticeAddress,
		EmailVerified: true,
		Locale:        "pt-BR",
	}
}

// signInNoticeRequest submits code on the sign-in code step, with the request's id and settings.
func signInNoticeRequest(t *testing.T, settings *record.Settings, code string) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Add(ceremony.IdField, testCeremonyId)
	form.Add("otp", code)
	req, err := http.NewRequest(http.MethodPost, "/auth/otp", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	ctx := requestid.NewContext(req.Context(), signInNoticeRequestId)
	return req.WithContext(reqctx.WithSettings(ctx, settings))
}

// stubSignInEnrolment answers an enrolment whose authenticator write commits, up to the rotation.
func stubSignInEnrolment(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User) {
	database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
	database.On("TryConsumeUserOTPStep", mock.Anything, mock.Anything, user.Id, mock.Anything).Return(true, nil).Once()
	datamocks.ExpectRunInTransaction(database, otpEnrolTx)
	database.On("TryEstablishUserOTP", mock.Anything, otpEnrolTx, user.Id, user.OtpConfigGeneration, mock.Anything).
		Return(true, nil).Once()
	database.On("IncrementUserOtpConfigGeneration", mock.Anything, otpEnrolTx, user.Id).Return(int64(1), nil).Once()
	database.On("ClearPendingOTPEnrollment", mock.Anything, otpEnrolTx, user.Id).Return(nil).Once()
	database.On("ClearUserOtpConsecutiveFailures", mock.Anything, otpEnrolTx, user.Id).Return(nil).Once()
	database.On("ReplaceUserRecoveryCodes", mock.Anything, otpEnrolTx, user.Id, mock.Anything).Return(nil).Once()
	database.On("GetUserByIdForUpdate", mock.Anything, otpEnrolTx, user.Id).Return(user, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventEnabledOTP, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventRecoveryCodesCreated, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessOtp, mock.Anything).Return().Once()
}

func TestHandleAuthOtpPost_TellsTheUserTwoFactorWasSetUpDuringTheSignIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		// saveErr is the rotation's failure, nil for a sign-in that goes on.
		saveErr error
	}{
		{"the sign-in goes on to the recovery codes", nil},
		// The authenticator was stored before the rotation failed, so the user is told anyway.
		{"the ceremony can't be saved after the authenticator was stored", errors.New("session store down")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &signInNoticeJobs{}

			handler := buildAuthOtpPost(authOtpPostDeps{
				pageRenderer:  pageRenderer,
				ceremonyStore: ceremonyStore,
				database:      database,
				auditLogger:   auditLogger,
				notifier:      accountnotice.New(pageRenderer, emailSender, jobs),
			})

			secret := otpTestMintedSecret(t)
			req := signInNoticeRequest(t, signInNoticeSettings(), otptest.Code(t, secret, time.Now()))
			rr := httptest.NewRecorder()

			authContext := &ceremony.AuthContext{
				AuthState:  ceremony.AuthStateLevel2OTP,
				CeremonyId: testCeremonyId,
				UserId:     1,
				ClientId:   "test-client",
				OTPKeyURL:  otpTestKeyURL(secret),
			}
			ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)
			user := signInNoticeUser()
			stubSignInEnrolment(database, auditLogger, user)
			ceremonyStore.On("RegenerateSession", rr, req, testCeremonyId, int64(1)).Return(tc.saveErr).Once()
			if tc.saveErr == nil {
				ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()
			} else {
				pageRenderer.On("InternalServerError", rr, req, mock.Anything).Return().Once()
			}

			handler.ServeHTTP(rr, req)

			// The email renderer and the sender have no expectations yet, so a notice sent
			// inside the request would already have failed the case.
			if tc.saveErr == nil {
				require.Equal(t, http.StatusSeeOther, rr.Code)
			}
			require.Len(t, jobs.jobs, 1, "the step hands off exactly one notice")
			assert.Equal(t, afterresponse.ClassSecurityNotice, jobs.classes[0])
			codes := append([]string(nil), authContext.RecoveryCodes...)

			var renderLocale string
			var bound map[string]interface{}
			pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
				"/emails/email_otp_enabled.html", mock.Anything).
				Run(func(args mock.Arguments) {
					renderLocale = i18n.LocaleTag(args.Get(0).(*http.Request).Context())
					bound = args.Get(3).(map[string]interface{})
				}).Return(bytes.NewBufferString("<p>rendered notice</p>"), nil).Once()
			var sent *emaildelivery.SendEmailInput
			emailSender.On("SendEmail", mock.Anything,
				emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com"},
				mock.Anything).
				Run(func(args mock.Arguments) { sent = args.Get(2).(*emaildelivery.SendEmailInput) }).
				Return(emaildelivery.SendResult{}, nil).Once()

			jobs.jobs[0](jobs.ctxs[0])

			require.NotNil(t, sent)
			assert.Equal(t, signInNoticeAddress, sent.To)
			assert.Equal(t, "A autenticação de dois fatores foi configurada", sent.Subject)
			assert.Equal(t, "pt-BR", renderLocale, "the notice is rendered in the user's language")
			assert.Equal(t, "Joana Reis", bound["name"])
			assert.NotContains(t, bound, "link", "the notice carries no link")
			for key, value := range bound {
				for _, code := range codes {
					assert.NotContains(t, fmt.Sprint(value), code, "the notice carries no recovery code, found under %q", key)
				}
			}
		})
	}
}

// Where no notice may go, the step hands nothing off: a code checked against the authenticator
// the user already had, an enrolment lost to a change elsewhere, one rolled back, and one made
// with an unverified address.
func TestHandleAuthOtpPost_SendsNoSetUpNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(t *testing.T, secret string, rr *httptest.ResponseRecorder, req *http.Request,
			authContext *ceremony.AuthContext, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
			ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer)
	}{
		{"the user already had an authenticator",
			func(t *testing.T, secret string, rr *httptest.ResponseRecorder, req *http.Request,
				authContext *ceremony.AuthContext, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer) {
				user := signInNoticeUser()
				user.OTPEnabled = true
				user.OTPSecretEncrypted = encryptOTPForTest(t, secret)
				database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
				database.On("TryConsumeEnrolledUserOTPStep", mock.Anything, mock.Anything, user.Id, mock.Anything, user.OtpConfigGeneration).
					Return(true, nil).Once()
				database.On("ClearUserOtpConsecutiveFailures", mock.Anything, mock.Anything, user.Id).Return(nil).Maybe()
				auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessOtp, mock.Anything).Return().Once()
				ceremonyStore.On("RegenerateSession", rr, req, testCeremonyId, int64(1)).Return(nil).Once()
				ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()
			}},
		{"the enrolment is lost to a change elsewhere",
			func(t *testing.T, secret string, rr *httptest.ResponseRecorder, req *http.Request,
				authContext *ceremony.AuthContext, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer) {
				authContext.OTPKeyURL = otpTestKeyURL(secret)
				user := signInNoticeUser()
				database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
				database.On("TryConsumeUserOTPStep", mock.Anything, mock.Anything, user.Id, mock.Anything).Return(true, nil).Once()
				datamocks.ExpectRunInTransaction(database, otpEnrolTx)
				database.On("TryEstablishUserOTP", mock.Anything, otpEnrolTx, user.Id, user.OtpConfigGeneration, mock.Anything).
					Return(false, nil).Once()
				ceremonyStore.On("ClearAuthContext", rr, req, testCeremonyId).Return(nil).Once()
				pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html", mock.Anything).
					Return(nil).Once()
			}},
		{"the enrolment rolls back",
			func(t *testing.T, secret string, rr *httptest.ResponseRecorder, req *http.Request,
				authContext *ceremony.AuthContext, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer) {
				authContext.OTPKeyURL = otpTestKeyURL(secret)
				user := signInNoticeUser()
				database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
				database.On("TryConsumeUserOTPStep", mock.Anything, mock.Anything, user.Id, mock.Anything).Return(true, nil).Once()
				datamocks.ExpectRunInTransaction(database, otpEnrolTx)
				database.On("TryEstablishUserOTP", mock.Anything, otpEnrolTx, user.Id, user.OtpConfigGeneration, mock.Anything).
					Return(true, nil).Once()
				database.On("IncrementUserOtpConfigGeneration", mock.Anything, otpEnrolTx, user.Id).
					Return(int64(0), errors.New("increment failed")).Once()
				pageRenderer.On("InternalServerError", rr, req, mock.Anything).Return().Once()
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			jobs := &signInNoticeJobs{}

			handler := buildAuthOtpPost(authOtpPostDeps{
				pageRenderer:  pageRenderer,
				ceremonyStore: ceremonyStore,
				database:      database,
				auditLogger:   auditLogger,
				notifier:      accountnotice.New(pageRenderer, accounthandlersmocks.NewEmailSender(t), jobs),
			})

			authContext := &ceremony.AuthContext{
				AuthState:  ceremony.AuthStateLevel2OTP,
				CeremonyId: testCeremonyId,
				UserId:     1,
				ClientId:   "test-client",
			}
			ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

			secret := otpTestMintedSecret(t)
			req := signInNoticeRequest(t, signInNoticeSettings(), otptest.Code(t, secret, time.Now()))
			rr := httptest.NewRecorder()
			tc.arrange(t, secret, rr, req, authContext, database, auditLogger, ceremonyStore, pageRenderer)

			handler.ServeHTTP(rr, req)

			assert.Empty(t, jobs.jobs, "no notice is handed off")
		})
	}
}

// An enrolment with an unverified address is answered as any other, and hands off nothing.
func TestHandleAuthOtpPost_SendsNoSetUpNoticeToAnUnverifiedAddress(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	jobs := &signInNoticeJobs{}

	handler := buildAuthOtpPost(authOtpPostDeps{
		pageRenderer:  pageRenderer,
		ceremonyStore: ceremonyStore,
		database:      database,
		auditLogger:   auditLogger,
		notifier:      accountnotice.New(pageRenderer, accounthandlersmocks.NewEmailSender(t), jobs),
	})

	secret := otpTestMintedSecret(t)
	req := signInNoticeRequest(t, signInNoticeSettings(), otptest.Code(t, secret, time.Now()))
	rr := httptest.NewRecorder()
	authContext := &ceremony.AuthContext{
		AuthState:  ceremony.AuthStateLevel2OTP,
		CeremonyId: testCeremonyId,
		UserId:     1,
		ClientId:   "test-client",
		OTPKeyURL:  otpTestKeyURL(secret),
	}
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)
	user := signInNoticeUser()
	user.EmailVerified = false
	stubSignInEnrolment(database, auditLogger, user)
	ceremonyStore.On("RegenerateSession", rr, req, testCeremonyId, int64(1)).Return(nil).Once()
	ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Empty(t, jobs.jobs, "no notice is handed off")
}

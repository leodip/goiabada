package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/requestid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The sign-in code step's two other notices (#724, #737): a sign-in with a recovery code tells
// the user, with how many unused codes are left, and the refusal whose count reached
// record.OtpConsecutiveFailureLimit, which disables the authenticator, tells them that, once per
// lockout. The step's operation reports each as a plain value, and the handler hands it off after
// its response, as it does the set-up notice. A refused or missing recovery code, a refusal that
// does not reach the limit and one against an authenticator already disabled tell nobody.

// enrolledNoticeUser is the user signing in, with an authenticator at generation 3, a verified
// address, a name and the locale given.
func enrolledNoticeUser(t *testing.T, locale string) *record.User {
	t.Helper()
	user := signInNoticeUser()
	user.Locale = locale
	user.OTPEnabled = true
	user.OTPSecretEncrypted = encryptOTPForTest(t, otpTestMintedSecret(t))
	user.OtpConfigGeneration = 3
	return user
}

// recoveryNoticeRequest submits code on the recovery-code form, with the request's id and settings.
func recoveryNoticeRequest(t *testing.T, settings *record.Settings, code string) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Add(ceremony.IdField, testCeremonyId)
	form.Add("recoveryCode", code)
	req, err := http.NewRequest(http.MethodPost, "/auth/otp", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	ctx := requestid.NewContext(req.Context(), signInNoticeRequestId)
	return req.WithContext(reqctx.WithSettings(ctx, settings))
}

// otpNoticeCeremony is a ceremony at the sign-in code step for user 1, with no enrolment key.
func otpNoticeCeremony() *ceremony.AuthContext {
	return &ceremony.AuthContext{
		AuthState:  ceremony.AuthStateLevel2OTP,
		CeremonyId: testCeremonyId,
		UserId:     1,
		ClientId:   "test-client",
	}
}

// stubAcceptedRecoveryCode answers a recovery code that is claimed, leaving remaining unused.
func stubAcceptedRecoveryCode(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
	user *record.User, remaining int) {
	database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
	expectOTPWriteTransactions(database)
	expectUserRowLocked(database, user)
	database.On("TryUseUserRecoveryCode", mock.Anything, mock.Anything, user.Id,
		recoveryCodeHashForTest(recoveryCodeNormalized)).Return(true, nil).Once()
	database.On("CountUnusedUserRecoveryCodes", mock.Anything, mock.Anything, user.Id).Return(remaining, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessRecoveryCode, mock.Anything).Return().Once()
}

// capturedSignInNotice is what one notice's render and send were handed.
type capturedSignInNotice struct {
	renderLocale string
	bound        map[string]interface{}
	sent         *emaildelivery.SendEmailInput
}

// expectSignInNotice registers the render of page and the send, capturing what each was handed.
func expectSignInNotice(pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender,
	page string) *capturedSignInNotice {
	captured := &capturedSignInNotice{}
	pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html", page, mock.Anything).
		Run(func(args mock.Arguments) {
			captured.renderLocale = i18n.LocaleTag(args.Get(0).(*http.Request).Context())
			captured.bound = args.Get(3).(map[string]interface{})
		}).Return(bytes.NewBufferString("<p>rendered notice</p>"), nil).Once()
	emailSender.On("SendEmail", mock.Anything,
		emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com"},
		mock.Anything).
		Run(func(args mock.Arguments) { captured.sent = args.Get(2).(*emaildelivery.SendEmailInput) }).
		Return(emaildelivery.SendResult{}, nil).Once()
	return captured
}

func TestHandleAuthOtpPost_TellsTheUserARecoveryCodeSignedIn(t *testing.T) {
	for _, tc := range []struct {
		name          string
		locale        string
		remaining     int
		saveErr       error
		expectSubject string
	}{
		{"an English user with nine codes left", "en", 9, nil, "A recovery code was used to sign in"},
		{"a Brazilian Portuguese user with none left", "pt-BR", 0, nil, "Um código de recuperação foi usado para entrar"},
		// The code was spent before the rotation failed, so the user is told anyway.
		{"the ceremony can't be saved after the code was spent", "en", 4, errors.New("session store down"),
			"A recovery code was used to sign in"},
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

			req := recoveryNoticeRequest(t, signInNoticeSettings(), recoveryCodeTyped)
			rr := httptest.NewRecorder()
			ceremonyStore.On("GetAuthContext", mock.Anything).Return(otpNoticeCeremony(), nil)
			stubAcceptedRecoveryCode(database, auditLogger, enrolledNoticeUser(t, tc.locale), tc.remaining)
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

			captured := expectSignInNotice(pageRenderer, emailSender, "/emails/email_recovery_code_used.html")
			jobs.jobs[0](jobs.ctxs[0])

			require.NotNil(t, captured.sent)
			assert.Equal(t, signInNoticeAddress, captured.sent.To)
			assert.Equal(t, tc.expectSubject, captured.sent.Subject)
			assert.Equal(t, tc.locale, captured.renderLocale, "the notice is rendered in the user's language")
			assert.Equal(t, "Joana Reis", captured.bound["name"])
			assert.Equal(t, tc.remaining, captured.bound["remaining"], "the notice says how many unused codes are left")
			assert.NotContains(t, captured.bound, "link", "the notice carries no link")
			for key, value := range captured.bound {
				assert.NotContains(t, strings.ToLower(fmt.Sprint(value)), recoveryCodeNormalized[:8],
					"the notice carries no recovery code, found under %q", key)
			}
		})
	}
}

// Where no recovery-code notice may go, the step hands nothing off: a wrong code, a used one, no
// code, and an accepted code with SMTP off or to an unverified address.
func TestHandleAuthOtpPost_SendsNoRecoveryCodeNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    string
		arrange func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
			database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
			ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer)
	}{
		{"a wrong code", recoveryCodeTyped,
			func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
				database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer) {
				database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
				expectOTPWriteTransactions(database)
				expectUserRowLocked(database, user)
				database.On("TryUseUserRecoveryCode", mock.Anything, mock.Anything, user.Id, mock.Anything).Return(false, nil).Once()
				database.On("UserRecoveryCodeExists", mock.Anything, mock.Anything, user.Id, mock.Anything).Return(false, nil).Once()
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
					Return(&record.Client{ClientIdentifier: "test-client"}, nil)
				auditLogger.On("Log", mock.Anything, audit.EventAuthFailedRecoveryCode, mock.Anything).Return().Once()
				pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_recovery_code.html",
					mock.Anything).Return(nil).Once()
			}},
		{"a code already used", recoveryCodeTyped,
			func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
				database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer) {
				database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
				expectOTPWriteTransactions(database)
				expectUserRowLocked(database, user)
				database.On("TryUseUserRecoveryCode", mock.Anything, mock.Anything, user.Id, mock.Anything).Return(false, nil).Once()
				database.On("UserRecoveryCodeExists", mock.Anything, mock.Anything, user.Id, mock.Anything).Return(true, nil).Once()
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
					Return(&record.Client{ClientIdentifier: "test-client"}, nil)
				auditLogger.On("Log", mock.Anything, audit.EventRecoveryCodeReplayDetected, mock.Anything).Return().Once()
				auditLogger.On("Log", mock.Anything, audit.EventAuthFailedRecoveryCode, mock.Anything).Return().Once()
				pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_recovery_code.html",
					mock.Anything).Return(nil).Once()
			}},
		{"no code", "  ",
			func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
				database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer) {
				database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
					Return(&record.Client{ClientIdentifier: "test-client"}, nil)
				pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_recovery_code.html",
					mock.Anything).Return(nil).Once()
			}},
		{"an accepted code with SMTP off", recoveryCodeTyped,
			func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
				database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer) {
				settings.SMTPEnabled = false
				stubAcceptedRecoveryCode(database, auditLogger, user, 9)
				ceremonyStore.On("RegenerateSession", rr, req, testCeremonyId, int64(1)).Return(nil).Once()
				ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()
			}},
		{"an accepted code for an unverified address", recoveryCodeTyped,
			func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
				database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer) {
				user.EmailVerified = false
				stubAcceptedRecoveryCode(database, auditLogger, user, 9)
				ceremonyStore.On("RegenerateSession", rr, req, testCeremonyId, int64(1)).Return(nil).Once()
				ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()
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

			settings := signInNoticeSettings()
			req := recoveryNoticeRequest(t, settings, tc.code)
			rr := httptest.NewRecorder()
			ceremonyStore.On("GetAuthContext", mock.Anything).Return(otpNoticeCeremony(), nil)
			tc.arrange(rr, req, enrolledNoticeUser(t, "en"), settings, database, auditLogger, ceremonyStore, pageRenderer)

			handler.ServeHTTP(rr, req)

			assert.Empty(t, jobs.jobs, "no notice is handed off")
		})
	}
}

// otpCodeNoticeRequest submits code on the code form, with the request's id and settings.
func otpCodeNoticeRequest(t *testing.T, code string) *http.Request {
	t.Helper()
	return signInNoticeRequest(t, signInNoticeSettings(), code)
}

// stubRefusedCode answers a code refused against user's authenticator: a wrong code, or, with
// replay, the right one whose step was already spent. reachesLimit is what the count's statement
// reports: whether this refusal is the one that moved the count to the limit.
func stubRefusedCode(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, pageRenderer *handlersmocks.PageRenderer,
	rr *httptest.ResponseRecorder, req *http.Request, user *record.User, replay bool, reachesLimit bool) {
	database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(&record.Client{ClientIdentifier: "test-client"}, nil)
	if replay {
		database.On("TryConsumeEnrolledUserOTPStep", mock.Anything, mock.Anything, user.Id, mock.Anything,
			user.OtpConfigGeneration).Return(false, nil).Once()
		auditLogger.On("Log", mock.Anything, audit.EventOTPCodeReplayDetected, mock.Anything).Return().Once()
	}
	expectOTPWriteTransactions(database)
	expectUserRowLocked(database, user)
	database.On("IncrementUserOtpConsecutiveFailures", mock.Anything, mock.Anything, user.Id, user.OtpConfigGeneration).
		Return(reachesLimit, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventAuthFailedOtp, mock.Anything).Return().Once()
	if reachesLimit {
		auditLogger.On("Log", mock.Anything, audit.EventOTPAuthenticatorDisabled, mock.Anything).Return().Once()
	}
	pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil).Once()
}

func TestHandleAuthOtpPost_TellsTheUserTheRefusalThatDisabledTheirAuthenticator(t *testing.T) {
	for _, tc := range []struct {
		name          string
		locale        string
		replay        bool
		expectSubject string
	}{
		{"a wrong code, to an English user", "en", false, "Your authenticator was disabled after too many wrong codes"},
		{"a replayed code, to a German user", "de", true, "Ihre Authenticator-App wurde nach zu vielen falschen Codes gesperrt"},
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

			user := enrolledNoticeUser(t, tc.locale)
			user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit - 1
			secret := otpTestMintedSecret(t)
			user.OTPSecretEncrypted = encryptOTPForTest(t, secret)
			code := "000000"
			if tc.replay {
				code = otptest.Code(t, secret, time.Now())
			}
			req := otpCodeNoticeRequest(t, code)
			rr := httptest.NewRecorder()
			ceremonyStore.On("GetAuthContext", mock.Anything).Return(otpNoticeCeremony(), nil)
			stubRefusedCode(database, auditLogger, pageRenderer, rr, req, user, tc.replay, true)

			handler.ServeHTTP(rr, req)

			assert.Empty(t, rr.Header().Get("Location"), "the code is refused like any other")
			require.Len(t, jobs.jobs, 1, "the step hands off exactly one notice")
			assert.Equal(t, afterresponse.ClassSecurityNotice, jobs.classes[0])

			captured := expectSignInNotice(pageRenderer, emailSender, "/emails/email_otp_lockout.html")
			jobs.jobs[0](jobs.ctxs[0])

			require.NotNil(t, captured.sent)
			assert.Equal(t, signInNoticeAddress, captured.sent.To)
			assert.Equal(t, tc.expectSubject, captured.sent.Subject)
			assert.Equal(t, tc.locale, captured.renderLocale, "the notice is rendered in the user's language")
			assert.Equal(t, "Joana Reis", captured.bound["name"])
			assert.NotContains(t, captured.bound, "link", "the notice carries no link")
		})
	}
}

// The lockout is told once: a refusal that leaves the count under the limit tells nobody, and
// neither does one against an authenticator already disabled, which moves no count. With SMTP off
// or an unverified address the disabling refusal tells nobody either.
func TestHandleAuthOtpPost_SendsNoLockoutNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
			database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, pageRenderer *handlersmocks.PageRenderer)
	}{
		{"a refusal under the limit",
			func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
				database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, pageRenderer *handlersmocks.PageRenderer) {
				user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit - 2
				stubRefusedCode(database, auditLogger, pageRenderer, rr, req, user, false, false)
			}},
		{"a refusal after the authenticator was disabled",
			func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
				database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, pageRenderer *handlersmocks.PageRenderer) {
				user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit
				database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil)
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
					Return(&record.Client{ClientIdentifier: "test-client"}, nil)
				auditLogger.On("Log", mock.Anything, audit.EventAuthFailedOtp, mock.Anything).Return().Once()
				pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).
					Return(nil).Once()
			}},
		{"the disabling refusal with SMTP off",
			func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
				database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, pageRenderer *handlersmocks.PageRenderer) {
				settings.SMTPEnabled = false
				user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit - 1
				stubRefusedCode(database, auditLogger, pageRenderer, rr, req, user, false, true)
			}},
		{"the disabling refusal for an unverified address",
			func(rr *httptest.ResponseRecorder, req *http.Request, user *record.User, settings *record.Settings,
				database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, pageRenderer *handlersmocks.PageRenderer) {
				user.EmailVerified = false
				user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit - 1
				stubRefusedCode(database, auditLogger, pageRenderer, rr, req, user, false, true)
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

			settings := signInNoticeSettings()
			req := signInNoticeRequest(t, settings, "000000")
			rr := httptest.NewRecorder()
			ceremonyStore.On("GetAuthContext", mock.Anything).Return(otpNoticeCeremony(), nil)
			tc.arrange(rr, req, enrolledNoticeUser(t, "en"), settings, database, auditLogger, pageRenderer)

			handler.ServeHTTP(rr, req)

			assert.Empty(t, rr.Header().Get("Location"), "the code is refused")
			assert.Empty(t, jobs.jobs, "no notice is handed off")
		})
	}
}

// A lockout notice that cannot be sent is one Error record on the request's id, and nothing else:
// the refusal was answered before it ran.
func TestHandleAuthOtpPost_AFailedLockoutNoticeIsOneErrorRecord(t *testing.T) {
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

	user := enrolledNoticeUser(t, "en")
	user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit - 1
	req := otpCodeNoticeRequest(t, "000000")
	rr := httptest.NewRecorder()
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(otpNoticeCeremony(), nil)
	stubRefusedCode(database, auditLogger, pageRenderer, rr, req, user, false, true)

	handler.ServeHTTP(rr, req)
	require.Len(t, jobs.jobs, 1)

	pageRenderer.On("RenderTemplateToBuffer", mock.Anything, mock.Anything, "/emails/email_otp_lockout.html", mock.Anything).
		Return(bytes.NewBufferString("<p>rendered notice</p>"), nil).Once()
	emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(emaildelivery.SendResult{}, errors.New("relay refused")).Once()

	capture := logtest.CaptureSlog(t)
	jobs.jobs[0](jobs.ctxs[0])

	records := capture.Records()
	require.Len(t, records, 1, capture.Text())
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, "unable to send an account notice", records[0].Message)
	assert.Equal(t, "otp_lockout", records[0].Attrs["notice"])
	assert.Equal(t, signInNoticeRequestId, records[0].Attrs["request_id"])
	assert.Equal(t, user.Id, records[0].Attrs["user_id"])
	assert.NotContains(t, capture.Text(), signInNoticeAddress, "the record names no address")
}

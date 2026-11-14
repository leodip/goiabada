package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/requestid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The two-factor notices (#724): setting up an authenticator on the Account pages tells the user,
// mentioning the recovery codes it came with; turning it off there tells them; an administrator
// turning it off tells them an administrator did. Each is sent after the change commits and after
// the response, to the account's verified address, in the user's language, with no link and no
// code, against the security_notice budget. A refusal, a lost compare-and-set or a rollback sends
// nothing.

const (
	otpNoticeSubject   = "the-subject"
	otpNoticePassword  = "P4ss!word"
	otpNoticeAddress   = "carla.mendes@example.com"
	otpNoticeRequestId = "req-otp-0001"
)

// otpNoticeUser is the caller part way through an enrolment (otpTestUser), with a verified
// address and a name.
func otpNoticeUser(t *testing.T) *record.User {
	t.Helper()
	user := otpTestUser(t, otpNoticePassword)
	user.Subject = otpNoticeSubject
	user.GivenName = "Carla"
	user.FamilyName = "Mendes"
	user.Email = otpNoticeAddress
	user.EmailVerified = true
	return user
}

// withNoticeContext gives a request the request's id and settings.
func withNoticeContext(req *http.Request, settings *record.Settings) *http.Request {
	ctx := requestid.NewContext(req.Context(), otpNoticeRequestId)
	return req.WithContext(reqctx.WithSettings(ctx, settings))
}

// stubOTPEnable answers an enable that commits: the read, the claim, the establish transaction,
// the two audit events and the read the response is built from. The audit events are the logger's
// only expectations, so a notice that wrote an audit entry of its own would fail the case.
func stubOTPEnable(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User) {
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), otpNoticeSubject).Return(user, nil).Once()
	database.On("TryConsumeUserOTPStep", mock.Anything, (*sql.Tx)(nil), user.Id, mock.Anything).Return(true, nil).Once()
	datamocks.ExpectRunInTransaction(database, otpDisableTx)
	database.On("TryEstablishUserOTP", mock.Anything, otpDisableTx, user.Id, user.OtpConfigGeneration, mock.Anything).
		Return(true, nil).Once()
	database.On("IncrementUserOtpConfigGeneration", mock.Anything, otpDisableTx, user.Id).Return(int64(1), nil).Once()
	database.On("ClearPendingOTPEnrollment", mock.Anything, otpDisableTx, user.Id).Return(nil).Once()
	database.On("ClearUserOtpConsecutiveFailures", mock.Anything, otpDisableTx, user.Id).Return(nil).Once()
	database.On("GetUserByIdForUpdate", mock.Anything, otpDisableTx, user.Id).Return(user, nil).Once()
	database.On("ReplaceUserRecoveryCodes", mock.Anything, otpDisableTx, user.Id, mock.Anything).Return(nil).Once()
	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), user.Id).Return(user, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventEnabledOTP, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventRecoveryCodesCreated, mock.Anything).Return().Once()
}

// stubOTPRemove answers a removal of user's authenticator that commits, read by readMethod with
// readKey: the removal transaction, the audit event and the read the response is built from.
func stubOTPRemove(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User,
	readMethod string, readKey interface{}) {
	database.On(readMethod, mock.Anything, (*sql.Tx)(nil), readKey).Return(user, nil).Once()
	datamocks.ExpectRunInTransaction(database, otpDisableTx)
	database.On("TryRemoveUserOTP", mock.Anything, otpDisableTx, user.Id, user.OtpConfigGeneration).Return(true, nil).Once()
	database.On("ResetUserOTPStep", mock.Anything, otpDisableTx, user.Id).Return(nil).Once()
	database.On("DeleteUserRecoveryCodes", mock.Anything, otpDisableTx, user.Id).Return(nil).Once()
	database.On("IncrementUserOtpConfigGeneration", mock.Anything, otpDisableTx, user.Id).Return(int64(1), nil).Once()
	database.On("GetUserByIdForUpdate", mock.Anything, otpDisableTx, user.Id).Return(user, nil).Once()
	database.On("LowerUserSessionsToPassword", mock.Anything, otpDisableTx, user.Id, "pwd").Return(nil).Once()
	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), user.Id).Return(user, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDisabledOTP, mock.Anything).Return().Once()
}

// renderedNotice fakes the renderer's answer to a notice: the subject the notice's definition gives in
// the language the request carries, which only the right email and the right language give, and a
// body.
func renderedNotice(r *http.Request, email *emailtemplate.Email, _ emailtemplate.Values) emailtemplate.Message {
	return emailtemplate.Message{
		Subject: email.BuiltIn[emailtemplate.Language(i18n.LocaleTag(r.Context()))].Subject,
		HTML:    "<p>rendered notice</p>",
	}
}

// expectNotice registers the render of email and the send, capturing what each was handed.
type capturedNotice struct {
	renderLocale string
	values       emailtemplate.Values
	sent         *emaildelivery.SendEmailInput
}

func expectNotice(pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender,
	email *emailtemplate.Email) *capturedNotice {
	captured := &capturedNotice{}
	pageRenderer.On("RenderEmail", mock.Anything, email, mock.Anything).
		Run(func(args mock.Arguments) {
			captured.renderLocale = i18n.LocaleTag(args.Get(0).(*http.Request).Context())
			captured.values = args.Get(2).(emailtemplate.Values)
		}).Return(renderedNotice, nil).Once()
	emailSender.On("SendEmail", mock.Anything,
		emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com"},
		mock.Anything).
		Run(func(args mock.Arguments) {
			captured.sent = args.Get(2).(*emaildelivery.SendEmailInput)
		}).Return(emaildelivery.SendResult{}, nil).Once()
	return captured
}

func accountOTPNoticeHandler(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, jobs *heldJobs,
	pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) http.Handler {
	return HandleAccountOTPPut(database, auditLogger, unlimitedCredentials{}, testDataCipher,
		accountnotice.New(pageRenderer, emailSender, jobs))
}

func TestHandleAccountOTPPut_TellsTheUserTwoFactorWasSetUp(t *testing.T) {
	for _, tc := range []struct {
		name          string
		locale        string
		expectSubject string
	}{
		{"an English user", "en", "Two-factor authentication was set up"},
		{"a Brazilian Portuguese user", "pt-BR", "A autenticação de dois fatores foi configurada"},
		{"a French user", "fr", "L’authentification à deux facteurs a été configurée"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &heldJobs{}
			user := otpNoticeUser(t)
			user.Locale = tc.locale
			stubOTPEnable(database, auditLogger, user)

			rr := httptest.NewRecorder()
			accountOTPNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).ServeHTTP(rr,
				withNoticeContext(accountOTPEnableRequest(t, otpNoticeSubject, otpNoticePassword, currentOtpCode(t)),
					passwordNoticeSettings()))

			// The renderer and the sender have no expectations yet, so a notice sent inside the
			// request would already have failed the case.
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			var body api.UpdateAccountOTPResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			require.Len(t, body.RecoveryCodes, 10)

			captured := expectNotice(pageRenderer, emailSender, emailtemplate.OTPEnabled)
			jobs.runAll(t, afterresponse.ClassSecurityNotice)

			require.NotNil(t, captured.sent)
			assert.Equal(t, otpNoticeAddress, captured.sent.To)
			assert.Equal(t, tc.expectSubject, captured.sent.Subject)
			assert.Equal(t, tc.locale, captured.renderLocale, "the notice is rendered in the user's language")
			assert.Equal(t, "Carla Mendes", captured.values.Name)
			assert.Empty(t, captured.values.Link, "the notice carries no link")
			for _, code := range body.RecoveryCodes {
				assert.NotContains(t, fmt.Sprintf("%+v", captured.values), code, "the notice carries no recovery code")
			}
			assert.NotContains(t, captured.sent.Subject+captured.sent.HtmlBody, body.RecoveryCodes[0])
		})
	}
}

func TestHandleAccountOTPPut_TellsTheUserTwoFactorWasTurnedOff(t *testing.T) {
	for _, tc := range []struct {
		name          string
		locale        string
		expectSubject string
	}{
		{"an English user", "en", "Two-factor authentication was turned off"},
		{"a German user", "de", "Die Zwei-Faktor-Authentifizierung wurde deaktiviert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &heldJobs{}
			user := otpNoticeUser(t)
			user.OTPEnabled = true
			user.Locale = tc.locale
			stubOTPRemove(database, auditLogger, user, "GetUserBySubject", otpNoticeSubject)

			rr := httptest.NewRecorder()
			accountOTPNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).ServeHTTP(rr,
				withNoticeContext(accountOTPDisableRequest(t, otpNoticeSubject, otpNoticePassword), passwordNoticeSettings()))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			captured := expectNotice(pageRenderer, emailSender, emailtemplate.OTPDisabled)
			jobs.runAll(t, afterresponse.ClassSecurityNotice)

			require.NotNil(t, captured.sent)
			assert.Equal(t, otpNoticeAddress, captured.sent.To)
			assert.Equal(t, tc.expectSubject, captured.sent.Subject)
			assert.Equal(t, tc.locale, captured.renderLocale)
			assert.Equal(t, "Carla Mendes", captured.values.Name)
			assert.Empty(t, captured.values.Link, "the notice carries no link")
		})
	}
}

// Where no notice may go, the request hands nothing off: SMTP off and an unverified address with
// the change made, and a refusal, a lost compare-and-set or a rollback with no change at all.
func TestHandleAccountOTPPut_SendsNoNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		enable     bool
		expectCode int
		arrange    func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
			user *record.User, settings *record.Settings)
		password string
	}{
		{"set up with SMTP off", true, http.StatusOK,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				settings.SMTPEnabled = false
				stubOTPEnable(database, auditLogger, user)
			}, ""},
		{"set up with an unverified address", true, http.StatusOK,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				user.EmailVerified = false
				stubOTPEnable(database, auditLogger, user)
			}, ""},
		{"turned off with SMTP off", false, http.StatusOK,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				settings.SMTPEnabled = false
				user.OTPEnabled = true
				stubOTPRemove(database, auditLogger, user, "GetUserBySubject", otpNoticeSubject)
			}, ""},
		{"turned off with an unverified address", false, http.StatusOK,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				user.EmailVerified = false
				user.OTPEnabled = true
				stubOTPRemove(database, auditLogger, user, "GetUserBySubject", otpNoticeSubject)
			}, ""},
		{"set up with a wrong password", true, http.StatusBadRequest,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), otpNoticeSubject).Return(user, nil).Once()
			}, "wrong-password"},
		{"turned off with a wrong password", false, http.StatusBadRequest,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				user.OTPEnabled = true
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), otpNoticeSubject).Return(user, nil).Once()
			}, "wrong-password"},
		{"set up losing its compare-and-set", true, http.StatusBadRequest,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), otpNoticeSubject).Return(user, nil).Once()
				database.On("TryConsumeUserOTPStep", mock.Anything, (*sql.Tx)(nil), user.Id, mock.Anything).Return(true, nil).Once()
				datamocks.ExpectRunInTransaction(database, otpDisableTx)
				database.On("TryEstablishUserOTP", mock.Anything, otpDisableTx, user.Id, user.OtpConfigGeneration, mock.Anything).
					Return(false, nil).Once()
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), user.Id).
					Return(&record.User{Id: user.Id, Enabled: true, OTPEnabled: true}, nil).Once()
			}, ""},
		{"turned off losing its compare-and-set", false, http.StatusBadRequest,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				user.OTPEnabled = true
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), otpNoticeSubject).Return(user, nil).Once()
				datamocks.ExpectRunInTransaction(database, otpDisableTx)
				database.On("TryRemoveUserOTP", mock.Anything, otpDisableTx, user.Id, user.OtpConfigGeneration).Return(false, nil).Once()
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), user.Id).
					Return(&record.User{Id: user.Id, Enabled: true, OTPEnabled: false}, nil).Once()
			}, ""},
		{"set up rolling back", true, http.StatusInternalServerError,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), otpNoticeSubject).Return(user, nil).Once()
				database.On("TryConsumeUserOTPStep", mock.Anything, (*sql.Tx)(nil), user.Id, mock.Anything).Return(true, nil).Once()
				datamocks.ExpectRunInTransaction(database, otpDisableTx)
				database.On("TryEstablishUserOTP", mock.Anything, otpDisableTx, user.Id, user.OtpConfigGeneration, mock.Anything).
					Return(true, nil).Once()
				database.On("IncrementUserOtpConfigGeneration", mock.Anything, otpDisableTx, user.Id).
					Return(int64(0), errors.New("increment failed")).Once()
			}, ""},
		{"turned off rolling back", false, http.StatusInternalServerError,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				user.OTPEnabled = true
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), otpNoticeSubject).Return(user, nil).Once()
				datamocks.ExpectRunInTransaction(database, otpDisableTx)
				database.On("TryRemoveUserOTP", mock.Anything, otpDisableTx, user.Id, user.OtpConfigGeneration).Return(true, nil).Once()
				database.On("ResetUserOTPStep", mock.Anything, otpDisableTx, user.Id).Return(errors.New("reset failed")).Once()
			}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			jobs := &heldJobs{}
			settings := passwordNoticeSettings()
			user := otpNoticeUser(t)
			tc.arrange(t, database, auditLogger, user, settings)
			password := tc.password
			if password == "" {
				password = otpNoticePassword
			}
			var req *http.Request
			if tc.enable {
				req = accountOTPEnableRequest(t, otpNoticeSubject, password, currentOtpCode(t))
			} else {
				req = accountOTPDisableRequest(t, otpNoticeSubject, password)
			}

			rr := httptest.NewRecorder()
			accountOTPNoticeHandler(database, auditLogger, jobs, handlersmocks.NewPageRenderer(t), accounthandlersmocks.NewEmailSender(t)).
				ServeHTTP(rr, withNoticeContext(req, settings))

			require.Equal(t, tc.expectCode, rr.Code, rr.Body.String())
			assert.Empty(t, jobs.jobs, "no notice is handed off")
		})
	}
}

// A notice that cannot be sent is one Error record on the request's id, and nothing else: the
// change was answered before it ran.
func TestHandleAccountOTPPut_AFailedNoticeIsOneErrorRecord(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	pageRenderer := handlersmocks.NewPageRenderer(t)
	emailSender := accounthandlersmocks.NewEmailSender(t)
	jobs := &heldJobs{}
	user := otpNoticeUser(t)
	user.OTPEnabled = true
	stubOTPRemove(database, auditLogger, user, "GetUserBySubject", otpNoticeSubject)

	rr := httptest.NewRecorder()
	accountOTPNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).ServeHTTP(rr,
		withNoticeContext(accountOTPDisableRequest(t, otpNoticeSubject, otpNoticePassword), passwordNoticeSettings()))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	pageRenderer.On("RenderEmail", mock.Anything, emailtemplate.OTPDisabled, mock.Anything).
		Return(renderedNotice, nil).Once()
	emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(emaildelivery.SendResult{}, errors.New("relay refused")).Once()

	capture := logtest.CaptureSlog(t)
	jobs.runAll(t, afterresponse.ClassSecurityNotice)

	records := capture.Records()
	require.Len(t, records, 1, capture.Text())
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, "unable to send an account notice", records[0].Message)
	assert.Equal(t, "otp_disabled", records[0].Attrs["notice"])
	assert.Equal(t, otpNoticeRequestId, records[0].Attrs["request_id"])
	assert.Equal(t, user.Id, records[0].Attrs["user_id"])
	assert.NotContains(t, capture.Text(), otpNoticeAddress, "the record names no address")
}

// adminOTPNoticeRequest is the administrator's switch turning the user's authenticator off, with a
// manage-scoped token, the request's id and settings.
func adminOTPNoticeRequest(t *testing.T, settings *record.Settings, userId int64) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]bool{"enabled": false})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/otp", userId), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", fmt.Sprint(userId))
	return setTokenContextWithClaims(withNoticeContext(req, settings),
		map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject, "auth_time": float64(1)})
}

func adminOTPNoticeHandler(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, jobs *heldJobs,
	pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) http.Handler {
	return HandleUserOTPPut(database, auditLogger, accountnotice.New(pageRenderer, emailSender, jobs))
}

func TestHandleUserOTPPut_TellsTheUserAnAdministratorTurnedItOff(t *testing.T) {
	for _, tc := range []struct {
		name          string
		locale        string
		expectSubject string
	}{
		{"an English user", "en", "An administrator turned off your two-factor authentication"},
		{"an Italian user", "it", "Un amministratore ha disattivato la tua autenticazione a due fattori"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &heldJobs{}
			user := otpNoticeUser(t)
			user.OTPEnabled = true
			user.Locale = tc.locale
			stubOTPRemove(database, auditLogger, user, "GetUserById", user.Id)

			rr := httptest.NewRecorder()
			adminOTPNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).
				ServeHTTP(rr, adminOTPNoticeRequest(t, passwordNoticeSettings(), user.Id))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			captured := expectNotice(pageRenderer, emailSender, emailtemplate.OTPDisabledByAdministrator)
			jobs.runAll(t, afterresponse.ClassSecurityNotice)

			require.NotNil(t, captured.sent)
			assert.Equal(t, otpNoticeAddress, captured.sent.To)
			assert.Equal(t, tc.expectSubject, captured.sent.Subject)
			assert.Equal(t, tc.locale, captured.renderLocale)
			assert.Equal(t, "Carla Mendes", captured.values.Name)
			assert.NotContains(t, strings.ToLower(fmt.Sprintf("%+v", captured.values)), adminSubject, "the notice doesn't name the administrator")
		})
	}
}

func TestHandleUserOTPPut_SendsNoNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expectCode int
		arrange    func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User,
			settings *record.Settings)
	}{
		{"SMTP is off", http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				settings.SMTPEnabled = false
				stubOTPRemove(database, auditLogger, user, "GetUserById", user.Id)
			}},
		{"the address is unverified", http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				user.EmailVerified = false
				stubOTPRemove(database, auditLogger, user, "GetUserById", user.Id)
			}},
		{"two-factor authentication is already off", http.StatusBadRequest,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				user.OTPEnabled = false
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), user.Id).Return(user, nil).Once()
			}},
		{"the removal loses its compare-and-set", http.StatusBadRequest,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), user.Id).Return(user, nil).Once()
				datamocks.ExpectRunInTransaction(database, otpDisableTx)
				database.On("TryRemoveUserOTP", mock.Anything, otpDisableTx, user.Id, user.OtpConfigGeneration).Return(false, nil).Once()
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), user.Id).
					Return(&record.User{Id: user.Id, Enabled: true, OTPEnabled: false}, nil).Once()
			}},
		{"the removal rolls back", http.StatusInternalServerError,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), user.Id).Return(user, nil).Once()
				datamocks.ExpectRunInTransaction(database, otpDisableTx)
				database.On("TryRemoveUserOTP", mock.Anything, otpDisableTx, user.Id, user.OtpConfigGeneration).Return(true, nil).Once()
				database.On("ResetUserOTPStep", mock.Anything, otpDisableTx, user.Id).Return(errors.New("reset failed")).Once()
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			jobs := &heldJobs{}
			settings := passwordNoticeSettings()
			user := otpNoticeUser(t)
			user.OTPEnabled = true
			tc.arrange(database, auditLogger, user, settings)

			rr := httptest.NewRecorder()
			adminOTPNoticeHandler(database, auditLogger, jobs, handlersmocks.NewPageRenderer(t), accounthandlersmocks.NewEmailSender(t)).
				ServeHTTP(rr, adminOTPNoticeRequest(t, settings, user.Id))

			require.Equal(t, tc.expectCode, rr.Code, rr.Body.String())
			assert.Empty(t, jobs.jobs, "no notice is handed off")
		})
	}
}

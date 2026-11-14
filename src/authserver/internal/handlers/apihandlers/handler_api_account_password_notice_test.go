package apihandlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/requestid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The password change's notice to the user (#724): sent after the change commits and after the
// response, with SMTP on, to the account's verified address, in the user's language, with no link
// and no password, and against the security_notice budget. Nothing is sent for a change that was
// refused or rolled back, and a notice that fails is one Error record.

const (
	passwordNoticeCurrent   = "0ldP4ss!word"
	passwordNoticeNew       = "N3wP4ss!word-that-is-long"
	passwordNoticeSubject   = "the-subject"
	passwordNoticeAddress   = "ana.silva@example.com"
	passwordNoticeRequestId = "req-password-0001"
)

// passwordNoticeUser is the caller: a verified address and a name, with the current password.
func passwordNoticeUser(t *testing.T) *record.User {
	t.Helper()
	hash, err := passwordhash.Hash(passwordNoticeCurrent)
	require.NoError(t, err)
	return &record.User{
		Id:            42,
		Subject:       passwordNoticeSubject,
		Enabled:       true,
		GivenName:     "Ana",
		FamilyName:    "Silva",
		Email:         passwordNoticeAddress,
		EmailVerified: true,
		PasswordHash:  hash,
	}
}

// passwordNoticeSettings are the request's settings with SMTP on, so a case that expects no
// notice asserts it where one could have been sent.
func passwordNoticeSettings() *record.Settings {
	return &record.Settings{
		AppName:        "Goiabada",
		PasswordPolicy: record.PasswordPolicyLow,
		SMTPEnabled:    true,
		SMTPHost:       "smtp.example.com",
		SMTPPort:       587,
		SMTPFromEmail:  "noreply@example.com",
	}
}

// passwordNoticeRequest is the change as the console sends it, carrying the request's id and
// settings.
func passwordNoticeRequest(t *testing.T, settings *record.Settings, current string) *http.Request {
	t.Helper()
	req := accountPasswordRequest(t, map[string]interface{}{"sub": passwordNoticeSubject}, current, passwordNoticeNew)
	ctx := requestid.NewContext(req.Context(), passwordNoticeRequestId)
	return req.WithContext(reqctx.WithSettings(ctx, settings))
}

// stubPasswordChange answers a change that commits: the read, the hash write, the sweep and the
// two audit events, which are the logger's only expectations, so a notice that wrote an audit
// entry of its own would fail the case.
func stubPasswordChange(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User) {
	database.On("GetUserBySubject", mock.Anything, mock.Anything, passwordNoticeSubject).Return(user, nil).Once()
	database.On("GetUserByIdForUpdate", mock.Anything, apiRevokeTx, user.Id).Return(user, nil).Once()
	database.On("SetUserPasswordHash", mock.Anything, apiRevokeTx, user.Id, mock.Anything).Return(nil).Once()
	stubSweep(database, user.Id, 8)
	auditLogger.On("Log", mock.Anything, audit.EventChangedPassword, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventRevokedUserAuthState, mock.Anything).Return().Once()
}

func passwordNoticeHandler(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, jobs *heldJobs,
	pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) http.Handler {
	return HandleAccountPasswordPut(database, accountvalidation.NewPasswordValidator(), auditLogger, unlimitedCredentials{},
		accountnotice.New(pageRenderer, emailSender, jobs), &recordingLogoutTokens{})
}

func TestHandleAccountPasswordPut_TellsTheUserAfterTheResponse(t *testing.T) {
	for _, tc := range []struct {
		name          string
		pageLanguage  string
		locale        string
		renderLocale  string
		expectSubject string
	}{
		{"an English user", "", "en", "en", "Your password was changed"},
		{"a user with no stored locale", "", "", "en", "Your password was changed"},
		{"a Brazilian Portuguese user", "", "pt-BR", "pt-BR", "Sua senha foi alterada"},
		{"a German user", "", "de", "de", "Ihr Passwort wurde geändert"},
		{"a Spanish user", "", "es", "es", "Tu contraseña ha cambiado"},
		{"an Italian user", "", "it", "it", "La tua password è stata cambiata"},
		{"a user who chose French, over a German locale", "fr", "de", "fr", "Votre mot de passe a été modifié"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &heldJobs{}
			user := passwordNoticeUser(t)
			user.Locale = tc.locale
			user.PageLanguage = tc.pageLanguage
			stubPasswordChange(database, auditLogger, user)

			rr := httptest.NewRecorder()
			passwordNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).
				ServeHTTP(rr, passwordNoticeRequest(t, passwordNoticeSettings(), passwordNoticeCurrent))

			// The renderer and the sender have no expectations yet, so a notice sent inside the
			// request would already have failed the case.
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			var renderLocale string
			var values emailtemplate.Values
			pageRenderer.On("RenderEmail", mock.Anything, emailtemplate.PasswordChanged, mock.Anything).
				Run(func(args mock.Arguments) {
					renderLocale = i18n.LocaleTag(args.Get(0).(*http.Request).Context())
					values = args.Get(2).(emailtemplate.Values)
				}).Return(renderedNotice, nil).Once()
			var sendCtx context.Context
			var sent *emaildelivery.SendEmailInput
			emailSender.On("SendEmail", mock.Anything,
				emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com"},
				mock.Anything).
				Run(func(args mock.Arguments) {
					sendCtx = args.Get(0).(context.Context)
					sent = args.Get(2).(*emaildelivery.SendEmailInput)
				}).Return(emaildelivery.SendResult{}, nil).Once()

			jobs.runAll(t, afterresponse.ClassSecurityNotice)

			require.NotNil(t, sent)
			assert.Equal(t, passwordNoticeAddress, sent.To, "the notice goes to the account's own address")
			assert.Equal(t, tc.expectSubject, sent.Subject)
			assert.Equal(t, "<p>rendered notice</p>", sent.HtmlBody)
			assert.Equal(t, tc.renderLocale, renderLocale, "the notice is rendered in the user's language")
			assert.Equal(t, "Ana Silva", values.Name)
			assert.Empty(t, values.Link, "the notice carries no link")
			for _, secret := range []string{passwordNoticeNew, passwordNoticeCurrent} {
				assert.NotContains(t, fmt.Sprintf("%+v", values), secret, "the notice carries no password")
			}
			assert.Equal(t, passwordNoticeRequestId, requestid.FromContext(sendCtx),
				"the job's records carry the request's id")
		})
	}
}

// Where no notice may go, the request hands nothing off: SMTP off and an unverified address with
// the change made, and a refusal or a rollback with no change at all.
func TestHandleAccountPasswordPut_SendsNoNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expectCode int
		arrange    func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
			user *record.User, settings *record.Settings) (current string)
	}{
		{"SMTP is off", http.StatusOK,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				user *record.User, settings *record.Settings) string {
				settings.SMTPEnabled = false
				stubPasswordChange(database, auditLogger, user)
				return passwordNoticeCurrent
			}},
		{"the address is unverified", http.StatusOK,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				user *record.User, settings *record.Settings) string {
				user.EmailVerified = false
				stubPasswordChange(database, auditLogger, user)
				return passwordNoticeCurrent
			}},
		{"the current password is wrong", http.StatusBadRequest,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				user *record.User, settings *record.Settings) string {
				database.On("GetUserBySubject", mock.Anything, mock.Anything, passwordNoticeSubject).Return(user, nil).Once()
				return "not-the-password"
			}},
		{"the change rolls back", http.StatusInternalServerError,
			func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				user *record.User, settings *record.Settings) string {
				database.On("GetUserBySubject", mock.Anything, mock.Anything, passwordNoticeSubject).Return(user, nil).Once()
				datamocks.ExpectRunInTransaction(database, apiRevokeTx)
				database.On("GetUserByIdForUpdate", mock.Anything, apiRevokeTx, user.Id).Return(user, nil).Once()
				database.On("SetUserPasswordHash", mock.Anything, apiRevokeTx, user.Id, mock.Anything).Return(nil).Once()
				database.On("IncrementUserAuthStateGeneration", mock.Anything, apiRevokeTx, user.Id).
					Return(int64(0), errors.New("increment failed")).Once()
				return passwordNoticeCurrent
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			jobs := &heldJobs{}
			user := passwordNoticeUser(t)
			settings := passwordNoticeSettings()
			current := tc.arrange(t, database, auditLogger, user, settings)

			rr := httptest.NewRecorder()
			passwordNoticeHandler(database, auditLogger, jobs, handlersmocks.NewPageRenderer(t), accounthandlersmocks.NewEmailSender(t)).
				ServeHTTP(rr, passwordNoticeRequest(t, settings, current))

			require.Equal(t, tc.expectCode, rr.Code, rr.Body.String())
			assert.Empty(t, jobs.jobs, "no notice is handed off")
		})
	}
}

// A notice that cannot be rendered or sent never fails or undoes the change, which was answered
// 200 before the job ran. It is one Error record on the request's id, and no audit entry.
func TestHandleAccountPasswordPut_AFailedNoticeIsAnErrorRecordAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		renderErr error
		sendErr   error
	}{
		{"the render fails", assert.AnError, nil},
		{"the send fails", nil, assert.AnError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &heldJobs{}
			stubPasswordChange(database, auditLogger, passwordNoticeUser(t))

			rr := httptest.NewRecorder()
			passwordNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).
				ServeHTTP(rr, passwordNoticeRequest(t, passwordNoticeSettings(), passwordNoticeCurrent))
			require.Equal(t, http.StatusOK, rr.Code, "the change is answered before the notice is attempted")

			if tc.renderErr != nil {
				pageRenderer.On("RenderEmail", mock.Anything, mock.Anything, mock.Anything).
					Return(emailtemplate.Message{}, tc.renderErr).Once()
			} else {
				pageRenderer.On("RenderEmail", mock.Anything, mock.Anything, mock.Anything).
					Return(emailtemplate.Message{Subject: "s", HTML: "<p>x</p>"}, nil).Once()
				emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(emaildelivery.SendResult{}, tc.sendErr).Once()
			}
			jobs.runAll(t, afterresponse.ClassSecurityNotice)

			records := capture.Records()
			require.Len(t, records, 1, capture.Text())
			assert.Equal(t, slog.LevelError, records[0].Level)
			assert.Equal(t, passwordNoticeRequestId, records[0].Attrs["request_id"])
			assert.Equal(t, int64(42), records[0].Attrs["user_id"])
			assert.Equal(t, "password_changed", records[0].Attrs["notice"])
			assert.NotNil(t, records[0].Attrs["error"])
			assert.NotContains(t, capture.Text(), passwordNoticeAddress, "the record names no address")
			if tc.renderErr != nil {
				emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

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
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The new-set notice (#724, #737): a new set of recovery codes made on the Account pages tells the
// user, after the set is stored and after the response, at the account's verified address, in the
// user's language, with no link and none of the codes, against the security_notice budget. A
// refusal, a set lost to the authenticator's removal meanwhile, or a rollback sends nothing.

const recoveryNoticeAddress = "tiago.lopes@example.com"

// recoveryNoticeUser is the caller, with an authenticator, a verified address and a name.
func recoveryNoticeUser(t *testing.T) *record.User {
	t.Helper()
	user := recoveryCodesUser(t)
	user.GivenName = "Tiago"
	user.FamilyName = "Lopes"
	user.Email = recoveryNoticeAddress
	user.EmailVerified = true
	return user
}

// stubNewRecoveryCodes answers a new set that commits: the read, the replacement under the
// user's row and the audit event, the logger's only expectation.
func stubNewRecoveryCodes(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User) {
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()
	datamocks.ExpectRunInTransaction(database, recoveryCodesTx)
	database.On("GetUserByIdForUpdate", mock.Anything, recoveryCodesTx, user.Id).Return(user, nil).Once()
	database.On("ReplaceUserRecoveryCodes", mock.Anything, recoveryCodesTx, user.Id, mock.Anything).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventRecoveryCodesCreated, mock.Anything).Return().Once()
}

func recoveryNoticeHandler(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, jobs *heldJobs,
	pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) http.Handler {
	return HandleAccountRecoveryCodesPost(database, auditLogger, &countingCredentials{},
		accountnotice.New(pageRenderer, emailSender, jobs))
}

func recoveryNoticeRequest(t *testing.T, settings *record.Settings, password string) *http.Request {
	t.Helper()
	return withNoticeContext(recoveryCodesPostRequest(t, password), settings)
}

func TestHandleAccountRecoveryCodesPost_TellsTheUserANewSetWasMade(t *testing.T) {
	for _, tc := range []struct {
		name          string
		locale        string
		expectSubject string
	}{
		{"an English user", "en", "Your recovery codes were replaced"},
		{"an Italian user", "it", "I tuoi codici di recupero sono stati sostituiti"},
		{"a Spanish user", "es", "Se han sustituido tus códigos de recuperación"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &heldJobs{}
			user := recoveryNoticeUser(t)
			user.Locale = tc.locale
			stubNewRecoveryCodes(database, auditLogger, user)

			rr := httptest.NewRecorder()
			recoveryNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).
				ServeHTTP(rr, recoveryNoticeRequest(t, passwordNoticeSettings(), recoveryCodesPassword))

			// The renderer and the sender have no expectations yet, so a notice sent inside the
			// request would already have failed the case.
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			var body api.CreateAccountRecoveryCodesResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			require.Len(t, body.RecoveryCodes, 10)

			captured := expectNotice(pageRenderer, emailSender, "/emails/email_recovery_codes_replaced.html")
			jobs.runAll(t, afterresponse.ClassSecurityNotice)

			require.NotNil(t, captured.sent)
			assert.Equal(t, recoveryNoticeAddress, captured.sent.To)
			assert.Equal(t, tc.expectSubject, captured.sent.Subject)
			assert.Equal(t, tc.locale, captured.renderLocale, "the notice is rendered in the user's language")
			assert.Equal(t, "Tiago Lopes", captured.bound["name"])
			assert.NotContains(t, captured.bound, "link", "the notice carries no link")
			for key, value := range captured.bound {
				for _, code := range body.RecoveryCodes {
					assert.NotContains(t, fmt.Sprint(value), code, "the notice carries no recovery code, found under %q", key)
				}
			}
		})
	}
}

// Where no notice may go, the request hands nothing off: SMTP off and an unverified address with
// the set replaced, and a refusal, an authenticator removed meanwhile or a rollback with no set
// stored.
func TestHandleAccountRecoveryCodesPost_SendsNoNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		password   string
		expectCode int
		arrange    func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User,
			settings *record.Settings)
	}{
		{"SMTP is off", recoveryCodesPassword, http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				settings.SMTPEnabled = false
				stubNewRecoveryCodes(database, auditLogger, user)
			}},
		{"the address is unverified", recoveryCodesPassword, http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				user.EmailVerified = false
				stubNewRecoveryCodes(database, auditLogger, user)
			}},
		{"a wrong password", "Wr0ng!pass", http.StatusBadRequest,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()
			}},
		{"no authenticator", recoveryCodesPassword, http.StatusBadRequest,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				user.OTPEnabled = false
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()
			}},
		{"the authenticator is removed meanwhile", recoveryCodesPassword, http.StatusBadRequest,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()
				datamocks.ExpectRunInTransaction(database, recoveryCodesTx)
				removed := *user
				removed.OTPEnabled = false
				database.On("GetUserByIdForUpdate", mock.Anything, recoveryCodesTx, user.Id).Return(&removed, nil).Once()
			}},
		{"the replacement rolls back", recoveryCodesPassword, http.StatusInternalServerError,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, user *record.User, settings *record.Settings) {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()
				datamocks.ExpectRunInTransaction(database, recoveryCodesTx)
				database.On("GetUserByIdForUpdate", mock.Anything, recoveryCodesTx, user.Id).Return(user, nil).Once()
				database.On("ReplaceUserRecoveryCodes", mock.Anything, recoveryCodesTx, user.Id, mock.Anything).
					Return(errors.New("replace failed")).Once()
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			jobs := &heldJobs{}
			settings := passwordNoticeSettings()
			user := recoveryNoticeUser(t)
			tc.arrange(database, auditLogger, user, settings)

			rr := httptest.NewRecorder()
			recoveryNoticeHandler(database, auditLogger, jobs, handlersmocks.NewPageRenderer(t), accounthandlersmocks.NewEmailSender(t)).
				ServeHTTP(rr, recoveryNoticeRequest(t, settings, tc.password))

			require.Equal(t, tc.expectCode, rr.Code, rr.Body.String())
			assert.Empty(t, jobs.jobs, "no notice is handed off")
		})
	}
}

// A notice that cannot be rendered is one Error record on the request's id, and nothing else: the
// new set was answered before it ran.
func TestHandleAccountRecoveryCodesPost_AFailedNoticeIsOneErrorRecord(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	pageRenderer := handlersmocks.NewPageRenderer(t)
	emailSender := accounthandlersmocks.NewEmailSender(t)
	jobs := &heldJobs{}
	user := recoveryNoticeUser(t)
	stubNewRecoveryCodes(database, auditLogger, user)

	rr := httptest.NewRecorder()
	recoveryNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).
		ServeHTTP(rr, recoveryNoticeRequest(t, passwordNoticeSettings(), recoveryCodesPassword))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	pageRenderer.On("RenderTemplateToBuffer", mock.Anything, mock.Anything, "/emails/email_recovery_codes_replaced.html", mock.Anything).
		Return((*bytes.Buffer)(nil), errors.New("template missing")).Once()

	capture := logtest.CaptureSlog(t)
	jobs.runAll(t, afterresponse.ClassSecurityNotice)

	records := capture.Records()
	require.Len(t, records, 1, capture.Text())
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, "unable to render an account notice", records[0].Message)
	assert.Equal(t, "recovery_codes_replaced", records[0].Attrs["notice"])
	assert.Equal(t, otpNoticeRequestId, records[0].Attrs["request_id"])
	assert.Equal(t, user.Id, records[0].Attrs["user_id"])
	assert.NotContains(t, capture.Text(), recoveryNoticeAddress, "the record names no address")
}

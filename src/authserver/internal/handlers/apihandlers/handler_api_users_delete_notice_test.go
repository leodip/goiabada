package apihandlers

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/requestid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The notice for an administrator's deletion of a user (#783 decision 10): "An administrator
// deleted your account", sent after the deletion commits and after the response, to the address of
// the user's row as the deletion's transaction read it under its lock, in the user's language,
// naming no administrator, with no link, against the security_notice budget. SMTP off, an
// unverified address, a refusal and a rollback send nothing.

const (
	adminDeletionNoticeUserId    = int64(81)
	adminDeletionNoticeAddress   = "elisa.rocha@example.com"
	adminDeletionNoticeRequestId = "req-admin-deletion-0001"
)

// discardNotices is a notifier for the cases that are about something other than the notice.
type discardNotices struct{}

func (discardNotices) Send(*http.Request, accountnotice.Notice, accountnotice.Recipient) {}

// adminDeletionNoticeRow is the user as a read finds them: enabled, with a verified address and a
// name.
func adminDeletionNoticeRow() *record.User {
	return &record.User{
		Id:            adminDeletionNoticeUserId,
		Subject:       "the-deleted-user",
		Enabled:       true,
		GivenName:     "Elisa",
		FamilyName:    "Rocha",
		Email:         adminDeletionNoticeAddress,
		EmailVerified: true,
	}
}

// adminDeletionNoticeRequest is the administrator's deletion, with a manage-scoped token, the
// request's id and settings.
func adminDeletionNoticeRequest(settings *record.Settings) *http.Request {
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d", adminDeletionNoticeUserId), nil)
	req.SetPathValue("id", fmt.Sprint(adminDeletionNoticeUserId))
	ctx := requestid.NewContext(req.Context(), adminDeletionNoticeRequestId)
	ctx = reqctx.WithSettings(ctx, settings)
	return setTokenContextWithClaims(req.WithContext(ctx),
		map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject, "auth_time": float64(1)})
}

// stubAdminDeletionUpToTheWrite answers the handler's read before the transaction (before), the
// administrators' lock, the row as the transaction reads it under its lock (locked) and the guard's
// reads, which find that the user holds no manage.
func stubAdminDeletionUpToTheWrite(database *datamocks.Database, before *record.User, locked *record.User) {
	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), adminDeletionNoticeUserId).Return(before, nil).Once()
	datamocks.ExpectRunInTransaction(database, guardTx)
	expectAdministratorsLock(database, guardTx)
	database.On("GetUserByIdForUpdate", mock.Anything, guardTx, adminDeletionNoticeUserId).Return(locked, nil).Once()
	database.On("GetUserPermissionByUserIdAndPermissionId", mock.Anything, guardTx, adminDeletionNoticeUserId, permManage).
		Return(nil, nil).Once()
	database.On("GetUserGroupsByUserId", mock.Anything, guardTx, adminDeletionNoticeUserId).
		Return([]record.UserGroup{}, nil).Once()
}

// stubAdminDeletion answers a deletion that commits: stubAdminDeletionUpToTheWrite, the delete and
// the audit event. The audit event is the logger's only expectation, so a notice that wrote an
// audit entry of its own would fail the case.
func stubAdminDeletion(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
	before *record.User, locked *record.User) {
	stubAdminDeletionUpToTheWrite(database, before, locked)
	database.On("DeleteUser", mock.Anything, guardTx, adminDeletionNoticeUserId).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDeletedUser, mock.Anything).Return().Once()
}

func adminDeletionNoticeHandler(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, jobs *heldJobs,
	pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) http.Handler {
	return HandleUserDelete(database, auditLogger, accountnotice.New(pageRenderer, emailSender, jobs))
}

func TestHandleUserDelete_TellsTheUserAnAdministratorDeletedTheirAccount(t *testing.T) {
	for _, tc := range []struct {
		name          string
		locale        string
		locked        func() *record.User
		expectSubject string
		expectTo      string
	}{
		{"an English user", "en", adminDeletionNoticeRow,
			"An administrator deleted your account", adminDeletionNoticeAddress},
		{"a Brazilian Portuguese user", "pt-BR", adminDeletionNoticeRow,
			"Um administrador excluiu a sua conta", adminDeletionNoticeAddress},
		{"a German user", "de", adminDeletionNoticeRow,
			"Ihr Konto wurde von der Administration gelöscht", adminDeletionNoticeAddress},
		{
			// The address is the one the row the deletion read under its lock holds, not the one
			// the handler's earlier read saw.
			name:   "the address changed before the deletion took the row",
			locale: "en",
			locked: func() *record.User {
				row := adminDeletionNoticeRow()
				row.Email = "elisa.new@example.com"
				return row
			},
			expectSubject: "An administrator deleted your account",
			expectTo:      "elisa.new@example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &heldJobs{}
			locked := tc.locked()
			locked.Locale = tc.locale
			stubAdminDeletion(database, auditLogger, adminDeletionNoticeRow(), locked)

			rr := httptest.NewRecorder()
			adminDeletionNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).
				ServeHTTP(rr, adminDeletionNoticeRequest(passwordNoticeSettings()))

			// The renderer and the sender have no expectations yet, so a notice sent inside the
			// request would already have failed the case.
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.JSONEq(t, `{"success":true}`, rr.Body.String())

			var renderLocale string
			var bound map[string]interface{}
			pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
				"/emails/email_account_deleted_by_administrator.html", mock.Anything).
				Run(func(args mock.Arguments) {
					renderLocale = i18n.LocaleTag(args.Get(0).(*http.Request).Context())
					bound = args.Get(3).(map[string]interface{})
				}).Return(bytes.NewBufferString("<p>rendered notice</p>"), nil).Once()
			var sent *emaildelivery.SendEmailInput
			emailSender.On("SendEmail", mock.Anything,
				emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com"},
				mock.Anything).
				Run(func(args mock.Arguments) {
					sent = args.Get(2).(*emaildelivery.SendEmailInput)
				}).Return(emaildelivery.SendResult{}, nil).Once()

			jobs.runAll(t, afterresponse.ClassSecurityNotice)

			require.NotNil(t, sent)
			assert.Equal(t, tc.expectTo, sent.To)
			assert.Equal(t, tc.expectSubject, sent.Subject)
			assert.Equal(t, tc.locale, renderLocale, "the notice is rendered in the user's language")
			assert.Equal(t, "Elisa Rocha", bound["name"])
			assert.NotContains(t, bound, "link", "the notice carries no link")
			for key, value := range bound {
				assert.NotContains(t, strings.ToLower(fmt.Sprint(value)), adminSubject,
					"the notice doesn't name the administrator, found under %q", key)
			}
		})
	}
}

// Where no notice may go, the request hands nothing off: SMTP off and an unverified address with
// the user deleted, and a refusal, a user deleted by another request meanwhile, or a rollback with
// nothing deleted by this one.
func TestHandleUserDelete_SendsNoNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expectCode int
		arrange    func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings)
	}{
		{"SMTP is off", http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				settings.SMTPEnabled = false
				stubAdminDeletion(database, auditLogger, adminDeletionNoticeRow(), adminDeletionNoticeRow())
			}},
		{
			// Decided from the row the deletion read under its lock, not from the read before it.
			"the address was unverified when the deletion took the row", http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				locked := adminDeletionNoticeRow()
				locked.EmailVerified = false
				stubAdminDeletion(database, auditLogger, adminDeletionNoticeRow(), locked)
			}},
		{"the user does not exist", http.StatusNotFound,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), adminDeletionNoticeUserId).Return(nil, nil).Once()
			}},
		{
			// Another request deleted the user after this one read them: this one deleted nothing.
			"the user was deleted meanwhile", http.StatusNotFound,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), adminDeletionNoticeUserId).
					Return(adminDeletionNoticeRow(), nil).Once()
				datamocks.ExpectRunInTransaction(database, guardTx)
				expectAdministratorsLock(database, guardTx)
				database.On("GetUserByIdForUpdate", mock.Anything, guardTx, adminDeletionNoticeUserId).
					Return(nil, nil).Once()
			}},
		{"the user is the last administrator", http.StatusConflict,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), adminDeletionNoticeUserId).
					Return(adminDeletionNoticeRow(), nil).Once()
				datamocks.ExpectRunInTransaction(database, guardTx)
				expectAdministratorsLock(database, guardTx)
				database.On("GetUserByIdForUpdate", mock.Anything, guardTx, adminDeletionNoticeUserId).
					Return(adminDeletionNoticeRow(), nil).Once()
				database.On("GetUserPermissionByUserIdAndPermissionId", mock.Anything, guardTx, adminDeletionNoticeUserId, permManage).
					Return(&record.UserPermission{Id: 9, UserId: adminDeletionNoticeUserId, PermissionId: permManage}, nil).Once()
				expectHoldersCounted(database, guardTx, 1, 0)
				database.On("DeleteUser", mock.Anything, guardTx, adminDeletionNoticeUserId).Return(nil).Once()
			}},
		{"the deletion rolls back", http.StatusInternalServerError,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				stubAdminDeletionUpToTheWrite(database, adminDeletionNoticeRow(), adminDeletionNoticeRow())
				database.On("DeleteUser", mock.Anything, guardTx, adminDeletionNoticeUserId).
					Return(errors.New("delete failed")).Once()
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			jobs := &heldJobs{}
			settings := passwordNoticeSettings()
			tc.arrange(database, auditLogger, settings)

			rr := httptest.NewRecorder()
			adminDeletionNoticeHandler(database, auditLogger, jobs, handlersmocks.NewPageRenderer(t), accounthandlersmocks.NewEmailSender(t)).
				ServeHTTP(rr, adminDeletionNoticeRequest(settings))

			require.Equal(t, tc.expectCode, rr.Code, rr.Body.String())
			assert.Empty(t, jobs.jobs, "no notice is handed off")
			if tc.expectCode == http.StatusNotFound {
				code, _ := decodeErrorEnvelope(t, rr)
				assert.Equal(t, "NOT_FOUND", code)
				database.AssertNotCalled(t, "DeleteUser", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

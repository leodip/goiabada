package apihandlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
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

// The notice for a password an administrator sets (#724): sent after the change commits and after
// the response, to the account's verified address, saying an administrator changed it, and against
// the security_notice budget. A first password sends nothing (decision 6), and whether the account
// had one is read from the row the write replaces, inside its transaction, not from the read the
// handler made before it.

const (
	adminPasswordNoticeUserId    = int64(77)
	adminPasswordNoticeNew       = "N3wP4ss!word-set-by-admin"
	adminPasswordNoticeAddress   = "bruno.costa@example.com"
	adminPasswordNoticeRequestId = "req-admin-password-0001"
)

// adminPasswordNoticeRow is the account as a read finds it: a verified address, a name and the
// password hash given, "" for an account whose setup link is still pending.
func adminPasswordNoticeRow(passwordHash string) *record.User {
	return &record.User{
		Id:            adminPasswordNoticeUserId,
		Subject:       "the-target",
		Enabled:       true,
		GivenName:     "Bruno",
		FamilyName:    "Costa",
		Email:         adminPasswordNoticeAddress,
		EmailVerified: true,
		PasswordHash:  passwordHash,
	}
}

// adminPasswordNoticeRequest is the administrator's save, with a manage-scoped token, the request's
// id and settings.
func adminPasswordNoticeRequest(t *testing.T, settings *record.Settings, newPassword string) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]string{"newPassword": newPassword})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/password", adminPasswordNoticeUserId),
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", fmt.Sprint(adminPasswordNoticeUserId))
	ctx := requestid.NewContext(req.Context(), adminPasswordNoticeRequestId)
	ctx = reqctx.WithSettings(ctx, settings)
	return setTokenContextWithClaims(req.WithContext(ctx),
		map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject, "auth_time": float64(1)})
}

// stubAdminPasswordSet answers a save that commits: the handler's read before the transaction
// (before), the row the write replaces (replaced), the write, the sweep, the two audit events and
// the read the response is built from. The audit events are the logger's only expectations, so a
// notice that wrote an audit entry of its own would fail the case.
func stubAdminPasswordSet(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
	before *record.User, replaced *record.User) {
	database.On("GetUserById", mock.Anything, mock.Anything, adminPasswordNoticeUserId).Return(before, nil).Once()
	database.On("GetUserByIdForUpdate", mock.Anything, apiRevokeTx, adminPasswordNoticeUserId).Return(replaced, nil).Once()
	database.On("SetUserPasswordHash", mock.Anything, apiRevokeTx, adminPasswordNoticeUserId, mock.Anything).Return(nil).Once()
	stubSweep(database, adminPasswordNoticeUserId, 5)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedUserAuthentication, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventRevokedUserAuthState, mock.Anything).Return().Once()
	database.On("GetUserById", mock.Anything, mock.Anything, adminPasswordNoticeUserId).
		Return(adminPasswordNoticeRow("the-new-hash"), nil).Once()
}

func adminPasswordNoticeHandler(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, jobs *heldJobs,
	pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) http.Handler {
	return HandleUserPasswordPut(database, accountvalidation.NewPasswordValidator(), auditLogger,
		accountnotice.New(pageRenderer, emailSender, jobs))
}

func TestHandleUserPasswordPut_TellsTheUserAnAdministratorChangedIt(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before        *record.User
		replaced      func() *record.User
		locale        string
		renderLocale  string
		expectSubject string
		expectTo      string
	}{
		{
			name:          "an English user whose password is replaced",
			before:        adminPasswordNoticeRow("the-old-hash"),
			replaced:      func() *record.User { return adminPasswordNoticeRow("the-old-hash") },
			locale:        "en",
			renderLocale:  "en",
			expectSubject: "An administrator changed your password",
			expectTo:      adminPasswordNoticeAddress,
		},
		{
			name:          "a Brazilian Portuguese user",
			before:        adminPasswordNoticeRow("the-old-hash"),
			replaced:      func() *record.User { return adminPasswordNoticeRow("the-old-hash") },
			locale:        "pt-BR",
			renderLocale:  "pt-BR",
			expectSubject: "Um administrador alterou a sua senha",
			expectTo:      adminPasswordNoticeAddress,
		},
		{
			// The handler's own read found the account with no password, but its setup link was
			// used before the transaction took the row: the write replaces a password, so the
			// user is told.
			name:          "a setup link used meanwhile gave the account a password",
			before:        adminPasswordNoticeRow(""),
			replaced:      func() *record.User { return adminPasswordNoticeRow("the-hash-the-setup-link-set") },
			locale:        "en",
			renderLocale:  "en",
			expectSubject: "An administrator changed your password",
			expectTo:      adminPasswordNoticeAddress,
		},
		{
			// The address is the one the row the write replaces holds, not the one the earlier
			// read saw.
			name:   "the address changed before the transaction took the row",
			before: adminPasswordNoticeRow("the-old-hash"),
			replaced: func() *record.User {
				row := adminPasswordNoticeRow("the-old-hash")
				row.Email = "bruno.new@example.com"
				return row
			},
			locale:        "en",
			renderLocale:  "en",
			expectSubject: "An administrator changed your password",
			expectTo:      "bruno.new@example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &heldJobs{}
			replaced := tc.replaced()
			replaced.Locale = tc.locale
			stubAdminPasswordSet(database, auditLogger, tc.before, replaced)

			rr := httptest.NewRecorder()
			adminPasswordNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender).
				ServeHTTP(rr, adminPasswordNoticeRequest(t, passwordNoticeSettings(), adminPasswordNoticeNew))

			// The renderer and the sender have no expectations yet, so a notice sent inside the
			// request would already have failed the case.
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			var renderLocale string
			var bound map[string]interface{}
			pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
				"/emails/email_password_changed_by_administrator.html", mock.Anything).
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
			assert.Equal(t, tc.renderLocale, renderLocale, "the notice is rendered in the user's language")
			assert.Equal(t, "Bruno Costa", bound["name"])
			assert.NotContains(t, bound, "link", "the notice carries no link")
			for key, value := range bound {
				assert.NotContains(t, fmt.Sprint(value), adminPasswordNoticeNew, "the notice carries no password, found under %q", key)
			}
		})
	}
}

// Where no notice may go, the request hands nothing off: a first password, whichever read saw it,
// SMTP off and an unverified address with the change made, and a refusal or a rollback with no
// change at all.
func TestHandleUserPasswordPut_SendsNoNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expectCode int
		arrange    func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings)
		// newPassword is what the administrator submits, adminPasswordNoticeNew when empty.
		newPassword string
	}{
		{"the account has no password yet", http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				stubAdminPasswordSet(database, auditLogger, adminPasswordNoticeRow(""), adminPasswordNoticeRow(""))
			}, ""},
		{
			// Decided from the row the write replaces, not from the read before the transaction.
			"the earlier read saw a password the row the write replaces doesn't have", http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				stubAdminPasswordSet(database, auditLogger, adminPasswordNoticeRow("the-old-hash"), adminPasswordNoticeRow(""))
			}, ""},
		{"SMTP is off", http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				settings.SMTPEnabled = false
				stubAdminPasswordSet(database, auditLogger, adminPasswordNoticeRow("the-old-hash"), adminPasswordNoticeRow("the-old-hash"))
			}, ""},
		{"the address is unverified", http.StatusOK,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				replaced := adminPasswordNoticeRow("the-old-hash")
				replaced.EmailVerified = false
				stubAdminPasswordSet(database, auditLogger, adminPasswordNoticeRow("the-old-hash"), replaced)
			}, ""},
		{"the new password is refused", http.StatusBadRequest,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				database.On("GetUserById", mock.Anything, mock.Anything, adminPasswordNoticeUserId).
					Return(adminPasswordNoticeRow("the-old-hash"), nil).Once()
			}, "short"},
		{"the change rolls back", http.StatusInternalServerError,
			func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, settings *record.Settings) {
				database.On("GetUserById", mock.Anything, mock.Anything, adminPasswordNoticeUserId).
					Return(adminPasswordNoticeRow("the-old-hash"), nil).Once()
				datamocks.ExpectRunInTransaction(database, apiRevokeTx)
				database.On("GetUserByIdForUpdate", mock.Anything, apiRevokeTx, adminPasswordNoticeUserId).
					Return(adminPasswordNoticeRow("the-old-hash"), nil).Once()
				database.On("SetUserPasswordHash", mock.Anything, apiRevokeTx, adminPasswordNoticeUserId, mock.Anything).
					Return(nil).Once()
				database.On("IncrementUserAuthStateGeneration", mock.Anything, apiRevokeTx, adminPasswordNoticeUserId).
					Return(int64(0), errors.New("increment failed")).Once()
			}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			jobs := &heldJobs{}
			settings := passwordNoticeSettings()
			tc.arrange(database, auditLogger, settings)
			newPassword := tc.newPassword
			if newPassword == "" {
				newPassword = adminPasswordNoticeNew
			}

			rr := httptest.NewRecorder()
			adminPasswordNoticeHandler(database, auditLogger, jobs, handlersmocks.NewPageRenderer(t), accounthandlersmocks.NewEmailSender(t)).
				ServeHTTP(rr, adminPasswordNoticeRequest(t, settings, newPassword))

			require.Equal(t, tc.expectCode, rr.Code, rr.Body.String())
			assert.Empty(t, jobs.jobs, "no notice is handed off")
		})
	}
}

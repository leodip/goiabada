package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The settings ceiling: the email settings, which decide where reset links go, and the audit-log
// settings, which can switch off the record every other refusal rests on, are changed only by an
// authserver:manage token. manage-settings is refused 403 MANAGE_SCOPE_REQUIRED with an
// insufficient_scope challenge naming authserver:manage, writes nothing and leaves one
// administrator_change_refused record naming the settings ceiling (#402 decisions 1, 4, 5 and 7).

// settingsCeilingSave is one of the reserved settings writes, with a well-formed body.
type settingsCeilingSave struct {
	name    string
	path    string
	body    func(t *testing.T) string
	handler func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler
}

// unreachableSMTPPort is a port on the loopback address that nothing listens on: a refused request
// that dialled it would be answered 400 rather than refused.
func unreachableSMTPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return port
}

// listeningSMTPPort is a port on the loopback address that accepts connections for the test.
func listeningSMTPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func emailSettingsBody(t *testing.T, enabled bool, port int) string {
	t.Helper()
	body := map[string]interface{}{"smtpEnabled": enabled}
	if enabled {
		body["smtpHost"] = "127.0.0.1"
		body["smtpPort"] = port
		body["smtpEncryption"] = "none"
		body["smtpFromName"] = "Attacker"
		body["smtpFromEmail"] = "reset-links@attacker.test"
	}
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	return string(encoded)
}

func emailSettingsHandler(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
	return HandleSettingsEmailPut(database, accountvalidation.NewEmailValidator(nil), auditLogger, testDataCipher)
}

func auditLogsSettingsHandler(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
	return HandleSettingsAuditLogsPut(database, auditLogger)
}

// settingsCeilingSaves is the reserved writes, each with a body that would change the setting. The
// enabled email save names a port nothing listens on, so a refusal that came after the
// connectivity dial would be answered 400 instead.
var settingsCeilingSaves = []settingsCeilingSave{
	{
		name:    "email settings, pointing SMTP elsewhere",
		path:    "/api/v1/admin/settings/email",
		body:    func(t *testing.T) string { return emailSettingsBody(t, true, unreachableSMTPPort(t)) },
		handler: emailSettingsHandler,
	},
	{
		name:    "email settings, switching SMTP off",
		path:    "/api/v1/admin/settings/email",
		body:    func(t *testing.T) string { return emailSettingsBody(t, false, 0) },
		handler: emailSettingsHandler,
	},
	{
		name: "audit-log settings, switching logging off",
		path: "/api/v1/admin/settings/audit-logs",
		body: func(t *testing.T) string {
			return `{"auditLogsInConsoleEnabled":false,"auditLogsInDatabaseEnabled":false,"auditLogRetentionDays":1}`
		},
		handler: auditLogsSettingsHandler,
	},
}

// serveSettingsSave runs a reserved save on a PUT carrying body, as a caller whose validated token
// carries scope, or with no validated token at all when scope is empty.
func serveSettingsSave(save settingsCeilingSave, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
	body, scope string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, save.path, strings.NewReader(body))
	r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{
		SMTPEnabled:                true,
		SMTPHost:                   "smtp.example.test",
		SMTPPort:                   587,
		AuditLogsInConsoleEnabled:  true,
		AuditLogsInDatabaseEnabled: true,
		AuditLogRetentionDays:      90,
	}))
	if scope != "" {
		r = setTokenContextWithClaims(r, map[string]interface{}{"scope": scope, "sub": grantCaller})
	}
	rr := httptest.NewRecorder()
	save.handler(database, auditLogger).ServeHTTP(rr, r)
	return rr
}

func TestSettingsCeiling_EveryCallerBelowManageIsRefused(t *testing.T) {
	callers := []struct {
		name  string
		scope string
	}{
		{name: "manage-settings", scope: "authserver:manage-settings"},
		{name: "every granular scope", scope: "authserver:admin-read authserver:manage-users authserver:manage-clients authserver:manage-settings authserver:browser-sessions"},
		{name: "a scope that only resembles manage", scope: "authserver:manage-account other:manage"},
		{name: "no validated token", scope: ""},
	}

	for _, save := range settingsCeilingSaves {
		for _, caller := range callers {
			t.Run(save.name+"/"+caller.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				records := recordLoggedEvents(auditLogger)

				rr := serveSettingsSave(save, database, auditLogger, save.body(t), caller.scope)

				status := rr.Code
				code, description := decodeErrorEnvelope(t, rr)
				assertManageScopeRequired(t, rr, status, code, description)
				database.AssertNotCalled(t, "UpdateSettings", mock.Anything, mock.Anything, mock.Anything)

				require.Len(t, *records, 1, "one record per refused request, and not the settings change's own")
				refusal := (*records)[0]
				assert.Equal(t, "administrator_change_refused", refusal.event)
				assert.Equal(t, http.MethodPut, refusal.details["method"])
				assert.Contains(t, refusal.details, "route")
				assert.Equal(t, "settings", refusal.details["ceiling"])
				assert.NotContains(t, refusal.details, "targetKind", "a settings write has no target")
				assert.NotContains(t, refusal.details, "targetId", "a settings write has no target")
				assert.NotContains(t, refusal.details, "permissionIds")
				if caller.scope != "" {
					assert.Equal(t, grantCaller, refusal.details["loggedInUser"])
				}
			})
		}
	}
}

// The refusal comes after the request's own 400 answers: a body that does not decode, or a value
// out of bounds, is answered as before, and nothing is audited.
func TestSettingsCeiling_AMalformedRequestIsAnsweredFirst(t *testing.T) {
	cases := []struct {
		name string
		save settingsCeilingSave
		body string
	}{
		{name: "email settings, a body that does not decode", save: settingsCeilingSaves[0], body: "{"},
		{name: "email settings, no host", save: settingsCeilingSaves[0],
			body: `{"smtpEnabled":true,"smtpHost":"","smtpPort":25,"smtpEncryption":"none","smtpFromEmail":"a@b.test"}`},
		{name: "email settings, a password together with its removal", save: settingsCeilingSaves[0],
			body: `{"smtpEnabled":true,"smtpHost":"127.0.0.1","smtpPort":25,"smtpEncryption":"none","smtpFromEmail":"a@b.test",` +
				`"smtpPassword":"secret","clearSmtpPassword":true}`},
		{name: "audit-log settings, a body that does not decode", save: settingsCeilingSaves[2], body: "{"},
		{name: "audit-log settings, negative retention", save: settingsCeilingSaves[2],
			body: `{"auditLogsInConsoleEnabled":true,"auditLogsInDatabaseEnabled":true,"auditLogRetentionDays":-1}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			rr := serveSettingsSave(c.save, database, auditLogger, c.body, "authserver:manage-settings")

			assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "UpdateSettings", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// authserver:manage changes both settings as before: the save is written and audited under its own
// event, and nothing is refused.
func TestSettingsCeiling_AManageTokenChangesTheReservedSettings(t *testing.T) {
	cases := []struct {
		name  string
		save  settingsCeilingSave
		body  func(t *testing.T) string
		event string
	}{
		{name: "email settings, enabled", save: settingsCeilingSaves[0],
			body:  func(t *testing.T) string { return emailSettingsBody(t, true, listeningSMTPPort(t)) },
			event: "updated_smtp_settings"},
		{name: "email settings, disabled", save: settingsCeilingSaves[1], body: settingsCeilingSaves[1].body,
			event: "updated_smtp_settings"},
		{name: "audit-log settings", save: settingsCeilingSaves[2], body: settingsCeilingSaves[2].body,
			event: "updated_audit_logs_settings"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			database.On("UpdateSettings", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.Settings")).Return(nil).Once()
			records := recordLoggedEvents(auditLogger)

			rr := serveSettingsSave(c.save, database, auditLogger, c.body(t), "authserver:manage")

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
			database.AssertExpectations(t)
			require.Len(t, *records, 1)
			assert.Equal(t, c.event, (*records)[0].event)
		})
	}
}

// The settings that stay with manage-settings are not under the ceiling: it still changes them.
func TestSettingsCeiling_ManageSettingsKeepsTheOtherSettings(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("UpdateSettings", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.Settings")).Return(nil).Once()
	records := recordLoggedEvents(auditLogger)

	body := `{"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":86400}`
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/sessions", strings.NewReader(body))
	r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{}))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage-settings", "sub": grantCaller})
	rr := httptest.NewRecorder()
	HandleSettingsSessionsPut(database, auditLogger).ServeHTTP(rr, r)

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	database.AssertExpectations(t)
	require.Len(t, *records, 1)
	assert.NotEqual(t, "administrator_change_refused", (*records)[0].event)
}

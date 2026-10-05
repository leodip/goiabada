package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The settings ceiling on PUT /settings/email and PUT /settings/audit-logs: the email settings
// decide where reset links go and the audit-log settings can switch off the record every refusal
// rests on, so only an authserver:manage token changes them (#402 decisions 1, 4, 5 and 7).
//
// Each row runs three ways: manage-settings is refused 403 MANAGE_SCOPE_REQUIRED with the
// insufficient_scope challenge, leaves the settings row as it was, writes no record of a change and
// leaves exactly one administrator_change_refused row naming the settings ceiling; the same token
// still changes the settings outside the ceiling; and authserver:manage changes both.

// settingsCeilingWrite is one reserved settings write, with a body that would change the row.
type settingsCeilingWrite struct {
	name  string
	route string
	body  any
	// event is the record the write leaves when it is made.
	event string
}

var settingsCeilingWrites = []settingsCeilingWrite{
	{
		name:  "pointing SMTP at another server",
		route: "/api/v1/admin/settings/email",
		body: api.UpdateSettingsEmailRequest{
			SMTPEnabled:    true,
			SMTPHost:       "mailpit",
			SMTPPort:       1025,
			SMTPEncryption: "none",
			SMTPFromName:   "Not the operator",
			SMTPFromEmail:  "ceiling@settings.test",
		},
		event: "updated_smtp_settings",
	},
	{
		name:  "switching SMTP off",
		route: "/api/v1/admin/settings/email",
		body:  api.UpdateSettingsEmailRequest{SMTPEnabled: false},
		event: "updated_smtp_settings",
	},
	{
		name:  "switching the audit log off",
		route: "/api/v1/admin/settings/audit-logs",
		body: api.UpdateSettingsAuditLogsRequest{
			AuditLogsInConsoleEnabled:  false,
			AuditLogsInDatabaseEnabled: false,
			AuditLogRetentionDays:      1,
		},
		event: "updated_audit_logs_settings",
	},
}

// eventRows is how many rows of one event one request left.
func eventRows(t *testing.T, readerToken, event, requestId string) int {
	t.Helper()
	logs, resp := getAuditLogs(t, readerToken, "auditEvent="+url.QueryEscape(event)+"&requestId="+url.QueryEscape(requestId))
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return len(logs.AuditLogs)
}

func settingsRow(t *testing.T) *record.Settings {
	t.Helper()
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	return settings
}

func TestSettingsCeiling_ManageSettingsCannotChangeTheReservedSettings(t *testing.T) {
	// SMTP on, so that switching it off is a change, and the database log on, so that rows are read
	// back from it.
	changeSettings(t, func(settings *record.Settings) {
		settings.AuditLogsInDatabaseEnabled = true
		settings.AuditLogsInConsoleEnabled = true
		settings.AuditLogRetentionDays = 90
		settings.SMTPEnabled = true
		settings.SMTPHost = "mailpit"
		settings.SMTPPort = 1025
		settings.SMTPFromEmail = "operator@settings.test"
	})
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageSettingsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

	for _, write := range settingsCeilingWrites {
		t.Run(write.name, func(t *testing.T) {
			before := settingsRow(t)

			resp, requestId := sendAdmin(t, granularToken, http.MethodPut, write.route, write.body)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			var envelope struct {
				ErrorCode        string `json:"error_code"`
				ErrorDescription string `json:"error_description"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
			assert.Equal(t, "MANAGE_SCOPE_REQUIRED", envelope.ErrorCode)
			assert.Contains(t, envelope.ErrorDescription, "authserver:manage")
			challenge := resp.Header.Get("WWW-Authenticate")
			assert.True(t, strings.HasPrefix(challenge, `Bearer realm="`), "a Bearer challenge with its realm: %q", challenge)
			assert.Contains(t, challenge, `error="insufficient_scope"`)
			assert.Contains(t, challenge, `scope="authserver:manage"`)

			assert.Empty(t, settingsChanges(before, settingsRow(t)), "the refused request changed nothing")
			assert.Zero(t, eventRows(t, manageToken, write.event, requestId), "no record of a change that was not made")

			rows := refusalRows(t, manageToken, requestId)
			require.Len(t, rows, 1, "exactly one administrator_change_refused row for the refused request")
			row := rows[0]
			assert.Equal(t, caller.ClientIdentifier, row["loggedInUser"], "the caller is the token's sub")
			assert.Equal(t, http.MethodPut, row["method"])
			assert.Equal(t, write.route, row["route"])
			assert.Equal(t, "settings", row["ceiling"])
			assert.NotContains(t, row, "targetKind", "a settings write has no target")
			assert.NotContains(t, row, "targetId", "a settings write has no target")
		})
	}
}

// manage-settings keeps the settings decision 7 leaves with it.
func TestSettingsCeiling_ManageSettingsStillChangesTheOtherSettings(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageSettingsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })

	before := settingsRow(t)
	resp, requestId := sendAdmin(t, granularToken, http.MethodPut, "/api/v1/admin/settings/sessions", api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: before.UserSessionIdleTimeoutInSeconds + 60,
		UserSessionMaxLifetimeInSeconds: before.UserSessionMaxLifetimeInSeconds + 60,
	})
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, before.UserSessionIdleTimeoutInSeconds+60, settingsRow(t).UserSessionIdleTimeoutInSeconds)
	assert.Empty(t, refusalRows(t, manageToken, requestId))
}

func TestSettingsCeiling_AManageTokenChangesTheReservedSettings(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) {
		settings.AuditLogsInDatabaseEnabled = true
		settings.AuditLogsInConsoleEnabled = true
		settings.AuditLogRetentionDays = 90
		settings.SMTPEnabled = true
		settings.SMTPHost = "mailpit"
		settings.SMTPPort = 1025
		settings.SMTPFromEmail = "operator@settings.test"
	})
	manageToken, _ := createAdminClientWithToken(t)

	for _, write := range settingsCeilingWrites {
		t.Run(write.name, func(t *testing.T) {
			// Each write's own record is read back from the database log, which the audit-log write
			// switches off, so each starts from it switched on.
			// The row is restored when the subtest ends, so each write changes the one the parent set.
			before := changeSettings(t, func(settings *record.Settings) { settings.AuditLogsInDatabaseEnabled = true })

			resp, requestId := sendAdmin(t, manageToken, http.MethodPut, write.route, write.body)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
			assert.NotEmpty(t, settingsChanges(before, settingsRow(t)), "the write changed the settings row")
			assert.Equal(t, 1, eventRows(t, manageToken, write.event, requestId), "the change is recorded under its own event")
			assert.Empty(t, refusalRows(t, manageToken, requestId))
		})
	}
}

package apihandlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// updated_audit_logs_settings records a change that took effect, so a save the database refuses
// records nothing.
func TestSettingsAuditLogsPut_AFailedSaveRecordsNothing(t *testing.T) {
	logtest.CaptureSlog(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("UpdateSettings", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.Settings")).
		Return(errors.New("the database refused the save")).Once()
	save := settingsCeilingSaves[2]

	rr := serveSettingsSave(save, database, auditLogger, save.body(t), "authserver:manage")

	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The event is recorded after the save, under the settings the request started with, which are the
// audit logger's switches: switching both sinks off is still recorded, by the sinks it turns off.
func TestSettingsAuditLogsPut_SwitchingLoggingOffIsRecordedUnderTheOldSwitches(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var steps []string
	var saved record.Settings
	database.On("UpdateSettings", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.Settings")).
		Run(func(args mock.Arguments) {
			steps = append(steps, "save")
			saved = *args.Get(2).(*record.Settings)
		}).
		Return(nil).Once()
	var atLog *record.Settings
	records := &[]loggedEvent{}
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			steps = append(steps, "log")
			atLog, _ = reqctx.SettingsFrom(args.Get(0).(context.Context))
			*records = append(*records, loggedEvent{event: args.String(1), details: args.Get(2).(map[string]interface{})})
		}).
		Return().Once()
	save := settingsCeilingSaves[2]

	rr := serveSettingsSave(save, database, auditLogger, save.body(t), "authserver:manage")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []string{"save", "log"}, steps)
	assert.False(t, saved.AuditLogsInConsoleEnabled)
	assert.False(t, saved.AuditLogsInDatabaseEnabled)
	assert.Equal(t, 1, saved.AuditLogRetentionDays)

	require.Len(t, *records, 1)
	assert.Equal(t, "updated_audit_logs_settings", (*records)[0].event)
	assert.Equal(t, false, (*records)[0].details["audit_logs_in_console_enabled"])
	assert.Equal(t, false, (*records)[0].details["audit_logs_in_database_enabled"])
	assert.Equal(t, 1, (*records)[0].details["audit_log_retention_days"])
	require.NotNil(t, atLog, "no settings on the context the event was logged with")
	assert.True(t, atLog.AuditLogsInConsoleEnabled, "the event was logged under the new console switch")
	assert.True(t, atLog.AuditLogsInDatabaseEnabled, "the event was logged under the new database switch")
}

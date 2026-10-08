package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// updated_audit_logs_settings is recorded before the save, under the old settings, so that switching
// logging off still records who did it. A save the database then refuses leaves the event behind,
// holding the values asked for. The audit log page says so (#519), and this holds it to the handler.
func TestSettingsAuditLogsPut_AFailedSaveIsStillRecordedWithTheRequestedValues(t *testing.T) {
	logtest.CaptureSlog(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("UpdateSettings", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.Settings")).
		Return(errors.New("the database refused the save")).Once()
	records := recordLoggedEvents(auditLogger)
	save := settingsCeilingSaves[2]

	rr := serveSettingsSave(save, database, auditLogger, save.body(t), "authserver:manage")

	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
	database.AssertExpectations(t)
	require.Len(t, *records, 1)
	assert.Equal(t, "updated_audit_logs_settings", (*records)[0].event)
	assert.Equal(t, false, (*records)[0].details["auditLogsInConsoleEnabled"])
	assert.Equal(t, false, (*records)[0].details["auditLogsInDatabaseEnabled"])
	assert.Equal(t, 1, (*records)[0].details["auditLogRetentionDays"])
}

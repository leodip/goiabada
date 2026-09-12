package audit

import (
	"log/slog"
	"testing"

	mocks "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestAuditLogger_ConsoleRecordCarriesTheEventAndTheDetails is the console half of AuditLogger,
// at the seam auditlog.LogToConsole now owns.
//
// These three cases used to marshal an envelope into the message field and compare the message
// against an expected JSON document. That is the shape #320 decision 7 replaced: a collector
// consuming this log as JSON had to parse `msg` a second time to reach the field it was querying
// on. So they now read the event name and the details off the record, which is where a consumer
// reads them.
func TestAuditLogger_ConsoleRecordCarriesTheEventAndTheDetails(t *testing.T) {
	testCases := []struct {
		name    string
		event   string
		details map[string]interface{}
	}{
		{
			name:  "Basic log event",
			event: "user_login",
			details: map[string]interface{}{
				"user_id": "123",
				"ip":      "192.168.1.1",
			},
		},
		{
			name:    "Log event with empty details",
			event:   "system_startup",
			details: map[string]interface{}{},
		},
		{
			name:  "Log event with nested details",
			event: "data_update",
			details: map[string]interface{}{
				"user": map[string]interface{}{
					"id":   "456",
					"name": "John Doe",
				},
				"changes": []string{"email", "phone"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logs := testutil.CaptureSlog(t)

			// Create mock DB that returns settings with console enabled, DB disabled
			mockDB := mocks.NewDatabase(t)
			settings := &models.Settings{
				AuditLogsInConsoleEnabled:  true,
				AuditLogsInDatabaseEnabled: false,
			}
			mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil)

			NewAuditLogger(mockDB).Log(tc.event, tc.details)

			records := logs.Records()
			require.Len(t, records, 1, "one audit event, one console record")
			assert.Equal(t, slog.LevelInfo, records[0].Level)
			assert.Equal(t, "audit event", records[0].Message,
				"one message for every event, so the name a consumer filters on is an attribute")
			assert.Equal(t, tc.event, records[0].Attrs["event"])
			assert.Equal(t, tc.details, records[0].Attrs["details"],
				"the details reach the record as the map, nesting and slices intact, rather than as a JSON string inside the message")
		})
	}
}

func TestAuditLoggerDisabled(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	// Create mock DB that returns settings with both disabled
	mockDB := mocks.NewDatabase(t)
	settings := &models.Settings{
		AuditLogsInConsoleEnabled:  false,
		AuditLogsInDatabaseEnabled: false,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil)

	// Create an AuditLogger instance with both disabled
	auditLogger := NewAuditLogger(mockDB)

	// Call the Log method
	auditLogger.Log("test_event", map[string]interface{}{"key": "value"})

	// Get the logged output
	output := logs.Text()

	// Should be empty since both logging targets are disabled
	if output != "" {
		t.Errorf("Expected no output when both logging targets are disabled, but got: %v", output)
	}

	// Verify no DB write
	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything)
}

func TestAuditLogger_DBPersistence_Enabled(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Mock settings to enable DB persistence, disable console
	settings := &models.Settings{
		AuditLogsInConsoleEnabled:  false,
		AuditLogsInDatabaseEnabled: true,
		AuditLogRetentionDays:      90,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil)

	// Expect CreateAuditLog to be called
	mockDB.On("CreateAuditLog", mock.Anything, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.AuditEvent == "test_event" &&
			log.Details != "" &&
			log.CreatedAt.IsZero() // CreatedAt should be zero before DB call
	})).Return(nil).Once()

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event
	auditLogger.Log("test_event", map[string]interface{}{
		"user_id": "123",
		"action":  "login",
	})

	// Verify mock expectations
	mockDB.AssertExpectations(t)
}

func TestAuditLogger_DBPersistence_Disabled(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Mock settings to disable DB persistence
	settings := &models.Settings{
		AuditLogsInConsoleEnabled:  false,
		AuditLogsInDatabaseEnabled: false,
		AuditLogRetentionDays:      90,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil)

	// CreateAuditLog should NOT be called
	// (no mock.On call means assertion will fail if it's called)

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event
	auditLogger.Log("test_event", map[string]interface{}{
		"key": "value",
	})

	// Verify CreateAuditLog was not called
	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything)
}

func TestAuditLogger_SettingsError(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Mock settings call to return error
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(nil, assert.AnError)

	// CreateAuditLog should NOT be called due to settings error

	logs := testutil.CaptureSlog(t)

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event
	auditLogger.Log("test_event", map[string]interface{}{
		"key": "value",
	})

	// Verify error was logged
	output := logs.Text()
	assert.Contains(t, output, "unable to read the settings row for audit logging")

	// Verify CreateAuditLog was not called
	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything)
}

func TestAuditLogger_DBPersistence_CreateError(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Mock settings to enable DB persistence
	settings := &models.Settings{
		AuditLogsInConsoleEnabled:  false,
		AuditLogsInDatabaseEnabled: true,
		AuditLogRetentionDays:      90,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil)

	// Mock CreateAuditLog to return error
	mockDB.On("CreateAuditLog", mock.Anything, mock.Anything).Return(assert.AnError)

	logs := testutil.CaptureSlog(t)

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event (should not panic despite DB error)
	auditLogger.Log("test_event", map[string]interface{}{
		"key": "value",
	})

	// Verify error was logged
	output := logs.Text()
	assert.Contains(t, output, "unable to persist the audit log to the database")

	// Verify CreateAuditLog was called (even though it failed)
	mockDB.AssertExpectations(t)
}

func TestAuditLogger_DBPersistence_JSONMarshalError(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Mock settings to enable DB persistence
	settings := &models.Settings{
		AuditLogsInConsoleEnabled:  false,
		AuditLogsInDatabaseEnabled: true,
		AuditLogRetentionDays:      90,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil)

	// CreateAuditLog should NOT be called due to marshal error

	logs := testutil.CaptureSlog(t)

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event with un-marshalable details (channel cannot be marshaled to JSON)
	auditLogger.Log("test_event", map[string]interface{}{
		"channel": make(chan int),
	})

	// Verify error was logged
	output := logs.Text()
	assert.Contains(t, output, "unable to marshal the audit event details for the database")

	// Verify CreateAuditLog was not called
	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything)
}

func TestAuditLogger_BothConsoleAndDB(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Mock settings to enable both
	settings := &models.Settings{
		AuditLogsInConsoleEnabled:  true,
		AuditLogsInDatabaseEnabled: true,
		AuditLogRetentionDays:      90,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil)
	mockDB.On("CreateAuditLog", mock.Anything, mock.Anything).Return(nil)

	logs := testutil.CaptureSlog(t)

	// Create audit logger with BOTH console and DB enabled
	auditLogger := NewAuditLogger(mockDB)

	// Log an event
	auditLogger.Log("test_event", map[string]interface{}{
		"key": "value",
	})

	// Verify console output
	output := logs.Text()
	assert.Contains(t, output, "test_event")

	// Verify DB was called
	mockDB.AssertExpectations(t)
}

func TestAuditLogger_ConsoleEnabledDBDisabled(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Mock settings: console enabled, DB disabled
	settings := &models.Settings{
		AuditLogsInConsoleEnabled:  true,
		AuditLogsInDatabaseEnabled: false,
		AuditLogRetentionDays:      90,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil)

	logs := testutil.CaptureSlog(t)

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event
	auditLogger.Log("test_event", map[string]interface{}{
		"key": "value",
	})

	// Verify console output exists
	output := logs.Text()
	assert.Contains(t, output, "test_event")

	// Verify DB was NOT called
	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything)
}

func TestAuditLogger_NilDatabase(t *testing.T) {
	// Create audit logger with nil database (should not panic)
	auditLogger := NewAuditLogger(nil)

	// Log an event (should not panic, just return early)
	assert.NotPanics(t, func() {
		auditLogger.Log("test_event", map[string]interface{}{
			"key": "value",
		})
	})
}

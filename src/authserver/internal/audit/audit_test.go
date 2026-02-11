package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	mocks "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuditLogger(t *testing.T) {
	// Test cases
	testCases := []struct {
		name         string
		event        string
		details      map[string]interface{}
		expectedJSON string
	}{
		{
			name:  "Basic log event",
			event: "user_login",
			details: map[string]interface{}{
				"user_id": "123",
				"ip":      "192.168.1.1",
			},
			expectedJSON: `{"audit_event":"user_login","details":{"ip":"192.168.1.1","user_id":"123"}}`,
		},
		{
			name:         "Log event with empty details",
			event:        "system_startup",
			details:      map[string]interface{}{},
			expectedJSON: `{"audit_event":"system_startup","details":{}}`,
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
			expectedJSON: `{"audit_event":"data_update","details":{"changes":["email","phone"],"user":{"id":"456","name":"John Doe"}}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// Create a buffer to capture log output
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			slog.SetDefault(logger)

			// Create mock DB that returns settings with console enabled, DB disabled
			mockDB := mocks.NewDatabase(t)
			settings := &models.Settings{
				AuditLogsInConsoleEnabled:  true,
				AuditLogsInDatabaseEnabled: false,
			}
			mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil)

			// Create an AuditLogger instance
			auditLogger := NewAuditLogger(mockDB)

			// Call the Log method
			auditLogger.Log(tc.event, tc.details)

			// Get the logged output
			output := buf.String()

			// Parse the JSON log entry
			var logEntry map[string]interface{}
			err := json.Unmarshal([]byte(output), &logEntry)
			if err != nil {
				t.Fatalf("Failed to parse log output as JSON: %v", err)
			}

			// Extract the message field
			msg, ok := logEntry["msg"].(string)
			if !ok {
				t.Fatalf("Log entry does not contain 'msg' field")
			}

			// Compare the logged JSON with the expected JSON
			if !compareJSONStrings(t, tc.expectedJSON, msg) {
				t.Errorf("Logged JSON does not match expected JSON.\nExpected: %v\nGot: %v", tc.expectedJSON, msg)
			}
		})
	}
}

func TestAuditLoggerDisabled(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

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
	output := buf.String()

	// Should be empty since both logging targets are disabled
	if output != "" {
		t.Errorf("Expected no output when both logging targets are disabled, but got: %v", output)
	}

	// Verify no DB write
	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything)
}

// compareJSONStrings compares two JSON strings for equality
func compareJSONStrings(t *testing.T, expected, actual string) bool {
	var expectedMap, actualMap map[string]interface{}
	err := json.Unmarshal([]byte(expected), &expectedMap)
	if err != nil {
		t.Fatalf("Failed to parse expected JSON: %v", err)
	}
	err = json.Unmarshal([]byte(actual), &actualMap)
	if err != nil {
		t.Fatalf("Failed to parse actual JSON: %v", err)
	}

	// Marshal both maps back to JSON strings
	expectedJSON, err := json.Marshal(expectedMap)
	if err != nil {
		t.Fatalf("Failed to marshal expected JSON: %v", err)
	}
	actualJSON, err := json.Marshal(actualMap)
	if err != nil {
		t.Fatalf("Failed to marshal actual JSON: %v", err)
	}

	return string(expectedJSON) == string(actualJSON)
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

	// Capture logs to verify error is logged
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event
	auditLogger.Log("test_event", map[string]interface{}{
		"key": "value",
	})

	// Verify error was logged
	output := buf.String()
	assert.Contains(t, output, "failed to read settings for audit logging")

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

	// Capture logs to verify error is logged
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event (should not panic despite DB error)
	auditLogger.Log("test_event", map[string]interface{}{
		"key": "value",
	})

	// Verify error was logged
	output := buf.String()
	assert.Contains(t, output, "failed to persist audit log to database")

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

	// Capture logs to verify error is logged
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event with un-marshalable details (channel cannot be marshaled to JSON)
	auditLogger.Log("test_event", map[string]interface{}{
		"channel": make(chan int),
	})

	// Verify error was logged
	output := buf.String()
	assert.Contains(t, output, "failed to marshal audit event details for DB")

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

	// Capture console logs
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	// Create audit logger with BOTH console and DB enabled
	auditLogger := NewAuditLogger(mockDB)

	// Log an event
	auditLogger.Log("test_event", map[string]interface{}{
		"key": "value",
	})

	// Verify console output
	output := buf.String()
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

	// Capture console logs
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	// Create audit logger
	auditLogger := NewAuditLogger(mockDB)

	// Log an event
	auditLogger.Log("test_event", map[string]interface{}{
		"key": "value",
	})

	// Verify console output exists
	output := buf.String()
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

package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
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

	config.AuditLogsInConsole = true

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// Create a buffer to capture log output
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			slog.SetDefault(logger)

			// Create an AuditLogger instance
			auditLogger := NewAuditLogger()

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

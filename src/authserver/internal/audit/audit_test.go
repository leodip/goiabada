package audit

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/constants"
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

			NewAuditLogger(mockDB).Log(context.Background(), tc.event, tc.details)

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
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{"key": "value"})

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
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
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
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
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
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
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
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
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
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
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
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
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
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
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
		auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
			"key": "value",
		})
	})
}

// requestContext is a context carrying chi's request id under the key chimiddleware.GetReqID
// reads, which is what a request's context holds once the RequestID middleware at the root of
// both servers has run.
func requestContext(id string) context.Context {
	return context.WithValue(context.Background(), chimiddleware.RequestIDKey, id)
}

// TestAuditLogger_EveryRecordCarriesTheRequestId is the whole of #328 at this seam: all four
// records this function can write carry the request id when the context has one, and none carries
// it when the context has none. Four records rather than one because the three failures are the
// records an operator reads while working out why an event is missing, and a failure nobody can
// tie to a request is the same gap the event itself had.
//
// Nothing below names request_id at a call site. CaptureSlog installs logging.WrapRequestID, the
// same wrapper both servers install, so what these cases exercise is the injection in production
// and not a second copy of it.
func TestAuditLogger_EveryRecordCarriesTheRequestId(t *testing.T) {
	const requestId = "goiabada/req-0000042"

	records := []struct {
		name string
		// setup arranges the one record this row is about, and nothing else: each row disables the
		// target it is not testing so exactly one record is written.
		setup   func(mockDB *mocks.Database)
		details map[string]interface{}
		level   slog.Level
		message string
	}{
		{
			name: "the console record",
			setup: func(mockDB *mocks.Database) {
				mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(&models.Settings{
					AuditLogsInConsoleEnabled: true,
				}, nil)
			},
			details: map[string]interface{}{"email": "jane@example.com"},
			level:   slog.LevelInfo,
			message: "audit event",
		},
		{
			name: "the settings row could not be read",
			setup: func(mockDB *mocks.Database) {
				mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(nil, assert.AnError)
			},
			details: map[string]interface{}{"email": "jane@example.com"},
			level:   slog.LevelError,
			message: "unable to read the settings row for audit logging",
		},
		{
			name: "the details could not be marshalled",
			setup: func(mockDB *mocks.Database) {
				mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(&models.Settings{
					AuditLogsInDatabaseEnabled: true,
				}, nil)
			},
			// A channel is the value json.Marshal refuses, so this row reaches the marshal failure
			// rather than the persist one; CreateAuditLog is left unexpected, so the mock fails the
			// test if the row is written anyway.
			details: map[string]interface{}{"channel": make(chan int)},
			level:   slog.LevelError,
			message: "unable to marshal the audit event details for the database",
		},
		{
			name: "the row could not be persisted",
			setup: func(mockDB *mocks.Database) {
				mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(&models.Settings{
					AuditLogsInDatabaseEnabled: true,
				}, nil)
				mockDB.On("CreateAuditLog", mock.Anything, mock.Anything).Return(assert.AnError)
			},
			details: map[string]interface{}{"email": "jane@example.com"},
			level:   slog.LevelError,
			message: "unable to persist the audit log to the database",
		},
	}

	for _, rec := range records {
		t.Run(rec.name+", under the request's context", func(t *testing.T) {
			logs := testutil.CaptureSlog(t)
			mockDB := mocks.NewDatabase(t)
			rec.setup(mockDB)

			NewAuditLogger(mockDB).Log(requestContext(requestId), "auth_failed_pwd", rec.details)

			written := logs.Records()
			require.Len(t, written, 1, "exactly the record this case is about")
			require.Equal(t, rec.message, written[0].Message)
			assert.Equal(t, rec.level, written[0].Level)
			assert.Equal(t, requestId, written[0].Attrs["request_id"],
				"the record an operator filters by request_id is the one this request raised")
		})

		t.Run(rec.name+", under a context carrying no request", func(t *testing.T) {
			logs := testutil.CaptureSlog(t)
			mockDB := mocks.NewDatabase(t)
			rec.setup(mockDB)

			NewAuditLogger(mockDB).Log(context.Background(), "auth_failed_pwd", rec.details)

			written := logs.Records()
			require.Len(t, written, 1)
			require.Equal(t, rec.message, written[0].Message)
			assert.NotContains(t, written[0].Attrs, "request_id",
				"no request means the attribute is absent rather than empty")
		})
	}
}

// TestAuditLogger_TakesTheSettingsFromTheRequestContext is decision 5, the cheap half of #212
// folded in: on every route the settings middleware runs on, the row Log needs is already on the
// request context, so the per-event fetch is skipped.
//
// The mock is given NO GetSettingsById expectation, which is what makes this case fail for its
// stated reason: mocks.NewDatabase(t) fails the test on an unexpected call, so a Log that read the
// row anyway is reported as the unexpected read rather than passing quietly.
func TestAuditLogger_TakesTheSettingsFromTheRequestContext(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	mockDB := mocks.NewDatabase(t)
	mockDB.On("CreateAuditLog", mock.Anything, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.AuditEvent == "auth_success_pwd"
	})).Return(nil).Once()

	ctx := context.WithValue(requestContext("goiabada/req-0000007"), constants.ContextKeySettings,
		&models.Settings{AuditLogsInConsoleEnabled: true, AuditLogsInDatabaseEnabled: true})

	NewAuditLogger(mockDB).Log(ctx, "auth_success_pwd", map[string]interface{}{"userId": int64(1)})

	written := logs.Records()
	require.Len(t, written, 1, "both targets were enabled by the settings on the context")
	assert.Equal(t, "audit event", written[0].Message)
	assert.Equal(t, "goiabada/req-0000007", written[0].Attrs["request_id"])
	mockDB.AssertExpectations(t)
	mockDB.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything)
}

// The fallback, which is what keeps the five root registrations and the rate limiter's three tiers
// working: those routes never pass through the settings middleware, so nothing is on the context
// and the row is read exactly as before.
//
// Two shapes of absent are covered, and the typed nil is the one worth its own case: the type
// assertion succeeds on a (*models.Settings)(nil), so a guard reading only the assertion's second
// result would go on to dereference it and panic in the audit path of every event.
func TestAuditLogger_ReadsTheSettingsRowWhenTheContextHasNone(t *testing.T) {
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{name: "nothing on the context", ctx: requestContext("goiabada/req-0000008")},
		{
			name: "a typed nil on the context",
			ctx: context.WithValue(requestContext("goiabada/req-0000008"),
				constants.ContextKeySettings, (*models.Settings)(nil)),
		},
		{
			name: "a value of another type on the context",
			ctx: context.WithValue(requestContext("goiabada/req-0000008"),
				constants.ContextKeySettings, "not a settings row"),
		},
	}

	for _, tc := range contexts {
		t.Run(tc.name, func(t *testing.T) {
			logs := testutil.CaptureSlog(t)

			mockDB := mocks.NewDatabase(t)
			mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(&models.Settings{
				AuditLogsInConsoleEnabled: true,
			}, nil).Once()

			assert.NotPanics(t, func() {
				NewAuditLogger(mockDB).Log(tc.ctx, "auth_success_pwd",
					map[string]interface{}{"userId": int64(1)})
			})

			written := logs.Records()
			require.Len(t, written, 1)
			assert.Equal(t, "audit event", written[0].Message)
			assert.Equal(t, "goiabada/req-0000008", written[0].Attrs["request_id"])
			mockDB.AssertExpectations(t)
		})
	}
}

// TestAuditLogger_TheRowCarriesTheRequestIdTheLogCarries is the row half of #328, and decision 7
// stated as an assertion: what CreateAuditLog is handed is not chi's raw id but the string
// core/logging renders onto the record, so the value an administrator reads off the admin page is
// the value they grep the log for.
//
// Every case enables both targets and compares the row's field against the console record's
// request_id attribute rather than against a second expected value, because equality between the
// two is the property, not the rendering itself. The expected renderings below are written out by
// hand rather than taken from logging.FieldForLog, so a change to the clip or the escape fails
// here instead of agreeing with itself.
//
// The id is client-chosen: chi's RequestID middleware adopts an inbound X-Request-Id header
// verbatim, bounded only by the server's 1 MiB header cap, which is why the oversized and the
// non-printable cases are here and not just the well-behaved one.
func TestAuditLogger_TheRowCarriesTheRequestIdTheLogCarries(t *testing.T) {
	ids := []struct {
		name     string
		ctx      context.Context
		expected string
		// alsoOnTheRecord says the console record carries request_id at all, which it does not
		// when there is no request: the injection skips an empty id rather than writing "".
		alsoOnTheRecord bool
	}{
		{
			name:            "an id of chi's own shape",
			ctx:             requestContext("goiabada/req-0000042"),
			expected:        "goiabada/req-0000042",
			alsoOnTheRecord: true,
		},
		{
			name:            "a proxy's correlation uuid, adopted from the header",
			ctx:             requestContext("6d8f4a2e-0c3b-4a1e-9f77-2b5d1c8e4a90"),
			expected:        "6d8f4a2e-0c3b-4a1e-9f77-2b5d1c8e4a90",
			alsoOnTheRecord: true,
		},
		{
			name:     "no request at all, which is what the startup backfill's row carries",
			ctx:      context.Background(),
			expected: "",
		},
		{
			name:     "a request id the middleware never reached",
			ctx:      requestContext(""),
			expected: "",
		},
		{
			// 300 bytes is past MaxLoggedField, so the stored value is the 128-byte prefix and
			// the counted marker naming the true length. The marker is the reason the clip is
			// FieldForLog's and not a plain truncation: two different 300-byte ids sharing a
			// prefix stay different strings on the page and in the log.
			name:            "an id past the log's clip",
			ctx:             requestContext(strings.Repeat("x", 300)),
			expected:        strings.Repeat("x", 128) + "[truncated, 128 of 300 bytes]",
			alsoOnTheRecord: true,
		},
		{
			// Nothing in net/http refuses a tab, a newline or a lone continuation byte in a
			// header value, so an unauthenticated client can put one here. Escaped before it
			// reaches the column, as it is before it reaches the record.
			name:            "an id carrying bytes a header may hold and a column should not",
			ctx:             requestContext("req\t42\nmore\x80"),
			expected:        "req%0942%0Amore%80",
			alsoOnTheRecord: true,
		},
	}

	for _, tc := range ids {
		t.Run(tc.name, func(t *testing.T) {
			logs := testutil.CaptureSlog(t)

			var row *models.AuditLog
			mockDB := mocks.NewDatabase(t)
			mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(&models.Settings{
				AuditLogsInConsoleEnabled:  true,
				AuditLogsInDatabaseEnabled: true,
			}, nil)
			mockDB.On("CreateAuditLog", mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { row = args.Get(1).(*models.AuditLog) }).
				Return(nil).Once()

			NewAuditLogger(mockDB).Log(tc.ctx, "auth_failed_pwd",
				map[string]interface{}{"email": "jane@example.com"})

			mockDB.AssertExpectations(t)
			require.NotNil(t, row, "the row handed to CreateAuditLog")
			assert.Equal(t, tc.expected, row.RequestId,
				"the persisted request id is the log's own rendering of it, not chi's raw string")

			written := logs.Records()
			require.Len(t, written, 1, "the console record")
			if !tc.alsoOnTheRecord {
				assert.NotContains(t, written[0].Attrs, "request_id",
					"no id means no attribute, and the row's empty string says the same thing")
				return
			}
			assert.Equal(t, row.RequestId, written[0].Attrs["request_id"],
				"the whole point of the column: the page and the log show one string, not two")
		})
	}
}

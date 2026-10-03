package audit

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fakeSwitches is the switches port as a value: it answers the switches it holds, or err, and
// records every context it was asked with. Where the answer comes from -- the request's settings
// or the row -- is the production adapter's business and is tested beside it, in
// middleware/middleware_settings_test.go (#433).
type fakeSwitches struct {
	switches Switches
	err      error
	asked    []context.Context
	// liveWhenAsked is each asked context's Err() == nil at the moment of the call. Read later it
	// would say nothing: Log cancels its detached context on return.
	liveWhenAsked []bool
}

func (f *fakeSwitches) AuditSwitches(ctx context.Context) (Switches, error) {
	f.asked = append(f.asked, ctx)
	f.liveWhenAsked = append(f.liveWhenAsked, ctx.Err() == nil)
	return f.switches, f.err
}

func consoleOnly() *fakeSwitches  { return &fakeSwitches{switches: Switches{Console: true}} }
func databaseOnly() *fakeSwitches { return &fakeSwitches{switches: Switches{Database: true}} }
func bothTargets() *fakeSwitches {
	return &fakeSwitches{switches: Switches{Console: true, Database: true}}
}
func noTarget() *fakeSwitches { return &fakeSwitches{} }

// TestLogger_ConsoleRecordCarriesTheEventAndTheDetails is the console half of Logger,
// at the seam LogToConsole owns.
//
// These three cases used to marshal an envelope into the message field and compare the message
// against an expected JSON document. That is the shape #320 decision 7 replaced: a collector
// consuming this log as JSON had to parse `msg` a second time to reach the field it was querying
// on. So they now read the event name and the details off the record, which is where a consumer
// reads them.
func TestLogger_ConsoleRecordCarriesTheEventAndTheDetails(t *testing.T) {
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
			logs := logtest.CaptureSlog(t)

			// Console enabled, database disabled, so the strict mock refuses any write.
			mockDB := mocks.NewDatabase(t)

			NewLogger(mockDB, consoleOnly()).Log(context.Background(), tc.event, tc.details)

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

func TestLoggerDisabled(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	mockDB := mocks.NewDatabase(t)

	auditLogger := NewLogger(mockDB, noTarget())

	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{"key": "value"})

	// Should be empty since both logging targets are disabled
	output := logs.Text()
	if output != "" {
		t.Errorf("Expected no output when both logging targets are disabled, but got: %v", output)
	}

	// Verify no DB write
	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything, mock.Anything)
}

func TestLogger_DBPersistence_Enabled(t *testing.T) {
	mockDB := mocks.NewDatabase(t)

	// Expect CreateAuditLog to be called
	mockDB.On("CreateAuditLog", mock.Anything, mock.Anything, mock.MatchedBy(func(log *models.AuditLog) bool {
		return log.AuditEvent == "test_event" &&
			log.Details != "" &&
			log.CreatedAt.IsZero() // CreatedAt should be zero before DB call
	})).Return(nil).Once()

	auditLogger := NewLogger(mockDB, databaseOnly())

	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
		"user_id": "123",
		"action":  "login",
	})

	mockDB.AssertExpectations(t)
}

func TestLogger_DBPersistence_Disabled(t *testing.T) {
	mockDB := mocks.NewDatabase(t)

	// CreateAuditLog should NOT be called
	// (no mock.On call means assertion will fail if it's called)

	auditLogger := NewLogger(mockDB, noTarget())

	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
		"key": "value",
	})

	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything, mock.Anything)
}

// TestLogger_SwitchesError is the port failing: the event is logged as lost and written
// nowhere, and the request it came from is not failed.
func TestLogger_SwitchesError(t *testing.T) {
	mockDB := mocks.NewDatabase(t)

	logs := logtest.CaptureSlog(t)

	auditLogger := NewLogger(mockDB, &fakeSwitches{
		// The switches an erroring port happens to return must not be acted on.
		switches: Switches{Console: true, Database: true},
		err:      assert.AnError,
	})

	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
		"key": "value",
	})

	records := logs.Records()
	require.Len(t, records, 1, "the failure, and no console record of the event")
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, "unable to read the audit switches", records[0].Message)
	assert.Equal(t, "test_event", records[0].Attrs["event"])

	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything, mock.Anything)
}

func TestLogger_DBPersistence_CreateError(t *testing.T) {
	mockDB := mocks.NewDatabase(t)

	// Mock CreateAuditLog to return error
	mockDB.On("CreateAuditLog", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError)

	logs := logtest.CaptureSlog(t)

	auditLogger := NewLogger(mockDB, databaseOnly())

	// Log an event (should not panic despite DB error)
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
		"key": "value",
	})

	output := logs.Text()
	assert.Contains(t, output, "unable to persist the audit log to the database")

	// Verify CreateAuditLog was called (even though it failed)
	mockDB.AssertExpectations(t)
}

func TestLogger_DBPersistence_JSONMarshalError(t *testing.T) {
	mockDB := mocks.NewDatabase(t)

	// CreateAuditLog should NOT be called due to marshal error

	logs := logtest.CaptureSlog(t)

	auditLogger := NewLogger(mockDB, databaseOnly())

	// Log an event with un-marshalable details (channel cannot be marshaled to JSON)
	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
		"channel": make(chan int),
	})

	output := logs.Text()
	assert.Contains(t, output, "unable to marshal the audit event details for the database")

	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything, mock.Anything)
}

func TestLogger_BothConsoleAndDB(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	mockDB.On("CreateAuditLog", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	logs := logtest.CaptureSlog(t)

	auditLogger := NewLogger(mockDB, bothTargets())

	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
		"key": "value",
	})

	output := logs.Text()
	assert.Contains(t, output, "test_event")

	mockDB.AssertExpectations(t)
}

func TestLogger_ConsoleEnabledDBDisabled(t *testing.T) {
	mockDB := mocks.NewDatabase(t)

	logs := logtest.CaptureSlog(t)

	auditLogger := NewLogger(mockDB, consoleOnly())

	auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
		"key": "value",
	})

	output := logs.Text()
	assert.Contains(t, output, "test_event")

	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything, mock.Anything)
}

// TestLogger_NilDependencies: a logger built without a database or without a switches port
// records nothing and does not panic.
func TestLogger_NilDependencies(t *testing.T) {
	t.Run("no database", func(t *testing.T) {
		switches := bothTargets()
		auditLogger := NewLogger(nil, switches)

		assert.NotPanics(t, func() {
			auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
				"key": "value",
			})
		})
		assert.Empty(t, switches.asked, "nothing to write to, so nothing to ask")
	})

	t.Run("no switches", func(t *testing.T) {
		mockDB := mocks.NewDatabase(t)
		auditLogger := NewLogger(mockDB, nil)

		assert.NotPanics(t, func() {
			auditLogger.Log(context.Background(), "test_event", map[string]interface{}{
				"key": "value",
			})
		})
		mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything, mock.Anything)
	})
}

// TestLogger_AsksTheSwitchesOncePerEventWithTheCallersValues: Log reads the switches through
// its port and nowhere else, once for each event, on a context still carrying the caller's
// values -- which is what lets the adapter find the request's settings rather than read the row.
func TestLogger_AsksTheSwitchesOncePerEventWithTheCallersValues(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	switches := noTarget()
	auditLogger := NewLogger(mockDB, switches)

	ctx := requestContext("goiabada/req-0000007")
	auditLogger.Log(ctx, "auth_success_pwd", map[string]interface{}{"userId": int64(1)})
	auditLogger.Log(ctx, "auth_failed_pwd", map[string]interface{}{"userId": int64(1)})

	require.Len(t, switches.asked, 2)
	for _, asked := range switches.asked {
		assert.Equal(t, "goiabada/req-0000007", chimiddleware.GetReqID(asked))
	}
}

// requestContext is a context carrying chi's request id under the key chimiddleware.GetReqID
// reads, which is what a request's context holds once the RequestID middleware at the root of
// both servers has run.
func requestContext(id string) context.Context {
	return context.WithValue(context.Background(), chimiddleware.RequestIDKey, id)
}

// TestLogger_EveryRecordCarriesTheRequestId is the whole of #328 at this seam: all four
// records this function can write carry the request id when the context has one, and none carries
// it when the context has none. Four records rather than one because the three failures are the
// records an operator reads while working out why an event is missing, and a failure nobody can
// tie to a request is the same gap the event itself had.
//
// Nothing below names request_id at a call site. CaptureSlog installs logging.WrapRequestID, the
// same wrapper both servers install, so what these cases exercise is the injection in production
// and not a second copy of it.
func TestLogger_EveryRecordCarriesTheRequestId(t *testing.T) {
	const requestId = "goiabada/req-0000042"

	records := []struct {
		name string
		// switches and setup arrange the one record this row is about, and nothing else: each row
		// disables the target it is not testing so exactly one record is written.
		switches func() *fakeSwitches
		setup    func(mockDB *mocks.Database)
		details  map[string]interface{}
		level    slog.Level
		message  string
	}{
		{
			name:     "the console record",
			switches: consoleOnly,
			setup:    func(mockDB *mocks.Database) {},
			details:  map[string]interface{}{"email": "jane@example.com"},
			level:    slog.LevelInfo,
			message:  "audit event",
		},
		{
			name:     "the switches could not be read",
			switches: func() *fakeSwitches { return &fakeSwitches{err: assert.AnError} },
			setup:    func(mockDB *mocks.Database) {},
			details:  map[string]interface{}{"email": "jane@example.com"},
			level:    slog.LevelError,
			message:  "unable to read the audit switches",
		},
		{
			name:     "the details could not be marshalled",
			switches: databaseOnly,
			setup:    func(mockDB *mocks.Database) {},
			// A channel is the value json.Marshal refuses, so this row reaches the marshal failure
			// rather than the persist one; CreateAuditLog is left unexpected, so the mock fails the
			// test if the row is written anyway.
			details: map[string]interface{}{"channel": make(chan int)},
			level:   slog.LevelError,
			message: "unable to marshal the audit event details for the database",
		},
		{
			name:     "the row could not be persisted",
			switches: databaseOnly,
			setup: func(mockDB *mocks.Database) {
				mockDB.On("CreateAuditLog", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError)
			},
			details: map[string]interface{}{"email": "jane@example.com"},
			level:   slog.LevelError,
			message: "unable to persist the audit log to the database",
		},
	}

	for _, rec := range records {
		t.Run(rec.name+", under the request's context", func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			mockDB := mocks.NewDatabase(t)
			rec.setup(mockDB)

			NewLogger(mockDB, rec.switches()).Log(requestContext(requestId), "auth_failed_pwd", rec.details)

			written := logs.Records()
			require.Len(t, written, 1, "exactly the record this case is about")
			require.Equal(t, rec.message, written[0].Message)
			assert.Equal(t, rec.level, written[0].Level)
			assert.Equal(t, requestId, written[0].Attrs["request_id"],
				"the record an operator filters by request_id is the one this request raised")
		})

		t.Run(rec.name+", under a context carrying no request", func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			mockDB := mocks.NewDatabase(t)
			rec.setup(mockDB)

			NewLogger(mockDB, rec.switches()).Log(context.Background(), "auth_failed_pwd", rec.details)

			written := logs.Records()
			require.Len(t, written, 1)
			require.Equal(t, rec.message, written[0].Message)
			assert.NotContains(t, written[0].Attrs, "request_id",
				"no request means the attribute is absent rather than empty")
		})
	}
}

// TestLogger_TheRowCarriesTheRequestIdTheLogCarries is the row half of #328, and decision 7
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
func TestLogger_TheRowCarriesTheRequestIdTheLogCarries(t *testing.T) {
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
			logs := logtest.CaptureSlog(t)

			var row *models.AuditLog
			mockDB := mocks.NewDatabase(t)
			mockDB.On("CreateAuditLog", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { row = args.Get(2).(*models.AuditLog) }).
				Return(nil).Once()

			NewLogger(mockDB, bothTargets()).Log(tc.ctx, "auth_failed_pwd",
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

package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditLogsPage is the endpoint's port, implemented directly: it records the filter each read was
// given and answers the rows it holds.
type auditLogsPage struct {
	rows    []record.AuditLog
	total   int
	err     error
	filters []record.AuditLogFilter
}

func (p *auditLogsPage) GetAuditLogsPaginated(_ context.Context, _ *sql.Tx, _ int, _ int,
	filter record.AuditLogFilter) ([]record.AuditLog, int, error) {
	p.filters = append(p.filters, filter)
	return p.rows, p.total, p.err
}

func getAuditLogsPage(t *testing.T, database *auditLogsPage, query string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	HandleAuditLogsGet(database).ServeHTTP(rr,
		httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs?"+query, nil))
	return rr
}

// The userId filter reaches the read as the user id, beside whichever other filters the caller set:
// the database combines them with AND (#780 decision 3).
func TestHandleAuditLogsGet_TheUserFilterReachesTheReadWithTheOthers(t *testing.T) {
	testCases := []struct {
		name  string
		query string
		want  record.AuditLogFilter
	}{
		{"the user alone", "userId=42", record.AuditLogFilter{UserId: 42}},
		{"the user and the event", "userId=42&auditEvent=user_login",
			record.AuditLogFilter{AuditEvent: "user_login", UserId: 42}},
		{"the user and the request id", "userId=7&requestId=host/abc-000001",
			record.AuditLogFilter{RequestId: "host/abc-000001", UserId: 7}},
		{"all three", "userId=7&auditEvent=user_login&requestId=host/abc-000001",
			record.AuditLogFilter{AuditEvent: "user_login", RequestId: "host/abc-000001", UserId: 7}},
		{"the largest id", "userId=9223372036854775807",
			record.AuditLogFilter{UserId: 9223372036854775807}},
		{"no user", "auditEvent=user_login", record.AuditLogFilter{AuditEvent: "user_login"}},
		{"an empty user sets no filter", "userId=", record.AuditLogFilter{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := &auditLogsPage{rows: []record.AuditLog{}}

			rr := getAuditLogsPage(t, database, tc.query)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, []record.AuditLogFilter{tc.want}, database.filters)
		})
	}
}

// A userId that is not a positive integer is refused rather than ignored: ignoring it would list
// every user's events under a filter the caller believes is set (#780 decision 3).
func TestHandleAuditLogsGet_AUserIdThatIsNotAPositiveIntegerIsRefused(t *testing.T) {
	for _, value := range []string{
		"abc",
		"0",
		"-3",
		"1.5",
		"5x",
		"%205",                // a leading space
		"9223372036854775808", // one past the largest id
	} {
		t.Run(value, func(t *testing.T) {
			database := &auditLogsPage{rows: []record.AuditLog{}}

			rr := getAuditLogsPage(t, database, "userId="+value)

			require.Equal(t, http.StatusBadRequest, rr.Code)
			assert.JSONEq(t, `{"error_code":"VALIDATION_ERROR","error_description":"Invalid userId value"}`,
				rr.Body.String())
			assert.Empty(t, database.filters, "a refused filter reads nothing")
		})
	}
}

// Every entry answers the user it is about and the user who acted, each null when the row names
// none, and never left out (#780 decision 6).
func TestHandleAuditLogsGet_EveryEntryAnswersItsUserColumns(t *testing.T) {
	created := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	database := &auditLogsPage{
		total: 4,
		rows: []record.AuditLog{
			{Id: 4, CreatedAt: created, AuditEvent: "updated_user_details", Details: "{}",
				UserId:         sql.NullInt64{Int64: 42, Valid: true},
				LoggedInUserId: sql.NullInt64{Int64: 7, Valid: true}},
			{Id: 3, CreatedAt: created, AuditEvent: "user_login", Details: "{}",
				UserId: sql.NullInt64{Int64: 42, Valid: true}},
			{Id: 2, CreatedAt: created, AuditEvent: "updated_settings", Details: "{}",
				LoggedInUserId: sql.NullInt64{Int64: 7, Valid: true}},
			{Id: 1, CreatedAt: created, AuditEvent: "updated_settings", Details: "{}"},
		},
	}

	rr := getAuditLogsPage(t, database, "")

	require.Equal(t, http.StatusOK, rr.Code)
	var body struct {
		AuditLogs []map[string]any `json:"auditLogs"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Len(t, body.AuditLogs, 4)

	wantUserIds := []any{float64(42), float64(42), nil, nil}
	wantLoggedInUserIds := []any{float64(7), nil, float64(7), nil}
	for i, entry := range body.AuditLogs {
		assert.Contains(t, entry, "userId", "entry %d carries userId, null or not", i)
		assert.Contains(t, entry, "loggedInUserId", "entry %d carries loggedInUserId, null or not", i)
		assert.Equal(t, wantUserIds[i], entry["userId"], "entry %d's userId", i)
		assert.Equal(t, wantLoggedInUserIds[i], entry["loggedInUserId"], "entry %d's loggedInUserId", i)
	}
}

// When the read fails, the record names the user filter the caller asked for.
func TestHandleAuditLogsGet_ErrorRecordNamesTheUserFilter(t *testing.T) {
	database := &auditLogsPage{err: errs.New("engine is down")}
	capture := logtest.CaptureSlog(t)

	rr := getAuditLogsPage(t, database, "userId=42")

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	attrs := oneErrorRecord(t, capture)
	assert.EqualValues(t, 42, attrs["filter_user_id"])
}

package datatests

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuditLog(t *testing.T) {
	t.Run("Success - Create audit log", func(t *testing.T) {
		auditLog := &record.AuditLog{
			AuditEvent: "test_event",
			Details:    `{"user_id": "123", "action": "login"}`,
		}

		before := time.Now().UTC()
		err := database.CreateAuditLog(context.Background(), nil, auditLog)
		after := time.Now().UTC()
		require.NoError(t, err)

		// Verify ID was assigned
		assert.Positive(t, auditLog.Id)

		// Verify CreatedAt was set, from a reading taken during the call
		assert.WithinRange(t, auditLog.CreatedAt, before, after)
	})

	t.Run("Success - CreatedAt overridden", func(t *testing.T) {
		// Even if we set CreatedAt, it should be overridden
		pastTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		auditLog := &record.AuditLog{
			AuditEvent: "test_event",
			Details:    `{"key": "value"}`,
			CreatedAt:  pastTime,
		}

		before := time.Now().UTC()
		err := database.CreateAuditLog(context.Background(), nil, auditLog)
		after := time.Now().UTC()
		require.NoError(t, err)

		// Verify CreatedAt was overridden to current time (not pastTime)
		assert.WithinRange(t, auditLog.CreatedAt, before, after)
	})

	t.Run("Error - Empty audit event", func(t *testing.T) {
		auditLog := &record.AuditLog{
			AuditEvent: "",
			Details:    `{"key": "value"}`,
		}

		err := database.CreateAuditLog(context.Background(), nil, auditLog)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty audit_event")
	})

	t.Run("Success - Empty details defaults to empty JSON", func(t *testing.T) {
		auditLog := &record.AuditLog{
			AuditEvent: "test_event",
			Details:    "",
		}

		err := database.CreateAuditLog(context.Background(), nil, auditLog)
		require.NoError(t, err)
		assert.Positive(t, auditLog.Id)
	})

	// #328: the request id written is the request id read back, on every engine, and a row
	// written off a request reads '' rather than NULL. The values are the shapes the column
	// actually receives: chi's own, a proxy's uuid adopted from the header, and the clipped
	// rendering of an oversized one, which is the longest string that can reach the column.
	t.Run("Success - the request id round-trips", func(t *testing.T) {
		requestIds := []struct {
			name string
			id   string
		}{
			{name: "chi's own shape", id: "goiabada/req-0000042"},
			{name: "a proxy's correlation uuid", id: "6d8f4a2e-0c3b-4a1e-9f77-2b5d1c8e4a90"},
			{name: "no request", id: ""},
			{
				name: "the log's clipped rendering of an oversized id, 157 bytes",
				id:   strings.Repeat("x", 128) + "[truncated, 128 of 300 bytes]",
			},
		}

		for _, tc := range requestIds {
			t.Run(tc.name, func(t *testing.T) {
				event := "request_id_roundtrip_" + fake.LetterN(12)
				require.NoError(t, database.CreateAuditLog(context.Background(), nil, &record.AuditLog{
					AuditEvent: event,
					Details:    `{"test": "data"}`,
					RequestId:  tc.id,
				}))

				logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, record.AuditLogFilter{AuditEvent: event})
				require.NoError(t, err)
				require.Equal(t, 1, total)
				require.Len(t, logs, 1)
				assert.Equalf(t, tc.id, logs[0].RequestId,
					"the id the viewer shows must be the id the writer stored, byte for byte, on %s", dbType())
			})
		}
	})
}

func TestDeleteOldAuditLogs_NoMatchingLogs(t *testing.T) {
	// Create recent audit logs
	for i := 0; i < 5; i++ {
		auditLog := &record.AuditLog{
			AuditEvent: "recent_log",
			Details:    `{"test": "data"}`,
		}
		err := database.CreateAuditLog(context.Background(), nil, auditLog)
		require.NoError(t, err)
	}

	t.Run("No logs deleted when all are recent", func(t *testing.T) {
		// Cutoff is 90 days ago, all logs are recent
		cutoff := time.Now().UTC().Add(-90 * 24 * time.Hour)

		deleted, err := database.DeleteOldAuditLogs(context.Background(), nil, cutoff, 1000)
		require.NoError(t, err)

		// Should delete 0 logs (all are recent)
		assert.Equal(t, 0, deleted)
	})
}

func TestGetAuditLogsPaginated(t *testing.T) {
	// Create test audit logs
	events := []string{
		"user_login",
		"user_logout",
		"user_login",
		"admin_action",
		"user_login",
		"data_update",
	}

	for _, event := range events {
		auditLog := &record.AuditLog{
			AuditEvent: event,
			Details:    `{"test": "data"}`,
		}
		err := database.CreateAuditLog(context.Background(), nil, auditLog)
		require.NoError(t, err)
		time.Sleep(timestampTick)
	}

	t.Run("Get all logs - first page", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 3, record.AuditLogFilter{})
		require.NoError(t, err)

		assert.GreaterOrEqual(t, total, 6) // At least 6 from this test
		assert.Len(t, logs, 3)

		// Verify ordering (newest first)
		assert.Equal(t, "data_update", logs[0].AuditEvent)
	})

	t.Run("Get all logs - second page", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 2, 3, record.AuditLogFilter{})
		require.NoError(t, err)

		assert.GreaterOrEqual(t, total, 6)
		assert.LessOrEqual(t, len(logs), 3) // May be less if we're at the end
	})

	t.Run("Filter by audit event", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, record.AuditLogFilter{AuditEvent: "user_login"})
		require.NoError(t, err)

		assert.GreaterOrEqual(t, total, 3) // At least 3 user_login events from this test
		assert.GreaterOrEqual(t, len(logs), 3)

		// Verify all returned logs match filter
		for _, log := range logs {
			assert.Equal(t, "user_login", log.AuditEvent)
		}
	})

	t.Run("Filter with no matches", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, record.AuditLogFilter{AuditEvent: "nonexistent_event_12345"})
		require.NoError(t, err)

		assert.Equal(t, 0, total)
		assert.Empty(t, logs)
	})

	t.Run("Invalid page defaults to 1", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 0, 10, record.AuditLogFilter{})
		require.NoError(t, err)

		assert.Positive(t, total)
		assert.NotEmpty(t, logs)
	})

	t.Run("Invalid page size defaults to 20", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 0, record.AuditLogFilter{})
		require.NoError(t, err)

		assert.Positive(t, total)
		assert.NotEmpty(t, logs)
	})
}

func TestGetAuditLogsPaginated_Sorting(t *testing.T) {
	// Create logs with known order
	testEvents := []string{"event_1", "event_2", "event_3", "event_4", "event_5"}

	for _, event := range testEvents {
		auditLog := &record.AuditLog{
			AuditEvent: event,
			Details:    `{"test": "data"}`,
		}
		err := database.CreateAuditLog(context.Background(), nil, auditLog)
		require.NoError(t, err)
		time.Sleep(timestampTick)
	}

	t.Run("Logs sorted by created_at DESC", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, record.AuditLogFilter{})
		require.NoError(t, err)

		assert.Positive(t, total)
		assert.NotEmpty(t, logs)

		// Verify newest first (event_5 was created last)
		// Find event_5 in the results
		foundEvent5 := false
		for _, log := range logs {
			if log.AuditEvent == "event_5" {
				foundEvent5 = true
				break
			}
		}
		assert.True(t, foundEvent5, "Expected to find event_5 in first page of results")
	})
}

// #328: the request id filter. It is an exact match over a value the client chose, so what it
// must never do is list one request's audit entries under another request's id.
func TestGetAuditLogsPaginated_RequestIdFilter(t *testing.T) {
	requestId := "itest-" + fake.LetterN(16)
	otherRequestId := "itest-" + fake.LetterN(16)
	event := "request_id_filter_" + fake.LetterN(10)
	otherEvent := "request_id_filter_" + fake.LetterN(10)

	// Three rows, so that each filter has both a match and a non-match to separate:
	// two share the request id under different events, and one shares an event under a
	// different request id.
	rows := []struct {
		event     string
		requestId string
	}{
		{event, requestId},
		{otherEvent, requestId},
		{event, otherRequestId},
	}
	for _, row := range rows {
		require.NoError(t, database.CreateAuditLog(context.Background(), nil, &record.AuditLog{
			AuditEvent: row.event,
			Details:    `{"test": "data"}`,
			RequestId:  row.requestId,
		}))
		time.Sleep(timestampTick)
	}

	t.Run("the filter alone returns every entry that request raised", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, record.AuditLogFilter{RequestId: requestId})
		require.NoError(t, err)

		assert.Equal(t, 2, total)
		require.Len(t, logs, 2)
		for _, log := range logs {
			assert.Equal(t, requestId, log.RequestId)
		}
	})

	t.Run("combined with the audit event both narrow", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, record.AuditLogFilter{AuditEvent: event, RequestId: requestId})
		require.NoError(t, err)

		assert.Equal(t, 1, total)
		require.Len(t, logs, 1)
		assert.Equal(t, event, logs[0].AuditEvent)
		assert.Equal(t, requestId, logs[0].RequestId)
	})

	t.Run("an id nothing carries yields nothing", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, record.AuditLogFilter{RequestId: "itest-" + fake.LetterN(16)})
		require.NoError(t, err)

		assert.Equal(t, 0, total)
		assert.Empty(t, logs)
	})

	t.Run("an empty id is no filter at all", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, record.AuditLogFilter{AuditEvent: event})
		require.NoError(t, err)

		assert.Equal(t, 2, total, "both entries under this event, whatever request raised them")
		require.Len(t, logs, 2)
	})
}

// The engine decides which rows come back for `=`, and two of the four engines make that
// decision differently from Go: SQL Server pads for `=`, so 'corr' = 'corr ' is true under
// every collation it has. Two rows whose ids differ only by a trailing space are therefore
// two requests to this package and one request to that engine, and an operator filtering on
// one must not be shown the other's entries, nor be told there are more of them than the page
// lists. Page size 1 is what separates a page that was guarded from a total that was not: an
// unguarded count answers 2 where the page holds 1 (#328).
func TestGetAuditLogsPaginated_RequestIdFilterIsByteExact(t *testing.T) {
	event := "request_id_guard_" + fake.LetterN(10)
	unpadded := "corr-" + fake.LetterN(12)
	padded := unpadded + " "

	// Both rows are about one user, so the statements that also filter by user are held to the
	// same byte-exact match (#780).
	user := int64(fake.Number(1_000_000_000, 2_000_000_000))
	for _, id := range []string{unpadded, padded} {
		require.NoError(t, database.CreateAuditLog(context.Background(), nil, &record.AuditLog{
			AuditEvent: event,
			Details:    `{"test": "data"}`,
			RequestId:  id,
			UserId:     sql.NullInt64{Int64: user, Valid: true},
		}))
		time.Sleep(timestampTick)
	}

	// With the event and the user and without them, since each combination is its own statement.
	// The ids are unique to this test, so the request id alone lists the same rows.
	for _, tc := range []struct {
		name       string
		auditEvent string
		userId     int64
		filter     string
	}{
		{name: "the id without the trailing space", auditEvent: event, filter: unpadded},
		{name: "the id with the trailing space", auditEvent: event, filter: padded},
		{name: "the id without the trailing space, alone", filter: unpadded},
		{name: "the id with the trailing space, alone", filter: padded},
		{name: "the id without the trailing space, with the user", userId: user, filter: unpadded},
		{name: "the id with the trailing space, with the user", userId: user, filter: padded},
		{name: "the id without the trailing space, with the event and the user", auditEvent: event, userId: user, filter: unpadded},
		{name: "the id with the trailing space, with the event and the user", auditEvent: event, userId: user, filter: padded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 1,
				record.AuditLogFilter{AuditEvent: tc.auditEvent, RequestId: tc.filter, UserId: tc.userId})
			require.NoError(t, err)

			require.Len(t, logs, 1)
			assert.Equalf(t, tc.filter, logs[0].RequestId,
				"the page listed an entry carrying an id the filter did not ask for, on %s", dbType())
			assert.Equalf(t, len(logs), total,
				"the total counted an entry the page did not list, on %s", dbType())
		})
	}
}

// userColumn is a user column holding id, or NULL for 0.
func userColumn(id int64) sql.NullInt64 {
	return sql.NullInt64{Int64: id, Valid: id != 0}
}

// #780: the user an audit row is about and the user who acted are written and read back as they
// were given, on every engine, and a row naming neither reads NULL for both, as every row written
// before the columns existed does. 2^53+1 is above what a float64 holds exactly, so an id passed
// through one on its way to or from the engine would come back changed.
func TestCreateAuditLog_TheUserColumnsRoundTrip(t *testing.T) {
	const beyondAFloat = int64(9007199254740993)
	for _, tc := range []struct {
		name           string
		userId         int64
		loggedInUserId int64
	}{
		{name: "about one user and made by another", userId: 41, loggedInUserId: 7},
		{name: "about a user, made on no user's token", userId: 41},
		{name: "made by a user, about no one", loggedInUserId: 7},
		{name: "naming neither"},
		{name: "an id beyond a float's exact range", userId: beyondAFloat, loggedInUserId: beyondAFloat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := "user_columns_roundtrip_" + fake.LetterN(12)
			written := &record.AuditLog{
				AuditEvent:     event,
				Details:        `{"test": "data"}`,
				UserId:         userColumn(tc.userId),
				LoggedInUserId: userColumn(tc.loggedInUserId),
			}
			require.NoError(t, database.CreateAuditLog(context.Background(), nil, written))

			logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, record.AuditLogFilter{AuditEvent: event})
			require.NoError(t, err)
			require.Equal(t, 1, total)
			require.Len(t, logs, 1)
			assert.Equal(t, written.Id, logs[0].Id)
			assert.Equalf(t, userColumn(tc.userId), logs[0].UserId, "user_id read back on %s", dbType())
			assert.Equalf(t, userColumn(tc.loggedInUserId), logs[0].LoggedInUserId, "logged_in_user_id read back on %s", dbType())
		})
	}
}

// #780 decisions 3 and 7: the user filter lists the rows about the user or made by them, each once,
// newest first, and narrows every other filter it is combined with. Each combination of the three
// filters is its own statement, so each is read here, and each expected page is written out by
// hand from the rows below.
func TestGetAuditLogsPaginated_UserFilter(t *testing.T) {
	// The user ids are unique to this test run, so the user filter alone lists only these rows;
	// no foreign key holds them to a users row, as none holds an audit row's.
	user := int64(fake.Number(1_000_000_000, 2_000_000_000))
	other, third, nobody := user+1, user+2, user+3
	event := "user_filter_" + fake.LetterN(10)
	otherEvent := "user_filter_" + fake.LetterN(10)
	request := "itest-" + fake.LetterN(16)
	otherRequest := "itest-" + fake.LetterN(16)

	// Written oldest first; each page below lists them newest first.
	rows := []struct {
		name           string
		event, request string
		userId         int64
		loggedInUserId int64
	}{
		{"about", event, request, user, 0},
		{"by", otherEvent, request, other, user},
		{"about and by", event, otherRequest, user, user},
		{"neither", event, request, other, third},
		{"no user columns", event, request, 0, 0},
		{"by, about no one", otherEvent, otherRequest, 0, user},
	}
	ids := map[string]int64{}
	for _, row := range rows {
		auditLog := &record.AuditLog{
			AuditEvent:     row.event,
			Details:        `{"test": "data"}`,
			RequestId:      row.request,
			UserId:         userColumn(row.userId),
			LoggedInUserId: userColumn(row.loggedInUserId),
		}
		require.NoError(t, database.CreateAuditLog(context.Background(), nil, auditLog))
		ids[row.name] = auditLog.Id
		time.Sleep(timestampTick)
	}

	for _, tc := range []struct {
		name   string
		filter record.AuditLogFilter
		want   []string
	}{
		{"the user alone lists the rows about them and the rows they made",
			record.AuditLogFilter{UserId: user}, []string{"by, about no one", "about and by", "by", "about"}},
		{"a user named only as the one a row is about",
			record.AuditLogFilter{UserId: other}, []string{"neither", "by"}},
		{"a user named only as the one who acted",
			record.AuditLogFilter{UserId: third}, []string{"neither"}},
		{"an id no row names lists nothing",
			record.AuditLogFilter{UserId: nobody}, nil},
		{"the user and the event",
			record.AuditLogFilter{UserId: user, AuditEvent: event}, []string{"about and by", "about"}},
		{"the user and the request id",
			record.AuditLogFilter{UserId: user, RequestId: request}, []string{"by", "about"}},
		{"the user, the event and the request id",
			record.AuditLogFilter{UserId: user, AuditEvent: event, RequestId: request}, []string{"about"}},
		{"the user, the event and the request id, matching nothing together",
			record.AuditLogFilter{UserId: third, AuditEvent: otherEvent, RequestId: request}, nil},
		{"the event alone lists rows with and without user columns",
			record.AuditLogFilter{AuditEvent: event}, []string{"no user columns", "neither", "about and by", "about"}},
		{"the request id alone",
			record.AuditLogFilter{RequestId: request}, []string{"no user columns", "neither", "by", "about"}},
		{"the event and the request id",
			record.AuditLogFilter{AuditEvent: event, RequestId: request}, []string{"no user columns", "neither", "about"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10, tc.filter)
			require.NoError(t, err)

			want := []int64{}
			for _, name := range tc.want {
				want = append(want, ids[name])
			}
			got := []int64{}
			for _, log := range logs {
				got = append(got, log.Id)
			}
			assert.Equalf(t, want, got, "the rows %v, newest first, on %s", tc.want, dbType())
			assert.Equalf(t, len(want), total, "the total counts each listed row once, on %s", dbType())
		})
	}

	t.Run("the user's rows page newest first, under the same total", func(t *testing.T) {
		first, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 3, record.AuditLogFilter{UserId: user})
		require.NoError(t, err)
		assert.Equal(t, 4, total)
		require.Len(t, first, 3)
		assert.Equal(t, []int64{ids["by, about no one"], ids["about and by"], ids["by"]},
			[]int64{first[0].Id, first[1].Id, first[2].Id})

		second, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 2, 3, record.AuditLogFilter{UserId: user})
		require.NoError(t, err)
		assert.Equal(t, 4, total)
		require.Len(t, second, 1)
		assert.Equal(t, ids["about"], second[0].Id)
	})
}

// #781 decision 5: one user's audit events are every row about the user or made by them, each
// once, in id order, oldest first, all of them at once. Each expected list is written out by hand
// from the rows below.
func TestGetAuditLogsByUserId(t *testing.T) {
	// The user ids are unique to this test run, so each read lists only these rows; no foreign key
	// holds them to a users row, as none holds an audit row's.
	user := int64(fake.Number(1_000_000_000, 2_000_000_000))
	other, third, nobody := user+1, user+2, user+3

	// Written oldest first, so id order is the order they are listed in.
	rows := []struct {
		name           string
		userId         int64
		loggedInUserId int64
	}{
		{"about", user, 0},
		{"by", other, user},
		{"about and by", user, user},
		{"neither", other, third},
		{"no user columns", 0, 0},
		{"by, about no one", 0, user},
	}
	ids := map[string]int64{}
	for _, row := range rows {
		auditLog := &record.AuditLog{
			AuditEvent:     "user_audit_logs_" + fake.LetterN(10),
			Details:        `{"test": "data"}`,
			RequestId:      "itest-" + fake.LetterN(16),
			UserId:         userColumn(row.userId),
			LoggedInUserId: userColumn(row.loggedInUserId),
		}
		require.NoError(t, database.CreateAuditLog(context.Background(), nil, auditLog))
		ids[row.name] = auditLog.Id
	}

	for _, tc := range []struct {
		name   string
		userId int64
		want   []string
	}{
		{"the rows about the user and the rows they made, oldest first",
			user, []string{"about", "by", "about and by", "by, about no one"}},
		{"a user named only as the one a row is about",
			other, []string{"by", "neither"}},
		{"a user named only as the one who acted",
			third, []string{"neither"}},
		{"an id no row names lists nothing",
			nobody, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs, err := database.GetAuditLogsByUserId(context.Background(), nil, tc.userId)
			require.NoError(t, err)

			want := []int64{}
			for _, name := range tc.want {
				want = append(want, ids[name])
			}
			got := []int64{}
			for _, log := range logs {
				got = append(got, log.Id)
			}
			assert.Equalf(t, want, got, "the rows %v, oldest first, on %s", tc.want, dbType())
		})
	}

	t.Run("each row reads back whole", func(t *testing.T) {
		written := &record.AuditLog{
			AuditEvent:     "user_audit_logs_whole_" + fake.LetterN(10),
			Details:        `{"user_id": "41"}`,
			RequestId:      "itest-" + fake.LetterN(16),
			UserId:         userColumn(nobody),
			LoggedInUserId: userColumn(third),
		}
		require.NoError(t, database.CreateAuditLog(context.Background(), nil, written))

		logs, err := database.GetAuditLogsByUserId(context.Background(), nil, nobody)
		require.NoError(t, err)
		require.Len(t, logs, 1)
		assert.Equal(t, written.Id, logs[0].Id)
		assert.Equal(t, written.AuditEvent, logs[0].AuditEvent)
		assert.Equal(t, written.Details, logs[0].Details)
		assert.Equal(t, written.RequestId, logs[0].RequestId)
		assert.Equal(t, userColumn(nobody), logs[0].UserId)
		assert.Equal(t, userColumn(third), logs[0].LoggedInUserId)
		assert.WithinDurationf(t, written.CreatedAt, logs[0].CreatedAt, time.Second, "created_at read back on %s", dbType())
	})
}

// #781 decision 5: the read is not paged. The admin API's page holds at most 200 rows, so a user
// with more than that is read whole, in id order.
func TestGetAuditLogsByUserId_ReadsMoreThanAPage(t *testing.T) {
	user := int64(fake.Number(2_000_000_001, 3_000_000_000))
	const written = 205

	var want []int64
	for i := 0; i < written; i++ {
		auditLog := &record.AuditLog{
			AuditEvent: "user_audit_logs_many",
			Details:    `{"test": "data"}`,
			UserId:     userColumn(user),
		}
		require.NoError(t, database.CreateAuditLog(context.Background(), nil, auditLog))
		want = append(want, auditLog.Id)
	}

	logs, err := database.GetAuditLogsByUserId(context.Background(), nil, user)
	require.NoError(t, err)
	got := []int64{}
	for _, log := range logs {
		got = append(got, log.Id)
	}
	assert.Equalf(t, want, got, "all %d rows, oldest first, on %s", written, dbType())
}

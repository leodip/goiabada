package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /api/v1/admin/audit-logs
//
// The tests below insert their own audit log rows under a unique event name and
// then filter on it. Querying whatever ambient rows the rest of the suite happens
// to have written would make the pagination and total assertions depend on test
// ordering.

const auditLogsURL = "/api/v1/admin/audit-logs"

// seedAuditLogs writes count rows under a unique event name, oldest first, and
// returns the event name. Rows are spaced a second apart because the handler
// orders by created_at DESC, so an even spread keeps the expected page contents
// deterministic.
func seedAuditLogs(t *testing.T, count int) string {
	t.Helper()
	auditEvent := "test_audit_event_" + fake.LetterN(10)
	base := time.Now().UTC().Add(-time.Duration(count) * time.Second)

	for i := 0; i < count; i++ {
		auditLog := &record.AuditLog{
			CreatedAt:  base.Add(time.Duration(i) * time.Second),
			AuditEvent: auditEvent,
			Details:    fmt.Sprintf(`{"seq":%d}`, i),
		}
		err := database.CreateAuditLog(context.Background(), nil, auditLog)
		assert.NoError(t, err)
	}
	return auditEvent
}

func getAuditLogs(t *testing.T, accessToken string, query string) (*api.GetAuditLogsResponse, *http.Response) {
	t.Helper()
	url := appConfig.AuthServer.BaseURL + auditLogsURL
	if query != "" {
		url += "?" + query
	}

	resp := makeAPIRequest(t, "GET", url, accessToken, nil)

	var body api.GetAuditLogsResponse
	if resp.StatusCode == http.StatusOK {
		err := json.NewDecoder(resp.Body).Decode(&body)
		assert.NoError(t, err)
	}
	return &body, resp
}

func TestAPIAuditLogsGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	auditEvent := seedAuditLogs(t, 3)

	body, resp := getAuditLogs(t, accessToken, "auditEvent="+auditEvent)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	assert.Equal(t, 3, body.Total)
	assert.Len(t, body.AuditLogs, 3)

	for _, entry := range body.AuditLogs {
		assert.Equal(t, auditEvent, entry.AuditEvent)
		assert.NotZero(t, entry.Id)
		assert.NotEmpty(t, entry.Details)
		// createdAt is a time.Time now, and the decode above is what proves it is still ISO
		// 8601 on the wire: encoding/json accepts nothing else into a time.Time, so a payload
		// that stopped being RFC3339 would have failed getAuditLogs rather than this line.
		// What is left to say here is that the instant survived the round trip (#373).
		assert.False(t, entry.CreatedAt.IsZero(), "createdAt must carry the instant the row was written")
	}
}

// Newest first, per the handler's created_at DESC ordering.
func TestAPIAuditLogsGet_NewestFirst(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	auditEvent := seedAuditLogs(t, 3)

	body, resp := getAuditLogs(t, accessToken, "auditEvent="+auditEvent)
	defer func() { _ = resp.Body.Close() }()

	assert.Len(t, body.AuditLogs, 3)
	// The seed wrote seq 0 oldest through seq 2 newest.
	assert.Contains(t, body.AuditLogs[0].Details, `"seq":2`)
	assert.Contains(t, body.AuditLogs[2].Details, `"seq":0`)
}

func TestAPIAuditLogsGet_DefaultPaging(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	auditEvent := seedAuditLogs(t, 2)

	body, resp := getAuditLogs(t, accessToken, "auditEvent="+auditEvent)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, body.Page, "page must default to 1")
	assert.Equal(t, 20, body.Size, "size must default to 20")
}

func TestAPIAuditLogsGet_Paging(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	auditEvent := seedAuditLogs(t, 5)

	t.Run("first page", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, "auditEvent="+auditEvent+"&page=1&size=2")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 5, body.Total, "total must count every match, not just this page")
		assert.Equal(t, 1, body.Page)
		assert.Equal(t, 2, body.Size)
		assert.Len(t, body.AuditLogs, 2)
	})

	t.Run("last page is partial", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, "auditEvent="+auditEvent+"&page=3&size=2")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 5, body.Total)
		assert.Len(t, body.AuditLogs, 1)
	})

	t.Run("page past the end is empty", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, "auditEvent="+auditEvent+"&page=99&size=2")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 5, body.Total)
		assert.Empty(t, body.AuditLogs)
	})

	t.Run("pages do not overlap", func(t *testing.T) {
		first, resp1 := getAuditLogs(t, accessToken, "auditEvent="+auditEvent+"&page=1&size=2")
		defer func() { _ = resp1.Body.Close() }()
		second, resp2 := getAuditLogs(t, accessToken, "auditEvent="+auditEvent+"&page=2&size=2")
		defer func() { _ = resp2.Body.Close() }()

		seen := map[int64]bool{}
		for _, e := range first.AuditLogs {
			seen[e.Id] = true
		}
		for _, e := range second.AuditLogs {
			assert.False(t, seen[e.Id], "id %d appeared on both pages", e.Id)
		}
	})
}

// Unparseable or out-of-range paging parameters fall back to the defaults rather
// than erroring. Note that a size above the 200 cap does NOT clamp to 200: it is
// ignored and the default 20 applies.
func TestAPIAuditLogsGet_PagingParameterFallbacks(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	auditEvent := seedAuditLogs(t, 1)

	testCases := []struct {
		name     string
		query    string
		wantPage int
		wantSize int
	}{
		{"non-numeric page", "page=abc", 1, 20},
		{"zero page", "page=0", 1, 20},
		{"negative page", "page=-5", 1, 20},
		{"non-numeric size", "size=abc", 1, 20},
		{"zero size", "size=0", 1, 20},
		{"negative size", "size=-5", 1, 20},
		{"size above the cap falls back to the default", "size=500", 1, 20},
		{"size at the cap is honored", "size=200", 1, 200},
		{"size just above the cap falls back", "size=201", 1, 20},
		{"empty values", "page=&size=", 1, 20},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, resp := getAuditLogs(t, accessToken, "auditEvent="+auditEvent+"&"+tc.query)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tc.wantPage, body.Page)
			assert.Equal(t, tc.wantSize, body.Size)
		})
	}
}

func TestAPIAuditLogsGet_EventFilter(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	eventA := seedAuditLogs(t, 2)
	eventB := seedAuditLogs(t, 3)

	t.Run("filter returns only the requested event", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, "auditEvent="+eventA)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 2, body.Total)
		for _, entry := range body.AuditLogs {
			assert.Equal(t, eventA, entry.AuditEvent)
		}
	})

	t.Run("a different event is filtered separately", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, "auditEvent="+eventB)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 3, body.Total)
		for _, entry := range body.AuditLogs {
			assert.Equal(t, eventB, entry.AuditEvent)
		}
	})

	t.Run("an unmatched event yields nothing", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, "auditEvent=no_such_event_"+fake.LetterN(8))
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 0, body.Total)
		assert.Empty(t, body.AuditLogs)
	})

	// With no filter the endpoint returns everything, so it must see at least the
	// rows just seeded.
	t.Run("no filter returns all events", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, "size=200")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.GreaterOrEqual(t, body.Total, 5)
	})
}

func TestAPIAuditLogs_UnauthorizedAndScope(t *testing.T) {
	url := appConfig.AuthServer.BaseURL + auditLogsURL

	// No token
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(bodyBytes), "Access token required.")

	// Invalid token
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// Insufficient scope: audit logs are readable only with a settings-read scope.
	tok := createClientCredentialsTokenWithoutRouteScope(t)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	bodyBytes3, _ := io.ReadAll(resp3.Body)
	assert.Contains(t, string(bodyBytes3), "Insufficient scope.")
}

// #328: the request id, end to end. An audited request writes a row carrying the id, and the
// endpoint finds that row by it.
//
// The audited request used here is the audit log settings PUT, which audits itself, so the
// whole chain is exercised through the API alone: the header arrives, chi adopts it,
// AuditLogger.Log takes it off the request context, the row stores the log's rendering of it,
// and the filter matches that same string. Reading audit_logs directly would prove the write
// and nothing about the endpoint.
//
// It also pins that the header is adopted from any client, verbatim (decision 9): that is chi's
// behaviour today, and a change to it should be a deliberate one rather than a silent one.
func auditedPutWithRequestId(t *testing.T, accessToken string, requestId string) {
	t.Helper()

	body, err := json.Marshal(api.UpdateSettingsAuditLogsRequest{
		AuditLogsInConsoleEnabled:  true,
		AuditLogsInDatabaseEnabled: true,
		AuditLogRetentionDays:      33,
	})
	require.NoError(t, err)

	req, err := http.NewRequest("PUT", appConfig.AuthServer.BaseURL+settingsAuditLogsURL,
		bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	if requestId != "" {
		req.Header.Set("X-Request-Id", requestId)
	}

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// enableAuditLogsInDatabase turns database audit logging on, since nothing is queryable
// without it, and restores the row when the test ends.
func enableAuditLogsInDatabase(t *testing.T) {
	t.Helper()
	changeSettings(t, func(settings *record.Settings) { settings.AuditLogsInDatabaseEnabled = true })
}

func TestAPIAuditLogsGet_RequestIdFilter(t *testing.T) {
	enableAuditLogsInDatabase(t)
	accessToken, _ := createAdminClientWithToken(t)

	t.Run("the id the client sent is the id the filter finds", func(t *testing.T) {
		requestId := "itest-" + fake.LetterN(16)
		auditedPutWithRequestId(t, accessToken, requestId)

		body, resp := getAuditLogs(t, accessToken, "requestId="+url.QueryEscape(requestId))
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 1, body.Total)
		if assert.Len(t, body.AuditLogs, 1) {
			assert.Equal(t, requestId, body.AuditLogs[0].RequestId)
			assert.Equal(t, audit.EventUpdatedAuditLogsSettings, body.AuditLogs[0].AuditEvent)
		}

		t.Run("and narrows further with the audit event", func(t *testing.T) {
			withEvent, resp := getAuditLogs(t, accessToken, "requestId="+url.QueryEscape(requestId)+
				"&auditEvent="+audit.EventUpdatedAuditLogsSettings)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, 1, withEvent.Total)
			assert.Len(t, withEvent.AuditLogs, 1)

			otherEvent, resp2 := getAuditLogs(t, accessToken, "requestId="+url.QueryEscape(requestId)+
				"&auditEvent=user_login")
			defer func() { _ = resp2.Body.Close() }()

			assert.Equal(t, 0, otherEvent.Total, "the two filters must both apply, not either")
			assert.Empty(t, otherEvent.AuditLogs)
		})
	})

	// The header is bounded nowhere but the server's 1 MiB header cap, so what the row can
	// carry is the log's clipped rendering and nothing longer. The filter finds the row by that
	// same string, which is what makes the value on the admin page the value an operator greps
	// the log for.
	t.Run("an oversized id is stored and found as the log renders it", func(t *testing.T) {
		oversized := strings.Repeat("x", 300)
		clipped := strings.Repeat("x", 128) + "[truncated, 128 of 300 bytes]"
		auditedPutWithRequestId(t, accessToken, oversized)

		body, resp := getAuditLogs(t, accessToken, "requestId="+url.QueryEscape(clipped))
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 1, body.Total)
		if assert.Len(t, body.AuditLogs, 1) {
			assert.Equal(t, clipped, body.AuditLogs[0].RequestId)
		}

		raw, resp2 := getAuditLogs(t, accessToken, "requestId="+url.QueryEscape(oversized))
		defer func() { _ = resp2.Body.Close() }()
		assert.Equal(t, 0, raw.Total, "the raw header is not what the row holds")
	})

	// No header means chi generates one, so an entry raised by a request always carries an id;
	// only entries written off a request, and rows older than the column, carry none.
	t.Run("with no header the entry still carries the id chi generated", func(t *testing.T) {
		before, resp := getAuditLogs(t, accessToken,
			"auditEvent="+audit.EventUpdatedAuditLogsSettings+"&size=1")
		defer func() { _ = resp.Body.Close() }()
		var lastIdBefore int64
		if len(before.AuditLogs) > 0 {
			lastIdBefore = before.AuditLogs[0].Id
		}

		auditedPutWithRequestId(t, accessToken, "")

		after, resp2 := getAuditLogs(t, accessToken,
			"auditEvent="+audit.EventUpdatedAuditLogsSettings+"&size=1")
		defer func() { _ = resp2.Body.Close() }()

		if assert.Len(t, after.AuditLogs, 1) {
			entry := after.AuditLogs[0]
			assert.NotEqual(t, lastIdBefore, entry.Id, "the PUT must have written a new entry")
			// chi's own shape, hostname/prefix-counter, not chi's exact alphabet.
			assert.Regexp(t, `^.+/.+-\d+$`, entry.RequestId)

			found, resp3 := getAuditLogs(t, accessToken, "requestId="+url.QueryEscape(entry.RequestId))
			defer func() { _ = resp3.Body.Close() }()
			assert.Equal(t, 1, found.Total, "the generated id must be searchable like any other")
		}
	})
}

// #780: the userId filter and the two user columns every entry answers.

// seededRow is one audit row a user-filter test writes: who it is about, who made it, and the
// request it was written on. A zero user id leaves that column NULL, as on a row written before
// the columns existed.
type seededRow struct {
	userId, loggedInUserId int64
	requestId              string
}

// seedAuditLogsWithUsers writes rows under a unique event name, oldest first and a second apart,
// each with its seq in the details, and returns the event name.
func seedAuditLogsWithUsers(t *testing.T, rows []seededRow) string {
	t.Helper()
	auditEvent := "test_audit_event_" + fake.LetterN(10)
	base := time.Now().UTC().Add(-time.Duration(len(rows)) * time.Second)

	for i, row := range rows {
		auditLog := &record.AuditLog{
			CreatedAt:      base.Add(time.Duration(i) * time.Second),
			AuditEvent:     auditEvent,
			Details:        fmt.Sprintf(`{"seq":%d}`, i),
			RequestId:      row.requestId,
			UserId:         sql.NullInt64{Int64: row.userId, Valid: row.userId != 0},
			LoggedInUserId: sql.NullInt64{Int64: row.loggedInUserId, Valid: row.loggedInUserId != 0},
		}
		require.NoError(t, database.CreateAuditLog(context.Background(), nil, auditLog))
	}
	return auditEvent
}

// userIdOfNoRealUser is an id far above any user this suite creates, so the rows a test seeds
// under it are the only rows the filter can find.
func userIdOfNoRealUser() int64 {
	return int64(fake.Number(1_000_000_000, 1_900_000_000))
}

// seqs is each entry's seq, in the order the page answered them.
func seqs(t *testing.T, entries []api.AuditLogResponse) []int {
	t.Helper()
	out := make([]int, 0, len(entries))
	for _, entry := range entries {
		var details struct {
			Seq int `json:"seq"`
		}
		require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
		out = append(out, details.Seq)
	}
	return out
}

func int64Ptr(v int64) *int64 { return &v }

func TestAPIAuditLogsGet_UserFilter(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := userIdOfNoRealUser()
	other := user + 1
	requestId := "user-filter-" + fake.LetterN(16)

	auditEvent := seedAuditLogsWithUsers(t, []seededRow{
		{userId: user},                                // 0: about the user
		{userId: other, loggedInUserId: user},         // 1: made by the user
		{userId: user, loggedInUserId: user},          // 2: about and by the user, listed once
		{userId: other, loggedInUserId: other},        // 3: naming neither
		{},                                            // 4: no user columns
		{userId: user, requestId: requestId},          // 5: about the user, on the request
		{loggedInUserId: other, requestId: requestId}, // 6: on the request, naming neither
		{userId: other, loggedInUserId: user, requestId: requestId}, // 7: by the user, on the request
	})
	// A row about the user under another event, which only the filters without auditEvent list.
	otherEvent := seedAuditLogsWithUsers(t, []seededRow{{userId: user, requestId: requestId}})

	testCases := []struct {
		name     string
		query    string
		wantSeqs []int
		events   []string
	}{
		{"the user and the event list the rows about them or by them, newest first",
			"userId=%d&auditEvent=" + auditEvent, []int{7, 5, 2, 1, 0}, nil},
		{"the user and the request id",
			"userId=%d&requestId=" + requestId, []int{0, 7, 5}, []string{otherEvent, auditEvent, auditEvent}},
		{"all three",
			"userId=%d&requestId=" + requestId + "&auditEvent=" + auditEvent, []int{7, 5}, nil},
		{"the user alone",
			"userId=%d", []int{0, 7, 5, 2, 1, 0}, []string{otherEvent, auditEvent, auditEvent, auditEvent, auditEvent, auditEvent}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, resp := getAuditLogs(t, accessToken, fmt.Sprintf(tc.query, user))
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, len(tc.wantSeqs), body.Total)
			assert.Equal(t, tc.wantSeqs, seqs(t, body.AuditLogs))
			if tc.events != nil {
				events := make([]string, 0, len(body.AuditLogs))
				for _, entry := range body.AuditLogs {
					events = append(events, entry.AuditEvent)
				}
				assert.Equal(t, tc.events, events)
			}
		})
	}

	t.Run("each entry answers the user it is about and the user who acted, null when none", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, "auditEvent="+auditEvent)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, []int{7, 6, 5, 4, 3, 2, 1, 0}, seqs(t, body.AuditLogs))
		// Newest first: seq 7 down to seq 0.
		wantUserIds := []*int64{int64Ptr(other), nil, int64Ptr(user), nil,
			int64Ptr(other), int64Ptr(user), int64Ptr(other), int64Ptr(user)}
		wantLoggedInUserIds := []*int64{int64Ptr(user), int64Ptr(other), nil, nil,
			int64Ptr(other), int64Ptr(user), int64Ptr(user), nil}
		for i, entry := range body.AuditLogs {
			assert.Equal(t, wantUserIds[i], entry.UserId, "seq %d's userId", 7-i)
			assert.Equal(t, wantLoggedInUserIds[i], entry.LoggedInUserId, "seq %d's loggedInUserId", 7-i)
		}
	})

	t.Run("an id no row names answers an empty page", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, fmt.Sprintf("userId=%d", userIdOfNoRealUser()+1_000_000_000))
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 0, body.Total)
		assert.Empty(t, body.AuditLogs)
	})

	t.Run("the user filter pages like the others", func(t *testing.T) {
		body, resp := getAuditLogs(t, accessToken, fmt.Sprintf("userId=%d&auditEvent=%s&page=2&size=2", user, auditEvent))
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 5, body.Total, "the total counts every match, not this page")
		assert.Equal(t, []int{2, 1}, seqs(t, body.AuditLogs))
	})
}

// A userId that is not a positive integer is refused, never ignored: ignoring it would list every
// user's events under a filter the caller believes is set (#780 decision 3).
func TestAPIAuditLogsGet_AUserIdThatIsNotAPositiveIntegerIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	for _, value := range []string{"", "abc", "0", "-4", "4.0", "99999999999999999999"} {
		t.Run(value, func(t *testing.T) {
			resp := makeAPIRequest(t, "GET",
				appConfig.AuthServer.BaseURL+auditLogsURL+"?userId="+url.QueryEscape(value), accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var body api.ErrorResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, "VALIDATION_ERROR", body.ErrorCode)
		})
	}
}

// End to end: a change an administrator makes through the Admin API with their own token is listed
// under the user changed and under the administrator, and says which is which. Disabling a user
// writes two entries, the change and the revocation it causes, and both name the two users.
func TestAPIAuditLogsGet_AChangeIsListedUnderBothUsers(t *testing.T) {
	requireDatabaseAuditLogs(t)
	readToken, _ := createAdminClientWithToken(t)
	adminToken, administrator := createUserAccessTokenWithScope(t,
		builtin.AuthServerResourceIdentifier+":"+builtin.ManageUsersPermissionIdentifier)
	changed := createUserToChange(t)
	require.NotEqual(t, administrator.Id, changed.Id)

	requestId := disableUserUnderRequestId(t, adminToken, changed)

	for _, who := range []struct {
		name string
		id   int64
	}{{"under the user changed", changed.Id}, {"under the administrator", administrator.Id}} {
		t.Run(who.name, func(t *testing.T) {
			body, resp := getAuditLogs(t, readToken,
				fmt.Sprintf("userId=%d&requestId=%s", who.id, url.QueryEscape(requestId)))
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, 2, body.Total)
			events := []string{}
			for _, entry := range body.AuditLogs {
				events = append(events, entry.AuditEvent)
				assert.Equal(t, int64Ptr(changed.Id), entry.UserId,
					"%s: userId is the user the change was made to", entry.AuditEvent)
				assert.Equal(t, int64Ptr(administrator.Id), entry.LoggedInUserId,
					"%s: loggedInUserId is the administrator whose token made the change", entry.AuditEvent)
			}
			assert.Equal(t, []string{"revoked_user_auth_state", "updated_user_details"}, events)
		})
	}

	t.Run("not under a user it does not name", func(t *testing.T) {
		body, resp := getAuditLogs(t, readToken,
			fmt.Sprintf("userId=%d&requestId=%s", userIdOfNoRealUser(), url.QueryEscape(requestId)))
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 0, body.Total, "the request's entries name two users, and this is neither")
		assert.Empty(t, body.AuditLogs)
	})
}

// A client credentials token has no user, so the change it makes is listed under the user changed
// only, and answers loggedInUserId null.
func TestAPIAuditLogsGet_AChangeMadeWithAClientCredentialsTokenNamesNoActingUser(t *testing.T) {
	requireDatabaseAuditLogs(t)
	clientToken, client := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	changed := createUserToChange(t)

	requestId := disableUserUnderRequestId(t, clientToken, changed)

	// All three filters together: the change's own entry, on its request, about the user.
	query := fmt.Sprintf("userId=%d&requestId=%s&auditEvent=updated_user_details", changed.Id,
		url.QueryEscape(requestId))
	body, resp := getAuditLogs(t, clientToken, query)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, 1, body.Total)
	assert.Equal(t, int64Ptr(changed.Id), body.AuditLogs[0].UserId)
	assert.Nil(t, body.AuditLogs[0].LoggedInUserId, "a client credentials token names no acting user")

	raw := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+auditLogsURL+"?"+query, clientToken, nil)
	defer func() { _ = raw.Body.Close() }()
	rawBody, err := io.ReadAll(raw.Body)
	require.NoError(t, err)
	assert.Contains(t, string(rawBody), `"loggedInUserId":null`, "the key is present, and null")
}

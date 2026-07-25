package integrationtests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
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
	auditEvent := "test_audit_event_" + gofakeit.LetterN(10)
	base := time.Now().UTC().Add(-time.Duration(count) * time.Second)

	for i := 0; i < count; i++ {
		auditLog := &models.AuditLog{
			CreatedAt:  base.Add(time.Duration(i) * time.Second),
			AuditEvent: auditEvent,
			Details:    fmt.Sprintf(`{"seq":%d}`, i),
		}
		err := database.CreateAuditLog(nil, auditLog)
		assert.NoError(t, err)
	}
	return auditEvent
}

func getAuditLogs(t *testing.T, accessToken string, query string) (*api.GetAuditLogsResponse, *http.Response) {
	t.Helper()
	url := config.GetAuthServer().BaseURL + auditLogsURL
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
		// createdAt is serialized as ISO 8601 and must parse back.
		_, err := time.Parse(time.RFC3339, entry.CreatedAt)
		assert.NoError(t, err, "createdAt %q must be ISO 8601", entry.CreatedAt)
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
		body, resp := getAuditLogs(t, accessToken, "auditEvent=no_such_event_"+gofakeit.LetterN(8))
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
	url := config.GetAuthServer().BaseURL + auditLogsURL

	// No token
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(bodyBytes), "Access token required.")

	// Invalid token
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// Insufficient scope: audit logs are readable only with a settings-read scope.
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	bodyBytes3, _ := io.ReadAll(resp3.Body)
	assert.Contains(t, string(bodyBytes3), "Insufficient scope.")
}

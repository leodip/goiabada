package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/oauth"
)

// The audit log viewer is the fifth paginated admin list and the only one whose
// page size is not 10, which is why it is worth its own cases: a clamp that
// counted pages at the wrong size would land on the wrong last page here and
// nowhere else.
//
// It already turned an unusable "?page=" into page 1, so what changes for it is
// the other half: it kept a page past the end for the query, and rendered an
// empty table under a bar highlighting the last page (#305).

type auditPagingApiClient struct {
	apiclient.ApiClient
	total int
	asked []int
	// events records the auditEvent filter each call carried, which the
	// re-query must not drop.
	events []string
	// requestIds records the same for the request id filter (#328).
	requestIds []string
}

func (c *auditPagingApiClient) GetAuditLogsPaginated(accessToken string, page, pageSize int,
	auditEvent string, requestId string) (*api.GetAuditLogsResponse, error) {

	c.asked = append(c.asked, page)
	c.events = append(c.events, auditEvent)
	c.requestIds = append(c.requestIds, requestId)

	return &api.GetAuditLogsResponse{
		AuditLogs: logsOnPage(c.total, page, pageSize),
		Total:     c.total,
		Page:      page,
		Size:      pageSize,
	}, nil
}

// logsOnPage is the slice of a log of total entries that page holds, each
// entry's Id being its 1-based position. The start < 0 arm stands for the
// negative SQL offset a real API cannot serve.
func logsOnPage(total, page, pageSize int) []api.AuditLogResponse {
	start := (page - 1) * pageSize
	if start < 0 || start >= total {
		return nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	logs := make([]api.AuditLogResponse, 0, end-start)
	for i := start; i < end; i++ {
		logs = append(logs, api.AuditLogResponse{Id: int64(i + 1), AuditEvent: "an-event"})
	}
	return logs
}

func renderAuditLogs(t *testing.T, rawPage string, total int) (map[string]interface{}, *auditPagingApiClient) {
	t.Helper()

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			t.Errorf("the handler answered 500: %v", args.Get(2))
		}).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/admin_settings_audit_log_viewer.html", mock.Anything).
		Return(nil).Maybe()

	target := "/admin/settings/audit-logs"
	if rawPage != "" {
		target += "?page=" + rawPage
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

	apiClient := &auditPagingApiClient{total: total}
	HandleAdminSettingsAuditLogViewerGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	var bind map[string]interface{}
	for _, call := range httpHelper.Calls {
		if call.Method == "RenderTemplate" {
			bind = call.Arguments.Get(4).(map[string]interface{})
		}
	}
	require.NotNil(t, bind, "the handler rendered nothing for ?page=%q", rawPage)
	return bind, apiClient
}

func TestHandleAdminSettingsAuditLogViewerGet_PageQueryParameter(t *testing.T) {
	// Twenty, not ten. Every "want" below is counted at this size.
	const pageSize = 20

	testCases := []struct {
		name      string
		raw       string
		total     int
		wantPage  int
		wantAsked []int
		why       string
	}{
		{"absent", "", 50, 1, []int{1}, "no parameter is page 1"},
		{"a word", "abc", 50, 1, []int{1}, "unparseable is page 1"},
		{"zero", "0", 50, 1, []int{1}, "pages are one-based"},
		{"negative", "-5", 50, 1, []int{1}, "negative is page 1"},
		{"past the largest int", "9223372036854775808", 50, 1, []int{1}, "out of range is page 1"},

		{"a middle page", "2", 50, 2, []int{2}, "asked once, no second query"},
		{"the last page", "3", 50, 3, []int{3}, "fifty entries is three pages of twenty"},
		{"an exact multiple", "2", 40, 2, []int{2}, "forty entries is two pages, not three"},

		// The page size is what these turn on: 25 entries is two pages at
		// twenty and three at ten, so a clamp counting at the wrong size lands
		// on the wrong page here.
		{"past the last, at this page size", "3", 25, 2, []int{3, 2}, "twenty-five entries is two pages of twenty"},
		{"far past the last", "99", 50, 3, []int{99, 3}, "the reported case"},
		{"one past the last", "4", 50, 3, []int{4, 3}, "clamped to the last page"},
		{"an empty log", "5", 0, 1, []int{5, 1}, "an empty log still has a page 1"},
		{"the largest int", "9223372036854775807", 50, 3, nil, "bounded, then clamped"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bind, apiClient := renderAuditLogs(t, tc.raw, tc.total)

			if tc.wantAsked != nil {
				assert.Equal(t, tc.wantAsked, apiClient.asked, "pages asked of the API: %s", tc.why)
			}
			require.NotEmpty(t, apiClient.asked, "the handler asked for nothing")
			require.LessOrEqual(t, len(apiClient.asked), 2, "the handler asked more than twice")
			for i, page := range apiClient.asked {
				assert.GreaterOrEqual(t, page, 1, "call %d asked for page %d", i, page)
				assert.GreaterOrEqual(t, (page-1)*pageSize, 0,
					"call %d asked for page %d, whose offset wrapped", i, page)
			}

			result, ok := bind["pageResult"].(AuditLogsPageResult)
			require.True(t, ok, "pageResult")
			assert.Equal(t, tc.wantPage, result.Page, "pageResult.Page: %s", tc.why)
			assert.Equal(t, tc.total, result.Total, "pageResult.Total")
			assert.Equal(t, pageSize, result.PageSize, "the page size this list is counted at")

			paginator, ok := bind["paginator"].(*pagination.Paginator)
			require.True(t, ok, "paginator")
			assert.Equal(t, tc.wantPage, currentPage(t, paginator),
				"the bar highlights a different page than the rows came from: %s", tc.why)

			// The rows bound are the settled page's rows -- and, when the
			// handler asked twice, the rows of the *second* answer. Keeping the
			// first answer is the natural half-fix, and it renders an empty
			// table under a correctly clamped bar, which is the bug wearing a
			// better bar.
			assert.Equal(t, logsOnPage(tc.total, tc.wantPage, pageSize), result.AuditLogs,
				"the rows are not page %d's: %s", tc.wantPage, tc.why)
			if tc.total > 0 {
				require.NotEmpty(t, result.AuditLogs, "page %d rendered no rows at all", tc.wantPage)
				assert.Equal(t, int64((tc.wantPage-1)*pageSize+1), result.AuditLogs[0].Id,
					"the first row is not the first of page %d", tc.wantPage)
			}
		})
	}
}

// TestHandleAdminSettingsAuditLogViewerGet_TheEventFilterSurvivesTheSecondQuery
// pins the argument the clamp is most likely to drop. The re-query repeats the
// whole call, and one that forgot the event filter would page through the
// unfiltered log while the filter dropdown still named an event.
func TestHandleAdminSettingsAuditLogViewerGet_TheEventFilterSurvivesTheSecondQuery(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { t.Errorf("the handler answered 500: %v", args.Get(2)) }).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Maybe()

	apiClient := &auditPagingApiClient{total: 50}

	req := httptest.NewRequest(http.MethodGet, "/admin/settings/audit-logs?page=99&auditEvent=UserAuthSuccess", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

	HandleAdminSettingsAuditLogViewerGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	require.Equal(t, 2, len(apiClient.asked), "the clamp should have cost a second query")
	assert.Equal(t, []string{"UserAuthSuccess", "UserAuthSuccess"}, apiClient.events,
		"the event filter was dropped on the way")
}

// TestHandleAdminSettingsAuditLogViewerGet_EveryTotalLandsOnAPageWithRows sweeps
// the page size boundary rather than picking totals by hand: for every log size
// around a page of twenty, a page far past the end must render the last page,
// and that page must have rows on it. An off-by-one in the page count shows up
// here as an empty table on an exact multiple.
func TestHandleAdminSettingsAuditLogViewerGet_EveryTotalLandsOnAPageWithRows(t *testing.T) {
	const pageSize = 20

	for total := 0; total <= 61; total++ {
		t.Run(strconv.Itoa(total), func(t *testing.T) {
			bind, apiClient := renderAuditLogs(t, "99", total)

			result := bind["pageResult"].(AuditLogsPageResult)

			wantPage := 1
			if total > 0 {
				wantPage = (total + pageSize - 1) / pageSize
			}
			assert.Equal(t, wantPage, result.Page, "total=%d", total)
			assert.Equal(t, wantPage, currentPage(t, bind["paginator"].(*pagination.Paginator)), "total=%d", total)
			assert.Equal(t, []int{99, wantPage}, apiClient.asked, "total=%d", total)

			if total > 0 {
				require.NotEmpty(t, result.AuditLogs, "total=%d: the last page has no rows", total)
			}
		})
	}
}

// renderAuditLogsWithQuery renders the viewer for a whole query string, which the
// page-size cases above do not need and the filter cases do.
func renderAuditLogsWithQuery(t *testing.T, rawQuery string, total int) (map[string]interface{}, *auditPagingApiClient) {
	t.Helper()

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { t.Errorf("the handler answered 500: %v", args.Get(2)) }).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/admin_settings_audit_log_viewer.html", mock.Anything).
		Return(nil).Maybe()

	req := httptest.NewRequest(http.MethodGet, "/admin/settings/audit-log-viewer?"+rawQuery, nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

	apiClient := &auditPagingApiClient{total: total}
	HandleAdminSettingsAuditLogViewerGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	var bind map[string]interface{}
	for _, call := range httpHelper.Calls {
		if call.Method == "RenderTemplate" {
			bind = call.Arguments.Get(4).(map[string]interface{})
		}
	}
	require.NotNil(t, bind, "the handler rendered nothing for ?%s", rawQuery)
	return bind, apiClient
}

// TestHandleAdminSettingsAuditLogViewerGet_TheRequestIdFilterReachesTheApiAndThePage
// is seam 8's handler half: the query parameter added in stage 3 has to be read here
// and handed back to the page, or the input the operator typed into empties itself on
// every render and the filter looks broken while the rows are right (#328).
func TestHandleAdminSettingsAuditLogViewerGet_TheRequestIdFilterReachesTheApiAndThePage(t *testing.T) {
	testCases := []struct {
		name      string
		rawQuery  string
		wantEvent string
		wantId    string
		wantLink  string
	}{
		{
			name:     "no filter at all",
			rawQuery: "page=1",
			wantLink: "/admin/settings/audit-log-viewer",
		},
		{
			name:      "the event alone",
			rawQuery:  "auditEvent=user_login",
			wantEvent: "user_login",
			wantLink:  "/admin/settings/audit-log-viewer?auditEvent=user_login",
		},
		{
			name:     "the request id alone",
			rawQuery: "requestId=host%2FPpg6bHPK5f-000012",
			wantId:   "host/Ppg6bHPK5f-000012",
			wantLink: "/admin/settings/audit-log-viewer?requestId=host%2FPpg6bHPK5f-000012",
		},
		{
			name:      "both",
			rawQuery:  "auditEvent=user_login&requestId=host%2FPpg6bHPK5f-000012",
			wantEvent: "user_login",
			wantId:    "host/Ppg6bHPK5f-000012",
			wantLink:  "/admin/settings/audit-log-viewer?auditEvent=user_login&requestId=host%2FPpg6bHPK5f-000012",
		},
		{
			// The id is whatever the client sent in X-Request-Id. An "&" in it
			// concatenated into the paginator's base link would become a second
			// parameter, and "page" would then be read from the attacker's half.
			name:     "an id carrying a query separator",
			rawQuery: "requestId=" + url.QueryEscape("x&page=9"),
			wantId:   "x&page=9",
			wantLink: "/admin/settings/audit-log-viewer?requestId=x%26page%3D9",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bind, apiClient := renderAuditLogsWithQuery(t, tc.rawQuery, 50)

			assert.Equal(t, []string{tc.wantId}, apiClient.requestIds,
				"the request id the API was asked for")
			assert.Equal(t, []string{tc.wantEvent}, apiClient.events,
				"the event the API was asked for")

			assert.Equal(t, tc.wantId, bind["selectedRequestId"], "selectedRequestId")
			assert.Equal(t, tc.wantEvent, bind["selectedEvent"], "selectedEvent")
			assert.Equal(t, tc.wantLink, bind["paginatorLink"], "paginatorLink")

			result, ok := bind["pageResult"].(AuditLogsPageResult)
			require.True(t, ok, "pageResult")
			assert.Equal(t, tc.wantId, result.RequestId, "pageResult.RequestId")
			assert.Equal(t, tc.wantEvent, result.AuditEvent, "pageResult.AuditEvent")
		})
	}
}

// TestHandleAdminSettingsAuditLogViewerGet_TheRequestIdFilterSurvivesTheSecondQuery is
// the event filter's case from #305 for the second filter: the clamp repeats the whole
// call, and one that forgot the id would page through the unfiltered log while the input
// still showed an id.
func TestHandleAdminSettingsAuditLogViewerGet_TheRequestIdFilterSurvivesTheSecondQuery(t *testing.T) {
	_, apiClient := renderAuditLogsWithQuery(t, "page=99&auditEvent=user_login&requestId=an-id", 50)

	require.Equal(t, 2, len(apiClient.asked), "the clamp should have cost a second query")
	assert.Equal(t, []string{"an-id", "an-id"}, apiClient.requestIds,
		"the request id filter was dropped on the way")
	assert.Equal(t, []string{"user_login", "user_login"}, apiClient.events,
		"the event filter was dropped on the way")
}

// TestAuditLogViewerLink owns the base URL the paginator appends "page" to. It is the
// one string on the page built from a client-chosen value, so every byte a request id
// can carry is escaped here: addUrlParam parses this string, and anything it reads as a
// separator becomes a parameter the handler would believe over its own.
func TestAuditLogViewerLink(t *testing.T) {
	testCases := []struct {
		name       string
		auditEvent string
		requestId  string
		want       string
	}{
		{"neither", "", "", "/admin/settings/audit-log-viewer"},
		{"the event alone", "user_login", "", "/admin/settings/audit-log-viewer?auditEvent=user_login"},
		{"the id alone", "", "an-id", "/admin/settings/audit-log-viewer?requestId=an-id"},
		{"both", "user_login", "an-id", "/admin/settings/audit-log-viewer?auditEvent=user_login&requestId=an-id"},
		{"an ampersand", "", "x&page=9", "/admin/settings/audit-log-viewer?requestId=x%26page%3D9"},
		{"a fragment marker", "", "x#y", "/admin/settings/audit-log-viewer?requestId=x%23y"},
		{"a space", "", "x y", "/admin/settings/audit-log-viewer?requestId=x+y"},
		{"a quote and a tag", "", `"><script>`, "/admin/settings/audit-log-viewer?requestId=%22%3E%3Cscript%3E"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			link := auditLogViewerLink(tc.auditEvent, tc.requestId)
			assert.Equal(t, tc.want, link)

			// What the paginator then does with it: the page number must be the
			// only "page" in the result, and the filters must survive the round
			// trip byte for byte.
			parsed, err := url.Parse(link)
			require.NoError(t, err)
			assert.Equal(t, tc.requestId, parsed.Query().Get("requestId"), "the id did not round-trip")
			assert.Equal(t, tc.auditEvent, parsed.Query().Get("auditEvent"), "the event did not round-trip")
			assert.Empty(t, parsed.Query()["page"], "the link already carries a page")
			assert.Empty(t, parsed.Fragment, "part of the link fell into a fragment")
		})
	}
}

func currentPage(t *testing.T, p *pagination.Paginator) int {
	t.Helper()

	current := 0
	for _, page := range p.Pages {
		if page.IsCurrent {
			require.Equal(t, 0, current, "the bar highlights more than one page")
			require.NotEqual(t, -1, page.Num, "the bar highlights an ellipsis")
			current = page.Num
		}
	}
	require.NotZero(t, current, "the bar highlights nothing")
	return current
}

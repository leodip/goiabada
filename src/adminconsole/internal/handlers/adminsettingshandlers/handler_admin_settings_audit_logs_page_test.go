package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
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
}

func (c *auditPagingApiClient) GetAuditLogsPaginated(accessToken string, page, pageSize int,
	auditEvent string, requestId string) (*api.GetAuditLogsResponse, error) {

	c.asked = append(c.asked, page)
	c.events = append(c.events, auditEvent)

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

package admingrouphandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/constants"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

// The group members list is one of the three admin lists that answered 500 to a
// "?page=" it could not use: "page=abc" and "page=0" each ended the request with
// an error screen, where the user list beside it showed page 1. It also kept a
// page past the end for the query, so "?page=99" over three pages rendered an
// empty table under a bar highlighting page 3 (#305).
//
// Both halves are asserted here: nothing below answers 500, and the rows and the
// bar always name the same page.

type membersPagingApiClient struct {
	apiclient.ApiClient
	total int
	asked []int
}

func (c *membersPagingApiClient) GetGroupById(accessToken string, groupId int64) (*models.Group, int, error) {
	return &models.Group{Id: groupId, GroupIdentifier: "some-group"}, 0, nil
}

func (c *membersPagingApiClient) GetGroupMembers(accessToken string, groupId int64,
	page, size int) ([]models.User, int, error) {

	c.asked = append(c.asked, page)
	return membersOnPage(c.total, page, size), c.total, nil
}

// membersOnPage is the slice of a list of total members that page holds, each
// member's Id being its 1-based position in the whole list. The start < 0 arm
// stands for the negative SQL offset a real API cannot serve.
func membersOnPage(total, page, pageSize int) []models.User {
	start := (page - 1) * pageSize
	if start < 0 || start >= total {
		return nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	users := make([]models.User, 0, end-start)
	for i := start; i < end; i++ {
		users = append(users, models.User{Id: int64(i + 1)})
	}
	return users
}

func renderMembers(t *testing.T, rawPage string, total int) (map[string]interface{}, []int) {
	t.Helper()

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			t.Errorf("the handler answered 500: %v", args.Get(2))
		}).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/admin_groups_members.html", mock.Anything).
		Return(nil).Maybe()

	target := "/admin/groups/3/members"
	if rawPage != "" {
		target += "?page=" + rawPage
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)

	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("groupId", "3")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx)
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}})

	apiClient := &membersPagingApiClient{total: total}
	HandleAdminGroupMembersGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))

	var bind map[string]interface{}
	for _, call := range httpHelper.Calls {
		if call.Method == "RenderTemplate" {
			bind = call.Arguments.Get(4).(map[string]interface{})
		}
	}
	require.NotNil(t, bind, "the handler rendered nothing for ?page=%q", rawPage)
	return bind, apiClient.asked
}

func TestHandleAdminGroupMembersGet_PageQueryParameter(t *testing.T) {
	const pageSize = 10

	testCases := []struct {
		name      string
		raw       string
		total     int
		wantPage  int
		wantAsked []int
		why       string
	}{
		// Every row in this block used to end in a 500.
		{"a word", "abc", 25, 1, []int{1}, "unparseable is page 1, not 500"},
		{"a decimal", "1.5", 25, 1, []int{1}, "still unparseable"},
		{"zero", "0", 25, 1, []int{1}, "zero is page 1, not 500"},
		{"negative", "-5", 25, 1, []int{1}, "negative is page 1, not 500"},
		{"past the largest int", "9223372036854775808", 25, 1, []int{1}, "out of range is page 1, not 500"},

		{"absent", "", 25, 1, []int{1}, "no parameter is page 1"},
		{"the first page", "1", 25, 1, []int{1}, "page 1 of three"},
		{"a middle page", "2", 25, 2, []int{2}, "asked once, no second query"},
		{"the last page", "3", 25, 3, []int{3}, "asked once"},

		{"one past the last", "4", 25, 3, []int{4, 3}, "clamped to the last page"},
		{"far past the last", "99", 25, 3, []int{99, 3}, "the reported case"},
		{"a group with no members", "5", 0, 1, []int{5, 1}, "an empty list still has a page 1"},
		{"the largest int", "9223372036854775807", 25, 3, nil, "bounded, then clamped"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bind, asked := renderMembers(t, tc.raw, tc.total)

			if tc.wantAsked != nil {
				assert.Equal(t, tc.wantAsked, asked, "pages asked of the API: %s", tc.why)
			}
			require.NotEmpty(t, asked, "the handler asked for nothing")
			require.LessOrEqual(t, len(asked), 2, "the handler asked more than twice")
			for i, page := range asked {
				assert.GreaterOrEqual(t, page, 1, "call %d asked for page %d", i, page)
				assert.GreaterOrEqual(t, (page-1)*pageSize, 0,
					"call %d asked for page %d, whose offset wrapped", i, page)
			}

			result, ok := bind["pageResult"].(PageResult)
			require.True(t, ok, "pageResult")
			assert.Equal(t, tc.wantPage, result.Page, "pageResult.Page: %s", tc.why)

			paginator, ok := bind["paginator"].(*pagination.Paginator)
			require.True(t, ok, "paginator")
			assert.Equal(t, tc.wantPage, currentPage(t, paginator),
				"the bar highlights a different page than the rows came from: %s", tc.why)

			assert.Equal(t, membersOnPage(tc.total, tc.wantPage, pageSize), result.Users,
				"the rows are not page %d's: %s", tc.wantPage, tc.why)
			if tc.total > 0 {
				require.NotEmpty(t, result.Users, "page %d rendered no rows at all", tc.wantPage)
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

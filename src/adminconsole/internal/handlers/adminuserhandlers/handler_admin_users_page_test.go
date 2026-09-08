package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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

// The user list is one of the five admin lists that page, and the five used to
// read "?page=" three different ways: this one and the audit log viewer turned
// anything unusable into page 1, while the other three answered 500. None of
// them clamped a page past the end, so "?page=99" over three pages rendered an
// empty table under a bar highlighting page 3 -- the bar clamped and the query
// did not (#305).
//
// The cases below are that whole contract at the handler, rather than at
// pagination.ParsePage and pagination.ClampPage where the arithmetic is tested:
// what the handler asks the API for, what it settles on, and that the rows and
// the bar name the same page.

// usersPagingApiClient answers the search from a list of a fixed size and
// records every page it was asked for, in order, which is what makes the second
// query after a clamp visible -- and its absence, when the page was already
// good, equally visible.
type usersPagingApiClient struct {
	apiclient.ApiClient
	total int
	asked []int
}

func (c *usersPagingApiClient) SearchUsersPaginated(accessToken, query string,
	page, pageSize int) ([]models.User, int, error) {

	c.asked = append(c.asked, page)
	return usersOnPage(c.total, page, pageSize), c.total, nil
}

// usersOnPage is the slice of a list of total users that page holds, each
// user's Id being its 1-based position in the whole list, so the rows a handler
// binds say which page they came from.
//
// The start < 0 arm is what a real API cannot have: it stands for the SQL
// "OFFSET (page-1)*size" going negative, which the auth server answers 500 to.
// Returning no rows here is the more forgiving of the two, so a test that
// passes has not leaned on the stub being kind.
func usersOnPage(total, page, pageSize int) []models.User {
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

// renderUsers runs the GET once for the given raw "?page=" value over a list of
// total users, and returns what the handler bound and which pages it asked for.
//
// InternalServerError is allowed but fails the test with the error it was
// given: three of these five handlers used to answer 500 to values this test
// sends, so "did not answer 500" is half of what is being asserted and deserves
// to read as itself rather than as a missing bind.
func renderUsers(t *testing.T, rawPage string, total int) (map[string]interface{}, []int) {
	t.Helper()

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			t.Errorf("the handler answered 500: %v", args.Get(2))
		}).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/admin_users.html", mock.Anything).
		Return(nil).Maybe()

	target := "/admin/users"
	if rawPage != "" {
		target += "?page=" + rawPage
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

	apiClient := &usersPagingApiClient{total: total}

	// A panic here is a failure, not a crash to explain: the sibling
	// groups-with-permission page panicked on a page number this test also
	// sends.
	HandleAdminUsersGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	var bind map[string]interface{}
	for _, call := range httpHelper.Calls {
		if call.Method == "RenderTemplate" {
			bind = call.Arguments.Get(4).(map[string]interface{})
		}
	}
	require.NotNil(t, bind, "the handler rendered nothing for ?page=%q", rawPage)
	return bind, apiClient.asked
}

func TestHandleAdminUsersGet_PageQueryParameter(t *testing.T) {
	const pageSize = 10

	testCases := []struct {
		name string
		raw  string
		// total is the size of the list behind the search.
		total int
		// wantPage is the page the handler must settle on: the page the rows
		// come from, the page bound in pageResult, and the page the bar
		// highlights.
		wantPage int
		// wantAsked is every page passed to the API, in order. A single entry
		// means the handler did not spend a second query; two mean it clamped
		// and asked again. Nil skips the check, for a raw value whose first
		// page is pagination's internal bound.
		wantAsked []int
		why       string
	}{
		// Unusable input. Every row here is one this handler already clamped,
		// and three of its four siblings answered 500 to.
		{"absent", "", 25, 1, []int{1}, "no parameter is page 1"},
		{"empty", "", 25, 1, []int{1}, "an empty parameter is page 1"},
		{"a word", "abc", 25, 1, []int{1}, "unparseable is page 1, not 500"},
		{"a decimal", "1.5", 25, 1, []int{1}, "still unparseable"},
		{"zero", "0", 25, 1, []int{1}, "pages are one-based"},
		{"negative", "-5", 25, 1, []int{1}, "negative is page 1, not 500"},
		{"an injection attempt", "2%20OR%201=1", 25, 1, []int{1}, "just an unparseable page"},

		// Inside the list: asked for once, and no second query spent.
		{"the first page", "1", 25, 1, []int{1}, "page 1 of three"},
		{"a middle page", "2", 25, 2, []int{2}, "page 2 of three, asked once"},
		{"the last page", "3", 25, 3, []int{3}, "page 3 of three, asked once"},
		{"an exact multiple", "3", 30, 3, []int{3}, "thirty rows is three pages, not four"},

		// Past the end: clamped to the last page, and asked again so the rows
		// match the bar. This is the report's own example.
		{"one past the last", "4", 25, 3, []int{4, 3}, "clamped to the last page"},
		{"far past the last", "99", 25, 3, []int{99, 3}, "the reported case"},
		{"past the end of one page", "7", 4, 1, []int{7, 1}, "a list smaller than a page"},

		// An empty list still has a page 1, holding a lone "[1]".
		{"an empty list", "5", 0, 1, []int{5, 1}, "nothing to show, on page 1"},
		{"an empty list, page 1", "1", 0, 1, []int{1}, "already page 1, asked once"},

		// The overflow. Unbounded, this reached the API as math.MaxInt and the
		// SQL offset built from it wrapped negative; the sibling
		// groups-with-permission page turned the same product into a slice
		// offset and panicked on it. The first page asked for is pagination's
		// internal bound, so only the settled page is pinned here -- the offset
		// property itself is asserted for every case below.
		{"the largest int", "9223372036854775807", 25, 3, nil, "bounded, then clamped to the last page"},
		{"past the largest int", "9223372036854775808", 25, 1, []int{1}, "does not parse at all"},
		{"a large power of two", "1099511627776", 25, 3, nil, "clamped like any page past the end"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bind, asked := renderUsers(t, tc.raw, tc.total)

			if tc.wantAsked != nil {
				assert.Equal(t, tc.wantAsked, asked, "pages asked of the API: %s", tc.why)
			}

			// Whatever was asked for, it was a page, and the offset built from
			// it did not wrap. This is the property that keeps a negative SQL
			// OFFSET, and the sibling page's slice panic, out of reach.
			require.NotEmpty(t, asked, "the handler asked for nothing")
			require.LessOrEqual(t, len(asked), 2, "the handler asked more than twice")
			for i, page := range asked {
				assert.GreaterOrEqual(t, page, 1, "call %d asked for page %d", i, page)
				assert.GreaterOrEqual(t, (page-1)*pageSize, 0,
					"call %d asked for page %d, whose offset wrapped", i, page)
			}
			assert.Equal(t, tc.wantPage, asked[len(asked)-1], "the page finally asked for: %s", tc.why)

			// The three things the page shows must name the same page: the
			// rows, the page number bound beside them, and the bar.
			result, ok := bind["pageResult"].(PageResult)
			require.True(t, ok, "pageResult")
			assert.Equal(t, tc.wantPage, result.Page, "pageResult.Page: %s", tc.why)
			assert.Equal(t, tc.total, result.Total, "pageResult.Total")

			paginator, ok := bind["paginator"].(*pagination.Paginator)
			require.True(t, ok, "paginator")
			assert.Equal(t, tc.wantPage, currentPage(t, paginator),
				"the bar highlights a different page than the rows came from: %s", tc.why)

			// And the rows are that page's rows. Ids are 1-based positions in
			// the whole list, so the first one says which page this is -- an
			// empty table under a bar highlighting the last page is exactly the
			// bug, and it would pass every assertion above.
			assert.Equal(t, usersOnPage(tc.total, tc.wantPage, pageSize), result.Users,
				"the rows are not page %d's: %s", tc.wantPage, tc.why)
			if tc.total > 0 {
				require.NotEmpty(t, result.Users, "page %d rendered no rows at all", tc.wantPage)
				assert.Equal(t, int64((tc.wantPage-1)*pageSize+1), result.Users[0].Id,
					"the first row is not the first of page %d", tc.wantPage)
			}
		})
	}
}

// currentPage is the page the bar draws as current, which is what a person
// looking at the screen would say they are on.
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

// TestHandleAdminUsersGet_ASearchIsCarriedIntoTheSecondQuery pins the argument
// the clamp is most likely to drop. The re-query repeats the whole call, and a
// second query that forgot the search box would page through every user while
// the bar and the search field still said otherwise.
func TestHandleAdminUsersGet_ASearchIsCarriedIntoTheSecondQuery(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { t.Errorf("the handler answered 500: %v", args.Get(2)) }).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Maybe()

	apiClient := &queryRecordingApiClient{total: 25}

	req := httptest.NewRequest(http.MethodGet, "/admin/users?page=99&query=ana", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

	HandleAdminUsersGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), req)

	require.Equal(t, 2, len(apiClient.queries), "the clamp should have cost a second query")
	assert.Equal(t, []string{"ana", "ana"}, apiClient.queries, "the search text was dropped on the way")
	assert.Equal(t, []string{"an-access-token", "an-access-token"}, apiClient.tokens,
		"the access token was dropped on the way")
}

type queryRecordingApiClient struct {
	apiclient.ApiClient
	total   int
	queries []string
	tokens  []string
}

func (c *queryRecordingApiClient) SearchUsersPaginated(accessToken, query string,
	page, pageSize int) ([]models.User, int, error) {

	c.queries = append(c.queries, query)
	c.tokens = append(c.tokens, accessToken)
	return usersOnPage(c.total, page, pageSize), c.total, nil
}

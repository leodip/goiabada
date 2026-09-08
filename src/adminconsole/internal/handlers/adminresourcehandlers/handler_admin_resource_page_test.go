package adminresourcehandlers

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The two "with permission" pages are the other two of the three admin lists
// that answered 500 to a "?page=" they could not use, and the groups one holds
// the only page offset the admin console computes for itself:
//
//	start := (pageInt - 1) * pageSize
//	...
//	pageGroups := allGroups[start:end]
//
// pageInt was checked only for being at least 1, so
// "?page=9223372036854775807" wrapped that product negative. The two guards
// below it bounded only from above, so they never saw it, and the slice
// panicked before anything rendered (#305). That is the case named
// TheOverflowingPageDoesNotPanic below; it is reachable only on a resource with
// no permissions defined, which is the arm that slices the list here rather
// than asking the API for a page of it.

// resourcePagingApiClient answers everything both handlers ask, from lists of a
// fixed size, and records the pages it was asked for.
type resourcePagingApiClient struct {
	apiclient.ApiClient

	// permissions is what the resource has; empty is the arm that paginates in
	// the handler.
	permissions []models.Permission
	total       int
	asked       []int
}

func (c *resourcePagingApiClient) GetResourceById(accessToken string, resourceId int64) (*models.Resource, error) {
	return &models.Resource{Id: resourceId, ResourceIdentifier: "some-resource"}, nil
}

func (c *resourcePagingApiClient) GetPermissionsByResource(accessToken string, resourceId int64) ([]models.Permission, error) {
	return c.permissions, nil
}

// GetAllGroups is the whole list, unpaginated: the handler slices it itself.
func (c *resourcePagingApiClient) GetAllGroups(accessToken string) ([]models.Group, error) {
	groups := make([]models.Group, 0, c.total)
	for i := 0; i < c.total; i++ {
		groups = append(groups, models.Group{Id: int64(i + 1), GroupIdentifier: "g" + strconv.Itoa(i+1)})
	}
	return groups, nil
}

func (c *resourcePagingApiClient) SearchGroupsWithPermissionAnnotation(accessToken string,
	permissionId int64, page, size int) ([]api.GroupWithPermissionResponse, int, error) {

	c.asked = append(c.asked, page)

	start, end, ok := window(c.total, page, size)
	if !ok {
		return nil, c.total, nil
	}
	groups := make([]api.GroupWithPermissionResponse, 0, end-start)
	for i := start; i < end; i++ {
		groups = append(groups, api.GroupWithPermissionResponse{
			GroupResponse: api.GroupResponse{Id: int64(i + 1), GroupIdentifier: "g" + strconv.Itoa(i+1)},
		})
	}
	return groups, c.total, nil
}

func (c *resourcePagingApiClient) GetUsersByPermission(accessToken string,
	permissionId int64, page, size int) ([]models.User, int, error) {

	c.asked = append(c.asked, page)

	start, end, ok := window(c.total, page, size)
	if !ok {
		return nil, c.total, nil
	}
	users := make([]models.User, 0, end-start)
	for i := start; i < end; i++ {
		users = append(users, models.User{Id: int64(i + 1)})
	}
	return users, c.total, nil
}

// window is the half-open range of a list of total items that page covers, and
// whether there is one at all. The start < 0 arm stands for the negative SQL
// offset a real API cannot serve.
func window(total, page, pageSize int) (start, end int, ok bool) {
	start = (page - 1) * pageSize
	if start < 0 || start >= total {
		return 0, 0, false
	}
	end = start + pageSize
	if end > total {
		end = total
	}
	return start, end, true
}

// aPermission is the one permission a resource has in the cases that exercise
// the API-backed arm.
func aPermission() []models.Permission {
	return []models.Permission{{Id: 42, PermissionIdentifier: "manage"}}
}

// testStore is a real session store over an in-memory backend, because both
// handlers read a flash out of the session before they render.
func testStore() *sessionstore.ServerSideStore {
	store, err := sessionstore.NewServerSideStore(
		sessionstore.NewMemoryBackend(),
		constants.SessionKeyJwt,
		false,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		},
		nil,
	)
	if err != nil {
		panic(err)
	}
	return store
}

// render runs one of the two GETs and returns what it bound and the pages it
// asked the API for. A 500 fails the test with the error it carried, since
// answering 500 to a typed page is half of what is being fixed.
func render(t *testing.T, handler http.HandlerFunc, template, rawPage string,
	httpHelper *mocks_handler_helpers.HttpHelper) map[string]interface{} {

	t.Helper()

	target := "/admin/resources/7/" + template
	if rawPage != "" {
		target += "?page=" + rawPage
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)

	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("resourceId", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx)
	ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}})

	handler.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))

	var bind map[string]interface{}
	for _, call := range httpHelper.Calls {
		if call.Method == "RenderTemplate" {
			bind = call.Arguments.Get(4).(map[string]interface{})
		}
	}
	require.NotNil(t, bind, "the handler rendered nothing for ?page=%q", rawPage)
	return bind
}

// newHelper is a helper mock that renders, and that fails the test rather than
// the request if the handler reaches for a 500.
func newHelper(t *testing.T) *mocks_handler_helpers.HttpHelper {
	t.Helper()

	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			t.Errorf("the handler answered 500: %v", args.Get(2))
		}).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Maybe()
	return httpHelper
}

func TestHandleAdminResourceGroupsWithPermissionGet_PageQueryParameter(t *testing.T) {
	const pageSize = 10

	testCases := []struct {
		name string
		raw  string
		// noPermissions takes the arm that slices the list in the handler,
		// which is where the panic was.
		noPermissions bool
		total         int
		wantPage      int
		wantAsked     []int
		why           string
	}{
		// These all used to end in a 500.
		{"a word", "abc", false, 25, 1, []int{1}, "unparseable is page 1, not 500"},
		{"zero", "0", false, 25, 1, []int{1}, "zero is page 1, not 500"},
		{"negative", "-5", false, 25, 1, []int{1}, "negative is page 1, not 500"},
		{"past the largest int", "9223372036854775808", false, 25, 1, []int{1}, "out of range is page 1, not 500"},

		{"absent", "", false, 25, 1, []int{1}, "no parameter is page 1"},
		{"a middle page", "2", false, 25, 2, []int{2}, "asked once, no second query"},
		{"the last page", "3", false, 25, 3, []int{3}, "asked once"},
		{"one past the last", "4", false, 25, 3, []int{4, 3}, "clamped to the last page"},
		{"far past the last", "99", false, 25, 3, []int{99, 3}, "the reported case"},
		{"the largest int", "9223372036854775807", false, 25, 3, nil, "bounded, then clamped"},

		// The arm that slices the list here. No API call carries a page, so
		// wantAsked is empty throughout: the clamp is arithmetic, not a second
		// query.
		{"no permissions, absent", "", true, 25, 1, []int{}, "page 1 of the whole group list"},
		{"no permissions, a word", "abc", true, 25, 1, []int{}, "unparseable is page 1, not 500"},
		{"no permissions, zero", "0", true, 25, 1, []int{}, "zero is page 1, not 500"},
		{"no permissions, a middle page", "2", true, 25, 2, []int{}, "sliced, not queried"},
		{"no permissions, past the last", "99", true, 25, 3, []int{}, "clamped to the last page"},
		{"no permissions, no groups", "3", true, 0, 1, []int{}, "an empty list still has a page 1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &resourcePagingApiClient{total: tc.total}
			if !tc.noPermissions {
				apiClient.permissions = aPermission()
			}

			httpHelper := newHelper(t)
			handler := HandleAdminResourceGroupsWithPermissionGet(httpHelper, testStore(), apiClient)
			bind := render(t, handler, "groups-with-permission", tc.raw, httpHelper)

			assertAsked(t, tc.wantAsked, apiClient.asked, tc.why)
			for i, page := range apiClient.asked {
				assert.GreaterOrEqual(t, page, 1, "call %d asked for page %d", i, page)
				assert.GreaterOrEqual(t, (page-1)*pageSize, 0,
					"call %d asked for page %d, whose offset wrapped", i, page)
			}

			result, ok := bind["pageResult"].(GroupsWithPermissionPageResult)
			require.True(t, ok, "pageResult")
			assert.Equal(t, tc.wantPage, result.Page, "pageResult.Page: %s", tc.why)
			assert.Equal(t, tc.total, result.Total, "pageResult.Total")

			paginator, ok := bind["paginator"].(*pagination.Paginator)
			require.True(t, ok, "paginator")
			assert.Equal(t, tc.wantPage, currentPage(t, paginator),
				"the bar highlights a different page than the rows came from: %s", tc.why)

			// The rows are that page's rows. Ids are 1-based positions in the
			// whole list, so the first one says which page this is.
			if tc.total > 0 {
				require.NotEmpty(t, result.Groups, "page %d rendered no rows at all", tc.wantPage)
				assert.Equal(t, int64((tc.wantPage-1)*pageSize+1), result.Groups[0].Id,
					"the first row is not the first of page %d", tc.wantPage)
			} else {
				assert.Empty(t, result.Groups)
			}
		})
	}
}

// TestHandleAdminResourceGroupsWithPermissionGet_TheOverflowingPageDoesNotPanic
// is the reported bug itself, run as the report describes it: a resource with
// no permissions, and a page number large enough that "(page-1)*pageSize" wraps
// negative. That slice expression panicked, so this test fails by panicking
// rather than by an assertion if the bound or the clamp is removed.
//
// The whole int64 top end is swept, not just math.MaxInt, because the wrap
// starts well before the largest int: at pageSize 10 any page above MaxInt/10
// overflows, and every one of those is a page a browser can send.
func TestHandleAdminResourceGroupsWithPermissionGet_TheOverflowingPageDoesNotPanic(t *testing.T) {
	const pageSize = 10

	raws := []string{
		"9223372036854775807", // math.MaxInt: the report's own value
		"9223372036854775806",
		"9223372036854775800",
		strconv.Itoa(math.MaxInt/pageSize + 1), // the first page whose offset wraps
		strconv.Itoa(math.MaxInt / 2),
		"1000000000000000000",
		"1099511627776",
		"2147483648",
	}

	// Every list size around a page boundary, plus an empty one: an empty list
	// is the case where the slice has no room at all for a bad offset to be
	// caught by luck.
	for _, total := range []int{0, 1, 9, 10, 11, 25} {
		for _, raw := range raws {
			t.Run(raw+"_over_"+strconv.Itoa(total), func(t *testing.T) {
				apiClient := &resourcePagingApiClient{total: total} // no permissions
				httpHelper := newHelper(t)
				handler := HandleAdminResourceGroupsWithPermissionGet(httpHelper, testStore(), apiClient)

				bind := render(t, handler, "groups-with-permission", raw, httpHelper)

				// It renders, and it renders the last page rather than nothing:
				// a bound that answered page 1 would be safe but wrong, since
				// every other page past the end lands on the last one.
				result := bind["pageResult"].(GroupsWithPermissionPageResult)
				wantPage := 1
				if total > 0 {
					wantPage = (total + pageSize - 1) / pageSize
				}
				assert.Equal(t, wantPage, result.Page, "a page past the end is the last page")
				assert.Equal(t, wantPage, currentPage(t, bind["paginator"].(*pagination.Paginator)))
				if total > 0 {
					require.NotEmpty(t, result.Groups)
					assert.Equal(t, int64((wantPage-1)*pageSize+1), result.Groups[0].Id)
				}
			})
		}
	}
}

func TestHandleAdminResourceUsersWithPermissionGet_PageQueryParameter(t *testing.T) {
	const pageSize = 10

	testCases := []struct {
		name          string
		raw           string
		noPermissions bool
		total         int
		wantPage      int
		wantAsked     []int
		why           string
	}{
		// These all used to end in a 500.
		{"a word", "abc", false, 25, 1, []int{1}, "unparseable is page 1, not 500"},
		{"zero", "0", false, 25, 1, []int{1}, "zero is page 1, not 500"},
		{"negative", "-5", false, 25, 1, []int{1}, "negative is page 1, not 500"},
		{"past the largest int", "9223372036854775808", false, 25, 1, []int{1}, "out of range is page 1, not 500"},

		{"absent", "", false, 25, 1, []int{1}, "no parameter is page 1"},
		{"a middle page", "2", false, 25, 2, []int{2}, "asked once, no second query"},
		{"the last page", "3", false, 25, 3, []int{3}, "asked once"},
		{"one past the last", "4", false, 25, 3, []int{4, 3}, "clamped to the last page"},
		{"far past the last", "99", false, 25, 3, []int{99, 3}, "the reported case"},
		{"nobody has the permission", "5", false, 0, 1, []int{5, 1}, "an empty list still has a page 1"},
		{"the largest int", "9223372036854775807", false, 25, 3, nil, "bounded, then clamped"},

		// With no permission selected nothing is listed and nothing is asked,
		// so every page number lands on the lone page 1 the bar draws.
		{"no permissions", "", true, 0, 1, []int{}, "nothing to list"},
		{"no permissions, a page", "4", true, 0, 1, []int{}, "still the lone page 1"},
		{"no permissions, the largest int", "9223372036854775807", true, 0, 1, []int{}, "still the lone page 1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiClient := &resourcePagingApiClient{total: tc.total}
			if !tc.noPermissions {
				apiClient.permissions = aPermission()
			}

			httpHelper := newHelper(t)
			handler := HandleAdminResourceUsersWithPermissionGet(httpHelper, testStore(), apiClient)
			bind := render(t, handler, "users-with-permission", tc.raw, httpHelper)

			assertAsked(t, tc.wantAsked, apiClient.asked, tc.why)
			for i, page := range apiClient.asked {
				assert.GreaterOrEqual(t, page, 1, "call %d asked for page %d", i, page)
				assert.GreaterOrEqual(t, (page-1)*pageSize, 0,
					"call %d asked for page %d, whose offset wrapped", i, page)
			}

			result, ok := bind["pageResult"].(UsersWithPermissionPageResult)
			require.True(t, ok, "pageResult")
			assert.Equal(t, tc.wantPage, result.Page, "pageResult.Page: %s", tc.why)
			assert.Equal(t, tc.total, result.Total, "pageResult.Total")

			paginator, ok := bind["paginator"].(*pagination.Paginator)
			require.True(t, ok, "paginator")
			assert.Equal(t, tc.wantPage, currentPage(t, paginator),
				"the bar highlights a different page than the rows came from: %s", tc.why)

			if tc.total > 0 {
				require.NotEmpty(t, result.Users, "page %d rendered no rows at all", tc.wantPage)
				assert.Equal(t, int64((tc.wantPage-1)*pageSize+1), result.Users[0].Id,
					"the first row is not the first of page %d", tc.wantPage)
			} else {
				assert.Empty(t, result.Users)
			}
		})
	}
}

// TestHandleAdminResourceUsersWithPermissionAddGet_PageIsCarriedNotRefused
// covers the sixth reader of "?page=" in the admin console. It does not
// paginate -- it carries the page forward into the link back to the list -- but
// it parsed the value the same strict way, so a page the list beside it
// rendered happily ended this page in a 500 (#305).
func TestHandleAdminResourceUsersWithPermissionAddGet_PageIsCarriedNotRefused(t *testing.T) {
	testCases := []struct {
		raw  string
		want int
	}{
		{"", 1},
		{"abc", 1},
		{"0", 1},
		{"-5", 1},
		{"9223372036854775808", 1},
		{"2", 2},
		{"99", 99}, // carried as it stands; the list it links to does the clamping
	}

	for _, tc := range testCases {
		t.Run(tc.raw, func(t *testing.T) {
			apiClient := &resourcePagingApiClient{permissions: aPermission()}
			httpHelper := newHelper(t)
			handler := HandleAdminResourceUsersWithPermissionAddGet(httpHelper, apiClient)
			bind := render(t, handler, "users-with-permission/add", tc.raw, httpHelper)

			assert.Equal(t, tc.want, bind["page"], "the page carried into the return link")
		})
	}
}

// assertAsked compares the pages the handler asked the API for against the
// pages it should have. A nil want skips the check, for a raw value whose first
// page is pagination's internal bound; an empty want means the handler asked
// nothing at all, which is the arm that slices the list itself.
func assertAsked(t *testing.T, want, got []int, why string) {
	t.Helper()

	switch {
	case want == nil:
	case len(want) == 0:
		assert.Empty(t, got, "the handler queried the API when it should not have: %s", why)
	default:
		assert.Equal(t, want, got, "pages asked of the API: %s", why)
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

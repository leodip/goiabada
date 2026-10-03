package adminresourcehandlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_handlers "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
)

// A request reaching a resource page with no token set on its context is a wiring defect: every
// one of these routes is mounted under RequiresScope. Each handler answers it with the one sentinel
// reqctx declares, through whichever writer its route answers with, and consults the API with
// nothing (#440).
func TestAdminResourceHandlers_AnAbsentTokenSetIsAnsweredWithTheSentinel(t *testing.T) {
	routed := handlertest.WithRouteParam("resourceId", "3")
	grant := func(subject string) []handlertest.Option {
		return []handlertest.Option{routed, handlertest.WithRouteParam(subject, "5"),
			handlertest.WithRouteParam("permissionId", "8")}
	}
	request := func(method, target string, opts ...handlertest.Option) *http.Request {
		return handlertest.Request(method, target, opts...)
	}

	type build func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc
	testCases := []struct {
		name    string
		build   build
		request *http.Request
	}{
		{"HandleAdminResourcesGet", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourcesGet(h, c)
		}, request(http.MethodGet, "/admin/resources")},
		{"HandleAdminResourceNewPost", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceNewPost(h, c)
		}, request(http.MethodPost, "/admin/resources/new",
			handlertest.WithForm(url.Values{"resourceIdentifier": {"some-resource"}}))},
		{"HandleAdminResourceSettingsGet", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceSettingsGet(h, testStore(), c)
		}, request(http.MethodGet, "/admin/resources/3/settings", routed)},
		{"HandleAdminResourceSettingsPost", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceSettingsPost(h, testStore(), c)
		}, request(http.MethodPost, "/admin/resources/3/settings", routed, handlertest.WithForm(url.Values{}))},
		{"HandleAdminResourceDeleteGet", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceDeleteGet(h, c)
		}, request(http.MethodGet, "/admin/resources/3/delete", routed)},
		{"HandleAdminResourceDeletePost", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceDeletePost(h, c)
		}, request(http.MethodPost, "/admin/resources/3/delete", routed, handlertest.WithForm(url.Values{}))},
		{"HandleAdminResourcePermissionsGet", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourcePermissionsGet(h, testStore(), c)
		}, request(http.MethodGet, "/admin/resources/3/permissions", routed)},
		{"HandleAdminResourcePermissionsPost", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourcePermissionsPost(h, testStore(), c)
		}, request(http.MethodPost, "/admin/resources/3/permissions", routed,
			handlertest.WithBody(strings.NewReader(`{"resourceId":3,"permissions":[],"expectedPermissions":[]}`)),
			handlertest.WithContentType("application/json"))},
		{"HandleAdminResourceUsersWithPermissionGet", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceUsersWithPermissionGet(h, testStore(), c)
		}, request(http.MethodGet, "/admin/resources/3/users-with-permission", routed)},
		{"HandleAdminResourceUsersWithPermissionAddGet", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceUsersWithPermissionAddGet(h, c)
		}, request(http.MethodGet, "/admin/resources/3/users-with-permission-add/8", routed,
			handlertest.WithRouteParam("permissionId", "8"))},
		{"HandleAdminResourceUsersWithPermissionSearchGet", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceUsersWithPermissionSearchGet(h, c)
		}, request(http.MethodGet, "/admin/resources/3/users-with-permission-add/8/search?query=jdoe", routed,
			handlertest.WithRouteParam("permissionId", "8"))},
		{"HandleAdminResourceUsersWithPermissionAddPermissionPost", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceUsersWithPermissionAddPermissionPost(h, c)
		}, request(http.MethodPost, "/admin/resources/3/users-with-permission/add/5/8", grant("userId")...)},
		{"HandleAdminResourceUsersWithPermissionRemovePermissionPost", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceUsersWithPermissionRemovePermissionPost(h, c)
		}, request(http.MethodPost, "/admin/resources/3/users-with-permission/remove/5/8", grant("userId")...)},
		{"HandleAdminResourceGroupsWithPermissionGet", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceGroupsWithPermissionGet(h, testStore(), c)
		}, request(http.MethodGet, "/admin/resources/3/groups-with-permission", routed)},
		{"HandleAdminResourceGroupsWithPermissionAddPermissionPost", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceGroupsWithPermissionAddPermissionPost(h, c)
		}, request(http.MethodPost, "/admin/resources/3/groups-with-permission/add/5/8", grant("groupId")...)},
		{"HandleAdminResourceGroupsWithPermissionRemovePermissionPost", func(h *mocks_handlers.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleAdminResourceGroupsWithPermissionRemovePermissionPost(h, c)
		}, request(http.MethodPost, "/admin/resources/3/groups-with-permission/remove/5/8", grant("groupId")...)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			var answered []error
			record := func(args mock.Arguments) { answered = append(answered, args.Get(2).(error)) }
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()

			apiClient := &resourceCtxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			require.Len(t, answered, 1, "the handler answers once")
			assert.True(t, errors.Is(answered[0], reqctx.ErrNoJwtInfo), "answered with %v", answered[0])
			assert.Empty(t, apiClient.seen, "nothing is asked of the API without a token")
		})
	}
}

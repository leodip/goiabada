package adminresourcehandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
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

	type build func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc
	testCases := []struct {
		name    string
		build   build
		request *http.Request
	}{
		{"HandleListGet", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleListGet(h, c)
		}, request(http.MethodGet, "/admin/resources")},
		{"HandleNewPost", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleNewPost(h, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/resources/new",
			handlertest.WithForm(url.Values{"resourceIdentifier": {"some-resource"}}))},
		{"HandleSettingsGet", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleSettingsGet(h, testStore(), c)
		}, request(http.MethodGet, "/admin/resources/3/settings", routed)},
		{"HandleSettingsPost", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleSettingsPost(h, testStore(), c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/resources/3/settings", routed, handlertest.WithForm(url.Values{}))},
		{"HandleDeleteGet", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleDeleteGet(h, c)
		}, request(http.MethodGet, "/admin/resources/3/delete", routed)},
		{"HandleDeletePost", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleDeletePost(h, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/resources/3/delete", routed, handlertest.WithForm(url.Values{}))},
		{"HandlePermissionsGet", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandlePermissionsGet(h, testStore(), c)
		}, request(http.MethodGet, "/admin/resources/3/permissions", routed)},
		{"HandlePermissionsPost", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandlePermissionsPost(h, testStore(), c)
		}, request(http.MethodPost, "/admin/resources/3/permissions", routed,
			handlertest.WithBody(strings.NewReader(`{"resourceId":3,"permissions":[],"expectedPermissions":[]}`)),
			handlertest.WithContentType("application/json"))},
		{"HandleUsersWithPermissionGet", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleUsersWithPermissionGet(h, testStore(), c)
		}, request(http.MethodGet, "/admin/resources/3/users-with-permission", routed)},
		{"HandleUsersWithPermissionAddGet", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleUsersWithPermissionAddGet(h, c)
		}, request(http.MethodGet, "/admin/resources/3/users-with-permission-add/8", routed,
			handlertest.WithRouteParam("permissionId", "8"))},
		{"HandleUsersWithPermissionSearchGet", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleUsersWithPermissionSearchGet(h, c)
		}, request(http.MethodGet, "/admin/resources/3/users-with-permission-add/8/search?query=jdoe", routed,
			handlertest.WithRouteParam("permissionId", "8"))},
		{"HandleUsersWithPermissionAddPermissionPost", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleUsersWithPermissionAddPermissionPost(h, c)
		}, request(http.MethodPost, "/admin/resources/3/users-with-permission/add/5/8", grant("userId")...)},
		{"HandleUsersWithPermissionRemovePermissionPost", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleUsersWithPermissionRemovePermissionPost(h, c)
		}, request(http.MethodPost, "/admin/resources/3/users-with-permission/remove/5/8", grant("userId")...)},
		{"HandleGroupsWithPermissionGet", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleGroupsWithPermissionGet(h, testStore(), c)
		}, request(http.MethodGet, "/admin/resources/3/groups-with-permission", routed)},
		{"HandleGroupsWithPermissionAddPermissionPost", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleGroupsWithPermissionAddPermissionPost(h, c)
		}, request(http.MethodPost, "/admin/resources/3/groups-with-permission/add/5/8", grant("groupId")...)},
		{"HandleGroupsWithPermissionRemovePermissionPost", func(h *handlersmocks.HttpHelper, c *resourceCtxRecordingApiClient) http.HandlerFunc {
			return HandleGroupsWithPermissionRemovePermissionPost(h, c)
		}, request(http.MethodPost, "/admin/resources/3/groups-with-permission/remove/5/8", grant("groupId")...)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			var answered []error
			record := func(args mock.Arguments) { answered = append(answered, args.Get(2).(error)) }
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()

			apiClient := &resourceCtxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			require.Len(t, answered, 1, "the handler answers once")
			require.ErrorIs(t, answered[0], reqctx.ErrNoJwtInfo, "answered with %v", answered[0])
			assert.Empty(t, apiClient.seen, "nothing is asked of the API without a token")
		})
	}
}

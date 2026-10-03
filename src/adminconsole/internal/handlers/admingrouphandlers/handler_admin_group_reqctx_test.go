package admingrouphandlers

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

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlers "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
)

// A request reaching a group page with no token set on its context is a wiring defect: every
// one of these routes is mounted under RequiresScope. Each handler answers it with the one
// sentinel reqctx declares, through whichever writer its route answers with, and consults the API
// with nothing (#440).
func TestAdminGroupHandlers_AnAbsentTokenSetIsAnsweredWithTheSentinel(t *testing.T) {
	routed := handlertest.WithRouteParam("groupId", "3")

	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlers.HttpHelper, apiClient apiclient.ApiClient) http.HandlerFunc
		request *http.Request
	}{
		{"HandleAdminGroupsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupsGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups")},
		{"HandleAdminGroupNewPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupNewPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/new",
			handlertest.WithForm(url.Values{"groupIdentifier": {"a-group"}}))},
		{"HandleAdminGroupAttributesGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupAttributesGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/attributes", routed)},
		{"HandleAdminGroupAttributesRemovePost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupAttributesRemovePost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/attributes/remove/5", routed,
			handlertest.WithRouteParam("attributeId", "5"))},
		{"HandleAdminGroupAttributesAddGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupAttributesAddGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/attributes/add", routed)},
		{"HandleAdminGroupAttributesAddPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupAttributesAddPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/attributes/add", routed,
			handlertest.WithForm(url.Values{"attributeKey": {"a-key"}}))},
		{"HandleAdminGroupAttributesEditGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupAttributesEditGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/attributes/edit/5", routed,
			handlertest.WithRouteParam("attributeId", "5"))},
		{"HandleAdminGroupAttributesEditPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupAttributesEditPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/attributes/edit/5", routed,
			handlertest.WithRouteParam("attributeId", "5"), handlertest.WithForm(url.Values{}))},
		{"HandleAdminGroupDeleteGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupDeleteGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/delete", routed)},
		{"HandleAdminGroupDeletePost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupDeletePost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/delete", routed,
			handlertest.WithForm(url.Values{"groupIdentifier": {"a-group"}}))},
		{"HandleAdminGroupMembersGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupMembersGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/members", routed)},
		{"HandleAdminGroupMembersAddGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupMembersAddGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/members/add", routed)},
		{"HandleAdminGroupMembersSearchGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupMembersSearchGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/members/search?query=jane", routed)},
		{"HandleAdminGroupMembersAddPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupMembersAddPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/members/add?userId=7", routed)},
		{"HandleAdminGroupMembersRemoveUserPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupMembersRemoveUserPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/members/remove/7", routed,
			handlertest.WithRouteParam("userId", "7"))},
		{"HandleAdminGroupPermissionsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupPermissionsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/permissions", routed)},
		{"HandleAdminGroupPermissionsPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupPermissionsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/permissions", routed,
			handlertest.WithBody(strings.NewReader(`{"groupId":3}`)))},
		{"HandleAdminGroupSettingsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupSettingsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/settings", routed)},
		{"HandleAdminGroupSettingsPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminGroupSettingsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/settings", routed,
			handlertest.WithForm(url.Values{}))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			var answered []error
			record := func(args mock.Arguments) { answered = append(answered, args.Get(2).(error)) }
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()

			apiClient := &groupCtxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			require.Len(t, answered, 1, "the handler answers once")
			assert.True(t, errors.Is(answered[0], reqctx.ErrNoJwtInfo), "answered with %v", answered[0])
			assert.Empty(t, apiClient.seen, "nothing is asked of the API without a token")
		})
	}
}

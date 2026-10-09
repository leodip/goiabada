package admingrouphandlers

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

// A request reaching a group page with no token set on its context is a wiring defect: every
// one of these routes is mounted under RequiresScope. Each handler answers it with the one
// sentinel reqctx declares, through whichever writer its route answers with, and consults the API
// with nothing (#440).
func TestAdminGroupHandlers_AnAbsentTokenSetIsAnsweredWithTheSentinel(t *testing.T) {
	routed := handlertest.WithRouteParam("groupId", "3")

	testCases := []struct {
		name    string
		build   func(httpHelper *handlersmocks.HttpHelper, apiClient *groupCtxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{"HandleListGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleListGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups")},
		{"HandleNewPost", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleNewPost(h, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/groups/new",
			handlertest.WithForm(url.Values{"groupIdentifier": {"a-group"}}))},
		{"HandleAttributesGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/attributes", routed)},
		{"HandleAttributesRemovePost", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesRemovePost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/attributes/remove/5", routed,
			handlertest.WithRouteParam("attributeId", "5"))},
		{"HandleAttributesAddGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesAddGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/attributes/add", routed)},
		{"HandleAttributesAddPost", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesAddPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/attributes/add", routed,
			handlertest.WithForm(url.Values{"attributeKey": {"a-key"}}))},
		{"HandleAttributesEditGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesEditGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/attributes/edit/5", routed,
			handlertest.WithRouteParam("attributeId", "5"))},
		{"HandleAttributesEditPost", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesEditPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/attributes/edit/5", routed,
			handlertest.WithRouteParam("attributeId", "5"), handlertest.WithForm(url.Values{}))},
		{"HandleDeleteGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleDeleteGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/delete", routed)},
		{"HandleDeletePost", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleDeletePost(h, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/delete", routed,
			handlertest.WithForm(url.Values{"groupIdentifier": {"a-group"}}))},
		{"HandleMembersGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleMembersGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/members", routed)},
		{"HandleMembersAddGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleMembersAddGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/members/add", routed)},
		{"HandleMembersSearchGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleMembersSearchGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/members/search?query=jane", routed)},
		{"HandleMembersAddPost", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleMembersAddPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/members/add?userId=7", routed)},
		{"HandleMembersRemoveUserPost", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleMembersRemoveUserPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/members/remove/7", routed,
			handlertest.WithRouteParam("userId", "7"))},
		{"HandlePermissionsGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandlePermissionsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/permissions", routed)},
		{"HandlePermissionsPost", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandlePermissionsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/permissions", routed,
			handlertest.WithBody(strings.NewReader(`{"groupId":3}`)))},
		{"HandleSettingsGet", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleSettingsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/groups/3/settings", routed)},
		{"HandleSettingsPost", func(h *handlersmocks.HttpHelper, c *groupCtxRecordingApiClient) http.HandlerFunc {
			return HandleSettingsPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/groups/3/settings", routed,
			handlertest.WithForm(url.Values{}))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			var answered []error
			record := func(args mock.Arguments) { answered = append(answered, args.Get(2).(error)) }
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()

			apiClient := &groupCtxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			require.Len(t, answered, 1, "the handler answers once")
			require.ErrorIs(t, answered[0], reqctx.ErrNoJwtInfo, "answered with %v", answered[0])
			assert.Empty(t, apiClient.seen, "nothing is asked of the API without a token")
		})
	}
}

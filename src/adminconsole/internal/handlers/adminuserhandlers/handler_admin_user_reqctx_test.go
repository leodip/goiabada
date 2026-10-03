package adminuserhandlers

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
	"github.com/leodip/goiabada/core/api"
)

// A request reaching a user page with no token set on its context is a wiring defect: every one of
// these routes is mounted under RequiresScope. Each handler answers it with the one sentinel reqctx
// declares, through whichever writer its route answers with, and consults the API with nothing
// (#440).
func TestAdminUserHandlers_AnAbsentTokenSetIsAnsweredWithTheSentinel(t *testing.T) {
	routed := handlertest.WithRouteParam("userId", "42")
	attribute := handlertest.WithRouteParam("attributeId", "21")
	jsonBody := func(body string) []handlertest.Option {
		return []handlertest.Option{
			handlertest.WithBody(strings.NewReader(body)),
			handlertest.WithContentType("application/json"),
		}
	}
	request := func(method, target string, opts ...handlertest.Option) *http.Request {
		return handlertest.Request(method, target, opts...)
	}

	type build func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc
	testCases := []struct {
		name    string
		build   build
		request *http.Request
	}{
		{"HandleAdminUsersGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUsersGet(h, c)
		}, request(http.MethodGet, "/admin/users")},
		{"HandleAdminUserNewPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserNewPost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/new",
			handlertest.WithSettings(&api.PublicSettingsResponse{}),
			handlertest.WithForm(url.Values{"email": {"jane@example.com"}, "password": {"N3w!word"}}))},
		{"HandleAdminUserDetailsGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserDetailsGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/details", routed)},
		{"HandleAdminUserDetailsPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserDetailsPost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/details", routed,
			handlertest.WithForm(url.Values{"enabled": {"on"}}))},
		{"HandleAdminUserProfileGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserProfileGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/profile", routed)},
		{"HandleAdminUserProfilePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserProfilePost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/profile", routed,
			handlertest.WithForm(url.Values{"username": {"jdoe"}}))},
		{"HandleAdminUserEmailGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserEmailGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/email", routed)},
		{"HandleAdminUserEmailPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserEmailPost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/email", routed,
			handlertest.WithForm(url.Values{"email": {"jane@example.com"}}))},
		{"HandleAdminUserAddressGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAddressGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/address", routed)},
		{"HandleAdminUserAddressPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAddressPost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/address", routed, handlertest.WithForm(url.Values{}))},
		{"HandleAdminUserPhoneGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserPhoneGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/phone", routed)},
		{"HandleAdminUserPhonePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserPhonePost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/phone", routed,
			handlertest.WithForm(url.Values{"phoneCountryUniqueId": {"BRA_0"}, "phoneNumber": {"5551234"}}))},
		{"HandleAdminUserAuthenticationGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAuthenticationGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/authentication", routed)},
		{"HandleAdminUserAuthenticationPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAuthenticationPost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/authentication", routed, handlertest.WithForm(url.Values{}))},
		{"HandleAdminUserPictureGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserPictureGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/picture", routed)},
		{"HandleAdminUserProfilePicturePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserProfilePicturePost(h, c)
		}, request(http.MethodPost, "/admin/users/42/picture", routed)},
		{"HandleAdminUserProfilePictureDelete", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserProfilePictureDelete(h, c)
		}, request(http.MethodDelete, "/admin/users/42/picture", routed)},
		{"HandleAdminUserGroupsGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserGroupsGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/groups", routed)},
		{"HandleAdminUserGroupsPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserGroupsPost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/groups",
			append([]handlertest.Option{routed}, jsonBody(`{"assignedGroupsIds":[5]}`)...)...)},
		{"HandleAdminUserPermissionsGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserPermissionsGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/permissions", routed)},
		{"HandleAdminUserPermissionsPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserPermissionsPost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/permissions",
			append([]handlertest.Option{routed}, jsonBody(`{"assignedPermissionsIds":[5]}`)...)...)},
		{"HandleAdminUserAttributesGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAttributesGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/attributes", routed)},
		{"HandleAdminUserAttributesRemovePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAttributesRemovePost(h, c)
		}, request(http.MethodPost, "/admin/users/42/attributes/21/remove", routed, attribute)},
		{"HandleAdminUserAttributesAddGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAttributesAddGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/attributes/add", routed)},
		{"HandleAdminUserAttributesAddPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAttributesAddPost(h, c)
		}, request(http.MethodPost, "/admin/users/42/attributes/add", routed,
			handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}}))},
		{"HandleAdminUserAttributesEditGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAttributesEditGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/attributes/21/edit", routed, attribute)},
		{"HandleAdminUserAttributesEditPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserAttributesEditPost(h, c)
		}, request(http.MethodPost, "/admin/users/42/attributes/21/edit", routed, attribute,
			handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}}))},
		{"HandleAdminUserConsentsGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserConsentsGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/consents", routed)},
		{"HandleAdminUserConsentsPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserConsentsPost(h, c)
		}, request(http.MethodPost, "/admin/users/42/consents",
			append([]handlertest.Option{routed}, jsonBody(`{"consentId":13}`)...)...)},
		{"HandleAdminUserSessionsGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserSessionsGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/sessions", routed)},
		{"HandleAdminUserSessionsPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserSessionsPost(h, c)
		}, request(http.MethodPost, "/admin/users/42/sessions",
			append([]handlertest.Option{routed}, jsonBody(`{"userSessionId":31}`)...)...)},
		{"HandleAdminUserDeleteGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserDeleteGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/delete", routed)},
		{"HandleAdminUserDeletePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminUserDeletePost(h, c)
		}, request(http.MethodPost, "/admin/users/42/delete", routed, handlertest.WithForm(url.Values{}))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			var answered []error
			record := func(args mock.Arguments) { answered = append(answered, args.Get(2).(error)) }
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()

			apiClient := &ctxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			require.Len(t, answered, 1, "the handler answers once")
			assert.True(t, errors.Is(answered[0], reqctx.ErrNoJwtInfo), "answered with %v", answered[0])
			assert.Empty(t, apiClient.seen, "nothing is asked of the API without a token")
		})
	}
}

// The new-user page and its save read the settings the middleware writes, to draw the password
// control SMTP decides. Without them, which only a wiring defect produces, each answers the one
// sentinel reqctx declares rather than panicking on a nil assertion, and renders nothing (#440).
func TestAdminUserNewPages_AbsentSettingsAreAnsweredWithTheSentinel(t *testing.T) {
	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlers.HttpHelper, apiClient *ctxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleAdminUserNewGet",
			build: func(h *mocks_handlers.HttpHelper, _ *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserNewGet(h)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/new", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminUserNewPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserNewPost(h, nil, c)
			},
			// An empty email is refused before the API, so the settings the refusal page draws
			// from are the first thing the handler needs.
			request: handlertest.Request(http.MethodPost, "/admin/users/new", handlertest.WithAccessToken(),
				handlertest.WithForm(url.Values{"email": {""}})),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			var refusedWith error
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { refusedWith, _ = args.Get(2).(error) }).Once()

			apiClient := &ctxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			assert.True(t, errors.Is(refusedWith, reqctx.ErrNoSettings), "answered with %v", refusedWith)
			httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything)
			assert.Empty(t, apiClient.seen, "nothing is asked of the API without settings")
		})
	}
}

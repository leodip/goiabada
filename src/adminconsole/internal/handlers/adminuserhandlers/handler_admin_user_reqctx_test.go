package adminuserhandlers

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
	request := handlertest.Request

	type build func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc
	testCases := []struct {
		name    string
		build   build
		request *http.Request
	}{
		{"HandleListGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleListGet(h, c)
		}, request(http.MethodGet, "/admin/users")},
		{"HandleNewPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleNewPost(h, nil, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/new",
			handlertest.WithSettings(&api.PublicSettingsResponse{}),
			handlertest.WithForm(url.Values{"email": {"jane@example.com"}, "password": {"N3w!word"}}))},
		{"HandleDetailsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleDetailsGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/details", routed)},
		{"HandleDetailsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleDetailsPost(h, nil, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/42/details", routed,
			handlertest.WithForm(url.Values{"enabled": {"on"}}))},
		{"HandleProfileGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleProfileGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/profile", routed)},
		{"HandleProfilePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleProfilePost(h, nil, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/42/profile", routed,
			handlertest.WithForm(url.Values{"username": {"jdoe"}}))},
		{"HandleEmailGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/email", routed)},
		{"HandleEmailPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailPost(h, nil, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/42/email", routed,
			handlertest.WithForm(url.Values{"email": {"jane@example.com"}}))},
		{"HandleAddressGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAddressGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/address", routed)},
		{"HandleAddressPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAddressPost(h, nil, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/42/address", routed, handlertest.WithForm(url.Values{}))},
		{"HandlePhoneGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePhoneGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/phone", routed)},
		{"HandlePhonePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePhonePost(h, nil, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/42/phone", routed,
			handlertest.WithForm(url.Values{"phoneCountryUniqueId": {"BRA_0"}, "phoneNumber": {"5551234"}}))},
		{"HandleAuthenticationGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAuthenticationGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/authentication", routed)},
		{"HandleAuthenticationPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAuthenticationPost(h, nil, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/42/authentication", routed, handlertest.WithForm(url.Values{}))},
		{"HandlePictureGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePictureGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/picture", routed)},
		{"HandleProfilePicturePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleProfilePicturePost(h, c)
		}, request(http.MethodPost, "/admin/users/42/picture", routed)},
		{"HandleProfilePictureDelete", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleProfilePictureDelete(h, c)
		}, request(http.MethodDelete, "/admin/users/42/picture", routed)},
		{"HandleGroupsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleGroupsGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/groups", routed)},
		{"HandleGroupsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleGroupsPost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/groups",
			append([]handlertest.Option{routed}, jsonBody(`{"assignedGroupsIds":[5]}`)...)...)},
		{"HandlePermissionsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePermissionsGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/permissions", routed)},
		{"HandlePermissionsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePermissionsPost(h, nil, c)
		}, request(http.MethodPost, "/admin/users/42/permissions",
			append([]handlertest.Option{routed}, jsonBody(`{"assignedPermissionsIds":[5]}`)...)...)},
		{"HandleAttributesGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/attributes", routed)},
		{"HandleAttributesRemovePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesRemovePost(h, c)
		}, request(http.MethodPost, "/admin/users/42/attributes/21/remove", routed, attribute)},
		{"HandleAttributesAddGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesAddGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/attributes/add", routed)},
		{"HandleAttributesAddPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesAddPost(h, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/42/attributes/add", routed,
			handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}}))},
		{"HandleAttributesEditGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesEditGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/attributes/21/edit", routed, attribute)},
		{"HandleAttributesEditPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAttributesEditPost(h, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/42/attributes/21/edit", routed, attribute,
			handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}}))},
		{"HandleConsentsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleConsentsGet(h, nil, c)
		}, request(http.MethodGet, "/admin/users/42/consents", routed)},
		{"HandleConsentsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleConsentsPost(h, c)
		}, request(http.MethodPost, "/admin/users/42/consents",
			append([]handlertest.Option{routed}, jsonBody(`{"consentId":13}`)...)...)},
		{"HandleSessionsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleSessionsGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/sessions", routed)},
		{"HandleSessionsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleSessionsPost(h, c)
		}, request(http.MethodPost, "/admin/users/42/sessions",
			append([]handlertest.Option{routed}, jsonBody(`{"userSessionId":31}`)...)...)},
		{"HandleDeleteGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleDeleteGet(h, c)
		}, request(http.MethodGet, "/admin/users/42/delete", routed)},
		{"HandleDeletePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleDeletePost(h, c, consoleBaseURL)
		}, request(http.MethodPost, "/admin/users/42/delete", routed, handlertest.WithForm(url.Values{}))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			var answered []error
			record := func(args mock.Arguments) { answered = append(answered, args.Get(2).(error)) }
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()

			apiClient := &ctxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			require.Len(t, answered, 1, "the handler answers once")
			require.ErrorIs(t, answered[0], reqctx.ErrNoJwtInfo, "answered with %v", answered[0])
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
		build   func(httpHelper *handlersmocks.HttpHelper, apiClient *ctxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleNewGet",
			build: func(h *handlersmocks.HttpHelper, _ *ctxRecordingApiClient) http.HandlerFunc {
				return HandleNewGet(h)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/new", handlertest.WithAccessToken()),
		},
		{
			name: "HandleNewPost",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleNewPost(h, nil, c, consoleBaseURL)
			},
			// An empty email is refused before the API, so the settings the refusal page draws
			// from are the first thing the handler needs.
			request: handlertest.Request(http.MethodPost, "/admin/users/new", handlertest.WithAccessToken(),
				handlertest.WithForm(url.Values{"email": {""}})),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			var refusedWith error
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { refusedWith, _ = args.Get(2).(error) }).Once()

			apiClient := &ctxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			require.ErrorIs(t, refusedWith, reqctx.ErrNoSettings, "answered with %v", refusedWith)
			httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything)
			assert.Empty(t, apiClient.seen, "nothing is asked of the API without settings")
		})
	}
}

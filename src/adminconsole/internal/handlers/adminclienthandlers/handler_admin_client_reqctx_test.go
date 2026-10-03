package adminclienthandlers

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

// A request reaching a client page with no token set on its context is a wiring defect: every
// one of these routes is mounted under RequiresScope. Each handler answers it with the one
// sentinel reqctx declares, through whichever writer its route answers with, and consults the API
// with nothing (#440).
func TestAdminClientHandlers_AnAbsentTokenSetIsAnsweredWithTheSentinel(t *testing.T) {
	routed := handlertest.WithRouteParam("clientId", "3")
	jsonBody := func() handlertest.Option {
		return handlertest.WithBody(strings.NewReader(`{"clientId":3}`))
	}

	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlers.HttpHelper, apiClient apiclient.ApiClient) http.HandlerFunc
		request *http.Request
	}{
		{"HandleAdminClientsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientsGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients")},
		{"HandleAdminClientNewPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientNewPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/new",
			handlertest.WithForm(url.Values{"clientIdentifier": {"a-client"}}))},
		{"HandleAdminClientAuthenticationGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientAuthenticationGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/authentication", routed)},
		{"HandleAdminClientAuthenticationPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientAuthenticationPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/authentication", routed,
			handlertest.WithForm(url.Values{}))},
		{"HandleAdminClientDeleteGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientDeleteGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/delete", routed)},
		{"HandleAdminClientDeletePost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientDeletePost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/delete", routed,
			handlertest.WithForm(url.Values{"clientIdentifier": {"a-client"}}))},
		{"HandleAdminClientLogoGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientLogoGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/logo", routed)},
		{"HandleAdminClientLogoPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientLogoPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/logo", routed)},
		{"HandleAdminClientLogoDelete", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientLogoDelete(h, c)
		}, handlertest.Request(http.MethodDelete, "/admin/clients/3/logo", routed)},
		{"HandleAdminClientOAuth2FlowsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientOAuth2FlowsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/oauth2-flows", routed)},
		{"HandleAdminClientOAuth2FlowsPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientOAuth2FlowsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/oauth2-flows", routed,
			handlertest.WithForm(url.Values{}))},
		{"HandleAdminClientPermissionsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientPermissionsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/permissions", routed)},
		{"HandleAdminClientPermissionsPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientPermissionsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/permissions", routed, jsonBody())},
		{"HandleAdminClientRedirectURIsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientRedirectURIsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/redirect-uris", routed)},
		{"HandleAdminClientRedirectURIsPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientRedirectURIsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/redirect-uris", routed, jsonBody())},
		{"HandleAdminClientUserSessionsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientUserSessionsGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions", routed)},
		{"HandleAdminClientUserSessionsPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientUserSessionsPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/user-sessions", routed,
			handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)),
			handlertest.WithContentType("application/json"))},
		{"HandleAdminClientSettingsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientSettingsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/settings", routed)},
		{"HandleAdminClientSettingsPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientSettingsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/settings", routed,
			handlertest.WithForm(url.Values{}))},
		{"HandleAdminClientTokensGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientTokensGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/tokens", routed)},
		{"HandleAdminClientTokensPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientTokensPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/tokens", routed,
			handlertest.WithForm(url.Values{}))},
		{"HandleAdminClientWebOriginsGet", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientWebOriginsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/web-origins", routed)},
		{"HandleAdminClientWebOriginsPost", func(h *mocks_handlers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
			return HandleAdminClientWebOriginsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/web-origins", routed, jsonBody())},
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

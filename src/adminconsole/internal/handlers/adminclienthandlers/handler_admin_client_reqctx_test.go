package adminclienthandlers

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
		build   func(httpHelper *handlersmocks.HttpHelper, apiClient *ctxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{"HandleListGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleListGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients")},
		{"HandleNewPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleNewPost(h, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/clients/new",
			handlertest.WithForm(url.Values{"clientIdentifier": {"a-client"}}))},
		{"HandleAuthenticationGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAuthenticationGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/authentication", routed)},
		{"HandleAuthenticationPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAuthenticationPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/authentication", routed,
			handlertest.WithForm(url.Values{}))},
		{"HandleDeleteGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleDeleteGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/delete", routed)},
		{"HandleDeletePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleDeletePost(h, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/delete", routed,
			handlertest.WithForm(url.Values{"clientIdentifier": {"a-client"}}))},
		{"HandleLogoGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleLogoGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/logo", routed)},
		{"HandleLogoPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleLogoPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/logo", routed)},
		{"HandleLogoDelete", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleLogoDelete(h, c)
		}, handlertest.Request(http.MethodDelete, "/admin/clients/3/logo", routed)},
		{"HandleOAuth2FlowsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleOAuth2FlowsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/oauth2-flows", routed)},
		{"HandleOAuth2FlowsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleOAuth2FlowsPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/oauth2-flows", routed,
			handlertest.WithForm(url.Values{}))},
		{"HandlePermissionsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePermissionsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/permissions", routed)},
		{"HandlePermissionsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePermissionsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/permissions", routed, jsonBody())},
		{"HandleRedirectURIsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleRedirectURIsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/redirect-uris", routed)},
		{"HandleRedirectURIsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleRedirectURIsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/redirect-uris", routed, jsonBody())},
		{"HandleUserSessionsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleUserSessionsGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions", routed)},
		{"HandleUserSessionsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleUserSessionsPost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/user-sessions", routed,
			handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)),
			handlertest.WithContentType("application/json"))},
		{"HandleSettingsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleSettingsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/settings", routed)},
		{"HandleSettingsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleSettingsPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/settings", routed,
			// The switch on, so the save reaches the allowance's write too.
			handlertest.WithForm(url.Values{"administrativeScopesAllowed": {"on"}}))},
		{"HandleTokensGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleTokensGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/tokens", routed)},
		{"HandleTokensPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleTokensPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/tokens", routed,
			handlertest.WithForm(url.Values{}))},
		{"HandleWebOriginsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleWebOriginsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/clients/3/web-origins", routed)},
		{"HandleWebOriginsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleWebOriginsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/clients/3/web-origins", routed, jsonBody())},
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

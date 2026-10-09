package adminsettingshandlers

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

// A request reaching a settings page with no token set on its context is a wiring defect: every
// one of these routes is mounted under RequiresScope. Each handler answers it with the one
// sentinel reqctx declares, through whichever writer its route answers with, and consults the API
// with nothing (#440).
func TestAdminSettingsHandlers_AnAbsentTokenSetIsAnsweredWithTheSentinel(t *testing.T) {
	testCases := []struct {
		name    string
		build   func(httpHelper *handlersmocks.HttpHelper, apiClient *ctxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{"HandleAuditLogsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAuditLogsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/audit-logs")},
		{"HandleAuditLogsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAuditLogsPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/settings/audit-logs", handlertest.WithForm(url.Values{}))},
		{"HandleAuditLogViewerGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAuditLogViewerGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/audit-log-viewer")},
		{"HandleEmailGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/email")},
		{"HandleEmailPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailPost(h, nil, c, nil, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/settings/email", handlertest.WithForm(url.Values{}))},
		{"HandleEmailSendTestGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailSendTestGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/email/send-test-email")},
		{"HandleEmailSendTestPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailSendTestPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/settings/email/send-test-email",
			handlertest.WithForm(url.Values{"destinationEmail": {"jane@example.com"}}))},
		{"HandleGeneralGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleGeneralGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/general")},
		{"HandleGeneralPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleGeneralPost(h, nil, c, nil, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/settings/general", handlertest.WithForm(url.Values{}))},
		{"HandleKeysGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleKeysGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/keys")},
		{"HandleKeysRotatePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleKeysRotatePost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/settings/keys/rotate")},
		{"HandleKeysRevokePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleKeysRevokePost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/settings/keys/revoke",
			handlertest.WithBody(strings.NewReader(`{"id":7}`)))},
		{"HandleSessionsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleSessionsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/sessions")},
		{"HandleSessionsPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleSessionsPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/settings/sessions", handlertest.WithForm(url.Values{}))},
		{"HandleTokensGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleTokensGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/tokens")},
		{"HandleTokensPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleTokensPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/settings/tokens", handlertest.WithForm(url.Values{}))},
		{"HandleUIThemeGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleUIThemeGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/ui-theme")},
		{"HandleUIThemePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleUIThemePost(h, nil, c, nil, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/admin/settings/ui-theme",
			handlertest.WithForm(url.Values{"themeSelection": {"dark"}}))},
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

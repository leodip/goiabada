package adminsettingshandlers

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

// A request reaching a settings page with no token set on its context is a wiring defect: every
// one of these routes is mounted under RequiresScope. Each handler answers it with the one
// sentinel reqctx declares, through whichever writer its route answers with, and consults the API
// with nothing (#440).
func TestAdminSettingsHandlers_AnAbsentTokenSetIsAnsweredWithTheSentinel(t *testing.T) {
	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlers.HttpHelper, apiClient *ctxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{"HandleAdminSettingsAuditLogsGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsAuditLogsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/audit-logs")},
		{"HandleAdminSettingsAuditLogsPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsAuditLogsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/settings/audit-logs", handlertest.WithForm(url.Values{}))},
		{"HandleAdminSettingsAuditLogViewerGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsAuditLogViewerGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/audit-log-viewer")},
		{"HandleAdminSettingsEmailGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsEmailGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/email")},
		{"HandleAdminSettingsEmailPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsEmailPost(h, nil, c, nil)
		}, handlertest.Request(http.MethodPost, "/admin/settings/email", handlertest.WithForm(url.Values{}))},
		{"HandleAdminSettingsEmailSendTestGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsEmailSendTestGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/email/send-test-email")},
		{"HandleAdminSettingsEmailSendTestPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsEmailSendTestPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/settings/email/send-test-email",
			handlertest.WithForm(url.Values{"destinationEmail": {"jane@example.com"}}))},
		{"HandleAdminSettingsGeneralGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsGeneralGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/general")},
		{"HandleAdminSettingsGeneralPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsGeneralPost(h, nil, c, nil)
		}, handlertest.Request(http.MethodPost, "/admin/settings/general", handlertest.WithForm(url.Values{}))},
		{"HandleAdminSettingsKeysGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsKeysGet(h, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/keys")},
		{"HandleAdminSettingsKeysRotatePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsKeysRotatePost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/settings/keys/rotate")},
		{"HandleAdminSettingsKeysRevokePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsKeysRevokePost(h, c)
		}, handlertest.Request(http.MethodPost, "/admin/settings/keys/revoke",
			handlertest.WithBody(strings.NewReader(`{"id":7}`)))},
		{"HandleAdminSettingsSessionsGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsSessionsGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/sessions")},
		{"HandleAdminSettingsSessionsPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsSessionsPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/settings/sessions", handlertest.WithForm(url.Values{}))},
		{"HandleAdminSettingsTokensGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsTokensGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/tokens")},
		{"HandleAdminSettingsTokensPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsTokensPost(h, nil, c)
		}, handlertest.Request(http.MethodPost, "/admin/settings/tokens", handlertest.WithForm(url.Values{}))},
		{"HandleAdminSettingsUIThemeGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsUIThemeGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/admin/settings/ui-theme")},
		{"HandleAdminSettingsUIThemePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAdminSettingsUIThemePost(h, nil, c, nil)
		}, handlertest.Request(http.MethodPost, "/admin/settings/ui-theme",
			handlertest.WithForm(url.Values{"themeSelection": {"dark"}}))},
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

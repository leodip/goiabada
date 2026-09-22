package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// Seam 4 for the settings pages (#386). See accounthandlers' file of the same name for what this
// owns and why the context is the assertion: the compiler accepts context.Background() where
// r.Context() belongs, so nothing else in the tree can see a handler that stopped carrying the
// request's cancellation into its outbound call.

type settingsCtxMarkerKey struct{}

// ctxRecordingApiClient records the context every settings method is called with and then refuses,
// so the handler takes its error path in the same pass.
type ctxRecordingApiClient struct {
	apiclient.ApiClient
	seen []context.Context
}

func (s *ctxRecordingApiClient) record(ctx context.Context) error {
	s.seen = append(s.seen, ctx)
	return errs.New("the auth server refused")
}

func (s *ctxRecordingApiClient) GetSettingsAuditLogs(ctx context.Context, _ string) (*api.SettingsAuditLogsResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateSettingsAuditLogs(ctx context.Context, _ string, _ *api.UpdateSettingsAuditLogsRequest) (*api.SettingsAuditLogsResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetAuditLogsPaginated(ctx context.Context, _ string, _, _ int, _, _ string) (*api.GetAuditLogsResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetAuditEventTypes(ctx context.Context, _ string) (*api.GetAuditEventTypesResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetSettingsEmail(ctx context.Context, _ string) (*api.SettingsEmailResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateSettingsEmail(ctx context.Context, _ string, _ *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) SendTestEmail(ctx context.Context, _ string, _ *api.SendTestEmailRequest) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) GetSettingsGeneral(ctx context.Context, _ string) (*api.SettingsGeneralResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateSettingsGeneral(ctx context.Context, _ string, _ *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetSettingsKeys(ctx context.Context, _ string) ([]api.SettingsSigningKeyResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) RotateSettingsKeys(ctx context.Context, _ string) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteSettingsKey(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) GetSettingsSessions(ctx context.Context, _ string) (*api.SettingsSessionsResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateSettingsSessions(ctx context.Context, _ string, _ *api.UpdateSettingsSessionsRequest) (*api.SettingsSessionsResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetSettingsTokens(ctx context.Context, _ string) (*api.SettingsTokensResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateSettingsTokens(ctx context.Context, _ string, _ *api.UpdateSettingsTokensRequest) (*api.SettingsTokensResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetSettingsUITheme(ctx context.Context, _ string) (*api.SettingsUIThemeResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateSettingsUITheme(ctx context.Context, _ string, _ *api.UpdateSettingsUIThemeRequest) (*api.SettingsUIThemeResponse, error) {
	return nil, s.record(ctx)
}

// newSettingsTestStore is a real store over an in-memory backend: the Get handlers here take a
// flash out of the session before they reach the API, and a nil store faults before the call this
// file is about.
func newSettingsTestStore() *sessionstore.ServerSideStore {
	store, err := sessionstore.NewServerSideStore(
		sessiontest.NewMemoryBackend(),
		constants.SessionKeyJwt,
		false,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		},
		nil,
	)
	if err != nil {
		panic(err)
	}
	return store
}

func TestAdminSettingsHandlers_EveryHandlerConsultsTheApiClientWithTheRequestsContext(t *testing.T) {
	// The cache is never reached: every row's client refuses, and the three handlers holding one
	// invalidate it only after a successful save.
	settingsCache := cache.NewSettingsCache("http://auth.example.invalid")

	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlerhelpers.HttpHelper, apiClient apiclient.ApiClient) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleAdminSettingsAuditLogsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsAuditLogsGet(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/settings/audit-logs", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsAuditLogViewerGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsAuditLogViewerGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/settings/audit-logs/viewer", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsEmailGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsEmailGet(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/settings/email", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsEmailPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsEmailPost(h, newSettingsTestStore(), c, settingsCache)
			},
			request: handlertest.Request(http.MethodPost, "/admin/settings/email",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
					"hostOrIP": {"smtp.example.com"}, "port": {"587"},
					"fromName": {"Goiabada"}, "fromEmail": {"noreply@example.com"},
				})),
		},
		{
			name: "HandleAdminSettingsEmailSendTestGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsEmailSendTestGet(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/settings/email/send-test",
				handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsEmailSendTestPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsEmailSendTestPost(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/settings/email/send-test",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
					"destinationEmail": {"jane@example.com"},
				})),
		},
		{
			name: "HandleAdminSettingsGeneralGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsGeneralGet(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/settings/general", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsGeneralPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsGeneralPost(h, newSettingsTestStore(), c, settingsCache)
			},
			request: handlertest.Request(http.MethodPost, "/admin/settings/general",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
					"appName": {"Goiabada"}, "issuer": {"https://auth.example.com"},
					"passwordPolicy": {"low"},
				})),
		},
		{
			name: "HandleAdminSettingsKeysGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsKeysGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/settings/keys", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsKeysRotatePost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsKeysRotatePost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/settings/keys/rotate",
				handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsKeysRevokePost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsKeysRevokePost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/settings/keys/revoke",
				handlertest.WithAccessToken(), handlertest.WithBody(strings.NewReader(`{"id":7}`))),
		},
		{
			name: "HandleAdminSettingsSessionsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsSessionsGet(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/settings/sessions", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsSessionsPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsSessionsPost(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/settings/sessions",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
					"userSessionIdleTimeoutInSeconds": {"900"},
					"userSessionMaxLifetimeInSeconds": {"86400"},
				})),
		},
		{
			name: "HandleAdminSettingsTokensGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsTokensGet(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/settings/tokens", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsTokensPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsTokensPost(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/settings/tokens",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
					"tokenExpirationInSeconds":                {"300"},
					"refreshTokenOfflineIdleTimeoutInSeconds": {"2592000"},
					"refreshTokenOfflineMaxLifetimeInSeconds": {"31536000"},
				})),
		},
		{
			name: "HandleAdminSettingsUIThemeGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsUIThemeGet(h, newSettingsTestStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/settings/ui-theme", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminSettingsUIThemePost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminSettingsUIThemePost(h, newSettingsTestStore(), c, settingsCache)
			},
			request: handlertest.Request(http.MethodPost, "/admin/settings/ui-theme",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{"uiTheme": {"dark"}})),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &ctxRecordingApiClient{}

			marked := tc.request.WithContext(
				context.WithValue(tc.request.Context(), settingsCtxMarkerKey{}, tc.name))

			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

			require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
			for i, seen := range apiClient.seen {
				assert.Equal(t, tc.name, seen.Value(settingsCtxMarkerKey{}),
					"call %d carried a context that is not the request's", i)
			}
		})
	}
}

package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// Seam 4 for the client pages whose calls have moved (#386). See accounthandlers' file of the same
// name for what this owns and why the context is the assertion.
//
// GetClientById records and then succeeds rather than refusing, because nearly every page here
// reads it first and everything below it would otherwise be unreachable.

type clientCtxMarkerKey struct{}

type ctxRecordingApiClient struct {
	apiclient.ApiClient
	seen []context.Context
}

func (s *ctxRecordingApiClient) record(ctx context.Context) error {
	s.seen = append(s.seen, ctx)
	return errs.New("the auth server refused")
}

// GetClientById records and then succeeds rather than refusing, because nearly every page here
// reads it first and everything below it would otherwise be unreachable.
func (s *ctxRecordingApiClient) GetClientById(ctx context.Context, _ string, clientId int64) (*api.ClientResponse, error) {
	s.seen = append(s.seen, ctx)
	return &api.ClientResponse{Id: clientId, ClientIdentifier: "a-client"}, nil
}

func (s *ctxRecordingApiClient) GetAllClients(ctx context.Context, _ string) ([]api.ClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetClientPermissions(ctx context.Context, _ string, _ int64) (*api.ClientResponse, []api.PermissionResponse, error) {
	return nil, nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetClientLogo(ctx context.Context, _ string, _ int64) (*apiclient.ClientLogoInfo, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteClient(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) GetSettingsGeneral(ctx context.Context, _ string) (*api.SettingsGeneralResponse, error) {
	s.seen = append(s.seen, ctx)
	return nil, errs.New("the auth server refused")
}

// GetClientSessionsByClientId records and succeeds rather than refusing, because the session
// delete below it is reached only through the page it answers.
func (s *ctxRecordingApiClient) GetClientSessionsByClientId(ctx context.Context, _ string, _ int64, _, _ int) (*api.GetClientSessionsResponse, error) {
	s.seen = append(s.seen, ctx)
	return &api.GetClientSessionsResponse{
		Sessions: []api.UserSessionDetailResponse{{Id: 31, UserId: 42}},
	}, nil
}

func (s *ctxRecordingApiClient) DeleteUserSessionById(ctx context.Context, _ string, _ int64) error {
	s.seen = append(s.seen, ctx)
	return errs.New("the auth server refused")
}

func TestAdminClientHandlers_TheMovedCallsCarryTheRequestsContext(t *testing.T) {
	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlerhelpers.HttpHelper, apiClient apiclient.ApiClient) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleAdminClientsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminClientPermissionsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientPermissionsGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/permissions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleAdminClientLogoGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientLogoGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/logo",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleAdminClientDeleteGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientDeleteGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/delete",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleAdminClientTokensGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientTokensGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/tokens",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleAdminClientSettingsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientSettingsGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/settings",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleAdminClientOAuth2Get",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientOAuth2Get(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/oauth2-flows",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleAdminClientRedirectURIsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientRedirectURIsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/redirect-uris",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleAdminClientUserSessionsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientUserSessionsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleAdminClientUserSessionsPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientUserSessionsPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/user-sessions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3"),
				handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)),
				handlertest.WithContentType("application/json")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &ctxRecordingApiClient{}

			marked := tc.request.WithContext(
				context.WithValue(tc.request.Context(), clientCtxMarkerKey{}, tc.name))

			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

			require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
			for i, seen := range apiClient.seen {
				assert.Equal(t, tc.name, seen.Value(clientCtxMarkerKey{}),
					"call %d carried a context that is not the request's", i)
			}
		})
	}
}

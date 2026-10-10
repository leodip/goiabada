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

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
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

func (s *ctxRecordingApiClient) GetClientLogo(ctx context.Context, _ string, _ int64) (*api.ClientLogoInfoResponse, error) {
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

func (s *ctxRecordingApiClient) CreateClient(ctx context.Context, _ string, _ *api.CreateClientRequest) (*api.ClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteClientLogo(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) GetAllResources(ctx context.Context, _ string) ([]api.ResourceResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateClient(ctx context.Context, _ string, _ int64, _ *api.UpdateClientSettingsRequest) (*api.ClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateClientAdministrativeScopes(ctx context.Context, _ string, _ int64, _ *api.UpdateClientAdministrativeScopesRequest) (*api.ClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateClientAuthentication(ctx context.Context, _ string, _ int64, _ *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateClientOAuth2Flows(ctx context.Context, _ string, _ int64, _ *api.UpdateClientOAuth2FlowsRequest) (*api.ClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateClientPermissions(ctx context.Context, _ string, _ int64, _ *api.UpdateClientPermissionsRequest) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateClientRedirectURIs(ctx context.Context, _ string, _ int64, _ *api.UpdateClientRedirectURIsRequest) (*api.ClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateClientTokens(ctx context.Context, _ string, _ int64, _ *api.UpdateClientTokensRequest) (*api.ClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateClientWebOrigins(ctx context.Context, _ string, _ int64, _ *api.UpdateClientWebOriginsRequest) (*api.ClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UploadClientLogo(ctx context.Context, _ string, _ int64, _ []byte, _ string) (*api.ClientLogoUploadResponse, error) {
	return nil, s.record(ctx)
}

func TestAdminClientHandlers_TheMovedCallsCarryTheRequestsContext(t *testing.T) {
	testCases := []struct {
		name    string
		build   func(httpHelper *handlersmocks.HttpHelper, apiClient *ctxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleListGet",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleListGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients", handlertest.WithAccessToken()),
		},
		{
			name: "HandlePermissionsGet",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandlePermissionsGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/permissions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleLogoGet",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleLogoGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/logo",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleDeleteGet",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleDeleteGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/delete",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleTokensGet",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleTokensGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/tokens",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleSettingsGet",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleSettingsGet(h, newTestSessionStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/settings",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleOAuth2FlowsGet",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleOAuth2FlowsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/oauth2-flows",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleRedirectURIsGet",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleRedirectURIsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/redirect-uris",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleUserSessionsGet",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleUserSessionsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/clients/3/user-sessions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3")),
		},
		{
			name: "HandleUserSessionsPost",
			build: func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleUserSessionsPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/clients/3/user-sessions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3"),
				handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)),
				handlertest.WithContentType("application/json")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJSON", mock.Anything, mock.Anything, mock.Anything).Maybe()
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

func (s *ctxRecordingApiClient) GetClientSecret(ctx context.Context, _ string, _ int64) (string, error) {
	return "", s.record(ctx)
}

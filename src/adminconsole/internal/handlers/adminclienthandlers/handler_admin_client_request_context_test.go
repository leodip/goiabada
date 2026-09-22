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
// Two settings reads from stage 10 and the two session pages from stage 11. The rest of this
// package's API calls are stage 12's and are characterized there.

type clientCtxMarkerKey struct{}

type ctxRecordingApiClient struct {
	apiclient.ApiClient
	seen []context.Context
}

// GetClientById is reached first and is stage 12's, so it still has no context and only has to
// succeed for the calls below it to happen at all.
func (s *ctxRecordingApiClient) GetClientById(_ string, clientId int64) (*api.ClientResponse, error) {
	return &api.ClientResponse{Id: clientId, ClientIdentifier: "a-client"}, nil
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

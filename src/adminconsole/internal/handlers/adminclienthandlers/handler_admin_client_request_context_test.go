package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// Seam 4 for the two client pages that read general settings (#386). See accounthandlers' file of
// the same name for what this owns and why the context is the assertion.
//
// The rest of this package's API calls are stage 12's and are characterized there; these two are
// here because GetSettingsGeneral moved in stage 10 and its callers came with it.

type clientCtxMarkerKey struct{}

type ctxRecordingApiClient struct {
	apiclient.ApiClient
	seen []context.Context
}

// GetClientById is reached first and is stage 12's, so it still has no context and only has to
// succeed for the settings read below it to happen at all.
func (s *ctxRecordingApiClient) GetClientById(_ string, clientId int64) (*api.ClientResponse, error) {
	return &api.ClientResponse{Id: clientId, ClientIdentifier: "a-client"}, nil
}

func (s *ctxRecordingApiClient) GetSettingsGeneral(ctx context.Context, _ string) (*api.SettingsGeneralResponse, error) {
	s.seen = append(s.seen, ctx)
	return nil, errs.New("the auth server refused")
}

func TestAdminClientHandlers_TheSettingsReadCarriesTheRequestsContext(t *testing.T) {
	testCases := []struct {
		name  string
		build func(httpHelper *mocks_handlerhelpers.HttpHelper, apiClient apiclient.ApiClient) http.HandlerFunc
		path  string
	}{
		{
			name: "HandleAdminClientOAuth2Get",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientOAuth2Get(h, nil, c)
			},
			path: "/admin/clients/3/oauth2-flows",
		},
		{
			name: "HandleAdminClientRedirectURIsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminClientRedirectURIsGet(h, nil, c)
			},
			path: "/admin/clients/3/redirect-uris",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &ctxRecordingApiClient{}

			request := handlertest.Request(http.MethodGet, tc.path,
				handlertest.WithAccessToken(), handlertest.WithRouteParam("clientId", "3"))
			marked := request.WithContext(
				context.WithValue(request.Context(), clientCtxMarkerKey{}, tc.name))

			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

			require.NotEmpty(t, apiClient.seen, "the handler must read the general settings")
			for i, seen := range apiClient.seen {
				assert.Equal(t, tc.name, seen.Value(clientCtxMarkerKey{}),
					"call %d carried a context that is not the request's", i)
			}
		})
	}
}

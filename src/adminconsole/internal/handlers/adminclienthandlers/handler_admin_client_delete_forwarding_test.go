package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// Decision 11 on a page that reads its entity through the API rather than through the database.
//
// handler_not_found_test.go owns the settings page, whose own nil check was already answering 404.
// This one owns the shape that was still live after that sweep and that the final review found: the
// delete page's guard wrote httpHelper.InternalServerError(w, r, err) and its `client == nil` check
// below it never fired, because every apiclient method funnels a non-2xx through parseAPIError. So
// a bookmark to a client another administrator had deleted rendered the 500 page, with a stack and
// a request id, for a URL that is simply no longer a thing.
//
// The 500 row is what keeps the fix narrow, and it is the row a sweep breaks: an API that is broken
// is still a server fault and still belongs in the log.
type deleteClientApiClient struct {
	apiclient.ApiClient
	err error
}

func (c *deleteClientApiClient) GetClientPermissions(_ context.Context, accessToken string, clientId int64) (*api.ClientResponse, []api.PermissionResponse, error) {
	if c.err != nil {
		return nil, nil, c.err
	}
	return &api.ClientResponse{Id: clientId}, nil, nil
}

func TestClientDeleteGet_ForwardsTheApisStatus(t *testing.T) {
	testCases := []struct {
		name         string
		apiErr       error
		wantNotFound bool
	}{
		{
			name: "a client the API says is gone",
			apiErr: &apiclient.APIError{
				Code:       "NOT_FOUND",
				Message:    "Client not found",
				StatusCode: http.StatusNotFound,
			},
			wantNotFound: true,
		},
		{
			name: "a server fault, which stays a 500 page",
			apiErr: &apiclient.APIError{
				Code:       "INTERNAL_SERVER_ERROR",
				Message:    "the database is on fire",
				StatusCode: http.StatusInternalServerError,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			if testCase.wantNotFound {
				httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			} else {
				httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
					Return().Once()
			}

			req := handlertest.Request(http.MethodGet, "/admin/clients/42/delete", handlertest.WithAccessToken())

			router := chi.NewRouter()
			router.Get("/admin/clients/{clientId}/delete",
				HandleAdminClientDeleteGet(httpHelper, &deleteClientApiClient{err: testCase.apiErr}))
			router.ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
		})
	}
}

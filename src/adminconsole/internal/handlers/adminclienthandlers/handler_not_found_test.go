package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/oauth"
)

// Decision 11 at this handler group's seam. Every one of these rows answered the 500 page before
// #279: a mistyped id, a link whose id the router never bound, a bookmark to something an
// administrator deleted last week. Each spent a stack and a request id telling the reader the
// server had broken, and RFC 9110 section 15.5.5 has the answer -- 404 "indicates that the origin
// server did not find a current representation for the target resource".
//
// The last two rows are what keeps the change narrow. A missing JWT context is an invariant the
// JWT middleware holds, and a 500 from the API is a server fault: both stay 500, and a sweep that
// turned every InternalServerError in this file into a NotFound would fail here.
//
// notFoundClientApiClient answers the one call the handler makes before it decides, and embeds the
// interface so any other method the handler reaches for panics rather than returning a helpful
// zero value.
type notFoundClientApiClient struct {
	apiclient.ApiClient
	entity *api.ClientResponse
	err    error
}

func (c *notFoundClientApiClient) GetClientById(accessToken string, id int64) (*api.ClientResponse, error) {
	return c.entity, c.err
}

func TestClient_StaleOrMalformedUrlAnswers404(t *testing.T) {
	const routePattern = "/admin/clients/{clientId}/settings"

	// present, gone and broken stand for the three answers the API can give this handler.
	present := &api.ClientResponse{Id: 42}
	gone := &apiclient.APIError{Code: "NOT_FOUND", Message: "Client not found", StatusCode: http.StatusNotFound}
	broken := &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError}

	testCases := []struct {
		name string
		// target is the URL. When routed is false the handler is called without a chi route
		// context, which is how an unbound URL parameter reads from inside chi.URLParam.
		target       string
		routed       bool
		withJwt      bool
		entity       *api.ClientResponse
		apiErr       error
		wantNotFound bool
	}{
		{
			name:         "an id that does not parse",
			target:       "/admin/clients/not-a-number/settings",
			routed:       true,
			withJwt:      true,
			entity:       present,
			wantNotFound: true,
		},
		{
			name:         "an id the router never bound",
			target:       "/admin/clients/42/settings",
			routed:       false,
			withJwt:      true,
			entity:       present,
			wantNotFound: true,
		},
		{
			name:         "an entity the API says is gone",
			target:       "/admin/clients/42/settings",
			routed:       true,
			withJwt:      true,
			apiErr:       gone,
			wantNotFound: true,
		},
		{
			name:         "an entity the API returns as nil without an error",
			target:       "/admin/clients/42/settings",
			routed:       true,
			withJwt:      true,
			wantNotFound: true,
		},
		{
			name:    "no JWT info in context, which is a middleware invariant and stays a 500",
			target:  "/admin/clients/42/settings",
			routed:  true,
			withJwt: false,
			entity:  present,
		},
		{
			name:    "a 500 from the API, which is a server fault and stays a 500",
			target:  "/admin/clients/42/settings",
			routed:  true,
			withJwt: true,
			apiErr:  broken,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handler_helpers.NewHttpHelper(t)
			if testCase.wantNotFound {
				httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			} else {
				httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
					Return().Once()
			}

			req := httptest.NewRequest(http.MethodGet, testCase.target, nil)
			if testCase.withJwt {
				req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
					oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))
			}

			apiClient := &notFoundClientApiClient{entity: testCase.entity, err: testCase.apiErr}
			handler := HandleAdminClientSettingsGet(httpHelper, nil, apiClient)
			w := httptest.NewRecorder()

			if testCase.routed {
				router := chi.NewRouter()
				router.Get(routePattern, handler)
				router.ServeHTTP(w, req)
			} else {
				handler.ServeHTTP(w, req)
			}

			httpHelper.AssertExpectations(t)
		})
	}
}

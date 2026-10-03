package adminclienthandlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlers "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/oauth"
)

// #225 at a handler's seam, rather than at HandleAPIErrorJSON's. render's
// api_error_helper_test.go owns what the helper decides; this owns that this handler reaches it
// at all, which is the half a reader cannot check by looking at the helper.
//
// The block it replaced did the routing itself and did it wrong: it matched *apiclient.APIError,
// took the message, and threw the status and the code away, so a 400 the API had explained arrived
// at JSONError as a bare error and came back as "An unexpected server error has occurred" with the
// explanation in the log. Eight handlers carried that block. The 500 row is what stops a fix from
// forwarding everything: a server fault still belongs in the log.
type permissionsApiClient struct {
	err error
}

func (c *permissionsApiClient) UpdateClientPermissions(_ context.Context, accessToken string, clientId int64, request *api.UpdateClientPermissionsRequest) error {
	return c.err
}

// The rest of the ports permissionsApiClient is passed to, which no test here reaches.

func (*permissionsApiClient) GetAllResources(context.Context, string) ([]api.ResourceResponse, error) {
	panic("unexpected call to GetAllResources")
}

func (*permissionsApiClient) GetClientPermissions(context.Context, string, int64) (*api.ClientResponse, []api.PermissionResponse, error) {
	panic("unexpected call to GetClientPermissions")
}

func TestClientPermissionsPost_ForwardsTheApisAnswer(t *testing.T) {
	testCases := []struct {
		name   string
		apiErr error
		// wantStatus is what must reach the browser; 0 means JSONError's generic 500 arm, with the
		// detail going to the log instead.
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{
			name: "a validation failure the administrator can act on",
			apiErr: &apiclient.APIError{
				Code:       "VALIDATION_ERROR",
				Message:    "Permission 7 does not belong to this client",
				StatusCode: http.StatusBadRequest,
			},
			wantStatus:  http.StatusBadRequest,
			wantCode:    "VALIDATION_ERROR",
			wantMessage: "Permission 7 does not belong to this client",
		},
		{
			name: "a race another administrator won",
			apiErr: &apiclient.APIError{
				Code:       "CONFLICT",
				Message:    "The client was modified by someone else",
				StatusCode: http.StatusConflict,
			},
			wantStatus:  http.StatusConflict,
			wantCode:    "CONFLICT",
			wantMessage: "The client was modified by someone else",
		},
		{
			name: "a client that is gone",
			apiErr: &apiclient.APIError{
				Code:       "NOT_FOUND",
				Message:    "Client not found",
				StatusCode: http.StatusNotFound,
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "not_found",
		},
		{
			name: "a server fault, which stays in the log",
			apiErr: &apiclient.APIError{
				Code:       "INTERNAL_SERVER_ERROR",
				Message:    "the database is on fire",
				StatusCode: http.StatusInternalServerError,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			var captured error
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					captured, _ = args.Get(2).(error)
				}).Return().Once()

			req := handlertest.Request(http.MethodPost, "/admin/clients/1/permissions",
				handlertest.WithAccessToken(),
				handlertest.WithBody(strings.NewReader("{\"clientId\": 1, \"assignedPermissionsIds\": [7]}")),
			)

			handler := HandleAdminClientPermissionsPost(httpHelper, nil,
				&permissionsApiClient{err: testCase.apiErr})
			handler.ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
			require.NotNil(t, captured, "the handler answered nothing")

			var detail *oauth.ErrorDetail
			if testCase.wantStatus == 0 {
				assert.False(t, errors.As(captured, &detail),
					"a server fault must not carry a status to the browser, got %v", captured)
				return
			}
			require.True(t, errors.As(captured, &detail),
				"expected an *ErrorDetail carrying a status, got %v", captured)
			assert.Equal(t, testCase.wantStatus, detail.HTTPStatus())
			assert.Equal(t, testCase.wantCode, detail.Code())
			if testCase.wantMessage != "" {
				assert.Equal(t, testCase.wantMessage, detail.Description(),
					"the API's own sentence is what makes the failure actionable")
			}
		})
	}
}

// TestClientPermissionsPost_MalformedBodyAnswers400 is decision 12 reached through json.Unmarshal
// rather than through a json.Decoder. Decision 12's own grep found only the Decode spelling; this
// handler reads the body with io.ReadAll and unmarshals it, which is the same condition by another
// route and answered the same 500 before #279.
func TestClientPermissionsPost_MalformedBodyAnswers400(t *testing.T) {
	httpHelper := mocks_handlers.NewHttpHelper(t)
	var captured error
	httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured, _ = args.Get(2).(error)
		}).Return().Once()

	req := handlertest.Request(http.MethodPost, "/admin/clients/1/permissions",
		handlertest.WithAccessToken(),
		handlertest.WithBody(strings.NewReader("{this is not json")),
	)

	handler := HandleAdminClientPermissionsPost(httpHelper, nil, &permissionsApiClient{})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	httpHelper.AssertExpectations(t)
	var detail *oauth.ErrorDetail
	require.True(t, errors.As(captured, &detail), "expected an *ErrorDetail carrying 400, got %v", captured)
	assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
	assert.Equal(t, "invalid_request_body", detail.Code())
}

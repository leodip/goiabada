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
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/oauth"
)

// #225 at a handler's seam, rather than at HandleAPIErrorJson's. api_error_helper_test.go owns what
// the helper decides; this owns that this handler reaches it at all, which is the half a reader
// cannot check by looking at the helper.
//
// The block it replaced did the routing itself and did it wrong: it matched *apiclient.APIError,
// took the message, and threw the status and the code away, so a 400 the API had explained arrived
// at JsonError as a bare error and came back as "An unexpected server error has occurred" with the
// explanation in the log. Eight handlers carried that block. The 500 row is what stops a fix from
// forwarding everything: a server fault still belongs in the log.
type permissionsApiClient struct {
	apiclient.ApiClient
	err error
}

func (c *permissionsApiClient) UpdateClientPermissions(accessToken string, clientId int64, request *api.UpdateClientPermissionsRequest) error {
	return c.err
}

func TestClientPermissionsPost_ForwardsTheApisAnswer(t *testing.T) {
	testCases := []struct {
		name   string
		apiErr error
		// wantStatus is what must reach the browser; 0 means JsonError's generic 500 arm, with the
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
			httpHelper := mocks_handler_helpers.NewHttpHelper(t)
			var captured error
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					captured, _ = args.Get(2).(error)
				}).Return().Once()

			req := httptest.NewRequest(http.MethodPost, "/admin/clients/1/permissions",
				strings.NewReader("{\"clientId\": 1, \"assignedPermissionsIds\": [7]}"))
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

			handler := HandleAdminClientPermissionsPost(httpHelper, nil,
				&permissionsApiClient{err: testCase.apiErr})
			handler.ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
			require.NotNil(t, captured, "the handler answered nothing")

			var detail *customerrors.ErrorDetail
			if testCase.wantStatus == 0 {
				assert.False(t, errors.As(captured, &detail),
					"a server fault must not carry a status to the browser, got %v", captured)
				return
			}
			require.True(t, errors.As(captured, &detail),
				"expected an *ErrorDetail carrying a status, got %v", captured)
			assert.Equal(t, testCase.wantStatus, detail.GetHttpStatusCode())
			assert.Equal(t, testCase.wantCode, detail.GetCode())
			if testCase.wantMessage != "" {
				assert.Equal(t, testCase.wantMessage, detail.GetDescription(),
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
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	var captured error
	httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured, _ = args.Get(2).(error)
		}).Return().Once()

	req := httptest.NewRequest(http.MethodPost, "/admin/clients/1/permissions",
		strings.NewReader("{this is not json"))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

	handler := HandleAdminClientPermissionsPost(httpHelper, nil, &permissionsApiClient{})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	httpHelper.AssertExpectations(t)
	var detail *customerrors.ErrorDetail
	require.True(t, errors.As(captured, &detail), "expected an *ErrorDetail carrying 400, got %v", captured)
	assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
	assert.Equal(t, "invalid_request_body", detail.GetCode())
}

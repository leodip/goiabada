package adminresourcehandlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/customerrors"
)

// Decision 13 on an AJAX preflight read, which is where the console's own sweep left the shape it
// had just corrected on the page beside it.
//
// The permission grid loads a resource before it does anything, and that read's guard called
// httpHelper.JsonError(w, r, err) with the *apiclient.APIError untouched. JsonError preserves a
// status only for a *customerrors.ErrorDetail, so an upstream 404 took the generic arm: HTTP 500,
// a stack and a request id in the log, and a modal telling the administrator the server had broken
// when what had happened is that somebody deleted the resource while their page was open. The guard
// two calls further down, on GetGroupPermissions, was already going through the classifier, which is
// what makes this the kind of gap a reader cannot see: both guards look the same and only one was.
//
// The 400 row is the reason the classifier rather than a bare JsonNotFound: forwarding the API's
// own sentence is what the browser shows.
type usersWithPermissionApiClient struct {
	apiclient.ApiClient
	err error
}

func (c *usersWithPermissionApiClient) GetResourceById(_ context.Context, accessToken string, resourceId int64) (*api.ResourceResponse, error) {
	return nil, c.err
}

func TestResourceUsersWithPermissionRemovePost_ForwardsTheApisStatusAsJson(t *testing.T) {
	testCases := []struct {
		name   string
		apiErr error
		// wantStatus 0 means JsonError's generic 500 arm, with the detail going to the log.
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{
			name: "a resource deleted while the page was open",
			apiErr: &apiclient.APIError{
				Code:       "NOT_FOUND",
				Message:    "Resource not found",
				StatusCode: http.StatusNotFound,
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "not_found",
		},
		{
			name: "a value the API refused, forwarded with its own sentence",
			apiErr: &apiclient.APIError{
				Code:       "VALIDATION_ERROR",
				Message:    "Invalid resource id",
				StatusCode: http.StatusBadRequest,
			},
			wantStatus:  http.StatusBadRequest,
			wantCode:    "VALIDATION_ERROR",
			wantMessage: "Invalid resource id",
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
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			var captured error
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					captured, _ = args.Get(2).(error)
				}).Return().Once()

			req := handlertest.Request(http.MethodPost,
				"/admin/resources/3/users-with-permission/9/permissions/5/remove",
				handlertest.WithAccessToken())

			router := chi.NewRouter()
			router.Post("/admin/resources/{resourceId}/users-with-permission/{userId}/permissions/{permissionId}/remove",
				HandleAdminResourceUsersWithPermissionRemovePermissionPost(httpHelper,
					&usersWithPermissionApiClient{err: testCase.apiErr}))
			router.ServeHTTP(httptest.NewRecorder(), req)

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
				assert.Equal(t, testCase.wantMessage, detail.GetDescription())
			}
		})
	}
}

package apihandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386 for the admin API handlers, and thin for the reason section 5 gives: the
// executor's behaviour belongs to the data tier and the retry loop to the scripted driver. All a
// handler can show is that the context it handed to its port was the REQUEST's.
//
// chi's request id is on this request's context and on no other, so a handler that passed
// context.Background() matches nothing and the strict mock reports an unexpected call.

const apiPropagatedRequestId = "goiabada/req-api-propagation-1"

func apiRequestCarryingId(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, apiPropagatedRequestId))
}

func theApiRequestsContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return chimiddleware.GetReqID(ctx) == apiPropagatedRequestId
	})
}

// The accept arm: the paged search is issued on behalf of the request that asked for it, which is
// also the read most worth cancelling, since it is the one an operator can make arbitrarily
// expensive from the query string.
func TestHandleAPIUsersSearchGet_SearchesUnderTheRequestsContext(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("SearchUsersPaginated", theApiRequestsContext(), mock.Anything, "ada", 1, 10).
		Return([]models.User{{Id: 1, Subject: "sub-1", Email: "ada@example.com"}}, 1, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIUsersSearchGet(database).ServeHTTP(rr, apiRequestCarryingId("/api/v1/admin/users/search?query=ada"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

// The reject arm: two annotations that cannot be combined are refused after the search but before
// either annotation read, so neither annotating port is reached at all.
func TestHandleAPIUsersSearchGet_ConflictingAnnotationsReachNoAnnotationPort(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("SearchUsersPaginated", theApiRequestsContext(), mock.Anything, "ada", 1, 10).
		Return([]models.User{{Id: 1, Subject: "sub-1"}}, 1, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIUsersSearchGet(database).ServeHTTP(rr,
		apiRequestCarryingId("/api/v1/admin/users/search?query=ada&annotateGroupMembership=1&annotatePermissionId=2"))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	database.AssertNotCalled(t, "GetUserGroupsByUserIds", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetUserPermissionsByUserIds", mock.Anything, mock.Anything, mock.Anything)
}

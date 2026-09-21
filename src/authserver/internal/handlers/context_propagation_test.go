package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/authserver/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386, and deliberately thin. What a query does with a context belongs to the data
// tier and what RunInTransaction does with it belongs to the scripted driver; all a handler can
// show is that the context it handed down was the REQUEST's and not one it invented. Repeating
// either of the other two here would break on every refactor while proving nothing.
//
// The matcher is what makes a failure name its cause. chi's request id is on the request's
// context and on no other, so a handler that passed context.Background() -- the exact defect the
// acceptance criterion forbids below a request boundary -- matches nothing, and the strict mock
// reports an unexpected call rather than letting the case pass.

const propagatedRequestId = "goiabada/req-propagation-1"

// requestCarryingId returns a request whose context holds an id nothing else can produce.
func requestCarryingId(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	return req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, propagatedRequestId))
}

// theRequestsContext matches only the context belonging to the request under test.
func theRequestsContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return chimiddleware.GetReqID(ctx) == propagatedRequestId
	})
}

// withURLParam binds a chi route parameter, which HandleProfilePictureGet reads before it reads
// anything else.
func withURLParam(req *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// TestHandleProfilePictureGet_ConsultsTheDatabaseUnderTheRequestsContext is the accept arm: both
// reads the handler makes carry the request's own context, one of them on a value derived from
// the other, which is the ordinary two-hop shape across this package.
func TestHandleProfilePictureGet_ConsultsTheDatabaseUnderTheRequestsContext(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	req := withURLParam(requestCarryingId(t, http.MethodGet, "/userinfo/picture/sub-1"), "subject", "sub-1")
	rr := httptest.NewRecorder()

	user := &models.User{Id: 7, Subject: "sub-1"}
	database.On("GetUserBySubject", theRequestsContext(), mock.Anything, "sub-1").Return(user, nil).Once()
	database.On("GetUserProfilePictureByUserId", theRequestsContext(), mock.Anything, int64(7)).
		Return(&models.UserProfilePicture{UserId: 7, ContentType: "image/png", Picture: []byte{1, 2, 3}}, nil).Once()

	HandleProfilePictureGet(httpHelper, database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "image/png", rr.Header().Get("Content-Type"))
	database.AssertExpectations(t)
}

// TestHandleProfilePictureGet_RefusedBeforeAnyQuery is the reject arm: a request the handler
// turns away reaches no port at all, so there is no context to get wrong. Without it the accept
// arm would also pass on a handler that queried unconditionally.
func TestHandleProfilePictureGet_RefusedBeforeAnyQuery(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	req := withURLParam(requestCarryingId(t, http.MethodGet, "/userinfo/picture/"), "subject", "")
	rr := httptest.NewRecorder()

	HandleProfilePictureGet(httpHelper, database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertNotCalled(t, "GetUserBySubject", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetUserProfilePictureByUserId", mock.Anything, mock.Anything, mock.Anything)
}

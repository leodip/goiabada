package apihandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/constants"
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

// Stage 6 adds the session half. The admin API's session pages are the widest reads in this
// package: one user's sessions, one client's sessions, each hydrating every client behind them,
// and each of them now issued on behalf of the request that asked.

// apiSessionsRequest is apiRequestCarryingId plus the chi id parameter and the settings the
// session handlers read, which is everything HandleAPIUserSessionsGet needs before its first query.
func apiSessionsRequest(userId string) *http.Request {
	req := apiRequestCarryingId("/api/v1/admin/users/" + userId + "/sessions")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userId)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, constants.ContextKeySettings, &models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	})
	return req.WithContext(ctx)
}

// The accept arm: all three reads -- the user, its sessions, and the clients those sessions
// authorized -- carry the request's own context, including the loader, which reaches the database
// a second time inside commondb.
func TestHandleAPIUserSessionsGet_ReadsSessionsUnderTheRequestsContext(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetUserById", theApiRequestsContext(), mock.Anything, int64(7)).
		Return(&models.User{Id: 7, Subject: "sub-7"}, nil).Once()
	database.On("GetUserSessionsByUserId", theApiRequestsContext(), mock.Anything, int64(7)).
		Return([]models.UserSession{}, nil).Once()
	database.On("UserSessionsLoadClients", theApiRequestsContext(), mock.Anything, mock.Anything).
		Return(nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIUserSessionsGet(database).ServeHTTP(rr, apiSessionsRequest("7"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

// The reject arm: an id that is not a number is refused before the first query, so no session
// port is reached at all and there is no context to get wrong.
func TestHandleAPIUserSessionsGet_MalformedIdReachesNoSessionPort(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	rr := httptest.NewRecorder()
	HandleAPIUserSessionsGet(database).ServeHTTP(rr, apiSessionsRequest("not-a-number"))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	database.AssertNotCalled(t, "GetUserSessionsByUserId", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "UserSessionsLoadClients", mock.Anything, mock.Anything, mock.Anything)
}

// Stage 7 adds the client, resource and permission half. The admin API's client pages are the
// widest reads in this package after the session ones: every client on the install, each hydrated
// with its redirect URIs and its web origins through two loaders that reach the database again
// inside commondb.

// apiClientRequest is apiRequestCarryingId plus the chi id parameter the single-client handlers
// read, which is everything HandleAPIClientGet needs before its first query.
func apiClientRequest(clientId string) *http.Request {
	req := apiRequestCarryingId("/api/v1/admin/clients/" + clientId)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", clientId)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// The accept arm: all three reads -- the client list and both loaders -- carry the request's own
// context. The loaders matter more than the list here, because each reaches the database a second
// time inside commondb and is the shape that would keep compiling with a context.Background()
// under it.
func TestHandleAPIClientsGet_ListsClientsUnderTheRequestsContext(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetAllClients", theApiRequestsContext(), mock.Anything).
		Return([]models.Client{{Id: 3, ClientIdentifier: "portal"}}, nil).Once()
	database.On("ClientLoadRedirectURIs", theApiRequestsContext(), mock.Anything, mock.Anything).
		Return(nil).Once()
	database.On("ClientLoadWebOrigins", theApiRequestsContext(), mock.Anything, mock.Anything).
		Return(nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIClientsGet(database).ServeHTTP(rr, apiRequestCarryingId("/api/v1/admin/clients"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

// The reject arm: an id that is not a number is refused before the first query, so neither the
// client read nor either loader is reached and there is no context to get wrong.
func TestHandleAPIClientGet_MalformedIdReachesNoClientPort(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	rr := httptest.NewRecorder()
	HandleAPIClientGet(database).ServeHTTP(rr, apiClientRequest("not-a-number"))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	database.AssertNotCalled(t, "GetClientById", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "ClientLoadRedirectURIs", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "ClientLoadWebOrigins", mock.Anything, mock.Anything, mock.Anything)
}

// apiResourcePermissionsRequest carries the resourceId parameter the permission listing reads.
func apiResourcePermissionsRequest(resourceId string) *http.Request {
	req := apiRequestCarryingId("/api/v1/admin/resources/" + resourceId + "/permissions")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", resourceId)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// The accept arm for the permission half: the listing and the resource hydration that follows it
// are both issued on behalf of the request that asked.
func TestHandleAPIPermissionsByResourceGet_ReadsPermissionsUnderTheRequestsContext(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetPermissionsByResourceId", theApiRequestsContext(), mock.Anything, int64(4)).
		Return([]models.Permission{{Id: 11, PermissionIdentifier: "read", ResourceId: 4}}, nil).Once()
	database.On("PermissionsLoadResources", theApiRequestsContext(), mock.Anything, mock.Anything).
		Return(nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIPermissionsByResourceGet(database).ServeHTTP(rr, apiResourcePermissionsRequest("4"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

// The reject arm: a resource id that is not a number is refused before the listing, so neither
// permission port is reached.
func TestHandleAPIPermissionsByResourceGet_MalformedResourceIdReachesNoPermissionPort(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	rr := httptest.NewRecorder()
	HandleAPIPermissionsByResourceGet(database).ServeHTTP(rr, apiResourcePermissionsRequest("not-a-number"))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	database.AssertNotCalled(t, "GetPermissionsByResourceId", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "PermissionsLoadResources", mock.Anything, mock.Anything, mock.Anything)
}

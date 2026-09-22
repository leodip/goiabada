package apihandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386 for the last batch of Database methods: groups, group attributes, group
// permissions, key pairs, settings and audit logs.
//
// Same argument and same thinness as context_propagation_test.go, whose apiRequestCarryingId and
// theApiRequestsContext this file reuses: the query's behaviour belongs to the data tier and the
// retry loop to the scripted driver, so all a handler shows here is that the context it handed to
// its port was the REQUEST's.

// apiIdRequest carries the chi "id" parameter, which is what every handler below reads before its
// first query and all any of them needs before it.
func apiIdRequest(target, id string) *http.Request {
	req := apiRequestCarryingId(target)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// The accept arm for the group half: the list read and the per-group member count are both issued
// on behalf of the request that asked. The count matters more than the list, because it runs once
// per group inside a loop and is the shape that would keep compiling with a context.Background()
// under it.
func TestHandleAPIGroupsGet_ListsGroupsUnderTheRequestsContext(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetAllGroups", theApiRequestsContext(), mock.Anything).
		Return([]models.Group{{Id: 5, GroupIdentifier: "admins"}}, nil).Once()
	database.On("CountGroupMembers", theApiRequestsContext(), mock.Anything, int64(5)).
		Return(2, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIGroupsGet(database).ServeHTTP(rr, apiRequestCarryingId("/api/v1/admin/groups"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

// The reject arm: an id that is not a number is refused before the first query, so neither the
// group read nor the member count is reached and there is no context to get wrong.
func TestHandleAPIGroupGet_MalformedIdReachesNoGroupPort(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	rr := httptest.NewRecorder()
	HandleAPIGroupGet(database).ServeHTTP(rr, apiIdRequest("/api/v1/admin/groups/not-a-number", "not-a-number"))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	database.AssertNotCalled(t, "GetGroupById", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "CountGroupMembers", mock.Anything, mock.Anything, mock.Anything)
}

// The accept arm for the loader: GroupLoadPermissions reaches the database twice inside commondb,
// once for the group's permission rows and once for the permissions themselves, and both hops
// carry whatever context the handler hands in. It is one of stage 1's five nil-transaction sites,
// so it is also the method most worth showing carries the request's own.
func TestHandleAPIGroupPermissionsGet_LoadsPermissionsUnderTheRequestsContext(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetGroupById", theApiRequestsContext(), mock.Anything, int64(5)).
		Return(&models.Group{Id: 5, GroupIdentifier: "admins"}, nil).Once()
	database.On("GroupLoadPermissions", theApiRequestsContext(), mock.Anything, mock.Anything).
		Return(nil).Once()
	database.On("CountGroupMembers", theApiRequestsContext(), mock.Anything, int64(5)).
		Return(0, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIGroupPermissionsGet(database).ServeHTTP(rr, apiIdRequest("/api/v1/admin/groups/5/permissions", "5"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

// The reject arm: a group id that is not a number is refused before the read, so the loader is
// never reached.
func TestHandleAPIGroupPermissionsGet_MalformedIdReachesNoPermissionPort(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	rr := httptest.NewRecorder()
	HandleAPIGroupPermissionsGet(database).ServeHTTP(rr, apiIdRequest("/api/v1/admin/groups/not-a-number/permissions", "not-a-number"))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	database.AssertNotCalled(t, "GetGroupById", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GroupLoadPermissions", mock.Anything, mock.Anything, mock.Anything)
}

// The accept arm for the key half: the signing keys page reads every key pair on the install, and
// reads it on behalf of the request that asked.
func TestHandleAPISettingsKeysGet_ReadsKeysUnderTheRequestsContext(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetAllSigningKeys", theApiRequestsContext(), mock.Anything).
		Return([]models.KeyPair{{Id: 9, KeyIdentifier: "kid-9", State: models.KeyStateCurrent.String()}}, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPISettingsKeysGet(database).ServeHTTP(rr, apiRequestCarryingId("/api/v1/admin/settings/keys"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

// The reject arm: a key id that is not a number is refused before the read, so neither the key
// read nor the delete is reached. The delete is the assertion worth having, because it is the one
// that would destroy a signing key: a revocation retires every token that key signed.
func TestHandleAPISettingsKeyDelete_MalformedIdReachesNoKeyPort(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	req := apiIdRequest("/api/v1/admin/settings/keys/not-a-number", "not-a-number")

	rr := httptest.NewRecorder()
	HandleAPISettingsKeyDelete(database, auditLogger).ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	database.AssertNotCalled(t, "GetKeyPairById", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "DeleteKeyPair", mock.Anything, mock.Anything, mock.Anything)
}

// The accept arm for the audit log half. It is the read most worth cancelling in this batch for
// the same reason the user search was in stage 7: an operator chooses the page size from the query
// string, and the count statement runs over the whole table whatever that size is.
func TestHandleAPIAuditLogsGet_ReadsLogsUnderTheRequestsContext(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetAuditLogsPaginated", theApiRequestsContext(), mock.Anything, 1, 20, "", "").
		Return([]models.AuditLog{{Id: 1, AuditEvent: "login"}}, 1, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAuditLogsGet(database).ServeHTTP(rr, apiRequestCarryingId("/api/v1/admin/audit-logs"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

// The reject arm here is not a refusal but a clamp, because this handler has no refusing branch:
// every malformed page and size falls back to the default rather than answering 400. So what the
// case pins is that the clamp happens BEFORE the read and that the read still carries the
// request's context -- a size of 500 reaches the database as 20, not as 500.
func TestHandleAPIAuditLogsGet_AnOutOfRangeSizeReachesTheDatabaseClamped(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetAuditLogsPaginated", theApiRequestsContext(), mock.Anything, 1, 20, "", "").
		Return([]models.AuditLog{}, 0, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAuditLogsGet(database).ServeHTTP(rr,
		apiRequestCarryingId("/api/v1/admin/audit-logs?page=0&size=500"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

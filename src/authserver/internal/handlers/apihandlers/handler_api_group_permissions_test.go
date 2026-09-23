package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// groupperms/count, the fourth swallowing site and the one #425 itself did not list: the group
// shown beside its permissions was published with 0 members on a failed count.
// requireCountFailureAnswered500 is handler_api_groups_test.go's.
func TestHandleAPIGroupPermissionsGet_AFailedCountAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetGroupById", mock.Anything, mock.Anything, int64(5)).
		Return(&models.Group{Id: 5, GroupIdentifier: "admins"}, nil).Once()
	database.On("GroupLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(0, errCountFailed).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIGroupPermissionsGet(database).ServeHTTP(rr, apiIdRequest("/api/v1/admin/groups/5/permissions", "5"))

	requireCountFailureAnswered500(t, rr, capture, 5)
}

func groupPermissionsPutRequest(t *testing.T, permissionIds ...int64) *http.Request {
	t.Helper()
	body, err := json.Marshal(api.UpdateGroupPermissionsRequest{PermissionIds: permissionIds})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/groups/5/permissions", bytes.NewReader(body))
	return setChiURLParam(req, "id", "5")
}

// A grant the handler loaded and then set out to remove was removed by a concurrent request
// before this one read it back. The lookup answers nil, which the handler dereferenced, so the
// request panicked. The grant is gone, which is what was asked, so the answer is the success and
// no removal is audited that this request did not make (#425, folded in).
func TestHandleAPIGroupPermissionsPut_AGrantAlreadyRemovedIsNotACrash(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	database.On("GetGroupById", mock.Anything, mock.Anything, int64(5)).
		Return(&models.Group{Id: 5, GroupIdentifier: "admins"}, nil).Once()
	database.On("GroupLoadPermissions", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*models.Group).Permissions = []models.Permission{{Id: 9}}
		}).Return(nil).Once()
	database.On("GetGroupPermissionByGroupIdAndPermissionId", mock.Anything, mock.Anything, int64(5), int64(9)).
		Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIGroupPermissionsPut(database, auditLogger).ServeHTTP(rr, groupPermissionsPutRequest(t))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertNotCalled(t, "DeleteGroupPermission", mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A permission the request names passed validation and was deleted before the handler read it
// again to grant it. The second read answers nil, which the handler dereferenced. The answer is
// the one validation gives the same permission a moment earlier: 404, and no grant written.
func TestHandleAPIGroupPermissionsPut_APermissionDeletedAfterValidationIsNotACrash(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	database.On("GetGroupById", mock.Anything, mock.Anything, int64(5)).
		Return(&models.Group{Id: 5, GroupIdentifier: "admins"}, nil).Once()
	database.On("GroupLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	database.On("GetPermissionById", mock.Anything, mock.Anything, int64(9)).
		Return(&models.Permission{Id: 9}, nil).Once()
	database.On("GetPermissionById", mock.Anything, mock.Anything, int64(9)).
		Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIGroupPermissionsPut(database, auditLogger).ServeHTTP(rr, groupPermissionsPutRequest(t, 9))

	require.Equal(t, http.StatusNotFound, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	database.AssertNotCalled(t, "CreateGroupPermission", mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

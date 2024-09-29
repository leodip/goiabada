package admingrouphandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminGroupPermissionsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
		{Id: 2, PermissionIdentifier: "permission2", ResourceId: 1},
	}
	group.Permissions = permissions

	resources := []models.Resource{
		{Id: 1, ResourceIdentifier: "resource1"},
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(&resources[0], nil)
	mockDB.On("GetAllResources", mock.Anything).Return(resources, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_permissions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		groupData, ok := data["group"].(struct {
			GroupId         int64
			GroupIdentifier string
			Permissions     map[int64]string
		})
		if !ok {
			return false
		}

		resourcesData, ok := data["resources"].([]models.Resource)
		if !ok {
			return false
		}

		savedSuccessfully, ok := data["savedSuccessfully"].(bool)
		if !ok {
			return false
		}

		// Validate the data passed to the template
		if groupData.GroupId != 1 || groupData.GroupIdentifier != "test-group" {
			return false
		}
		if len(groupData.Permissions) != 2 {
			return false
		}
		if len(resourcesData) != 1 || resourcesData[0].Id != 1 || resourcesData[0].ResourceIdentifier != "resource1" {
			return false
		}
		if savedSuccessfully != false {
			return false
		}
		if data["csrfField"] == nil {
			return false
		}

		return true
	})).Return(nil)

	handler := HandleAdminGroupPermissionsGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/permissions", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

func TestHandleAdminGroupPermissionsPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Permissions:     []models.Permission{{Id: 2, PermissionIdentifier: "permission2", ResourceId: 1}},
	}

	newPermission := &models.Permission{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
	mockDB.On("GetPermissionById", mock.Anything, int64(1)).Return(newPermission, nil)
	mockDB.On("CreateGroupPermission", mock.Anything, mock.AnythingOfType("*models.GroupPermission")).Return(nil)
	mockDB.On("GetGroupPermissionByGroupIdAndPermissionId", mock.Anything, int64(1), int64(2)).Return(&models.GroupPermission{Id: 1}, nil)
	mockDB.On("DeleteGroupPermission", mock.Anything, int64(1)).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-subject")

	mockAuditLogger.On("Log", constants.AuditAddedGroupPermission, mock.Anything).Return(nil)
	mockAuditLogger.On("Log", constants.AuditDeletedGroupPermission, mock.Anything).Return(nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.AnythingOfType("struct { Success bool }")).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		data := args.Get(2).(struct{ Success bool })
		json.NewEncoder(w).Encode(data)
	}).Return()

	handler := HandleAdminGroupPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	requestBody := `{"groupId": 1, "assignedPermissionsIds": [1]}`
	req, _ := http.NewRequest("POST", "/admin/groups/1/permissions", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response struct {
		Success bool `json:"success"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

func TestHandleAdminGroupPermissionsPost_InvalidGroupId(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	mockDB.On("GetGroupById", mock.Anything, int64(999)).Return(nil, nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "group not found"
	}))

	handler := HandleAdminGroupPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	requestBody := `{"groupId": 999, "assignedPermissionsIds": [1]}`
	req, _ := http.NewRequest("POST", "/admin/groups/999/permissions", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupPermissionsPost_NonExistentPermission(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Permissions:     []models.Permission{},
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
	mockDB.On("GetPermissionById", mock.Anything, int64(999)).Return(nil, nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "permission not found"
	}))

	handler := HandleAdminGroupPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	requestBody := `{"groupId": 1, "assignedPermissionsIds": [999]}`
	req, _ := http.NewRequest("POST", "/admin/groups/1/permissions", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupPermissionsPost_ErrorCreatingGroupPermission(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Permissions:     []models.Permission{},
	}

	newPermission := &models.Permission{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
	mockDB.On("GetPermissionById", mock.Anything, int64(1)).Return(newPermission, nil)
	mockDB.On("CreateGroupPermission", mock.Anything, mock.AnythingOfType("*models.GroupPermission")).Return(errors.New("database error"))

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "database error"
	}))

	handler := HandleAdminGroupPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	requestBody := `{"groupId": 1, "assignedPermissionsIds": [1]}`
	req, _ := http.NewRequest("POST", "/admin/groups/1/permissions", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupPermissionsPost_ErrorDeletingGroupPermission(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Permissions:     []models.Permission{{Id: 2, PermissionIdentifier: "permission2", ResourceId: 1}},
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
	mockDB.On("GetGroupPermissionByGroupIdAndPermissionId", mock.Anything, int64(1), int64(2)).Return(&models.GroupPermission{Id: 1}, nil)
	mockDB.On("DeleteGroupPermission", mock.Anything, int64(1)).Return(errors.New("database error"))

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "database error"
	}))

	handler := HandleAdminGroupPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	requestBody := `{"groupId": 1, "assignedPermissionsIds": []}`
	req, _ := http.NewRequest("POST", "/admin/groups/1/permissions", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupPermissionsPost_EmptyAssignedPermissions(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Permissions:     []models.Permission{{Id: 2, PermissionIdentifier: "permission2", ResourceId: 1}},
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
	mockDB.On("GetGroupPermissionByGroupIdAndPermissionId", mock.Anything, int64(1), int64(2)).Return(&models.GroupPermission{Id: 1}, nil)
	mockDB.On("DeleteGroupPermission", mock.Anything, int64(1)).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-subject")

	mockAuditLogger.On("Log", constants.AuditDeletedGroupPermission, mock.Anything).Return(nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.AnythingOfType("struct { Success bool }")).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		data := args.Get(2).(struct{ Success bool })
		json.NewEncoder(w).Encode(data)
	}).Return()

	handler := HandleAdminGroupPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	requestBody := `{"groupId": 1, "assignedPermissionsIds": []}`
	req, _ := http.NewRequest("POST", "/admin/groups/1/permissions", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response struct {
		Success bool `json:"success"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

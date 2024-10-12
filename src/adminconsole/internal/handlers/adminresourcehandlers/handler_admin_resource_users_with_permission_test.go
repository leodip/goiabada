package adminresourcehandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminResourceUsersWithPermissionGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: "test-resource",
		Description:        "Test Resource",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
		{Id: 2, PermissionIdentifier: "permission2", ResourceId: 1},
	}

	users := []models.User{
		{Id: 1, Username: "user1"},
		{Id: 2, Username: "user2"},
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, permissions).Return(nil)
	mockDB.On("GetUsersByPermissionIdPaginated", mock.Anything, int64(1), 1, 10).Return(users, len(users), nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_users_with_permission.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["resourceId"] == int64(1) &&
			data["resourceIdentifier"] == "test-resource" &&
			data["description"] == "Test Resource" &&
			len(data["permissions"].([]models.Permission)) == 2 &&
			data["selectedPermission"] == int64(1)
	})).Return(nil)

	handler := HandleAdminResourceUsersWithPermissionGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/resources/1/users-with-permission", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminResourceUsersWithPermissionRemovePermissionPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: "test-resource",
	}

	user := &models.User{
		Id:       1,
		Username: "testuser",
	}

	permission := &models.Permission{
		Id:                   1,
		PermissionIdentifier: "test-permission",
		ResourceId:           1,
	}

	userPermission := &models.UserPermission{
		Id:           1,
		UserId:       1,
		PermissionId: 1,
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)
	mockDB.On("UserLoadPermissions", mock.Anything, user).Run(func(args mock.Arguments) {
		userArg := args.Get(1).(*models.User)
		userArg.Permissions = []models.Permission{*permission}
	}).Return(nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{*permission}, nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything).Return(nil)
	mockDB.On("GetUserPermissionByUserIdAndPermissionId", mock.Anything, int64(1), int64(1)).Return(userPermission, nil)
	mockDB.On("DeleteUserPermission", mock.Anything, int64(1)).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
	mockAuditLogger.On("Log", constants.AuditDeletedUserPermission, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == int64(1) &&
			details["permissionId"] == int64(1) &&
			details["loggedInUser"] == "admin-user"
	})).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(struct{ Success bool })
		return ok && result.Success
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		err := json.NewEncoder(w).Encode(struct{ Success bool }{Success: true})
		assert.NoError(t, err)
	}).Return()

	handler := HandleAdminResourceUsersWithPermissionRemovePermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/resources/1/users/1/permissions/1/remove", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	rctx.URLParams.Add("userId", "1")
	rctx.URLParams.Add("permissionId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

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
}

func TestHandleAdminResourceUsersWithPermissionAddGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: "test-resource",
		Description:        "Test Resource",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
		{Id: 2, PermissionIdentifier: "permission2", ResourceId: 1},
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, permissions).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_users_with_permission_add.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["resourceId"] == int64(1) &&
			data["resourceIdentifier"] == "test-resource" &&
			data["description"] == "Test Resource" &&
			len(data["permissions"].([]models.Permission)) == 2 &&
			data["selectedPermission"] == int64(1)
	})).Return(nil)

	handler := HandleAdminResourceUsersWithPermissionAddGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/resources/1/users-with-permission/add?permissionId=1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	rctx.URLParams.Add("permissionId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminResourceUsersWithPermissionSearchGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: "test-resource",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
	}

	users := []models.User{
		{Id: 1, Username: "user1", Email: "user1@example.com"},
		{Id: 2, Username: "user2", Email: "user2@example.com"},
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, permissions).Return(nil)
	mockDB.On("SearchUsersPaginated", mock.Anything, "user", 1, 15).Return(users, len(users), nil)
	mockDB.On("UsersLoadPermissions", mock.Anything, users).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(SearchResult)
		return ok && len(result.Users) == 2
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		result := args.Get(2).(SearchResult)
		err := json.NewEncoder(w).Encode(result)
		assert.NoError(t, err)
	}).Return()

	handler := HandleAdminResourceUsersWithPermissionSearchGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/resources/1/users-with-permission/search?query=user&permissionId=1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	rctx.URLParams.Add("permissionId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response SearchResult
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Len(t, response.Users, 2)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminResourceUsersWithPermissionAddPermissionPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: "test-resource",
	}

	user := &models.User{
		Id:       1,
		Username: "testuser",
	}

	permission := &models.Permission{
		Id:                   1,
		PermissionIdentifier: "test-permission",
		ResourceId:           1,
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{*permission}, nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything).Return(nil)
	mockDB.On("CreateUserPermission", mock.Anything, mock.AnythingOfType("*models.UserPermission")).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
	mockAuditLogger.On("Log", constants.AuditAddedUserPermission, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == int64(1) &&
			details["permissionId"] == int64(1) &&
			details["loggedInUser"] == "admin-user"
	})).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(struct{ Success bool })
		return ok && result.Success
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		err := json.NewEncoder(w).Encode(struct{ Success bool }{Success: true})
		assert.NoError(t, err)
	}).Return()

	handler := HandleAdminResourceUsersWithPermissionAddPermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/resources/1/users/1/permissions/1/add", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	rctx.URLParams.Add("userId", "1")
	rctx.URLParams.Add("permissionId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

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
}

func TestHandleAdminResourceUsersWithPermissionGet_FilterOutUserinfoPermission(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
		Description:        "Auth Server",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
		{Id: 2, PermissionIdentifier: constants.UserinfoPermissionIdentifier, ResourceId: 1},
		{Id: 3, PermissionIdentifier: "permission3", ResourceId: 1},
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, permissions).Return(nil)
	mockDB.On("GetUsersByPermissionIdPaginated", mock.Anything, int64(1), 1, 10).Return([]models.User{}, 0, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_users_with_permission.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		permissions, ok := data["permissions"].([]models.Permission)
		return ok && len(permissions) == 2 &&
			permissions[0].PermissionIdentifier != constants.UserinfoPermissionIdentifier &&
			permissions[1].PermissionIdentifier != constants.UserinfoPermissionIdentifier
	})).Return(nil)

	handler := HandleAdminResourceUsersWithPermissionGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/resources/1/users-with-permission", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminResourceUsersWithPermissionRemovePermissionPost_FilterOutUserinfoPermission(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
	}

	user := &models.User{
		Id:       1,
		Username: "testuser",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
		{Id: 2, PermissionIdentifier: constants.UserinfoPermissionIdentifier, ResourceId: 1},
		{Id: 3, PermissionIdentifier: "permission3", ResourceId: 1},
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything).Return(nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "permission 2 does not belong to resource 1"
	})).Return()

	handler := HandleAdminResourceUsersWithPermissionRemovePermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/resources/1/users/1/permissions/2/remove", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	rctx.URLParams.Add("userId", "1")
	rctx.URLParams.Add("permissionId", "2")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuthHelper.AssertNotCalled(t, "GetLoggedInSubject")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminResourceUsersWithPermissionAddGet_FilterOutUserinfoPermission(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
		Description:        "Auth Server",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
		{Id: 2, PermissionIdentifier: constants.UserinfoPermissionIdentifier, ResourceId: 1},
		{Id: 3, PermissionIdentifier: "permission3", ResourceId: 1},
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, permissions).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_users_with_permission_add.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		permissions, ok := data["permissions"].([]models.Permission)
		return ok && len(permissions) == 2 &&
			permissions[0].PermissionIdentifier != constants.UserinfoPermissionIdentifier &&
			permissions[1].PermissionIdentifier != constants.UserinfoPermissionIdentifier
	})).Return(nil)

	handler := HandleAdminResourceUsersWithPermissionAddGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/resources/1/users-with-permission/add?permissionId=1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	rctx.URLParams.Add("permissionId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminResourceUsersWithPermissionAddPermissionPost_FilterOutUserinfoPermission(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
	}

	user := &models.User{
		Id:       1,
		Username: "testuser",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
		{Id: 2, PermissionIdentifier: constants.UserinfoPermissionIdentifier, ResourceId: 1},
		{Id: 3, PermissionIdentifier: "permission3", ResourceId: 1},
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything).Return(nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "permission 2 does not belong to resource 1"
	})).Return()

	handler := HandleAdminResourceUsersWithPermissionAddPermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/resources/1/users/1/permissions/2/add", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	rctx.URLParams.Add("userId", "1")
	rctx.URLParams.Add("permissionId", "2")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuthHelper.AssertNotCalled(t, "GetLoggedInSubject")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

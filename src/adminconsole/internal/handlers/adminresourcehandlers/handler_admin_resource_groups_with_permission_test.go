package adminresourcehandlers

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminResourceGroupsWithPermissionGet(t *testing.T) {
	t.Run("successful request", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
			Description:        "Test Resource",
		}

		permissions := []models.Permission{
			{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
			{Id: 2, PermissionIdentifier: "permission2", ResourceId: 1},
		}

		groups := []models.Group{
			{Id: 1, GroupIdentifier: "group1", Description: "Group 1"},
			{Id: 2, GroupIdentifier: "group2", Description: "Group 2"},
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, permissions).Return(nil)
		mockDB.On("GetAllGroupsPaginated", mock.Anything, 1, 10).Return(groups, len(groups), nil)
		mockDB.On("GroupsLoadPermissions", mock.Anything, groups).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_groups_with_permission.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			resourceId, resourceOk := data["resourceId"].(int64)
			assert.True(t, resourceOk, "resourceId should be an int64")
			assert.Equal(t, int64(1), resourceId, "resourceId should be 1")

			resourceIdentifier, resourceIdentifierOk := data["resourceIdentifier"].(string)
			assert.True(t, resourceIdentifierOk, "resourceIdentifier should be a string")
			assert.Equal(t, "test-resource", resourceIdentifier, "resourceIdentifier should be 'test-resource'")

			description, descriptionOk := data["description"].(string)
			assert.True(t, descriptionOk, "description should be a string")
			assert.Equal(t, "Test Resource", description, "description should be 'Test Resource'")

			permissions, permissionsOk := data["permissions"].([]models.Permission)
			assert.True(t, permissionsOk, "permissions should be a []models.Permission")
			assert.Len(t, permissions, 2, "permissions should contain 2 items")

			selectedPermission, selectedPermissionOk := data["selectedPermission"].(int64)
			assert.True(t, selectedPermissionOk, "selectedPermission should be an int64")
			assert.Equal(t, int64(1), selectedPermission, "selectedPermission should be 1")

			pageResult, pageResultOk := data["pageResult"].(GroupsWithPermissionPageResult)
			assert.True(t, pageResultOk, "pageResult should be a GroupsWithPermissionPageResult")
			assert.Equal(t, 1, pageResult.Page, "pageResult.Page should be 1")
			assert.Equal(t, 10, pageResult.PageSize, "pageResult.PageSize should be 10")
			assert.Equal(t, 2, pageResult.Total, "pageResult.Total should be 2")
			assert.Len(t, pageResult.Groups, 2, "pageResult.Groups should contain 2 items")

			_, csrfFieldOk := data["csrfField"].(template.HTML)
			assert.True(t, csrfFieldOk, "csrfField should be a template.HTML")

			return true
		})).Return(nil)

		handler := HandleAdminResourceGroupsWithPermissionGet(mockHttpHelper, mockSessionStore, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources/1/groups-with-permission", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
	})

	t.Run("resource not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(nil, nil)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "resource not found"
		}))

		handler := HandleAdminResourceGroupsWithPermissionGet(mockHttpHelper, mockSessionStore, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources/1/groups-with-permission", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("invalid resourceId", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "strconv.ParseInt: parsing \"invalid\": invalid syntax"
		}))

		handler := HandleAdminResourceGroupsWithPermissionGet(mockHttpHelper, mockSessionStore, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources/invalid/groups-with-permission", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("invalid page number", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)

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

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "invalid page 0"
		}))

		handler := HandleAdminResourceGroupsWithPermissionGet(mockHttpHelper, mockSessionStore, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources/1/groups-with-permission?page=0", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("filter out userinfo permission for authserver", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)

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

		groups := []models.Group{
			{Id: 1, GroupIdentifier: "group1", Description: "Group 1"},
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, permissions).Return(nil)
		mockDB.On("GetAllGroupsPaginated", mock.Anything, 1, 10).Return(groups, len(groups), nil)
		mockDB.On("GroupsLoadPermissions", mock.Anything, groups).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_groups_with_permission.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			permissions, permissionsOk := data["permissions"].([]models.Permission)
			assert.True(t, permissionsOk, "permissions should be a []models.Permission")
			assert.Len(t, permissions, 2, "permissions should contain 2 items (userinfo filtered out)")

			for _, perm := range permissions {
				assert.NotEqual(t, constants.UserinfoPermissionIdentifier, perm.PermissionIdentifier, "userinfo permission should be filtered out")
			}

			resourceIdentifier, resourceIdentifierOk := data["resourceIdentifier"].(string)
			assert.True(t, resourceIdentifierOk, "resourceIdentifier should be a string")
			assert.Equal(t, constants.AuthServerResourceIdentifier, resourceIdentifier, "resourceIdentifier should be auth server")

			return true
		})).Return(nil)

		handler := HandleAdminResourceGroupsWithPermissionGet(mockHttpHelper, mockSessionStore, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources/1/groups-with-permission", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
	})
}

func TestHandleAdminResourceGroupsWithPermissionAddPermissionPost(t *testing.T) {
	t.Run("successful permission addition", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		group := &models.Group{
			Id:              1,
			GroupIdentifier: "test-group",
		}

		permission := &models.Permission{
			Id:                   1,
			PermissionIdentifier: "test-permission",
			ResourceId:           1,
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
		mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{*permission}, nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything).Return(nil)
		mockDB.On("CreateGroupPermission", mock.Anything, mock.AnythingOfType("*models.GroupPermission")).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
		mockAuditLogger.On("Log", constants.AuditAddedGroupPermission, mock.Anything).Return(nil)

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
			result, ok := v.(struct{ Success bool })
			return ok && result.Success
		})).Run(func(args mock.Arguments) {
			w := args.Get(0).(http.ResponseWriter)
			json.NewEncoder(w).Encode(struct{ Success bool }{Success: true})
		}).Return()

		handler := HandleAdminResourceGroupsWithPermissionAddPermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/admin/resources/1/groups/1/permissions/1/add", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		rctx.URLParams.Add("groupId", "1")
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
	})

	t.Run("resource not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(nil, nil)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "resource not found"
		}))

		handler := HandleAdminResourceGroupsWithPermissionAddPermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/admin/resources/1/groups/1/permissions/1/add", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		rctx.URLParams.Add("groupId", "1")
		rctx.URLParams.Add("permissionId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("group not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(nil, nil)

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "group not found"
		}))

		handler := HandleAdminResourceGroupsWithPermissionAddPermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/admin/resources/1/groups/1/permissions/1/add", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		rctx.URLParams.Add("groupId", "1")
		rctx.URLParams.Add("permissionId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("permission not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		group := &models.Group{
			Id:              1,
			GroupIdentifier: "test-group",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
		mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{}, nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything).Return(nil)

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "permission 1 does not belong to resource 1"
		}))

		handler := HandleAdminResourceGroupsWithPermissionAddPermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/admin/resources/1/groups/1/permissions/1/add", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		rctx.URLParams.Add("groupId", "1")
		rctx.URLParams.Add("permissionId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("permission already added", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		group := &models.Group{
			Id:              1,
			GroupIdentifier: "test-group",
			Permissions:     []models.Permission{{Id: 1, PermissionIdentifier: "test-permission"}},
		}

		permission := &models.Permission{
			Id:                   1,
			PermissionIdentifier: "test-permission",
			ResourceId:           1,
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
		mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{*permission}, nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything).Return(nil)

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "group 1 already has permission 1"
		}))

		handler := HandleAdminResourceGroupsWithPermissionAddPermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/admin/resources/1/groups/1/permissions/1/add", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		rctx.URLParams.Add("groupId", "1")
		rctx.URLParams.Add("permissionId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("filter out userinfo permission for authserver", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: constants.AuthServerResourceIdentifier,
		}

		group := &models.Group{
			Id:              1,
			GroupIdentifier: "test-group",
		}

		permissions := []models.Permission{
			{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
			{Id: 2, PermissionIdentifier: constants.UserinfoPermissionIdentifier, ResourceId: 1},
			{Id: 3, PermissionIdentifier: "permission3", ResourceId: 1},
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
		mockDB.On("GroupLoadPermissions", mock.Anything, group).Return(nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything).Return(nil)

		// We're trying to add the userinfo permission, which should be filtered out
		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "permission 2 does not belong to resource 1"
		}))

		handler := HandleAdminResourceGroupsWithPermissionAddPermissionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/admin/resources/1/groups/1/permissions/2/add", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		rctx.URLParams.Add("groupId", "1")
		rctx.URLParams.Add("permissionId", "2") // This is the ID of the userinfo permission
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuthHelper.AssertNotCalled(t, "GetLoggedInSubject")
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

}

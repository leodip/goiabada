package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestHandleAdminUserPermissionsGet(t *testing.T) {
	t.Run("Valid user and permissions", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserPermissionsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/permissions", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Permissions = []models.Permission{
				{Id: 2, PermissionIdentifier: "write", ResourceId: 1},
				{Id: 1, PermissionIdentifier: "read", ResourceId: 1},
				{Id: 3, PermissionIdentifier: "delete", ResourceId: 2},
			}
		})

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(&models.Resource{Id: 1, ResourceIdentifier: "resource1"}, nil)
		mockDB.On("GetResourceById", mock.Anything, int64(2)).Return(&models.Resource{Id: 2, ResourceIdentifier: "resource2"}, nil)

		resources := []models.Resource{
			{Id: 1, ResourceIdentifier: "resource1"},
			{Id: 2, ResourceIdentifier: "resource2"},
			{Id: 3, ResourceIdentifier: "resource3"},
		}
		mockDB.On("GetAllResources", mock.Anything).Return(resources, nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_permissions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			userPermissions, ok := data["userPermissions"].(map[int64]string)
			if !ok {
				return false
			}

			expectedPermissions := map[int64]string{
				1: "resource1:read",
				2: "resource1:write",
				3: "resource2:delete",
			}

			if len(userPermissions) != len(expectedPermissions) {
				return false
			}

			for id, permission := range expectedPermissions {
				if userPermissions[id] != permission {
					return false
				}
			}

			resources, ok := data["resources"].([]models.Resource)
			if !ok || len(resources) != 3 {
				return false
			}

			for i := 0; i < len(resources)-1; i++ {
				if resources[i].ResourceIdentifier > resources[i+1].ResourceIdentifier {
					return false
				}
			}

			return data["user"] == user
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Valid user with no permissions", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserPermissionsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/permissions", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Permissions = []models.Permission{} // Empty permissions
		})

		resources := []models.Resource{
			{Id: 1, ResourceIdentifier: "resource1"},
			{Id: 2, ResourceIdentifier: "resource2"},
			{Id: 3, ResourceIdentifier: "resource3"},
		}
		mockDB.On("GetAllResources", mock.Anything).Return(resources, nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_permissions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			userPermissions, ok := data["userPermissions"].(map[int64]string)
			if !ok {
				return false
			}

			if len(userPermissions) != 0 {
				return false
			}

			resources, ok := data["resources"].([]models.Resource)
			if !ok || len(resources) != 3 {
				return false
			}

			// Verify resources are sorted
			for i := 0; i < len(resources)-1; i++ {
				if resources[i].ResourceIdentifier > resources[i+1].ResourceIdentifier {
					return false
				}
			}

			return data["user"] == user
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserPermissionsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/invalid/permissions", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserPermissionsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/permissions", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

func TestHandleAdminUserPermissionsPost(t *testing.T) {
	t.Run("Valid permission assignment, retention, and deletion", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		// Assign permissions 1, 2, and 4 (2 is new, 1 is retained, 3 will be deleted, 4 is new)
		reqBody := `{"assignedPermissionsIds": [1, 2, 4]}`
		req, err := http.NewRequest("POST", "/admin/users/123/permissions", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Permissions = []models.Permission{
				{Id: 1, PermissionIdentifier: "read"},
				{Id: 3, PermissionIdentifier: "delete"},
			}
		})

		mockDB.On("GetPermissionById", mock.Anything, int64(1)).Return(&models.Permission{Id: 1, PermissionIdentifier: "read"}, nil)

		// Mock for new permission 2
		mockDB.On("GetPermissionById", mock.Anything, int64(2)).Return(&models.Permission{Id: 2, PermissionIdentifier: "write"}, nil)
		mockDB.On("CreateUserPermission", mock.Anything, mock.MatchedBy(func(up *models.UserPermission) bool {
			return up.UserId == 123 && up.PermissionId == 2
		})).Return(nil)

		// Mock for new permission 4
		mockDB.On("GetPermissionById", mock.Anything, int64(4)).Return(&models.Permission{Id: 4, PermissionIdentifier: "update"}, nil)
		mockDB.On("CreateUserPermission", mock.Anything, mock.MatchedBy(func(up *models.UserPermission) bool {
			return up.UserId == 123 && up.PermissionId == 4
		})).Return(nil)

		// Mock for deleting permission 3
		mockDB.On("GetUserPermissionByUserIdAndPermissionId", mock.Anything, int64(123), int64(3)).
			Return(&models.UserPermission{Id: 30, UserId: 123, PermissionId: 3}, nil)
		mockDB.On("DeleteUserPermission", mock.Anything, int64(30)).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")

		// Audit logs for added permissions
		mockAuditLogger.On("Log", constants.AuditAddedUserPermission, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["permissionId"] == int64(2) && details["loggedInUser"] == "admin"
		})).Return(nil)
		mockAuditLogger.On("Log", constants.AuditAddedUserPermission, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["permissionId"] == int64(4) && details["loggedInUser"] == "admin"
		})).Return(nil)

		// Audit log for deleted permission
		mockAuditLogger.On("Log", constants.AuditDeletedUserPermission, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["permissionId"] == int64(3) && details["loggedInUser"] == "admin"
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockHttpHelper.On("EncodeJson", rr, req, mock.MatchedBy(func(result interface{}) bool {
			return result.(struct{ Success bool }).Success == true
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedPermissionsIds": [1, 2]}`
		req, err := http.NewRequest("POST", "/admin/users/invalid/permissions", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("JsonError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedPermissionsIds": [1, 2]}`
		req, err := http.NewRequest("POST", "/admin/users/123/permissions", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Permission not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedPermissionsIds": [1, 2]}`
		req, err := http.NewRequest("POST", "/admin/users/123/permissions", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Permissions = []models.Permission{} // User starts with no permissions
		})

		// Mock the first permission as found
		mockDB.On("GetPermissionById", mock.Anything, int64(1)).Return(&models.Permission{Id: 1, PermissionIdentifier: "read"}, nil)

		// Mock the second permission as not found
		mockDB.On("GetPermissionById", mock.Anything, int64(2)).Return(nil, nil)

		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "permission with id 2 not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Permission removal", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedPermissionsIds": [1]}`
		req, err := http.NewRequest("POST", "/admin/users/123/permissions", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Permissions = []models.Permission{{Id: 1, PermissionIdentifier: "read"}, {Id: 2, PermissionIdentifier: "write"}}
		})

		mockDB.On("GetUserPermissionByUserIdAndPermissionId", mock.Anything, int64(123), int64(2)).Return(&models.UserPermission{Id: 1, UserId: 123, PermissionId: 2}, nil)
		mockDB.On("DeleteUserPermission", mock.Anything, int64(1)).Return(nil)

		mockDB.On("GetPermissionById", mock.Anything, int64(1)).Return(&models.Permission{Id: 1, PermissionIdentifier: "read"}, nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditDeletedUserPermission, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["permissionId"] == int64(2) && details["loggedInUser"] == "admin"
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockHttpHelper.On("EncodeJson", rr, req, mock.MatchedBy(func(result interface{}) bool {
			return result.(struct{ Success bool }).Success == true
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

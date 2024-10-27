package adminuserhandlers

import (
	"context"
	"encoding/json"
	"errors"
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

func TestHandleAdminUserGroupsGet(t *testing.T) {
	t.Run("Valid user and groups", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserGroupsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/groups", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Groups = []models.Group{{Id: 1, GroupIdentifier: "group1"}}
		})

		allGroups := []models.Group{{Id: 1, GroupIdentifier: "group1"}, {Id: 2, GroupIdentifier: "group2"}}
		mockDB.On("GetAllGroups", mock.Anything).Return(allGroups, nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_groups.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["user"] == user &&
				len(data["userGroups"].(map[int64]string)) == 1 &&
				len(data["allGroups"].([]models.Group)) == 2
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

		handler := HandleAdminUserGroupsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/invalid/groups", nil)
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

		handler := HandleAdminUserGroupsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/groups", nil)
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

func TestHandleAdminUserGroupsPost(t *testing.T) {
	t.Run("Valid group assignment", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserGroupsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedGroupsIds": [1, 2]}`
		req, err := http.NewRequest("POST", "/admin/users/123/groups", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Groups = []models.Group{{Id: 1, GroupIdentifier: "group1"}}
		})

		mockDB.On("GetGroupById", mock.Anything, int64(2)).Return(&models.Group{Id: 2, GroupIdentifier: "group2"}, nil)

		// Updated mock with custom matcher
		mockDB.On("CreateUserGroup", mock.Anything, mock.MatchedBy(func(ug *models.UserGroup) bool {
			// Validate the UserGroup properties
			if ug.UserId != 123 {
				t.Errorf("Expected UserId to be 123, got %d", ug.UserId)
				return false
			}
			if ug.GroupId != 2 {
				t.Errorf("Expected GroupId to be 2, got %d", ug.GroupId)
				return false
			}
			return true
		})).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditUserAddedToGroup, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["groupId"] == int64(2) && details["loggedInUser"] == "admin"
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

		handler := HandleAdminUserGroupsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedGroupsIds": [1, 2]}`
		req, err := http.NewRequest("POST", "/admin/users/invalid/groups", strings.NewReader(reqBody))
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

		handler := HandleAdminUserGroupsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedGroupsIds": [1, 2]}`
		req, err := http.NewRequest("POST", "/admin/users/123/groups", strings.NewReader(reqBody))
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

	t.Run("Invalid JSON input", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserGroupsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `invalid json`
		req, err := http.NewRequest("POST", "/admin/users/123/groups", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err != nil && err.(*json.SyntaxError) != nil
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Group not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserGroupsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedGroupsIds": [1, 2]}`
		req, err := http.NewRequest("POST", "/admin/users/123/groups", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Groups = []models.Group{} // User has no groups initially
		})

		mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(nil, nil).Once()

		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "group not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Database error on CreateUserGroup", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserGroupsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedGroupsIds": [1, 2]}`
		req, err := http.NewRequest("POST", "/admin/users/123/groups", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Groups = []models.Group{{Id: 1, GroupIdentifier: "group1"}}
		})

		mockDB.On("GetGroupById", mock.Anything, int64(2)).Return(&models.Group{Id: 2, GroupIdentifier: "group2"}, nil)
		mockDB.On("CreateUserGroup", mock.Anything, mock.AnythingOfType("*models.UserGroup")).Return(errors.New("database error"))

		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Group removal", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserGroupsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedGroupsIds": [1]}`
		req, err := http.NewRequest("POST", "/admin/users/123/groups", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Groups = []models.Group{{Id: 1, GroupIdentifier: "group1"}, {Id: 2, GroupIdentifier: "group2"}}
		})

		mockDB.On("GetGroupById", mock.Anything, int64(2)).Return(&models.Group{Id: 2, GroupIdentifier: "group2"}, nil)
		mockDB.On("GetUserGroupByUserIdAndGroupId", mock.Anything, int64(123), int64(2)).Return(&models.UserGroup{Id: 1, UserId: 123, GroupId: 2}, nil)
		mockDB.On("DeleteUserGroup", mock.Anything, int64(1)).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditUserRemovedFromGroup, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["groupId"] == int64(2) && details["loggedInUser"] == "admin"
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

	t.Run("Database error on DeleteUserGroup", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserGroupsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"assignedGroupsIds": [1]}`
		req, err := http.NewRequest("POST", "/admin/users/123/groups", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
			user := args.Get(1).(*models.User)
			user.Groups = []models.Group{{Id: 1, GroupIdentifier: "group1"}, {Id: 2, GroupIdentifier: "group2"}}
		})

		mockDB.On("GetGroupById", mock.Anything, int64(2)).Return(&models.Group{Id: 2, GroupIdentifier: "group2"}, nil)
		mockDB.On("GetUserGroupByUserIdAndGroupId", mock.Anything, int64(123), int64(2)).Return(&models.UserGroup{Id: 1, UserId: 123, GroupId: 2}, nil)
		mockDB.On("DeleteUserGroup", mock.Anything, int64(1)).Return(errors.New("database error"))

		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

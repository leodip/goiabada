package admingrouphandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminGroupMembersRemoveUserPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
	}

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
		Email:   "user@example.com",
	}

	userGroup := &models.UserGroup{
		Id:      1,
		UserId:  1,
		GroupId: 1,
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)
	mockDB.On("GetUserGroupByUserIdAndGroupId", mock.Anything, int64(1), int64(1)).Return(userGroup, nil)
	mockDB.On("DeleteUserGroup", mock.Anything, int64(1)).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-subject")

	mockAuditLogger.On("Log", constants.AuditUserRemovedFromGroup, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == int64(1) &&
			details["groupId"] == int64(1) &&
			details["loggedInUser"] == "admin-subject"
	})).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(struct{ Success bool })
		return ok && result.Success
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		json.NewEncoder(w).Encode(struct{ Success bool }{Success: true})
	}).Return()

	handler := HandleAdminGroupMembersRemoveUserPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/groups/1/members/1/remove", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("userId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response struct {
		Success bool `json:"success"`
	}
	err := json.NewDecoder(rr.Body).Decode(&response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminGroupMembersRemoveUserPost_GroupNotFound(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(nil, nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "group not found"
	}))

	handler := HandleAdminGroupMembersRemoveUserPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/groups/1/members/1/remove", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("userId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminGroupMembersRemoveUserPost_UserNotFound(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "user not found"
	}))

	handler := HandleAdminGroupMembersRemoveUserPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/groups/1/members/1/remove", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("userId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminGroupMembersRemoveUserPost_UserNotInGroup(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
	}

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
		Email:   "user@example.com",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)
	mockDB.On("GetUserGroupByUserIdAndGroupId", mock.Anything, int64(1), int64(1)).Return(nil, nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "user not in group"
	}))

	handler := HandleAdminGroupMembersRemoveUserPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/groups/1/members/1/remove", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("userId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

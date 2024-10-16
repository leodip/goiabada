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

func TestHandleAdminGroupMembersAddGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_members_add.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["groupId"] == int64(1) &&
			data["groupIdentifier"] == "test-group" &&
			data["description"] == "Test Group"
	})).Return(nil)

	handler := HandleAdminGroupMembersAddGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/members/add", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupMembersSearchGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
	}

	user1UUID := uuid.New()
	user2UUID := uuid.New()
	users := []models.User{
		{Id: 1, Subject: user1UUID, Username: "user1", Email: "user1@example.com"},
		{Id: 2, Subject: user2UUID, Username: "user2", Email: "user2@example.com"},
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("SearchUsersPaginated", mock.Anything, "test", 1, 15).Return(users, 2, nil)
	mockDB.On("UsersLoadGroups", mock.Anything, users).Return(nil)

	// Set up expectation for EncodeJson with data validation
	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(result SearchResult) bool {
		if len(result.Users) != 2 {
			return false
		}
		expectedUsers := []UserResult{
			{Id: 1, Subject: user1UUID.String(), Username: "user1", Email: "user1@example.com", AddedToGroup: false},
			{Id: 2, Subject: user2UUID.String(), Username: "user2", Email: "user2@example.com", AddedToGroup: false},
		}
		for i, user := range result.Users {
			if user != expectedUsers[i] {
				return false
			}
		}
		return true
	})).Return()

	handler := HandleAdminGroupMembersSearchGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/members/search?query=test", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupMembersAddPost(t *testing.T) {
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
	mockDB.On("CreateUserGroup", mock.Anything, mock.AnythingOfType("*models.UserGroup")).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditUserAddedToGroup, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == int64(1) &&
			details["groupId"] == int64(1) &&
			details["loggedInUser"] == "test-subject"
	})).Return(nil)

	// Mock the JSON encoding
	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(struct{ Success bool })
		return ok && result.Success
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		result := args.Get(2).(struct{ Success bool })
		err := json.NewEncoder(w).Encode(result)
		assert.NoError(t, err)
	}).Return()

	handler := HandleAdminGroupMembersAddPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/groups/1/members/add?userId=1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
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

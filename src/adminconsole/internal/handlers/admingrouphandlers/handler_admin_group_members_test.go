package admingrouphandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminGroupMembersGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	users := []models.User{
		{Id: 1, Email: "user1@example.com"},
		{Id: 2, Email: "user2@example.com"},
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetGroupMembersPaginated", mock.Anything, int64(1), 1, 10).Return(users, 2, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_members.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		pageResult, ok := data["pageResult"].(PageResult)
		return ok &&
			data["groupId"] == int64(1) &&
			data["groupIdentifier"] == "test-group" &&
			data["description"] == "Test Group" &&
			pageResult.Page == 1 &&
			pageResult.PageSize == 10 &&
			pageResult.Total == 2 &&
			len(pageResult.Users) == 2
	})).Return(nil)

	handler := HandleAdminGroupMembersGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/members?page=1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupMembersGet_InvalidGroupId(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "groupId is required"
	}))

	handler := HandleAdminGroupMembersGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups//members", nil)
	rctx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertNotCalled(t, "GetGroupById")
}

func TestHandleAdminGroupMembersGet_GroupNotFound(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(nil, nil)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "group not found"
	}))

	handler := HandleAdminGroupMembersGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/members", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupMembersGet_InvalidPage(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "invalid page 0"
	}))

	handler := HandleAdminGroupMembersGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/members?page=0", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

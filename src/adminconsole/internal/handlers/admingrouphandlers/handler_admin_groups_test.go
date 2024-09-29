package admingrouphandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminGroupsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	groups := []*models.Group{
		{Id: 1, GroupIdentifier: "group1", Description: "Group 1"},
		{Id: 2, GroupIdentifier: "group2", Description: "Group 2"},
	}

	mockDB.On("GetAllGroups", mock.Anything).Return(groups, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		renderedGroups, ok := data["groups"].([]*models.Group)
		return ok && len(renderedGroups) == 2
	})).Return(nil)

	handler := HandleAdminGroupsGet(mockHttpHelper, mockDB)

	req, err := http.NewRequest("GET", "/admin/groups", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupsGet_DatabaseError(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockDB.On("GetAllGroups", mock.Anything).Return(nil, assert.AnError)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, assert.AnError).Return()

	handler := HandleAdminGroupsGet(mockHttpHelper, mockDB)

	req, err := http.NewRequest("GET", "/admin/groups", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupsGet_RenderError(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	groups := []*models.Group{}

	mockDB.On("GetAllGroups", mock.Anything).Return(groups, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups.html", mock.Anything).Return(assert.AnError)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, assert.AnError).Return()

	handler := HandleAdminGroupsGet(mockHttpHelper, mockDB)

	req, err := http.NewRequest("GET", "/admin/groups", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

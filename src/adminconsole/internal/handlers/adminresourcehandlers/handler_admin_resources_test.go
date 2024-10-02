package adminresourcehandlers

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

func TestHandleAdminResourcesGet(t *testing.T) {
	t.Run("successful retrieval of resources", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		resources := []models.Resource{
			{Id: 1, ResourceIdentifier: "resource1", Description: "Description 1"},
			{Id: 2, ResourceIdentifier: "resource2", Description: "Description 2"},
		}

		mockDB.On("GetAllResources", mock.Anything).Return(resources, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return len(data["resources"].([]models.Resource)) == 2
		})).Return(nil)

		handler := HandleAdminResourcesGet(mockHttpHelper, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		mockDB.On("GetAllResources", mock.Anything).Return(nil, assert.AnError)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err == assert.AnError
		})).Return()

		handler := HandleAdminResourcesGet(mockHttpHelper, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("render template error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		resources := []models.Resource{}

		mockDB.On("GetAllResources", mock.Anything).Return(resources, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources.html", mock.Anything).Return(assert.AnError)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err == assert.AnError
		})).Return()

		handler := HandleAdminResourcesGet(mockHttpHelper, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})
}

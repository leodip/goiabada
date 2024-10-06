package adminclienthandlers

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

func TestHandleAdminClientsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	clients := []models.Client{
		{Id: 1, ClientIdentifier: "client1"},
		{Id: 2, ClientIdentifier: "client2"},
	}

	mockDB.On("GetAllClients", mock.Anything).Return(clients, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		clientsData, ok := data["clients"].([]models.Client)
		return ok && len(clientsData) == 2 &&
			clientsData[0].Id == 1 && clientsData[0].ClientIdentifier == "client1" &&
			clientsData[1].Id == 2 && clientsData[1].ClientIdentifier == "client2"
	})).Return(nil)

	handler := HandleAdminClientsGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientsGet_DatabaseError(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockDB.On("GetAllClients", mock.Anything).Return(nil, assert.AnError)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, assert.AnError).Return()

	handler := HandleAdminClientsGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientsGet_RenderError(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	clients := []*models.Client{}

	mockDB.On("GetAllClients", mock.Anything).Return(clients, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients.html", mock.Anything).Return(assert.AnError)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, assert.AnError).Return()

	handler := HandleAdminClientsGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

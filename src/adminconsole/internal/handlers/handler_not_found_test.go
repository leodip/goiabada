package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleNotFoundGet_Success(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	handler := HandleNotFoundGet(mockHttpHelper)

	req, err := http.NewRequest("GET", "/non-existent-page", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()

	expectedBindData := map[string]interface{}{
		"_httpStatus": http.StatusNotFound,
	}

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/not_found.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return assert.Equal(t, expectedBindData, data)
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleNotFoundGet_RenderTemplateError(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	handler := HandleNotFoundGet(mockHttpHelper)

	req, err := http.NewRequest("GET", "/non-existent-page", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()

	expectedBindData := map[string]interface{}{
		"_httpStatus": http.StatusNotFound,
	}

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/not_found.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return assert.Equal(t, expectedBindData, data)
	})).Return(assert.AnError)

	mockHttpHelper.On("InternalServerError", rr, req, assert.AnError).Return()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
}

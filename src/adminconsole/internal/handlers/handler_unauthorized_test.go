package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleUnauthorizedGet_Success(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	handler := HandleUnauthorizedGet(mockHttpHelper)

	req, err := http.NewRequest("GET", "/unauthorized", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()

	expectedBindData := map[string]interface{}{
		"_httpStatus": http.StatusUnauthorized,
	}

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/unauthorized.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return assert.Equal(t, expectedBindData, data)
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleUnauthorizedGet_RenderTemplateError(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	handler := HandleUnauthorizedGet(mockHttpHelper)

	req, err := http.NewRequest("GET", "/unauthorized", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()

	expectedBindData := map[string]interface{}{
		"_httpStatus": http.StatusUnauthorized,
	}

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/unauthorized.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return assert.Equal(t, expectedBindData, data)
	})).Return(assert.AnError)

	mockHttpHelper.On("InternalServerError", rr, req, assert.AnError).Return()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
}

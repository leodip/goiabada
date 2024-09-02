package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/config"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleIndexGet(t *testing.T) {
	// Test case 1: Successful rendering
	t.Run("SuccessfulRendering", func(t *testing.T) {
		mockHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/index.html", mock.Anything).Return(nil)

		handler := HandleIndexGet(mockHelper)

		req, err := http.NewRequest("GET", "/", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHelper.AssertExpectations(t)
	})

	// Test case 2: RenderTemplate returns an error
	t.Run("RenderTemplateError", func(t *testing.T) {
		mockHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/index.html", mock.Anything).Return(assert.AnError)
		mockHelper.On("InternalServerError", mock.Anything, mock.Anything, assert.AnError).Return()

		handler := HandleIndexGet(mockHelper)

		req, err := http.NewRequest("GET", "/", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHelper.AssertExpectations(t)
	})

	// Test case 3: Verify correct bind data
	t.Run("VerifyBindData", func(t *testing.T) {
		mockHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/index.html", mock.MatchedBy(func(bind map[string]interface{}) bool {
			baseURL, ok := bind["AuthServerBaseUrl"]
			return ok && baseURL == config.GetAuthServer().BaseURL
		})).Return(nil)

		handler := HandleIndexGet(mockHelper)

		req, err := http.NewRequest("GET", "/", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHelper.AssertExpectations(t)
	})
}

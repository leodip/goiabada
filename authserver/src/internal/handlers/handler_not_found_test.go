package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleNotFoundGet(t *testing.T) {
	t.Run("Successful rendering", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)

		handler := HandleNotFoundGet(httpHelper)

		req, err := http.NewRequest("GET", "/non-existent-path", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		httpHelper.On("RenderTemplate",
			mock.AnythingOfType("*httptest.ResponseRecorder"),
			req,
			"/layouts/no_menu_layout.html",
			"/not_found.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["_httpStatus"] == http.StatusNotFound
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Rendering error", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)

		handler := HandleNotFoundGet(httpHelper)

		req, err := http.NewRequest("GET", "/non-existent-path", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		renderError := errors.New("rendering error")

		httpHelper.On("RenderTemplate",
			mock.AnythingOfType("*httptest.ResponseRecorder"),
			req,
			"/layouts/no_menu_layout.html",
			"/not_found.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["_httpStatus"] == http.StatusNotFound
			}),
		).Return(renderError)

		httpHelper.On("InternalServerError",
			mock.AnythingOfType("*httptest.ResponseRecorder"),
			req,
			renderError,
		)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})
}

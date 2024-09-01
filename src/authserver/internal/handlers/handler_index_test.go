package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"

	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

func TestHandleIndexGet(t *testing.T) {
	t.Run("Redirects to AdminConsoleBaseUrl", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

		handler := HandleIndexGet(httpHelper)

		req, err := http.NewRequest("GET", "/", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		config.Get().BaseURL = "http://admin.example.com"

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "http://admin.example.com", rr.Header().Get("Location"))
	})
}

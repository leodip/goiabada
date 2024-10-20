package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"

	"github.com/stretchr/testify/assert"
)

func TestHandleHealthCheckGet(t *testing.T) {
	t.Run("Successful health check", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

		handler := HandleHealthCheckGet(httpHelper)

		req, err := http.NewRequest("GET", "/health", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "healthy", rr.Body.String())
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})
}

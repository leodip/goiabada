package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleIndexGet(t *testing.T) {
	t.Run("Redirects to AdminConsoleBaseUrl", func(t *testing.T) {
		handler := HandleIndexGet(testAdminConsoleBaseURL)

		req, err := http.NewRequest("GET", "/", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "https://admin.test", rr.Header().Get("Location"))
	})
}

package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSettings(t *testing.T) {
	t.Run("Successful retrieval of settings", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		expectedSettings := &record.Settings{
			Id:      1,
			AppName: "TestApp",
		}
		mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(expectedSettings, nil)

		middleware := Settings(mockDB, PageFaults())

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		var contextSettings *record.Settings
		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contextSettings, _ = reqctx.SettingsFrom(r.Context())
		})).ServeHTTP(rr, req)

		assert.Equal(t, expectedSettings, contextSettings)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Database error", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, errors.New("database error"))

		middleware := Settings(mockDB, PageFaults())

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), "fatal failure in GetSettings() middleware")
	})
}

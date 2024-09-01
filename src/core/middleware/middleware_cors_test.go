package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMiddlewareCors(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		origin        string
		expectedAllow bool
		setupMock     func(*mocks_data.Database)
	}{
		{
			name:          "Allow CORS for openid-configuration",
			path:          "/.well-known/openid-configuration",
			origin:        "http://example.com",
			expectedAllow: true,
			setupMock:     func(db *mocks_data.Database) {},
		},
		{
			name:          "Allow CORS for certs",
			path:          "/certs",
			origin:        "http://example.com",
			expectedAllow: true,
			setupMock:     func(db *mocks_data.Database) {},
		},
		{
			name:          "Allow CORS for auth/token with valid origin",
			path:          "/auth/token",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("GetAllWebOrigins", mock.Anything).Return([]*models.WebOrigin{
					{Origin: "http://allowed.com"},
				}, nil)
			},
		},
		{
			name:          "Allow CORS for auth/logout with valid origin",
			path:          "/auth/logout",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("GetAllWebOrigins", mock.Anything).Return([]*models.WebOrigin{
					{Origin: "http://allowed.com"},
				}, nil)
			},
		},
		{
			name:          "Allow CORS for userinfo with valid origin",
			path:          "/userinfo",
			origin:        "http://allowed.com",
			expectedAllow: true,
			setupMock: func(db *mocks_data.Database) {
				db.On("GetAllWebOrigins", mock.Anything).Return([]*models.WebOrigin{
					{Origin: "http://allowed.com"},
				}, nil)
			},
		},
		{
			name:          "Disallow CORS for auth/token with invalid origin",
			path:          "/auth/token",
			origin:        "http://disallowed.com",
			expectedAllow: false,
			setupMock: func(db *mocks_data.Database) {
				db.On("GetAllWebOrigins", mock.Anything).Return([]*models.WebOrigin{
					{Origin: "http://allowed.com"},
				}, nil)
			},
		},
		{
			name:          "Disallow CORS for auth/logout with invalid origin",
			path:          "/auth/logout",
			origin:        "http://disallowed.com",
			expectedAllow: false,
			setupMock: func(db *mocks_data.Database) {
				db.On("GetAllWebOrigins", mock.Anything).Return([]*models.WebOrigin{
					{Origin: "http://allowed.com"},
				}, nil)
			},
		},
		{
			name:          "Disallow CORS for userinfo with invalid origin",
			path:          "/userinfo",
			origin:        "http://disallowed.com",
			expectedAllow: false,
			setupMock: func(db *mocks_data.Database) {
				db.On("GetAllWebOrigins", mock.Anything).Return([]*models.WebOrigin{
					{Origin: "http://allowed.com"},
				}, nil)
			},
		},
		{
			name:          "Disallow CORS for unknown path",
			path:          "/unknown",
			origin:        "http://example.com",
			expectedAllow: false,
			setupMock:     func(db *mocks_data.Database) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := mocks_data.NewDatabase(t)
			tt.setupMock(db)

			handler := MiddlewareCors(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("OPTIONS", tt.path, nil)
			req.Header.Set("Origin", tt.origin)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if tt.expectedAllow {
				assert.Equal(t, tt.origin, rr.Header().Get("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

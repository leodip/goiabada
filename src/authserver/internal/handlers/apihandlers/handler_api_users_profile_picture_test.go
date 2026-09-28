package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// setChiURLParam sets a chi URL parameter on the request
func setChiURLParam(req *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// setTokenContextWithClaims sets a JWT token with custom claims in the request context
func setTokenContextWithClaims(req *http.Request, claims map[string]interface{}) *http.Request {
	jwtToken := oauth.JwtToken{
		Claims: claims,
	}
	ctx := reqctx.WithValidatedToken(req.Context(), jwtToken)
	return req.WithContext(ctx)
}

func TestHandleAPIUserProfilePictureGet_NoUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database, testBaseURL)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users//profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleAPIUserProfilePictureGet_InvalidUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database, testBaseURL)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/invalid/profile-picture", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleAPIUserProfilePictureGet_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database, testBaseURL)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "NOT_FOUND", response["error_code"])

	database.AssertExpectations(t)
}

func TestHandleAPIUserProfilePictureGet_HasPicture(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database, testBaseURL)

	sub := fake.UUID()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("UserHasProfilePicture", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(true, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["hasPicture"].(bool))
	assert.Equal(t, testBaseURL+"/userinfo/picture/"+sub, response["pictureUrl"])

	database.AssertExpectations(t)
}

func TestHandleAPIUserProfilePictureGet_NoPicture(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database, testBaseURL)

	sub := fake.UUID()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("UserHasProfilePicture", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(false, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["hasPicture"].(bool))
	assert.Nil(t, response["pictureUrl"])

	database.AssertExpectations(t)
}

func TestHandleAPIUserProfilePicturePost_NoUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	req, _ := http.NewRequest("POST", "/api/v1/admin/users//profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleAPIUserProfilePicturePost_InvalidUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	req, _ := http.NewRequest("POST", "/api/v1/admin/users/invalid/profile-picture", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleAPIUserProfilePicturePost_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "NOT_FOUND", response["error_code"])

	database.AssertExpectations(t)
}

func TestHandleAPIUserProfilePicturePost_InvalidImage(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}

	invalidImageData := []byte("not a valid image")
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", invalidImageData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

// The size cap is the one the handler was handed, not the configured default: an image the
// default accepts is refused under a smaller injected cap, and the refusal names that cap (#434).
func TestHandleAPIUserProfilePicturePost_RefusesAnImageOverTheCapItWasHanded(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger, testBaseURL, 64)

	sub := fake.UUID()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}

	pictureData := createTestPNG(100, 100)
	require.Greater(t, len(pictureData), 64)
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", pictureData)
	require.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
	assert.Equal(t, "file size exceeds maximum allowed size of 64 bytes", response["error_description"])
}

func TestHandleAPIUserProfilePicturePost_CreateNew(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}
	adminSub := fake.UUID()

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, nil)
	database.On("CreateUserProfilePicture", mock.Anything, (*sql.Tx)(nil), mock.MatchedBy(func(pp *models.UserProfilePicture) bool {
		return pp.UserId == int64(123) && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedUserProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.Equal(t, testBaseURL+"/userinfo/picture/"+sub, response["pictureUrl"])

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIUserProfilePicturePost_UpdateExisting(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}
	existingPicture := &models.UserProfilePicture{
		Id:          1,
		UserId:      123,
		Picture:     []byte("old picture data"),
		ContentType: "image/jpeg",
	}
	adminSub := fake.UUID()

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(existingPicture, nil)
	database.On("UpdateUserProfilePicture", mock.Anything, (*sql.Tx)(nil), mock.MatchedBy(func(pp *models.UserProfilePicture) bool {
		return pp.Id == existingPicture.Id && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedUserProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIUserProfilePictureDelete_NoUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users//profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleAPIUserProfilePictureDelete_InvalidUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/invalid/profile-picture", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleAPIUserProfilePictureDelete_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "NOT_FOUND", response["error_code"])

	database.AssertExpectations(t)
}

func TestHandleAPIUserProfilePictureDelete_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	sub := fake.UUID()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}
	adminSub := fake.UUID()

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("DeleteUserProfilePicture", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.AuditDeletedUserProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIUserProfilePictureDelete_DatabaseError(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	sub := fake.UUID()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("DeleteUserProfilePicture", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", response["error_code"])

	database.AssertExpectations(t)
}

package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
	ctx := context.WithValue(req.Context(), constants.ContextKeyValidatedToken, jwtToken)
	return req.WithContext(ctx)
}

func TestHandleAPIUserProfilePictureGet_NoUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users//profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "USER_ID_REQUIRED", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIUserProfilePictureGet_InvalidUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/invalid/profile-picture", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INVALID_USER_ID", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIUserProfilePictureGet_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "USER_NOT_FOUND", response["error"].(map[string]interface{})["code"])

	database.AssertExpectations(t)
}

func TestHandleAPIUserProfilePictureGet_HasPicture(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database)

	sub := uuid.New()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("UserHasProfilePicture", (*sql.Tx)(nil), int64(123)).Return(true, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["hasPicture"].(bool))
	assert.Contains(t, response["pictureUrl"].(string), sub.String())

	database.AssertExpectations(t)
}

func TestHandleAPIUserProfilePictureGet_NoPicture(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIUserProfilePictureGet(database)

	sub := uuid.New()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("UserHasProfilePicture", (*sql.Tx)(nil), int64(123)).Return(false, nil)

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
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger)

	req, _ := http.NewRequest("POST", "/api/v1/admin/users//profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "USER_ID_REQUIRED", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIUserProfilePicturePost_InvalidUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger)

	req, _ := http.NewRequest("POST", "/api/v1/admin/users/invalid/profile-picture", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INVALID_USER_ID", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIUserProfilePicturePost_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger)

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "USER_NOT_FOUND", response["error"].(map[string]interface{})["code"])

	database.AssertExpectations(t)
}

func TestHandleAPIUserProfilePicturePost_InvalidImage(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}

	invalidImageData := []byte("not a valid image")
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", invalidImageData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INVALID_IMAGE", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIUserProfilePicturePost_CreateNew(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}
	adminSub := uuid.New().String()

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", (*sql.Tx)(nil), int64(123)).Return(nil, nil)
	database.On("CreateUserProfilePicture", (*sql.Tx)(nil), mock.MatchedBy(func(pp *models.UserProfilePicture) bool {
		return pp.UserId == int64(123) && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", constants.AuditUpdatedUserProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.Contains(t, response["pictureUrl"].(string), sub.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIUserProfilePicturePost_UpdateExisting(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePicturePost(database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}
	existingPicture := &models.UserProfilePicture{
		Id:          1,
		UserId:      123,
		Picture:     []byte("old picture data"),
		ContentType: "image/jpeg",
	}
	adminSub := uuid.New().String()

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", (*sql.Tx)(nil), int64(123)).Return(existingPicture, nil)
	database.On("UpdateUserProfilePicture", (*sql.Tx)(nil), mock.MatchedBy(func(pp *models.UserProfilePicture) bool {
		return pp.Id == existingPicture.Id && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", constants.AuditUpdatedUserProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
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
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users//profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "USER_ID_REQUIRED", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIUserProfilePictureDelete_InvalidUserId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/invalid/profile-picture", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INVALID_USER_ID", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIUserProfilePictureDelete_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "USER_NOT_FOUND", response["error"].(map[string]interface{})["code"])

	database.AssertExpectations(t)
}

func TestHandleAPIUserProfilePictureDelete_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}
	adminSub := uuid.New().String()

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("DeleteUserProfilePicture", (*sql.Tx)(nil), int64(123)).Return(nil)

	auditLogger.On("Log", constants.AuditDeletedUserProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
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
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIUserProfilePictureDelete(database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 123, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("DeleteUserProfilePicture", (*sql.Tx)(nil), int64(123)).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "DELETE_ERROR", response["error"].(map[string]interface{})["code"])

	database.AssertExpectations(t)
}

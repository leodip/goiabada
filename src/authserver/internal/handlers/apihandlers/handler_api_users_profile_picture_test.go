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
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
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

func TestHandleUserProfilePictureGet_NoUserId(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleUserProfilePictureGet(database, testBaseURL)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users//profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleUserProfilePictureGet_InvalidUserId(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleUserProfilePictureGet(database, testBaseURL)

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

func TestHandleUserProfilePictureGet_UserNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleUserProfilePictureGet(database, testBaseURL)

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

func TestHandleUserProfilePictureGet_HasPicture(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleUserProfilePictureGet(database, testBaseURL)

	sub := fake.UUID()
	user := &record.User{Id: 123, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("UserHasProfilePicture", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(true, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"hasPicture":true,"pictureUrl":"`+testBaseURL+`/userinfo/picture/`+sub+`"}`, rr.Body.String())

	database.AssertExpectations(t)
}

func TestHandleUserProfilePictureGet_NoPicture(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleUserProfilePictureGet(database, testBaseURL)

	sub := fake.UUID()
	user := &record.User{Id: 123, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("UserHasProfilePicture", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(false, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"hasPicture":false}`, rr.Body.String())

	database.AssertExpectations(t)
}

func TestHandleUserProfilePicturePost_NoUserId(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	req, _ := http.NewRequest("POST", "/api/v1/admin/users//profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleUserProfilePicturePost_InvalidUserId(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

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

func TestHandleUserProfilePicturePost_UserNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

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

func TestHandleUserProfilePicturePost_InvalidImage(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	user := &record.User{Id: 123, Subject: sub, Enabled: true}

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
	// The catalog key and its English sentence, through writeValidationError, as every other
	// validator on this API answers (#435).
	assert.Equal(t, "validator.image.unsupported_type", response["error_code"])
	assert.Equal(t, "The image type is not supported. Allowed types are JPEG, PNG, GIF and WebP.", response["error_description"])
}

// The size cap is the one the handler was handed, not the configured default: an image the
// default accepts is refused under a smaller injected cap, and the refusal names that cap (#434).
func TestHandleUserProfilePicturePost_RefusesAnImageOverTheCapItWasHanded(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePicturePost(database, auditLogger, testBaseURL, 64)

	sub := fake.UUID()
	user := &record.User{Id: 123, Subject: sub, Enabled: true}

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
	assert.Equal(t, "validator.image.too_large", response["error_code"])
	assert.Equal(t, "The image can be at most 64 bytes.", response["error_description"])
}

func TestHandleUserProfilePicturePost_CreateNew(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	user := &record.User{Id: 123, Subject: sub, Enabled: true}
	adminSub := fake.UUID()

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/users/123/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, nil)
	database.On("CreateUserProfilePicture", mock.Anything, (*sql.Tx)(nil), mock.MatchedBy(func(pp *record.UserProfilePicture) bool {
		return pp.UserId == int64(123) && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.EventUpdatedUserProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"success":true,"pictureUrl":"`+testBaseURL+`/userinfo/picture/`+sub+`"}`, rr.Body.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleUserProfilePicturePost_UpdateExisting(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	user := &record.User{Id: 123, Subject: sub, Enabled: true}
	existingPicture := &record.UserProfilePicture{
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
	database.On("UpdateUserProfilePicture", mock.Anything, (*sql.Tx)(nil), mock.MatchedBy(func(pp *record.UserProfilePicture) bool {
		return pp.Id == existingPicture.Id && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.EventUpdatedUserProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"success":true,"pictureUrl":"`+testBaseURL+`/userinfo/picture/`+sub+`"}`, rr.Body.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleUserProfilePictureDelete_NoUserId(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePictureDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users//profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleUserProfilePictureDelete_InvalidUserId(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePictureDelete(database, auditLogger)

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

func TestHandleUserProfilePictureDelete_UserNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePictureDelete(database, auditLogger)

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

func TestHandleUserProfilePictureDelete_Success(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePictureDelete(database, auditLogger)

	sub := fake.UUID()
	user := &record.User{Id: 123, Subject: sub, Enabled: true}
	adminSub := fake.UUID()

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/123/profile-picture", nil)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(user, nil)
	database.On("DeleteUserProfilePicture", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.EventDeletedUserProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"success":true}`, rr.Body.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleUserProfilePictureDelete_DatabaseError(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserProfilePictureDelete(database, auditLogger)

	sub := fake.UUID()
	user := &record.User{Id: 123, Subject: sub, Enabled: true}

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

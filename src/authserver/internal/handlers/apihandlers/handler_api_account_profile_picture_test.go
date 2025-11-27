package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// createTestPNG creates a valid PNG image with the specified dimensions
func createTestPNG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// createMultipartRequest creates a multipart request with a file
func createMultipartRequest(method, url string, fieldName string, fileData []byte) (*http.Request, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile(fieldName, "picture.png")
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(part, bytes.NewReader(fileData))
	if err != nil {
		return nil, err
	}
	_ = writer.Close()

	req, err := http.NewRequest(method, url, &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, nil
}

// setTokenContext sets a JWT token in the request context
func setTokenContext(req *http.Request, sub string) *http.Request {
	jwtToken := oauth.JwtToken{
		Claims: map[string]interface{}{
			"sub": sub,
		},
	}
	ctx := context.WithValue(req.Context(), constants.ContextKeyValidatedToken, jwtToken)
	return req.WithContext(ctx)
}

func TestHandleAPIAccountProfilePictureGet_NoToken(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"].(map[string]interface{})["code"], "UNAUTHORIZED")
}

func TestHandleAPIAccountProfilePictureGet_EmptySub(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, "")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"].(map[string]interface{})["code"], "INVALID_TOKEN")
}

func TestHandleAPIAccountProfilePictureGet_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database)

	sub := uuid.New().String()
	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", (*sql.Tx)(nil), sub).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePictureGet_HasPicture(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database)

	sub := uuid.New()
	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub.String())
	rr := httptest.NewRecorder()

	user := &models.User{Id: 1, Subject: sub, Enabled: true}
	database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)
	database.On("UserHasProfilePicture", (*sql.Tx)(nil), user.Id).Return(true, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["hasPicture"].(bool))
	assert.Contains(t, response["pictureUrl"].(string), sub.String())

	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePictureGet_NoPicture(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database)

	sub := uuid.New()
	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub.String())
	rr := httptest.NewRecorder()

	user := &models.User{Id: 1, Subject: sub, Enabled: true}
	database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)
	database.On("UserHasProfilePicture", (*sql.Tx)(nil), user.Id).Return(false, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["hasPicture"].(bool))
	assert.Nil(t, response["pictureUrl"])

	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePicturePost_NoToken(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger)

	req, _ := http.NewRequest("POST", "/api/v1/account/profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleAPIAccountProfilePicturePost_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger)

	sub := uuid.New().String()
	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", (*sql.Tx)(nil), sub).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePicturePost_NoFile(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("POST", "/api/v1/account/profile-picture", nil)
	req.Header.Set("Content-Type", "multipart/form-data")
	req = setTokenContext(req, sub.String())
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleAPIAccountProfilePicturePost_InvalidImage(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	// Create a request with invalid image data
	invalidImageData := []byte("not a valid image")
	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", invalidImageData)
	assert.NoError(t, err)
	req = setTokenContext(req, sub.String())
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INVALID_IMAGE", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIAccountProfilePicturePost_CreateNew(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setTokenContext(req, sub.String())
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", (*sql.Tx)(nil), user.Id).Return(nil, nil)
	database.On("CreateUserProfilePicture", (*sql.Tx)(nil), mock.MatchedBy(func(pp *models.UserProfilePicture) bool {
		return pp.UserId == user.Id && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", constants.AuditUpdatedOwnProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id
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

func TestHandleAPIAccountProfilePicturePost_UpdateExisting(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}
	existingPicture := &models.UserProfilePicture{
		Id:          1,
		UserId:      user.Id,
		Picture:     []byte("old picture data"),
		ContentType: "image/jpeg",
	}

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setTokenContext(req, sub.String())
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", (*sql.Tx)(nil), user.Id).Return(existingPicture, nil)
	database.On("UpdateUserProfilePicture", (*sql.Tx)(nil), mock.MatchedBy(func(pp *models.UserProfilePicture) bool {
		return pp.Id == existingPicture.Id && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", constants.AuditUpdatedOwnProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id
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

func TestHandleAPIAccountProfilePictureDelete_NoToken(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePictureDelete(httpHelper, database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/account/profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleAPIAccountProfilePictureDelete_UserNotFound(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePictureDelete(httpHelper, database, auditLogger)

	sub := uuid.New().String()
	req, _ := http.NewRequest("DELETE", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", (*sql.Tx)(nil), sub).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePictureDelete_Success(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePictureDelete(httpHelper, database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("DELETE", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub.String())
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)
	database.On("DeleteUserProfilePicture", (*sql.Tx)(nil), user.Id).Return(nil)

	auditLogger.On("Log", constants.AuditDeletedOwnProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id
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

func TestHandleAPIAccountProfilePictureDelete_DatabaseError(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePictureDelete(httpHelper, database, auditLogger)

	sub := uuid.New()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("DELETE", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub.String())
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)
	database.On("DeleteUserProfilePicture", (*sql.Tx)(nil), user.Id).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "DELETE_ERROR", response["error"].(map[string]interface{})["code"])

	database.AssertExpectations(t)
}

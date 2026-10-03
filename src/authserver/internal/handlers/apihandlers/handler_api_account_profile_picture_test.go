package apihandlers

import (
	"bytes"
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
	ctx := reqctx.WithValidatedToken(req.Context(), jwtToken)
	return req.WithContext(ctx)
}

func TestHandleAPIAccountProfilePictureGet_NoToken(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database, testBaseURL)

	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error_code"], "UNAUTHORIZED")
}

func TestHandleAPIAccountProfilePictureGet_EmptySub(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database, testBaseURL)

	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, "")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error_code"], "INVALID_TOKEN")
}

func TestHandleAPIAccountProfilePictureGet_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database, testBaseURL)

	sub := fake.UUID()
	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePictureGet_HasPicture(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database, testBaseURL)

	sub := fake.UUID()
	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	user := &models.User{Id: 1, Subject: sub, Enabled: true}
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)
	database.On("UserHasProfilePicture", mock.Anything, (*sql.Tx)(nil), user.Id).Return(true, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"hasPicture":true,"pictureUrl":"`+testBaseURL+`/userinfo/picture/`+sub+`"}`, rr.Body.String())

	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePictureGet_NoPicture(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIAccountProfilePictureGet(database, testBaseURL)

	sub := fake.UUID()
	req, _ := http.NewRequest("GET", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	user := &models.User{Id: 1, Subject: sub, Enabled: true}
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)
	database.On("UserHasProfilePicture", mock.Anything, (*sql.Tx)(nil), user.Id).Return(false, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"hasPicture":false}`, rr.Body.String())

	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePicturePost_NoToken(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	req, _ := http.NewRequest("POST", "/api/v1/account/profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleAPIAccountProfilePicturePost_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePicturePost_NoFile(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	// A well-formed multipart form whose file is under another field name.
	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "avatar", createTestPNG(100, 100))
	require.NoError(t, err)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, "NO_FILE", response["error_code"])
}

// A body past the handed cap and its multipart overhead is refused before any image is read, with
// the code it has always carried.
func TestHandleAPIAccountProfilePicturePost_BodyOverTheBound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger, testBaseURL, 64)

	sub := fake.UUID()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", bytes.Repeat([]byte{0xAB}, 64+2048))
	require.NoError(t, err)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, "FILE_TOO_LARGE", response["error_code"])
}

func TestHandleAPIAccountProfilePicturePost_InvalidImage(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	// Create a request with invalid image data
	invalidImageData := []byte("not a valid image")
	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", invalidImageData)
	assert.NoError(t, err)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)

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
func TestHandleAPIAccountProfilePicturePost_RefusesAnImageOverTheCapItWasHanded(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger, testBaseURL, 64)

	sub := fake.UUID()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	pictureData := createTestPNG(100, 100)
	require.Greater(t, len(pictureData), 64)
	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", pictureData)
	require.NoError(t, err)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, "validator.image.too_large", response["error_code"])
	assert.Equal(t, "The image can be at most 64 bytes.", response["error_description"])
}

func TestHandleAPIAccountProfilePicturePost_CreateNew(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/account/profile-picture", "picture", pictureData)
	assert.NoError(t, err)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), user.Id).Return(nil, nil)
	database.On("CreateUserProfilePicture", mock.Anything, (*sql.Tx)(nil), mock.MatchedBy(func(pp *models.UserProfilePicture) bool {
		return pp.UserId == user.Id && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedOwnProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"success":true,"pictureUrl":"`+testBaseURL+`/userinfo/picture/`+sub+`"}`, rr.Body.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePicturePost_UpdateExisting(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	sub := fake.UUID()
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
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), user.Id).Return(existingPicture, nil)
	database.On("UpdateUserProfilePicture", mock.Anything, (*sql.Tx)(nil), mock.MatchedBy(func(pp *models.UserProfilePicture) bool {
		return pp.Id == existingPicture.Id && pp.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedOwnProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"success":true,"pictureUrl":"`+testBaseURL+`/userinfo/picture/`+sub+`"}`, rr.Body.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePictureDelete_NoToken(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePictureDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/account/profile-picture", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleAPIAccountProfilePictureDelete_UserNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePictureDelete(database, auditLogger)

	sub := fake.UUID()
	req, _ := http.NewRequest("DELETE", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePictureDelete_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePictureDelete(database, auditLogger)

	sub := fake.UUID()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("DELETE", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)
	database.On("DeleteUserProfilePicture", mock.Anything, (*sql.Tx)(nil), user.Id).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.AuditDeletedOwnProfilePicture, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"success":true}`, rr.Body.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePictureDelete_GetUserFails_JSON500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePictureDelete(database, auditLogger)

	sub := fake.UUID()
	req, _ := http.NewRequest("DELETE", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	// This branch was the one 500 in the file still rendering error.html.
	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleAPIAccountProfilePictureDelete_DatabaseError(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountProfilePictureDelete(database, auditLogger)

	sub := fake.UUID()
	user := &models.User{Id: 1, Subject: sub, Enabled: true}

	req, _ := http.NewRequest("DELETE", "/api/v1/account/profile-picture", nil)
	req = setTokenContext(req, sub)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), sub).Return(user, nil)
	database.On("DeleteUserProfilePicture", mock.Anything, (*sql.Tx)(nil), user.Id).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", response["error_code"])

	database.AssertExpectations(t)
}

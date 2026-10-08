package handlers

import (
	"bytes"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// A profile picture is public at /userinfo/picture/{subject}, which the picture claim names: it is
// served with no token, under the type it was stored with, and never cached, since a user who
// replaces it should not keep showing the old one.
func TestHandleProfilePictureGet_Success(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)

	handler := HandleProfilePictureGet(pageRenderer, database)

	pictureData := createTestLogoData(64, 64)
	user := &record.User{Id: 42, Subject: "2bd9ff17-7cb1-4c11-8d6d-6a3e1a0f5a6b", Enabled: true}
	picture := &record.UserProfilePicture{Id: 1, UserId: 42, Picture: pictureData, ContentType: "image/png"}

	req, _ := http.NewRequest("GET", "/userinfo/picture/"+user.Subject, nil)
	req = setChiURLParamForHandlers(req, "subject", user.Subject)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), user.Subject).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), int64(42)).Return(picture, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "image/png", rr.Header().Get("Content-Type"))
	assert.Equal(t, "no-store, no-cache, must-revalidate", rr.Header().Get("Cache-Control"))
	assert.Empty(t, rr.Header().Get("ETag"))
	assert.Equal(t, fmt.Sprintf("%d", len(pictureData)), rr.Header().Get("Content-Length"))
	assert.True(t, bytes.Equal(pictureData, rr.Body.Bytes()))
}

// The endpoint reads no state of the user's: a disabled user's picture is served as an enabled
// one's is.
func TestHandleProfilePictureGet_ServedWhileTheUserIsDisabled(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)

	handler := HandleProfilePictureGet(pageRenderer, database)

	pictureData := createTestLogoData(64, 64)
	user := &record.User{Id: 42, Subject: "2bd9ff17-7cb1-4c11-8d6d-6a3e1a0f5a6b", Enabled: false}
	picture := &record.UserProfilePicture{Id: 1, UserId: 42, Picture: pictureData, ContentType: "image/png"}

	req, _ := http.NewRequest("GET", "/userinfo/picture/"+user.Subject, nil)
	req = setChiURLParamForHandlers(req, "subject", user.Subject)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), user.Subject).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), int64(42)).Return(picture, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, bytes.Equal(pictureData, rr.Body.Bytes()))
}

func TestHandleProfilePictureGet_EmptySubject(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)

	handler := HandleProfilePictureGet(pageRenderer, database)

	req, _ := http.NewRequest("GET", "/userinfo/picture/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleProfilePictureGet_UnknownSubject(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)

	handler := HandleProfilePictureGet(pageRenderer, database)

	req, _ := http.NewRequest("GET", "/userinfo/picture/unknown", nil)
	req = setChiURLParamForHandlers(req, "subject", "unknown")
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "unknown").Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleProfilePictureGet_NoPicture(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)

	handler := HandleProfilePictureGet(pageRenderer, database)

	user := &record.User{Id: 42, Subject: "2bd9ff17-7cb1-4c11-8d6d-6a3e1a0f5a6b", Enabled: true}

	req, _ := http.NewRequest("GET", "/userinfo/picture/"+user.Subject, nil)
	req = setChiURLParamForHandlers(req, "subject", user.Subject)
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), user.Subject).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), int64(42)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleProfilePictureGet_DatabaseError(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)

	handler := HandleProfilePictureGet(pageRenderer, database)

	req, _ := http.NewRequest("GET", "/userinfo/picture/some-subject", nil)
	req = setChiURLParamForHandlers(req, "subject", "some-subject")
	rr := httptest.NewRecorder()

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "some-subject").Return(nil, assert.AnError)
	pageRenderer.On("InternalServerError", rr, req, assert.AnError)

	handler.ServeHTTP(rr, req)

	pageRenderer.AssertExpectations(t)
}

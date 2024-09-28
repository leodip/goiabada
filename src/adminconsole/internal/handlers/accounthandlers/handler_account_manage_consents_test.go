package accounthandlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAccountManageConsentsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	userConsents := []models.UserConsent{
		{
			Id:        1,
			UserId:    user.Id,
			ClientId:  1,
			Scope:     "openid profile",
			GrantedAt: sql.NullTime{Time: time.Now(), Valid: true},
			Client: models.Client{
				ClientIdentifier: "client1",
				Description:      "Test Client 1",
			},
		},
		{
			Id:        2,
			UserId:    user.Id,
			ClientId:  2,
			Scope:     "openid email",
			GrantedAt: sql.NullTime{Time: time.Now(), Valid: true},
			Client: models.Client{
				ClientIdentifier: "client2",
				Description:      "Test Client 2",
			},
		},
	}

	mockDB.On("GetConsentsByUserId", mock.Anything, user.Id).Return(userConsents, nil)
	mockDB.On("UserConsentsLoadClients", mock.Anything, userConsents).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_manage_consents.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		consentsValue, ok := data["consents"]
		if !ok {
			return false
		}

		consentsReflect := reflect.ValueOf(consentsValue)
		if consentsReflect.Kind() != reflect.Slice || consentsReflect.Len() != 2 {
			return false
		}

		for i, expectedConsent := range []struct {
			ConsentId int64
			Client    string
		}{
			{ConsentId: 1, Client: "client1"},
			{ConsentId: 2, Client: "client2"},
		} {
			consentReflect := consentsReflect.Index(i)
			if consentReflect.Kind() != reflect.Struct {
				return false
			}

			consentIdField := consentReflect.FieldByName("ConsentId")
			clientField := consentReflect.FieldByName("Client")

			if !consentIdField.IsValid() || !clientField.IsValid() {
				return false
			}

			if consentIdField.Int() != expectedConsent.ConsentId || clientField.String() != expectedConsent.Client {
				return false
			}
		}

		_, csrfFieldExists := data["csrfField"]
		return csrfFieldExists
	})).Return(nil)

	handler := HandleAccountManageConsentsGet(mockHttpHelper, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/manage-consents", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAccountManageConsentsRevokePost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	userConsents := []models.UserConsent{
		{
			Id:       1,
			UserId:   user.Id,
			ClientId: 1,
			Scope:    "openid profile",
		},
	}

	mockDB.On("GetConsentsByUserId", mock.Anything, user.Id).Return(userConsents, nil)
	mockDB.On("DeleteUserConsent", mock.Anything, int64(1)).Return(nil)

	mockAuditLogger.On("Log", constants.AuditDeletedUserConsent, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["consentId"] == int64(1) && details["loggedInUser"] == user.Subject.String()
	})).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(data interface{}) bool {
		result, ok := data.(struct{ Success bool })
		return ok && result.Success
	})).Return(nil)

	handler := HandleAccountManageConsentsRevokePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := strings.NewReader(`{"consentId": 1}`)
	req, _ := http.NewRequest("POST", "/account/manage-consents/revoke", reqBody)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAccountManageConsentsGet_Unauthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountManageConsentsGet(mockHttpHelper, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/manage-consents", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
}

func TestHandleAccountManageConsentsRevokePost_Unauthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountManageConsentsRevokePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := strings.NewReader(`{"consentId": 1}`)
	req, _ := http.NewRequest("POST", "/account/manage-consents/revoke", reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "EncodeJson")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountManageConsentsRevokePost_InvalidJSON(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return strings.Contains(err.Error(), "invalid character")
	})).Return()

	handler := HandleAccountManageConsentsRevokePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := strings.NewReader(`{invalid json}`)
	req, _ := http.NewRequest("POST", "/account/manage-consents/revoke", reqBody)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountManageConsentsRevokePost_ConsentNotFound(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	userConsents := []models.UserConsent{
		{
			Id:       1,
			UserId:   user.Id,
			ClientId: 1,
			Scope:    "openid profile",
		},
	}

	mockDB.On("GetConsentsByUserId", mock.Anything, user.Id).Return(userConsents, nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return strings.Contains(err.Error(), "unable to revoke consent with id")
	})).Return()

	handler := HandleAccountManageConsentsRevokePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := strings.NewReader(`{"consentId": 2}`)
	req, _ := http.NewRequest("POST", "/account/manage-consents/revoke", reqBody)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

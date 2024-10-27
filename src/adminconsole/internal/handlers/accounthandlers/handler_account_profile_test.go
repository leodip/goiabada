package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	mocks_validator "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAccountProfileGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_profile.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["user"] == user
	})).Return(nil)

	handler := HandleAccountProfileGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/profile", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAccountProfilePost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockProfileValidator := mocks_validator.NewProfileValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockProfileValidator.On("ValidateProfile", mock.AnythingOfType("*validators.ValidateProfileInput")).Return(nil)

	mockInputSanitizer.On("Sanitize", mock.AnythingOfType("string")).Return(func(s string) string {
		return s
	})

	mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Id == user.Id &&
			u.Username == "newusername" &&
			u.GivenName == "John" &&
			u.FamilyName == "Doe" &&
			u.ZoneInfoCountryName == "Canada" &&
			u.ZoneInfo == "America/Moncton" &&
			u.Locale == "en-US" &&
			u.Gender == enums.GenderMale.String() &&
			u.BirthDate.Time.Format("2006-01-02") == "1990-01-01"
	})).Return(nil)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockAuditLogger.On("Log", constants.AuditUpdatedUserProfile, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == user.Subject.String()
	})).Return(nil)

	handler := HandleAccountProfilePost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockProfileValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("username", "newusername")
	form.Add("givenName", "John")
	form.Add("familyName", "Doe")
	form.Add("zoneInfo", "Canada___America/Moncton")
	form.Add("locale", "en-US")
	form.Add("gender", "1")
	form.Add("dateOfBirth", "1990-01-01")

	req, _ := http.NewRequest("POST", "/account/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
		"sub": user.Subject.String(),
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/account/profile", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockProfileValidator.AssertExpectations(t)
	mockInputSanitizer.AssertNumberOfCalls(t, "Sanitize", 5)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAccountProfilePost_ValidationError(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockProfileValidator := mocks_validator.NewProfileValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	validationError := customerrors.NewErrorDetail("invalid_profile", "Invalid profile data")
	mockProfileValidator.On("ValidateProfile", mock.AnythingOfType("*validators.ValidateProfileInput")).Return(validationError)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_profile.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid profile data"
	})).Return(nil)

	handler := HandleAccountProfilePost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockProfileValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("username", "invalid username")

	req, _ := http.NewRequest("POST", "/account/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
		"sub": user.Subject.String(),
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockProfileValidator.AssertExpectations(t)
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountProfileGet_Unauthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountProfileGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/profile", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
}

func TestHandleAccountProfilePost_Unauthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockProfileValidator := mocks_validator.NewProfileValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountProfilePost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockProfileValidator, mockInputSanitizer, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/account/profile", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
	mockProfileValidator.AssertNotCalled(t, "ValidateProfile")
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

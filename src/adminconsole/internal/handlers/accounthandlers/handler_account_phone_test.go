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

func TestHandleAccountPhoneGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	user := &models.User{
		Id:                         1,
		Subject:                    uuid.New(),
		PhoneNumberCountryUniqueId: "BRA_0",
		PhoneNumber:                "47991308505",
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_phone.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["selectedPhoneCountryUniqueId"] == user.PhoneNumberCountryUniqueId &&
			data["phoneNumber"] == user.PhoneNumber
	})).Return(nil)

	handler := HandleAccountPhoneGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/phone", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAccountPhoneGet_SavedSuccessfully(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	user := &models.User{
		Id:                         1,
		Subject:                    uuid.New(),
		PhoneNumberCountryUniqueId: "BRA_0",
		PhoneNumber:                "47991308505",
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	mockSession.AddFlash("true", "savedSuccessfully")
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_phone.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["selectedPhoneCountryUniqueId"] == user.PhoneNumberCountryUniqueId &&
			data["phoneNumber"] == user.PhoneNumber &&
			data["savedSuccessfully"] == true
	})).Return(nil)

	handler := HandleAccountPhoneGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/phone", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAccountPhoneGet_Unauthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountPhoneGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/phone", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockSessionStore.AssertNotCalled(t, "Get")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
}

func TestHandleAccountPhonePost(t *testing.T) {
	t.Run("Unauthorized", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validator.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

		handler := HandleAccountPhonePost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockPhoneValidator, mockInputSanitizer, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/account/phone", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

		mockAuthHelper.AssertExpectations(t)
		mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
		mockDB.AssertNotCalled(t, "GetUserBySubject")
		mockPhoneValidator.AssertNotCalled(t, "ValidatePhone")
		mockInputSanitizer.AssertNotCalled(t, "Sanitize")
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("Invalid Phone", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validator.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		user := &models.User{
			Id:      1,
			Subject: uuid.New(),
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
		mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

		validationError := customerrors.NewErrorDetail("invalid_phone", "Invalid phone number")
		mockPhoneValidator.On("ValidatePhone", mock.AnythingOfType("*validators.ValidatePhoneInput")).Return(validationError)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_phone.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Invalid phone number"
		})).Return(nil)

		handler := HandleAccountPhonePost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockPhoneValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("phoneCountryUniqueId", "US")
		form.Add("phoneNumber", "invalid")
		req, _ := http.NewRequest("POST", "/account/phone", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
			"sub": user.Subject.String(),
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockPhoneValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
		mockInputSanitizer.AssertNotCalled(t, "Sanitize")
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("Success", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validator.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		user := &models.User{
			Id:      1,
			Subject: uuid.New(),
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
		mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

		mockPhoneValidator.On("ValidatePhone", mock.AnythingOfType("*validators.ValidatePhoneInput")).Return(nil)

		mockInputSanitizer.On("Sanitize", mock.AnythingOfType("string")).Return(func(s string) string {
			return s
		})

		mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == user.Id &&
				u.PhoneNumberCountryUniqueId == "USA_0" &&
				u.PhoneNumberCountryCallingCode == "+1" &&
				u.PhoneNumber == "1800987987" &&
				!u.PhoneNumberVerified
		})).Return(nil)

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		mockAuditLogger.On("Log", constants.AuditUpdatedUserPhone, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == user.Id && details["loggedInUser"] == user.Subject.String()
		})).Return(nil)

		handler := HandleAccountPhonePost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockPhoneValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("phoneCountryUniqueId", "USA_0")
		form.Add("phoneNumber", "1800987987")
		req, _ := http.NewRequest("POST", "/account/phone", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
			"sub": user.Subject.String(),
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/account/phone", rr.Header().Get("Location"))

		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockPhoneValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Invalid Country", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validator.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		user := &models.User{
			Id:      1,
			Subject: uuid.New(),
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
		mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

		mockPhoneValidator.On("ValidatePhone", mock.AnythingOfType("*validators.ValidatePhoneInput")).Return(nil)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "Phone country is invalid")
		})).Once()

		handler := HandleAccountPhonePost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockPhoneValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("phoneCountryUniqueId", "INVALID")
		form.Add("phoneNumber", "1234567890")
		req, _ := http.NewRequest("POST", "/account/phone", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
			"sub": user.Subject.String(),
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockPhoneValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
		mockInputSanitizer.AssertNotCalled(t, "Sanitize")
		mockAuditLogger.AssertNotCalled(t, "Log")
	})
}

package accounthandlers

import (
	"context"
	"database/sql"
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
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	mocks_validator "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAccountEmailGet(t *testing.T) {
	testCases := []struct {
		name              string
		savedSuccessfully bool
	}{
		{
			name:              "Successfully retrieves user email without savedSuccessfully",
			savedSuccessfully: false,
		},
		{
			name:              "Successfully retrieves user email with savedSuccessfully true",
			savedSuccessfully: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			mockSessionStore := mocks_sessionstore.NewStore(t)
			mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)

			user := &models.User{
				Id:            1,
				Subject:       uuid.New(),
				Email:         "test@example.com",
				EmailVerified: true,
			}

			mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
			mockDB.On("GetUserBySubject", (*sql.Tx)(nil), user.Subject.String()).Return(user, nil)

			mockSession := &sessions.Session{Values: map[interface{}]interface{}{}}
			if tc.savedSuccessfully {
				mockSession.AddFlash("true", "savedSuccessfully")
			}
			mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
			if tc.savedSuccessfully {
				mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)
			}

			settings := &models.Settings{
				SMTPEnabled: true,
			}

			mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_email.html", mock.MatchedBy(func(bind map[string]interface{}) bool {
				if bind["savedSuccessfully"] != tc.savedSuccessfully {
					return false
				}
				if bind["email"] != user.Email {
					return false
				}
				if bind["emailVerified"] != user.EmailVerified {
					return false
				}
				if bind["emailConfirmation"] != "" {
					return false
				}
				if bind["smtpEnabled"] != settings.SMTPEnabled {
					return false
				}
				if _, ok := bind["csrfField"]; !ok {
					return false
				}
				return true
			})).Return(nil)

			handler := HandleAccountEmailGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

			req, _ := http.NewRequest("GET", "/account/email", nil)
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
				IdToken: &oauth.JwtToken{
					Claims: jwt.MapClaims{
						"sub": user.Subject.String(),
					},
				},
			}))
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, settings))

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			mockDB.AssertExpectations(t)
			mockHttpHelper.AssertExpectations(t)
			mockSessionStore.AssertExpectations(t)
		})
	}
}

func TestHandleAccountEmailPost(t *testing.T) {
	t.Run("ValidateEmailUpdate returns an error", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockEmailValidator := mocks_validator.NewEmailValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		user := &models.User{
			Id:      1,
			Subject: uuid.New(),
			Email:   "old@example.com",
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
		mockDB.On("GetUserBySubject", (*sql.Tx)(nil), user.Subject.String()).Return(user, nil)

		newEmail := "new@example.com"
		validationError := customerrors.NewErrorDetail("validation_error", "Invalid email")
		mockEmailValidator.On("ValidateEmailUpdate", mock.MatchedBy(func(input *validators.ValidateEmailInput) bool {
			return input.Email == newEmail && input.EmailConfirmation == newEmail && input.Subject == user.Subject.String()
		})).Return(validationError)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_email.html", mock.MatchedBy(func(bind map[string]interface{}) bool {
			return bind["error"] == validationError.GetDescription() &&
				bind["email"] == newEmail &&
				bind["emailConfirmation"] == newEmail
		})).Return(nil)

		handler := HandleAccountEmailPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockEmailValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("email", newEmail)
		form.Add("emailConfirmation", newEmail)
		req, _ := http.NewRequest("POST", "/account/email", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
		mockEmailValidator.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockInputSanitizer.AssertNotCalled(t, "Sanitize")
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("Happy path", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockEmailValidator := mocks_validator.NewEmailValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		user := &models.User{
			Id:      1,
			Subject: uuid.New(),
			Email:   "old@example.com",
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
		mockDB.On("GetUserBySubject", (*sql.Tx)(nil), user.Subject.String()).Return(user, nil)

		newEmail := "new@example.com"
		mockEmailValidator.On("ValidateEmailUpdate", mock.MatchedBy(func(input *validators.ValidateEmailInput) bool {
			return input.Email == newEmail && input.EmailConfirmation == newEmail && input.Subject == user.Subject.String()
		})).Return(nil)

		mockInputSanitizer.On("Sanitize", newEmail).Return(newEmail)
		mockDB.On("UpdateUser", (*sql.Tx)(nil), mock.MatchedBy(func(u *models.User) bool {
			return u.Id == user.Id && u.Email == newEmail && !u.EmailVerified
		})).Return(nil)

		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(&sessions.Session{
			Values: make(map[interface{}]interface{}),
		}, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.AnythingOfType("*sessions.Session")).Return(nil)

		mockAuditLogger.On("Log", constants.AuditUpdatedUserEmail, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == user.Id && details["loggedInUser"] == user.Subject.String()
		})).Return(nil)

		handler := HandleAccountEmailPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockEmailValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("email", newEmail)
		form.Add("emailConfirmation", newEmail)
		req, _ := http.NewRequest("POST", "/account/email", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
			IdToken: &oauth.JwtToken{
				Claims: jwt.MapClaims{
					"sub": user.Subject.String(),
				},
			},
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAdminConsole().BaseURL+"/account/email", rr.Header().Get("Location"))
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
		mockEmailValidator.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})
}

func TestHandleAccountEmailGet_Unauthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountEmailGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/email", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockSessionStore.AssertNotCalled(t, "Get")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
}

func TestHandleAccountEmailPost_Unauthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_validator.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountEmailPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockEmailValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("email", "new@example.com")
	form.Add("emailConfirmation", "new@example.com")
	req, _ := http.NewRequest("POST", "/account/email", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockSessionStore.AssertNotCalled(t, "Get")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
	mockEmailValidator.AssertNotCalled(t, "ValidateEmailUpdate")
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

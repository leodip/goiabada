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

func TestHandleAccountAddressGet(t *testing.T) {
	testCases := []struct {
		name              string
		savedSuccessfully bool
	}{
		{
			name:              "Successfully retrieves user address without savedSuccessfully",
			savedSuccessfully: false,
		},
		{
			name:              "Successfully retrieves user address with savedSuccessfully true",
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
				Id:                1,
				Subject:           uuid.New(),
				AddressLine1:      "123 Test St",
				AddressLine2:      "Apt 4",
				AddressLocality:   "Testville",
				AddressRegion:     "Teststate",
				AddressPostalCode: "12345",
				AddressCountry:    "Testland",
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

			mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_address.html", mock.MatchedBy(func(bind map[string]interface{}) bool {
				if bind["user"] != user {
					return false
				}
				address, ok := bind["address"].(struct {
					AddressLine1      string
					AddressLine2      string
					AddressLocality   string
					AddressRegion     string
					AddressPostalCode string
					AddressCountry    string
				})
				if !ok {
					return false
				}
				if address.AddressLine1 != user.AddressLine1 ||
					address.AddressLine2 != user.AddressLine2 ||
					address.AddressLocality != user.AddressLocality ||
					address.AddressRegion != user.AddressRegion ||
					address.AddressPostalCode != user.AddressPostalCode ||
					address.AddressCountry != user.AddressCountry {
					return false
				}

				if bind["savedSuccessfully"] != tc.savedSuccessfully {
					return false
				}
				if _, ok := bind["csrfField"]; !ok {
					return false
				}
				return true
			})).Return(nil)

			handler := HandleAccountAddressGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

			req, _ := http.NewRequest("GET", "/account/address", nil)
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
			mockSessionStore.AssertExpectations(t)
		})
	}
}

func TestHandleAccountAddressPost_AddressValidatorError(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAddressValidator := mocks_validator.NewAddressValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", (*sql.Tx)(nil), user.Subject.String()).Return(user, nil)

	expectedError := customerrors.NewErrorDetail("", "Invalid address")
	mockAddressValidator.On("ValidateAddress", mock.AnythingOfType("*validators.ValidateAddressInput")).
		Return(expectedError)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_address.html", mock.MatchedBy(func(bind map[string]interface{}) bool {
		if bind["user"] != user {
			return false
		}
		if bind["error"] != "Invalid address" {
			return false
		}
		if _, ok := bind["csrfField"]; !ok {
			return false
		}
		address, ok := bind["address"].(*validators.ValidateAddressInput)
		if !ok {
			return false
		}
		if address.AddressLine1 != "123 Test St" ||
			address.AddressLine2 != "Apt 4" ||
			address.AddressLocality != "Testville" ||
			address.AddressRegion != "Teststate" ||
			address.AddressPostalCode != "12345" ||
			address.AddressCountry != "Testland" {
			return false
		}
		return true
	})).Return(nil)

	handler := HandleAccountAddressPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockAddressValidator,
		mockInputSanitizer,
		mockAuditLogger,
	)

	req, _ := http.NewRequest("POST", "/account/address", strings.NewReader("addressLine1=123+Test+St&addressLine2=Apt+4&addressLocality=Testville&addressRegion=Teststate&addressPostalCode=12345&addressCountry=Testland"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	mockAddressValidator.AssertExpectations(t)
	mockAuthHelper.AssertNotCalled(t, "GetLoggedInSubject")
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountAddressPost_HappyPath(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAddressValidator := mocks_validator.NewAddressValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
	}

	mockDB.On("GetUserBySubject", (*sql.Tx)(nil), user.Subject.String()).Return(user, nil)

	mockAddressValidator.On("ValidateAddress", mock.AnythingOfType("*validators.ValidateAddressInput")).Return(nil)

	mockInputSanitizer.On("Sanitize", mock.AnythingOfType("string")).Return(func(s string) string {
		return s
	})

	mockDB.On("UpdateUser", (*sql.Tx)(nil), mock.AnythingOfType("*models.User")).Return(nil)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())

	mockAuditLogger.On("Log", constants.AuditUpdatedUserAddress, mock.MatchedBy(func(m map[string]interface{}) bool {
		userId, ok1 := m["userId"]
		loggedInUser, ok2 := m["loggedInUser"]
		return ok1 && ok2 && userId == int64(1) && loggedInUser == user.Subject.String()
	})).Return(nil)

	handler := HandleAccountAddressPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockAddressValidator,
		mockInputSanitizer,
		mockAuditLogger,
	)

	form := url.Values{}
	form.Add("addressLine1", "123 Test St")
	form.Add("addressLine2", "Apt 4")
	form.Add("addressLocality", "Testville")
	form.Add("addressRegion", "Teststate")
	form.Add("addressPostalCode", "12345")
	form.Add("addressCountry", "Testland")

	req, _ := http.NewRequest("POST", "/account/address", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	assert.Equal(t, config.Get().BaseURL+"/account/address", rr.Header().Get("Location"))

	mockDB.AssertExpectations(t)
	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAddressValidator.AssertExpectations(t)
	mockInputSanitizer.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)

	mockInputSanitizer.AssertNumberOfCalls(t, "Sanitize", 6)
}

func TestHandleAccountAddressGet_Unauthenticated(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountAddressGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/address", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockSessionStore.AssertNotCalled(t, "Get")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
}

func TestHandleAccountAddressPost_Unauthenticated(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAddressValidator := mocks_validator.NewAddressValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountAddressPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockAddressValidator,
		mockInputSanitizer,
		mockAuditLogger,
	)

	req, _ := http.NewRequest("POST", "/account/address", strings.NewReader("addressLine1=123+Test+St&addressLine2=Apt+4&addressLocality=Testville&addressRegion=Teststate&addressPostalCode=12345&addressCountry=Testland"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockSessionStore.AssertNotCalled(t, "Get")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
	mockAddressValidator.AssertNotCalled(t, "ValidateAddress")
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

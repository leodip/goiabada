package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAdminUserPhoneGet(t *testing.T) {
	t.Run("Valid user", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserPhoneGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/phone", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com", PhoneNumberCountryUniqueId: "US", PhoneNumber: "1234567890", PhoneNumberVerified: true}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_phone.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["user"] == user &&
				data["selectedPhoneCountryUniqueId"] == user.PhoneNumberCountryUniqueId &&
				data["phoneNumber"] == user.PhoneNumber &&
				data["phoneNumberVerified"] == user.PhoneNumberVerified &&
				data["page"] == "" &&
				data["query"] == "" &&
				data["savedSuccessfully"] == false &&
				data["csrfField"] != nil
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserPhoneGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/invalid/phone", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserPhoneGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/phone", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

func TestHandleAdminUserPhonePost(t *testing.T) {
	t.Run("Valid update", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validators.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPhonePost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPhoneValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("phoneCountryUniqueId", "USA_0")
		form.Add("phoneNumber", "1234567890")
		form.Add("phoneNumberVerified", "on")

		req, _ := http.NewRequest("POST", "/admin/users/123/phone", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockPhoneValidator.On("ValidatePhone", mock.MatchedBy(func(input *validators.ValidatePhoneInput) bool {
			return input.PhoneCountryUniqueId == "USA_0" && input.PhoneNumber == "1234567890"
		})).Return(nil)

		mockInputSanitizer.On("Sanitize", "1234567890").Return("1234567890")

		mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 123 &&
				u.PhoneNumberCountryUniqueId == "USA_0" &&
				u.PhoneNumberCountryCallingCode == "+1" &&
				u.PhoneNumber == "1234567890" &&
				u.PhoneNumberVerified == true
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditUpdatedUserPhone, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["loggedInUser"] == "admin"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "/admin/users/123/phone")

		mockDB.AssertExpectations(t)
		mockPhoneValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validators.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPhonePost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPhoneValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("POST", "/admin/users/invalid/phone", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validators.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPhonePost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPhoneValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("POST", "/admin/users/123/phone", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid phone", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validators.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPhonePost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPhoneValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("phoneCountryUniqueId", "US")
		form.Add("phoneNumber", "invalid-phone")

		req, _ := http.NewRequest("POST", "/admin/users/123/phone", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockPhoneValidator.On("ValidatePhone", mock.Anything).Return(customerrors.NewErrorDetail("", "Invalid phone number"))

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_phone.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Invalid phone number"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockPhoneValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid phone country", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validators.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPhonePost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPhoneValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("phoneCountryUniqueId", "INVALID")
		form.Add("phoneNumber", "1234567890")

		req, _ := http.NewRequest("POST", "/admin/users/123/phone", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockPhoneValidator.On("ValidatePhone", mock.MatchedBy(func(input *validators.ValidatePhoneInput) bool {
			return input.PhoneCountryUniqueId == "INVALID" && input.PhoneNumber == "1234567890"
		})).Return(nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "Phone country is invalid")
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockPhoneValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Empty phone number", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPhoneValidator := mocks_validators.NewPhoneValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserPhonePost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPhoneValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("phoneCountryUniqueId", "USA_0")
		form.Add("phoneNumber", "")
		form.Add("phoneNumberVerified", "on")

		req, _ := http.NewRequest("POST", "/admin/users/123/phone", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockPhoneValidator.On("ValidatePhone", mock.Anything).Return(nil)

		mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 123 &&
				u.PhoneNumberCountryUniqueId == "" &&
				u.PhoneNumberCountryCallingCode == "" &&
				u.PhoneNumber == "" &&
				u.PhoneNumberVerified == false
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditUpdatedUserPhone, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["loggedInUser"] == "admin"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "/admin/users/123/phone")

		mockDB.AssertExpectations(t)
		mockPhoneValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})
}

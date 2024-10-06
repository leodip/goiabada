package adminuserhandlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/biter777/countries"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
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

func TestHandleAdminUserAddressGet(t *testing.T) {
	t.Run("Valid user", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAddressGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/address?page=2&query=test", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		user := &models.User{
			Id:                123,
			Email:             "test@example.com",
			AddressLine1:      "123 Main St",
			AddressLine2:      "Apt 4B",
			AddressLocality:   "Springfield",
			AddressRegion:     "IL",
			AddressPostalCode: "62701",
			AddressCountry:    "US",
		}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_address.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			address, ok := data["address"].(Address)
			if !ok {
				return false
			}

			countries, ok := data["countries"].([]*countries.Country)
			if !ok {
				return false
			}

			return address.AddressLine1 == user.AddressLine1 &&
				address.AddressLine2 == user.AddressLine2 &&
				address.AddressLocality == user.AddressLocality &&
				address.AddressRegion == user.AddressRegion &&
				address.AddressPostalCode == user.AddressPostalCode &&
				address.AddressCountry == user.AddressCountry &&
				len(countries) > 0 &&
				data["page"] == "2" &&
				data["query"] == "test" &&
				data["user"] == user &&
				data["savedSuccessfully"] == false &&
				data["csrfField"] != nil
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAddressGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/invalid/address", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("Non-existent user", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAddressGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/456/address", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(456)).Return(nil, nil)
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("Database error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAddressGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/789/address", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "789")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(789)).Return(nil, errors.New("database error"))
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})
}

func TestHandleAdminUserAddressPost(t *testing.T) {
	t.Run("Valid input", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAddressValidator := mocks_validators.NewAddressValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAddressPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockAddressValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{
			"addressLine1":      {"123 Main St"},
			"addressLine2":      {"Apt 4B"},
			"addressLocality":   {"Springfield"},
			"addressRegion":     {"IL"},
			"addressPostalCode": {"62701"},
			"addressCountry":    {"US"},
		}

		req, _ := http.NewRequest("POST", "/admin/users/123/address", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(&models.User{Id: 123}, nil)
		mockAddressValidator.On("ValidateAddress", mock.Anything, mock.AnythingOfType("*validators.ValidateAddressInput")).Return(nil)
		mockInputSanitizer.On("Sanitize", mock.Anything).Return(func(input string) string {
			return input // Return the input unchanged for this test
		}).Times(6)

		// Custom matcher for UpdateUser
		mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(user *models.User) bool {
			return user.Id == 123 &&
				user.AddressLine1 == "123 Main St" &&
				user.AddressLine2 == "Apt 4B" &&
				user.AddressLocality == "Springfield" &&
				user.AddressRegion == "IL" &&
				user.AddressPostalCode == "62701" &&
				user.AddressCountry == "US"
		})).Return(nil)

		// Create a properly initialized session
		session := sessions.NewSession(mockSessionStore, constants.SessionName)
		session.Values = make(map[interface{}]interface{})
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(session, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")

		// Custom matcher for Log
		mockAuditLogger.On("Log", constants.AuditUpdatedUserAddress, mock.MatchedBy(func(details map[string]interface{}) bool {
			userId, ok := details["userId"].(int64)
			loggedInUser, ok2 := details["loggedInUser"].(string)
			return ok && ok2 && userId == 123 && loggedInUser == "admin"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/admin/users/123/address?page=&query=", rr.Header().Get("Location"))

		// Verify that all expectations were met
		mockDB.AssertExpectations(t)
		mockAddressValidator.AssertExpectations(t)
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
		mockAddressValidator := mocks_validators.NewAddressValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAddressPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockAddressValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("POST", "/admin/users/invalid/address", strings.NewReader(""))
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
		mockAddressValidator := mocks_validators.NewAddressValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAddressPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockAddressValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("POST", "/admin/users/123/address", strings.NewReader(""))
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

	t.Run("Invalid address", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAddressValidator := mocks_validators.NewAddressValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAddressPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockAddressValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{
			"addressLine1": {"Invalid Address"},
		}

		req, _ := http.NewRequest("POST", "/admin/users/123/address", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(&models.User{Id: 123}, nil)
		mockAddressValidator.On("ValidateAddress", mock.Anything, mock.AnythingOfType("*validators.ValidateAddressInput")).Return(customerrors.NewErrorDetail("", "Invalid address."))

		mockHttpHelper.On("RenderTemplate",
			mock.AnythingOfType("*httptest.ResponseRecorder"),
			mock.AnythingOfType("*http.Request"),
			"/layouts/menu_layout.html",
			"/admin_users_address.html",
			mock.MatchedBy(func(m map[string]interface{}) bool {
				// Check for the presence and types of expected keys
				address, hasAddress := m["address"].(*validators.ValidateAddressInput)
				countries, hasCountries := m["countries"].([]*countries.Country)
				user, hasUser := m["user"].(*models.User)
				errorMsg, hasError := m["error"].(string)

				// Validate the content
				isAddressValid := hasAddress && address != nil
				isCountriesValid := hasCountries && len(countries) > 0
				isUserValid := hasUser && user != nil && user.Id == 123
				isErrorValid := hasError && errorMsg == "Invalid address."

				return isAddressValid && isCountriesValid && isUserValid && isErrorValid
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAddressValidator.AssertExpectations(t)
	})

	t.Run("Database error on update", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAddressValidator := mocks_validators.NewAddressValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAddressPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockAddressValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{
			"addressLine1":   {"123 Main St"},
			"addressCountry": {"US"},
		}

		req, _ := http.NewRequest("POST", "/admin/users/123/address", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(&models.User{Id: 123}, nil)
		mockAddressValidator.On("ValidateAddress", mock.Anything, mock.AnythingOfType("*validators.ValidateAddressInput")).Return(nil)
		mockInputSanitizer.On("Sanitize", mock.Anything).Return(func(input string) string {
			return input
		}).Times(6)
		mockDB.On("UpdateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(errors.New("database error"))

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockAddressValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

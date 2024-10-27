package adminuserhandlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAdminUserAttributesEditGet(t *testing.T) {
	t.Run("Valid user and attribute", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAttributesEditGet(mockHttpHelper, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/attributes/456/edit", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		attribute := &models.UserAttribute{Id: 456, UserId: 123, Key: "testKey", Value: "testValue"}
		mockDB.On("GetUserAttributeById", mock.Anything, int64(456)).Return(attribute, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["user"] == user && data["attribute"] == attribute
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAttributesEditGet(mockHttpHelper, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/invalid/attributes/456/edit", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAttributesEditGet(mockHttpHelper, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/attributes/456/edit", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
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

	t.Run("Attribute not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAttributesEditGet(mockHttpHelper, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/attributes/456/edit", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)
		mockDB.On("GetUserAttributeById", mock.Anything, int64(456)).Return(nil, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "attribute not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

func TestHandleAdminUserAttributesEditPost(t *testing.T) {
	t.Run("Valid input", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAttributesEditPost(
			mockHttpHelper,
			mockAuthHelper,
			mockDB,
			mockIdentifierValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("attributeKey", "validKey")
		form.Add("attributeValue", "validValue")
		form.Add("includeInAccessToken", "on")
		form.Add("includeInIdToken", "on")

		req, _ := http.NewRequest("POST", "/admin/users/123/attributes/456/edit", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		attribute := &models.UserAttribute{Id: 456, UserId: 123, Key: "oldKey", Value: "oldValue"}
		mockDB.On("GetUserAttributeById", mock.Anything, int64(456)).Return(attribute, nil)

		mockIdentifierValidator.On("ValidateIdentifier", "validKey", false).Return(nil)
		mockInputSanitizer.On("Sanitize", "validValue").Return("sanitizedValue")
		mockDB.On("UpdateUserAttribute", mock.Anything, mock.MatchedBy(func(ua *models.UserAttribute) bool {
			return ua.Id == 456 &&
				ua.UserId == 123 &&
				ua.Key == "validKey" &&
				ua.Value == "sanitizedValue" &&
				ua.IncludeInAccessToken == true &&
				ua.IncludeInIdToken == true
		})).Return(nil)
		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditUpdatedUserAttribute, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) &&
				details["userAttributeId"] == int64(456) &&
				details["loggedInUser"] == "admin"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/admin/users/123/attributes?page=&query=", rr.Header().Get("Location"))

		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAttributesEditPost(
			mockHttpHelper,
			mockAuthHelper,
			mockDB,
			mockIdentifierValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("POST", "/admin/users/invalid/attributes/456/edit", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAttributesEditPost(
			mockHttpHelper,
			mockAuthHelper,
			mockDB,
			mockIdentifierValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("POST", "/admin/users/123/attributes/456/edit", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
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

	t.Run("Attribute not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAttributesEditPost(
			mockHttpHelper,
			mockAuthHelper,
			mockDB,
			mockIdentifierValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("POST", "/admin/users/123/attributes/456/edit", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)
		mockDB.On("GetUserAttributeById", mock.Anything, int64(456)).Return(nil, nil)
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "attribute not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Empty attribute key", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAttributesEditPost(
			mockHttpHelper,
			mockAuthHelper,
			mockDB,
			mockIdentifierValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("attributeKey", "")
		form.Add("attributeValue", "validValue")

		req, _ := http.NewRequest("POST", "/admin/users/123/attributes/456/edit", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		attribute := &models.UserAttribute{Id: 456, UserId: 123, Key: "oldKey", Value: "oldValue"}
		mockDB.On("GetUserAttributeById", mock.Anything, int64(456)).Return(attribute, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Attribute key is required"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid attribute key", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAttributesEditPost(
			mockHttpHelper,
			mockAuthHelper,
			mockDB,
			mockIdentifierValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("attributeKey", "invalid key")
		form.Add("attributeValue", "validValue")

		req, _ := http.NewRequest("POST", "/admin/users/123/attributes/456/edit", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		attribute := &models.UserAttribute{Id: 456, UserId: 123, Key: "oldKey", Value: "oldValue"}
		mockDB.On("GetUserAttributeById", mock.Anything, int64(456)).Return(attribute, nil)

		mockIdentifierValidator.On("ValidateIdentifier", "invalid key", false).Return(errors.New("Invalid identifier"))
		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Invalid identifier"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Attribute value too long", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAttributesEditPost(
			mockHttpHelper,
			mockAuthHelper,
			mockDB,
			mockIdentifierValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("attributeKey", "validKey")
		form.Add("attributeValue", strings.Repeat("a", 251))

		req, _ := http.NewRequest("POST", "/admin/users/123/attributes/456/edit", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		attribute := &models.UserAttribute{Id: 456, UserId: 123, Key: "oldKey", Value: "oldValue"}
		mockDB.On("GetUserAttributeById", mock.Anything, int64(456)).Return(attribute, nil)

		mockIdentifierValidator.On("ValidateIdentifier", "validKey", false).Return(nil)
		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return strings.HasPrefix(data["error"].(string), "The attribute value cannot exceed a maximum length of 250 characters")
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Database error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAttributesEditPost(
			mockHttpHelper,
			mockAuthHelper,
			mockDB,
			mockIdentifierValidator,
			mockInputSanitizer,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("attributeKey", "validKey")
		form.Add("attributeValue", "validValue")
		form.Add("includeInAccessToken", "on")
		form.Add("includeInIdToken", "on")

		req, _ := http.NewRequest("POST", "/admin/users/123/attributes/456/edit", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		rctx.URLParams.Add("attributeId", "456")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		attribute := &models.UserAttribute{Id: 456, UserId: 123, Key: "oldKey", Value: "oldValue"}
		mockDB.On("GetUserAttributeById", mock.Anything, int64(456)).Return(attribute, nil)

		mockIdentifierValidator.On("ValidateIdentifier", "validKey", false).Return(nil)
		mockInputSanitizer.On("Sanitize", "validValue").Return("sanitizedValue")
		mockDB.On("UpdateUserAttribute", mock.Anything, mock.AnythingOfType("*models.UserAttribute")).Return(errors.New("database error"))
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

package adminresourcehandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
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
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAdminResourceSettingsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: "test-resource",
		Description:        "Test Resource",
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["resourceId"] == int64(1) &&
			data["resourceIdentifier"] == "test-resource" &&
			data["description"] == "Test Resource"
	})).Return(nil)

	handler := HandleAdminResourceSettingsGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/resources/1/settings", nil)
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("resourceId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminResourceSettingsPost(t *testing.T) {
	t.Run("successful update", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "old-identifier",
			Description:        "Old description",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "new-identifier").Return(nil, nil)
		mockIdentifierValidator.On("ValidateIdentifier", "new-identifier", true).Return(nil)
		mockInputSanitizer.On("Sanitize", "new-identifier").Return("new-identifier")
		mockInputSanitizer.On("Sanitize", "New description").Return("New description")
		mockDB.On("UpdateResource", mock.Anything, mock.AnythingOfType("*models.Resource")).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
		mockAuditLogger.On("Log", constants.AuditUpdatedResource, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["resourceId"] == int64(1) &&
				details["resourceIdentifier"] == "new-identifier" &&
				details["loggedInUser"] == "admin-user"
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		handler := HandleAdminResourceSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("resourceIdentifier", "new-identifier")
		form.Add("description", "New description")

		req, _ := http.NewRequest("POST", "/admin/resources/1/settings", strings.NewReader(form.Encode()))
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/admin/resources/1/settings", rr.Header().Get("Location"))

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("invalid resource identifier", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "old-identifier",
			Description:        "Old description",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockIdentifierValidator.On("ValidateIdentifier", "invalid@identifier", true).Return(customerrors.NewErrorDetail("", "Invalid identifier"))

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Invalid identifier"
		})).Return(nil)

		handler := HandleAdminResourceSettingsPost(mockHttpHelper, nil, nil, mockDB, mockIdentifierValidator, nil, nil)

		form := url.Values{}
		form.Add("resourceIdentifier", "invalid@identifier")
		form.Add("description", "New description")

		req, _ := http.NewRequest("POST", "/admin/resources/1/settings", strings.NewReader(form.Encode()))
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
	})

	t.Run("resource identifier already in use", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "old-identifier",
			Description:        "Old description",
		}

		existingResource := &models.Resource{
			Id:                 2,
			ResourceIdentifier: "existing-identifier",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockIdentifierValidator.On("ValidateIdentifier", "existing-identifier", true).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "existing-identifier").Return(existingResource, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "The resource identifier is already in use."
		})).Return(nil)

		handler := HandleAdminResourceSettingsPost(mockHttpHelper, nil, nil, mockDB, mockIdentifierValidator, nil, nil)

		form := url.Values{}
		form.Add("resourceIdentifier", "existing-identifier")
		form.Add("description", "New description")

		req, _ := http.NewRequest("POST", "/admin/resources/1/settings", strings.NewReader(form.Encode()))
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
	})

	t.Run("description too long", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "old-identifier",
			Description:        "Old description",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockIdentifierValidator.On("ValidateIdentifier", "valid-identifier", true).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "valid-identifier").Return(nil, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return strings.HasPrefix(data["error"].(string), "The description cannot exceed a maximum length of")
		})).Return(nil)

		handler := HandleAdminResourceSettingsPost(mockHttpHelper, nil, nil, mockDB, mockIdentifierValidator, nil, nil)

		form := url.Values{}
		form.Add("resourceIdentifier", "valid-identifier")
		form.Add("description", strings.Repeat("a", 101))

		req, _ := http.NewRequest("POST", "/admin/resources/1/settings", strings.NewReader(form.Encode()))
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
	})

	t.Run("system level resource", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: constants.AuthServerResourceIdentifier,
			Description:        "Auth Server",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "cannot update settings for a system level resource"
		}))

		handler := HandleAdminResourceSettingsPost(mockHttpHelper, nil, nil, mockDB, nil, nil, nil)

		form := url.Values{}
		form.Add("resourceIdentifier", "new-identifier")
		form.Add("description", "New description")

		req, _ := http.NewRequest("POST", "/admin/resources/1/settings", strings.NewReader(form.Encode()))
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})
}

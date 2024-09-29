package adminresourcehandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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

func TestHandleAdminResourceNewGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		_, exists := data["csrfField"]
		return exists
	})).Return(nil)

	handler := HandleAdminResourceNewGet(mockHttpHelper)

	req, _ := http.NewRequest("GET", "/admin/resources/new", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminResourceNewPost(t *testing.T) {
	t.Run("successful resource creation", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockIdentifierValidator.On("ValidateIdentifier", "new-resource", true).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "new-resource").Return(nil, nil)
		mockInputSanitizer.On("Sanitize", "new-resource").Return("new-resource")
		mockInputSanitizer.On("Sanitize", "New Resource Description").Return("New Resource Description")
		mockDB.On("CreateResource", mock.Anything, mock.AnythingOfType("*models.Resource")).Return(nil)
		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")
		mockAuditLogger.On("Log", constants.AuditCreatedResource, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["resourceId"] != nil &&
				details["resourceIdentifier"] == "new-resource" &&
				details["loggedInUser"] == "test-subject"
		})).Return(nil)

		handler := HandleAdminResourceNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("resourceIdentifier", "new-resource")
		form.Add("description", "New Resource Description")

		req, _ := http.NewRequest("POST", "/admin/resources/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/admin/resources", rr.Header().Get("Location"))

		mockHttpHelper.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("invalid resource identifier", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockIdentifierValidator.On("ValidateIdentifier", "invalid@resource", true).Return(assert.AnError)
		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == assert.AnError.Error()
		})).Return(nil)

		handler := HandleAdminResourceNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("resourceIdentifier", "invalid@resource")
		form.Add("description", "Invalid Resource")

		req, _ := http.NewRequest("POST", "/admin/resources/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("resource identifier already in use", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		existingResource := &models.Resource{Id: 1, ResourceIdentifier: "existing-resource"}

		mockIdentifierValidator.On("ValidateIdentifier", "existing-resource", true).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "existing-resource").Return(existingResource, nil)
		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "The resource identifier is already in use."
		})).Return(nil)

		handler := HandleAdminResourceNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("resourceIdentifier", "existing-resource")
		form.Add("description", "Existing Resource")

		req, _ := http.NewRequest("POST", "/admin/resources/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("description too long", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			errorMsg, ok := data["error"].(string)
			return ok && strings.HasPrefix(errorMsg, "The description cannot exceed a maximum length of")
		})).Return(nil)

		handler := HandleAdminResourceNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("resourceIdentifier", "valid-resource")
		form.Add("description", strings.Repeat("a", 101))

		req, _ := http.NewRequest("POST", "/admin/resources/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockIdentifierValidator.AssertNotCalled(t, "ValidateIdentifier")
		mockDB.AssertNotCalled(t, "GetResourceByResourceIdentifier")
		mockInputSanitizer.AssertNotCalled(t, "Sanitize")
		mockDB.AssertNotCalled(t, "CreateResource")
		mockAuthHelper.AssertNotCalled(t, "GetLoggedInSubject")
		mockAuditLogger.AssertNotCalled(t, "Log")
	})
}

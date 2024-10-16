package admingrouphandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAdminGroupNewGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		_, exists := data["csrfField"]
		return exists
	})).Return(nil)

	handler := HandleAdminGroupNewGet(mockHttpHelper)

	req, _ := http.NewRequest("GET", "/admin/groups/new", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminGroupNewPost(t *testing.T) {
	t.Run("Successful group creation", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockIdentifierValidator.On("ValidateIdentifier", "new-group", true).Return(nil)
		mockDB.On("GetGroupByGroupIdentifier", mock.Anything, "new-group").Return(nil, nil)
		mockInputSanitizer.On("Sanitize", "new-group").Return("new-group")
		mockInputSanitizer.On("Sanitize", "New Group Description").Return("New Group Description")
		mockDB.On("CreateGroup", mock.Anything, mock.AnythingOfType("*models.Group")).Return(nil)
		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")
		mockAuditLogger.On("Log", constants.AuditCreatedGroup, mock.Anything).Return(nil)

		handler := HandleAdminGroupNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("groupIdentifier", "new-group")
		form.Add("description", "New Group Description")
		form.Add("includeInIdToken", "on")
		form.Add("includeInAccessToken", "on")

		req, _ := http.NewRequest("POST", "/admin/groups/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/admin/groups", rr.Header().Get("Location"))

		mockHttpHelper.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Invalid group identifier", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockIdentifierValidator.On("ValidateIdentifier", "invalid group", true).Return(errors.New("Invalid identifier"))
		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Invalid identifier"
		})).Return(nil)

		handler := HandleAdminGroupNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("groupIdentifier", "invalid group")
		form.Add("description", "Invalid Group")

		req, _ := http.NewRequest("POST", "/admin/groups/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("Group identifier already in use", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		existingGroup := &models.Group{Id: 1, GroupIdentifier: "existing-group"}

		mockIdentifierValidator.On("ValidateIdentifier", "existing-group", true).Return(nil)
		mockDB.On("GetGroupByGroupIdentifier", mock.Anything, "existing-group").Return(existingGroup, nil)
		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "The group identifier is already in use."
		})).Return(nil)

		handler := HandleAdminGroupNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("groupIdentifier", "existing-group")
		form.Add("description", "Existing Group")

		req, _ := http.NewRequest("POST", "/admin/groups/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("Description too long", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			errorMsg, ok := data["error"].(string)
			return ok && strings.HasPrefix(errorMsg, "The description cannot exceed a maximum length of")
		})).Return(nil)

		handler := HandleAdminGroupNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		form := url.Values{}
		form.Add("groupIdentifier", "valid-group")
		form.Add("description", strings.Repeat("a", 101))

		req, _ := http.NewRequest("POST", "/admin/groups/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockIdentifierValidator.AssertNotCalled(t, "ValidateIdentifier")
		mockDB.AssertNotCalled(t, "GetGroupByGroupIdentifier")
		mockInputSanitizer.AssertNotCalled(t, "Sanitize")
		mockDB.AssertNotCalled(t, "CreateGroup")
		mockAuthHelper.AssertNotCalled(t, "GetLoggedInSubject")
		mockAuditLogger.AssertNotCalled(t, "Log")
	})
}

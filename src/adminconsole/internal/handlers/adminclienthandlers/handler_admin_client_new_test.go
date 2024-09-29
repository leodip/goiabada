package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
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

func TestHandleAdminClientNewGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		_, csrfFieldExists := data["csrfField"]
		return csrfFieldExists
	})).Return(nil)

	handler := HandleAdminClientNewGet(mockHttpHelper)

	req, err := http.NewRequest("GET", "/admin/clients/new", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminClientNewPost_ValidInput(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockIdentifierValidator.On("ValidateIdentifier", "valid-client", true).Return(nil)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid-client").Return(nil, nil)
	mockInputSanitizer.On("Sanitize", mock.AnythingOfType("string")).Return(func(s string) string { return s })

	mockDB.On("CreateClient", mock.Anything, mock.MatchedBy(func(client *models.Client) bool {
		return client.ClientIdentifier == "valid-client" &&
			client.Description == "Test client" &&
			client.IsPublic == false &&
			client.ConsentRequired == false &&
			client.Enabled == true &&
			client.DefaultAcrLevel == enums.AcrLevel2Optional &&
			client.AuthorizationCodeEnabled == true &&
			client.ClientCredentialsEnabled == false &&
			client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingDefault.String() &&
			len(client.ClientSecretEncrypted) > 0
	})).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditCreatedClient, mock.MatchedBy(func(details map[string]interface{}) bool {
		clientIdentifier, clientIdentifierOk := details["clientIdentifier"].(string)
		loggedInUser, loggedInUserOk := details["loggedInUser"].(string)

		return clientIdentifierOk && clientIdentifier == "valid-client" &&
			loggedInUserOk && loggedInUser == "test-subject"
	})).Return(nil)

	handler := HandleAdminClientNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "valid-client")
	form.Add("description", "Test client")
	form.Add("authorizationCodeEnabled", "on")
	req, err := http.NewRequest("POST", "/admin/clients/new", strings.NewReader(form.Encode()))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		AESEncryptionKey: []byte("test-encryption-key-000000000000"),
	}))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockInputSanitizer.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminClientNewPost_EmptyClientIdentifier(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Client identifier is required."
	})).Return(nil)

	handler := HandleAdminClientNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "")
	form.Add("description", "Test client")
	req, err := http.NewRequest("POST", "/admin/clients/new", strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminClientNewPost_LongDescription(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "The description cannot exceed a maximum length of 100 characters."
	})).Return(nil)

	handler := HandleAdminClientNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "valid-client")
	form.Add("description", strings.Repeat("a", 101)) // 101 characters
	req, err := http.NewRequest("POST", "/admin/clients/new", strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminClientNewPost_InvalidIdentifier(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockIdentifierValidator.On("ValidateIdentifier", "invalid identifier", true).Return(errors.New("Invalid identifier"))

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid identifier"
	})).Return(nil)

	handler := HandleAdminClientNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "invalid identifier")
	form.Add("description", "Test client")
	req, err := http.NewRequest("POST", "/admin/clients/new", strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
}

func TestHandleAdminClientNewPost_ClientAlreadyExists(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockIdentifierValidator.On("ValidateIdentifier", "existing-client", true).Return(nil)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, "existing-client").Return(&models.Client{}, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "The client identifier is already in use."
	})).Return(nil)

	handler := HandleAdminClientNewPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "existing-client")
	form.Add("description", "Test client")
	req, err := http.NewRequest("POST", "/admin/clients/new", strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
}

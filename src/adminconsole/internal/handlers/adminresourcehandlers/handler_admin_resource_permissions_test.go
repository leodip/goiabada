package adminresourcehandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
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

func TestHandleAdminResourcePermissionsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: "test-resource",
		Description:        "Test Resource",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "permission1", ResourceId: 1},
		{Id: 2, PermissionIdentifier: "permission2", ResourceId: 1},
	}

	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_permissions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["resourceId"] == int64(1) &&
			data["resourceIdentifier"] == "test-resource" &&
			data["resourceDescription"] == "Test Resource" &&
			len(data["permissions"].([]models.Permission)) == 2
	})).Return(nil)

	handler := HandleAdminResourcePermissionsGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/resources/1/permissions", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("resourceId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminResourcePermissionsPost(t *testing.T) {
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
			ResourceIdentifier: "test-resource",
		}

		existingPermissions := []models.Permission{
			{Id: 1, PermissionIdentifier: "existing-permission", Description: "Existing Permission"},
			{Id: 2, PermissionIdentifier: "to-be-deleted-permission", Description: "To Be Deleted Permission"},
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(existingPermissions, nil)

		// Expectations for new permission
		mockIdentifierValidator.On("ValidateIdentifier", "new-permission", true).Return(nil)
		mockInputSanitizer.On("Sanitize", "new-permission").Return("new-permission")
		mockInputSanitizer.On("Sanitize", "New Permission").Return("New Permission")
		mockDB.On("CreatePermission", mock.Anything, mock.MatchedBy(func(p *models.Permission) bool {
			return p.PermissionIdentifier == "new-permission" && p.Description == "New Permission"
		})).Return(nil)

		// Expectations for existing permission (unchanged)
		mockIdentifierValidator.On("ValidateIdentifier", "existing-permission", true).Return(nil)
		mockInputSanitizer.On("Sanitize", "existing-permission").Return("existing-permission")
		mockInputSanitizer.On("Sanitize", "Existing Permission").Return("Existing Permission")
		mockDB.On("GetPermissionById", mock.Anything, int64(1)).Return(&existingPermissions[0], nil)
		mockDB.On("UpdatePermission", mock.Anything, mock.MatchedBy(func(p *models.Permission) bool {
			return p.Id == 1 && p.PermissionIdentifier == "existing-permission" && p.Description == "Existing Permission"
		})).Return(nil)

		// Expectation for deleting permission
		mockDB.On("DeletePermission", mock.Anything, int64(2)).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
		mockAuditLogger.On("Log", constants.AuditUpdatedResourcePermissions, mock.MatchedBy(func(details map[string]interface{}) bool {
			resourceId, resourceIdOk := details["resourceId"].(int64)
			loggedInUser, loggedInUserOk := details["loggedInUser"].(string)

			return resourceIdOk && resourceId == 1 &&
				loggedInUserOk && loggedInUser == "admin-user"
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v SavePermissionsResult) bool {
			return v.Success == true
		})).Run(func(args mock.Arguments) {
			w := args.Get(0).(http.ResponseWriter)
			result := args.Get(2).(SavePermissionsResult)
			json.NewEncoder(w).Encode(result)
		}).Return()

		handler := HandleAdminResourcePermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

		payload := SavePermissionsInput{
			ResourceId: 1,
			Permissions: []Permission{
				{Id: -1, Identifier: "new-permission", Description: "New Permission"},
				{Id: 1, Identifier: "existing-permission", Description: "Existing Permission"},
				// Note: "to-be-deleted-permission" is not included, simulating its deletion
			},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/admin/resources/1/permissions", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response SavePermissionsResult
		json.Unmarshal(rr.Body.Bytes(), &response)
		assert.True(t, response.Success)

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("resource not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(nil, nil)
		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "resource not found"
		})).Return()

		handler := HandleAdminResourcePermissionsPost(mockHttpHelper, nil, nil, mockDB, nil, nil, nil)

		payload := SavePermissionsInput{ResourceId: 1}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/admin/resources/1/permissions", bytes.NewBuffer(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("system level resource", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: constants.AuthServerResourceIdentifier,
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "system level resources cannot be modified"
		})).Return()

		handler := HandleAdminResourcePermissionsPost(mockHttpHelper, nil, nil, mockDB, nil, nil, nil)

		payload := SavePermissionsInput{ResourceId: 1}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/admin/resources/1/permissions", bytes.NewBuffer(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("invalid permission identifier", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockInputSanitizer.On("Sanitize", mock.Anything).Return("invalid-id")
		mockIdentifierValidator.On("ValidateIdentifier", "invalid-id", true).Return(customerrors.NewErrorDetail("", "Invalid permission"))

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v SavePermissionsResult) bool {
			return v.Success == false && v.Error == "Invalid permission"
		})).Return()

		handler := HandleAdminResourcePermissionsPost(mockHttpHelper, nil, nil, mockDB, mockIdentifierValidator, mockInputSanitizer, nil)

		payload := SavePermissionsInput{
			ResourceId: 1,
			Permissions: []Permission{
				{Id: -1, Identifier: "invalid-id", Description: "Invalid Permission"},
			},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/admin/resources/1/permissions", bytes.NewBuffer(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
	})

	t.Run("duplicate permission identifiers", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockInputSanitizer.On("Sanitize", mock.Anything).Return("duplicate-id")

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v SavePermissionsResult) bool {
			return v.Success == false && v.Error == "Permission duplicate-id is duplicated."
		})).Return()

		handler := HandleAdminResourcePermissionsPost(mockHttpHelper, nil, nil, mockDB, nil, mockInputSanitizer, nil)

		payload := SavePermissionsInput{
			ResourceId: 1,
			Permissions: []Permission{
				{Id: -1, Identifier: "duplicate-id", Description: "First Permission"},
				{Id: -1, Identifier: "duplicate-id", Description: "Second Permission"},
			},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/admin/resources/1/permissions", bytes.NewBuffer(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
	})

	t.Run("resourceId mismatch", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "resourceId mismatch"
		})).Return()

		handler := HandleAdminResourcePermissionsPost(mockHttpHelper, nil, nil, mockDB, nil, nil, nil)

		payload := SavePermissionsInput{
			ResourceId: 2, // Mismatched resourceId
			Permissions: []Permission{
				{Id: 1, Identifier: "permission1", Description: "Description"},
			},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/admin/resources/1/permissions", bytes.NewBuffer(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("empty permission identifier", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockInputSanitizer.On("Sanitize", mock.Anything).Return("")

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v SavePermissionsResult) bool {
			return v.Success == false && v.Error == "Permission identifier is required."
		})).Return()

		handler := HandleAdminResourcePermissionsPost(mockHttpHelper, nil, nil, mockDB, nil, mockInputSanitizer, nil)

		payload := SavePermissionsInput{
			ResourceId: 1,
			Permissions: []Permission{
				{Id: -1, Identifier: "", Description: "Description"},
			},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/admin/resources/1/permissions", bytes.NewBuffer(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
	})

	t.Run("permission description exceeding maximum length", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockInputSanitizer.On("Sanitize", mock.Anything).Return(strings.Repeat("a", 101))
		mockIdentifierValidator.On("ValidateIdentifier", mock.Anything, true).Return(nil)

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v SavePermissionsResult) bool {
			return v.Success == false && strings.HasPrefix(v.Error, "The description cannot exceed a maximum length of")
		})).Return()

		handler := HandleAdminResourcePermissionsPost(mockHttpHelper, nil, nil, mockDB, mockIdentifierValidator, mockInputSanitizer, nil)

		payload := SavePermissionsInput{
			ResourceId: 1,
			Permissions: []Permission{
				{Id: -1, Identifier: "permission1", Description: strings.Repeat("a", 101)},
			},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/admin/resources/1/permissions", bytes.NewBuffer(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
	})
}

func TestHandleAdminResourceValidatePermissionPost(t *testing.T) {
	t.Run("Valid permission", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)

		mockInputSanitizer.On("Sanitize", "valid-permission").Return("valid-permission")
		mockInputSanitizer.On("Sanitize", "Valid description").Return("Valid description")
		mockIdentifierValidator.On("ValidateIdentifier", "valid-permission", true).Return(nil)

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(result ValidatePermissionResult) bool {
			return result.Valid && result.Error == ""
		})).Return()

		handler := HandleAdminResourceValidatePermissionPost(mockHttpHelper, mockIdentifierValidator, mockInputSanitizer)

		body := []byte(`{"permissionIdentifier": "valid-permission", "description": "Valid description"}`)
		req, _ := http.NewRequest("POST", "/validate", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHttpHelper.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
	})

	t.Run("Invalid permission identifier", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)

		mockInputSanitizer.On("Sanitize", "invalid@permission").Return("invalid@permission")
		mockInputSanitizer.On("Sanitize", "Valid description").Return("Valid description")
		mockIdentifierValidator.On("ValidateIdentifier", "invalid@permission", true).Return(customerrors.NewErrorDetail("", "Invalid permission identifier"))

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(result ValidatePermissionResult) bool {
			return !result.Valid && result.Error == "Invalid permission identifier"
		})).Return()

		handler := HandleAdminResourceValidatePermissionPost(mockHttpHelper, mockIdentifierValidator, mockInputSanitizer)

		body := []byte(`{"permissionIdentifier": "invalid@permission", "description": "Valid description"}`)
		req, _ := http.NewRequest("POST", "/validate", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHttpHelper.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
	})

	t.Run("Empty permission identifier", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)

		mockInputSanitizer.On("Sanitize", "").Return("")
		mockInputSanitizer.On("Sanitize", "Valid description").Return("Valid description")

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(result ValidatePermissionResult) bool {
			return !result.Valid && result.Error == "Permission identifier is required."
		})).Return()

		handler := HandleAdminResourceValidatePermissionPost(mockHttpHelper, mockIdentifierValidator, mockInputSanitizer)

		body := []byte(`{"permissionIdentifier": "", "description": "Valid description"}`)
		req, _ := http.NewRequest("POST", "/validate", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHttpHelper.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
	})

	t.Run("Description too long", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)

		longDescription := string(make([]byte, 101))
		mockInputSanitizer.On("Sanitize", "valid-permission").Return("valid-permission")
		mockInputSanitizer.On("Sanitize", longDescription).Return(longDescription)
		mockIdentifierValidator.On("ValidateIdentifier", "valid-permission", true).Return(nil)

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(result ValidatePermissionResult) bool {
			return !result.Valid && result.Error == "The description cannot exceed a maximum length of 100 characters."
		})).Return()

		handler := HandleAdminResourceValidatePermissionPost(mockHttpHelper, mockIdentifierValidator, mockInputSanitizer)

		body, _ := json.Marshal(map[string]string{
			"permissionIdentifier": "valid-permission",
			"description":          longDescription,
		})
		req, _ := http.NewRequest("POST", "/validate", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHttpHelper.AssertExpectations(t)
		mockIdentifierValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
	})

	t.Run("Sanitized description differs from original", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)

		mockInputSanitizer.On("Sanitize", "valid-permission").Return("valid-permission")
		mockInputSanitizer.On("Sanitize", "Description with <script>").Return("Description with ")

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(result ValidatePermissionResult) bool {
			return !result.Valid && result.Error == "The description contains invalid characters, as we do not permit the use of HTML in the description."
		})).Return()

		handler := HandleAdminResourceValidatePermissionPost(mockHttpHelper, mockIdentifierValidator, mockInputSanitizer)

		body := []byte(`{"permissionIdentifier": "valid-permission", "description": "Description with <script>"}`)
		req, _ := http.NewRequest("POST", "/validate", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHttpHelper.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
	})
}

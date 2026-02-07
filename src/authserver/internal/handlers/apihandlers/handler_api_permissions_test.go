package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/inputsanitizer"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
)

// TestHandleAPIResourcePermissionsPut_BuiltInPermissionMissingFromDB verifies that when
// a built-in permission is missing from the system resource's database rows, the handler
// returns HTTP 500 with an appropriate integrity error message.
// This is a unit test because simulating a missing built-in permission in integration tests
// would cascade FK deletions that can't be rolled back.
func TestHandleAPIResourcePermissionsPut_BuiltInPermissionMissingFromDB(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	identifierValidator := validators.NewIdentifierValidator()
	inputSan := inputsanitizer.NewInputSanitizer()

	handler := HandleAPIResourcePermissionsPut(database, nil, identifierValidator, inputSan, auditLogger)

	// System-level resource (authserver)
	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
	}

	// Return existing permissions that are MISSING the "manage" built-in permission
	existingPerms := []models.Permission{
		{Id: 10, PermissionIdentifier: constants.UserinfoPermissionIdentifier, ResourceId: 1, Description: "Userinfo"},
		{Id: 11, PermissionIdentifier: constants.ManageAccountPermissionIdentifier, ResourceId: 1, Description: "Manage account"},
		// "manage" is intentionally missing
		{Id: 13, PermissionIdentifier: constants.AdminReadPermissionIdentifier, ResourceId: 1, Description: "Admin read"},
		{Id: 14, PermissionIdentifier: constants.ManageUsersPermissionIdentifier, ResourceId: 1, Description: "Manage users"},
		{Id: 15, PermissionIdentifier: constants.ManageClientsPermissionIdentifier, ResourceId: 1, Description: "Manage clients"},
		{Id: 16, PermissionIdentifier: constants.ManageSettingsPermissionIdentifier, ResourceId: 1, Description: "Manage settings"},
	}

	database.On("GetResourceById", (*sql.Tx)(nil), int64(1)).Return(resource, nil)
	database.On("GetPermissionsByResourceId", (*sql.Tx)(nil), int64(1)).Return(existingPerms, nil)

	// Build a valid request body that includes all the permissions we have
	var permUpserts []api.ResourcePermissionUpsert
	for _, p := range existingPerms {
		permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
			Id:                   p.Id,
			PermissionIdentifier: p.PermissionIdentifier,
			Description:          p.Description,
		})
	}
	reqBody := api.UpdateResourcePermissionsRequest{Permissions: permUpserts}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("PUT", "/api/v1/admin/resources/1/permissions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setChiURLParam(req, "resourceId", "1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	errObj := response["error"].(map[string]interface{})
	msg := errObj["message"].(string)
	assert.Contains(t, msg, "missing from the system resource")
	assert.Contains(t, msg, constants.ManagePermissionIdentifier)

	database.AssertExpectations(t)
}

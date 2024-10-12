package adminclienthandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminClientPermissionsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		ClientCredentialsEnabled: true,
	}

	clientPermissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "read", ResourceId: 1},
		{Id: 2, PermissionIdentifier: "write", ResourceId: 1},
	}

	resources := []models.Resource{
		{Id: 1, ResourceIdentifier: "test-resource"},
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil).Run(func(args mock.Arguments) {
		client := args.Get(1).(*models.Client)
		client.Permissions = clientPermissions
	})
	mockDB.On("PermissionsLoadResources", mock.Anything, clientPermissions).Return(nil)
	mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(&resources[0], nil)
	mockDB.On("GetAllResources", mock.Anything).Return(resources, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_permissions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		client, ok := data["client"].(struct {
			ClientId                 int64
			ClientIdentifier         string
			ClientCredentialsEnabled bool
			Permissions              map[int64]string
			IsSystemLevelClient      bool
		})
		return ok &&
			client.ClientId == 1 &&
			client.ClientIdentifier == "test-client" &&
			client.ClientCredentialsEnabled &&
			len(client.Permissions) == 2 &&
			client.Permissions[1] == "test-resource:read" &&
			client.Permissions[2] == "test-resource:write" &&
			!client.IsSystemLevelClient
	})).Return(nil)

	handler := HandleAdminClientPermissionsGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/permissions", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientPermissionsPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		ClientCredentialsEnabled: true,
	}

	// Initial permissions
	clientPermissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "read", ResourceId: 1},
		{Id: 2, PermissionIdentifier: "write", ResourceId: 1},
		{Id: 3, PermissionIdentifier: "delete", ResourceId: 1},
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil).Run(func(args mock.Arguments) {
		client := args.Get(1).(*models.Client)
		client.Permissions = clientPermissions
	})
	mockDB.On("PermissionsLoadResources", mock.Anything, clientPermissions).Return(nil)

	// Permission to be added
	mockDB.On("GetPermissionById", mock.Anything, int64(4)).Return(&models.Permission{Id: 4, PermissionIdentifier: "update", ResourceId: 1}, nil)
	mockDB.On("CreateClientPermission", mock.Anything, mock.MatchedBy(func(cp *models.ClientPermission) bool {
		return cp.ClientId == 1 && cp.PermissionId == 4
	})).Return(nil)

	// Permissions to be removed
	mockDB.On("GetClientPermissionByClientIdAndPermissionId", mock.Anything, int64(1), int64(1)).Return(&models.ClientPermission{Id: 1}, nil)
	mockDB.On("DeleteClientPermission", mock.Anything, int64(1)).Return(nil)
	mockDB.On("GetClientPermissionByClientIdAndPermissionId", mock.Anything, int64(1), int64(3)).Return(&models.ClientPermission{Id: 3}, nil)
	mockDB.On("DeleteClientPermission", mock.Anything, int64(3)).Return(nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditUpdatedClientPermissions, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == int64(1) && details["loggedInUser"] == "test-subject"
	})).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(struct{ Success bool })
		return ok && result.Success
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		err := json.NewEncoder(w).Encode(struct{ Success bool }{Success: true})
		assert.NoError(t, err)
	}).Return()

	handler := HandleAdminClientPermissionsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	// Request body:
	// - Permission 1 (read) is removed
	// - Permission 2 (write) is unchanged
	// - Permission 3 (delete) is removed
	// - Permission 4 (update) is added
	reqBody := `{"clientId": 1, "assignedPermissionsIds": [2, 4]}`
	req, _ := http.NewRequest("POST", "/admin/clients/1/permissions", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response struct {
		Success bool `json:"success"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	if assert.NoError(t, err) {
		assert.True(t, response.Success)
	}

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)

	// Additional assertions to verify the correct permissions were added, removed, and unchanged
	mockDB.AssertCalled(t, "CreateClientPermission", mock.Anything, mock.MatchedBy(func(cp *models.ClientPermission) bool {
		return cp.ClientId == 1 && cp.PermissionId == 4
	}))
	mockDB.AssertCalled(t, "DeleteClientPermission", mock.Anything, int64(1))
	mockDB.AssertCalled(t, "DeleteClientPermission", mock.Anything, int64(3))
	mockDB.AssertNotCalled(t, "DeleteClientPermission", mock.Anything, int64(2))
	mockDB.AssertNotCalled(t, "CreateClientPermission", mock.Anything, mock.MatchedBy(func(cp *models.ClientPermission) bool {
		return cp.PermissionId == 2
	}))
}

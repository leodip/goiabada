package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestAdminClientPermissions_Get_ClientNotFound(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/9999/permissions"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminClientPermissions_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/2/permissions"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %s", err)
	}

	assert.Equal(t, 200, resp.StatusCode)

	assert.True(t, strings.Contains(string(body), "\"Scope\": \"backend-svcA:create-product\""))
	assert.True(t, strings.Contains(string(body), "\"Scope\": \"backend-svcB:read-info\""))
}

func TestAdminClientPermissions_Post(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := lib.EncryptText(lib.GenerateRandomNumbers(60), settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	newClient := &models.Client{
		ClientIdentifier:         "c-" + gofakeit.UUID(),
		ClientSecretEncrypted:    clientSecretEncrypted,
		Description:              "This client is going to be deleted",
		Enabled:                  true,
		ConsentRequired:          true,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
	}

	err = database.CreateClient(nil, newClient)
	if err != nil {
		t.Fatal(err)
	}

	resource, err := database.GetResourceByResourceIdentifier(nil, "backend-svcA")
	if err != nil {
		t.Fatal(err)
	}

	svcAPermissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     newClient.Id,
		PermissionId: svcAPermissions[0].Id,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     newClient.Id,
		PermissionId: svcAPermissions[1].Id,
	})
	if err != nil {
		t.Fatal(err)
	}

	resource, err = database.GetResourceByResourceIdentifier(nil, "backend-svcB")
	if err != nil {
		t.Fatal(err)
	}

	svcBPermissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     newClient.Id,
		PermissionId: svcBPermissions[0].Id,
	})
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/permissions"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %s", err)
	}

	assert.Equal(t, 200, resp.StatusCode)

	assert.True(t, strings.Contains(string(body), "\"Scope\": \"backend-svcA:create-product\""))
	assert.True(t, strings.Contains(string(body), "\"Scope\": \"backend-svcA:read-product\""))
	assert.True(t, strings.Contains(string(body), "\"Scope\": \"backend-svcB:read-info\""))
	assert.False(t, strings.Contains(string(body), "\"Scope\": \"backend-svcB:write-info\""))

	data := struct {
		ClientId               int64   `json:"clientId"`
		AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
	}{
		ClientId:               newClient.Id,
		AssignedPermissionsIds: []int64{svcAPermissions[1].Id, svcBPermissions[0].Id, svcBPermissions[1].Id},
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", destUrl, strings.NewReader(string(jsonData)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	responseData := unmarshalToMap(t, resp)
	assert.Equal(t, true, responseData["Success"])

	client, err := database.GetClientById(nil, newClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	permissions, err := database.GetClientPermissionsByClientId(nil, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 3, len(permissions))

	found := false
	for _, permission := range permissions {
		if permission.PermissionId == svcAPermissions[0].Id {
			found = true
			break
		}
	}
	assert.False(t, found)

	found = false
	for _, permission := range permissions {
		if permission.PermissionId == svcAPermissions[1].Id {
			found = true
			break
		}
	}
	assert.True(t, found)

	found = false
	for _, permission := range permissions {
		if permission.PermissionId == svcBPermissions[0].Id {
			found = true
			break
		}
	}
	assert.True(t, found)

	found = false
	for _, permission := range permissions {
		if permission.PermissionId == svcBPermissions[1].Id {
			found = true
			break
		}
	}
	assert.True(t, found)
}

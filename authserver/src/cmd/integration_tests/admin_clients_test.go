package integrationtests

import (
	"strconv"
	"testing"

	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminClients_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	resource, err := database.GetResourceByResourceIdentifier(nil, "authserver")
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/get-permissions?resourceId=" + strconv.FormatInt(resource.Id, 10)
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	data := unmarshalToMap(t, resp)

	permissions := data["Permissions"].([]interface{})
	assert.Equal(t, 2, len(permissions))

	permission := permissions[0].(map[string]interface{})
	assert.Equal(t, "manage-account", permission["PermissionIdentifier"])

	permission = permissions[1].(map[string]interface{})
	assert.Equal(t, "admin-website", permission["PermissionIdentifier"])
}

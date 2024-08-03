package integrationtests

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestAdminGroupPermissions_Get(t *testing.T) {
	setup()

	resource, err := database.GetResourceByResourceIdentifier(nil, "backend-svcA")
	if err != nil {
		t.Fatal(err)
	}

	permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
	if err != nil {
		t.Fatal(err)
	}

	perm1 := permissions[0] // create-product

	resource, err = database.GetResourceByResourceIdentifier(nil, "backend-svcB")
	if err != nil {
		t.Fatal(err)
	}

	permissions, err = database.GetPermissionsByResourceId(nil, resource.Id)
	if err != nil {
		t.Fatal(err)
	}

	perm2 := permissions[1] // write-info

	group := &models.Group{
		GroupIdentifier: "g-" + gofakeit.UUID(),
		Description:     gofakeit.Sentence(10),
	}
	err = database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CreateGroupPermission(nil, &models.GroupPermission{
		GroupId:      group.Id,
		PermissionId: perm1.Id,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = database.CreateGroupPermission(nil, &models.GroupPermission{
		GroupId:      group.Id,
		PermissionId: perm2.Id,
	})
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/permissions"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %s", err)
	}

	if !strings.Contains(string(body), "backend-svcA:create-product") {
		t.Fatalf("Response body does not contain expected permission identifier for backend-svcA:create-product")
	}

	if !strings.Contains(string(body), "backend-svcB:write-info") {
		t.Fatalf("Response body does not contain expected permission identifier for backend-svcB:write-info")
	}

	buf := bytes.NewBuffer(body)
	doc, err := goquery.NewDocumentFromReader(buf)
	if err != nil {
		t.Fatalf("Error parsing response body: %s", err)
	}

	elem := doc.Find("option[data-resourceidentifier='authserver']").First()
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("option[data-resourceidentifier='backend-svcA']").First()
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("option[data-resourceidentifier='backend-svcB']").First()
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupPermissions_Post_PermissionNotFound(t *testing.T) {
	setup()

	group := &models.Group{
		GroupIdentifier: "g-" + gofakeit.UUID(),
		Description:     gofakeit.Sentence(10),
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/permissions"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	json := `{"groupId":` + strconv.Itoa(int(group.Id)) +
		`,"assignedPermissionsIds":[9999]}`

	req, err := http.NewRequest("POST", lib.GetBaseUrl()+"/admin/groups/"+strconv.Itoa(int(group.Id))+"/permissions", strings.NewReader(json))
	if err != nil {
		t.Fatalf("Error creating POST request: %s", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)

	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatalf("Error sending POST request: %s", err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminGroupPermissions_Post(t *testing.T) {
	setup()

	resource, err := database.GetResourceByResourceIdentifier(nil, "backend-svcA")
	if err != nil {
		t.Fatal(err)
	}

	permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
	if err != nil {
		t.Fatal(err)
	}

	perm1 := permissions[0] // create-product

	resource, err = database.GetResourceByResourceIdentifier(nil, "backend-svcB")
	if err != nil {
		t.Fatal(err)
	}

	permissions, err = database.GetPermissionsByResourceId(nil, resource.Id)
	if err != nil {
		t.Fatal(err)
	}

	perm2 := permissions[1] // write-info
	perm3 := permissions[0] // read-info

	group := &models.Group{
		GroupIdentifier: "g-" + gofakeit.UUID(),
		Description:     gofakeit.Sentence(10),
	}
	err = database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CreateGroupPermission(nil, &models.GroupPermission{
		GroupId:      group.Id,
		PermissionId: perm1.Id,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = database.CreateGroupPermission(nil, &models.GroupPermission{
		GroupId:      group.Id,
		PermissionId: perm2.Id,
	})
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/permissions"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	json := `{"groupId":` + strconv.Itoa(int(group.Id)) +
		`,"assignedPermissionsIds":[` + strconv.Itoa(int(perm1.Id)) + `,` + strconv.Itoa(int(perm3.Id)) + `]}`

	req, err := http.NewRequest("POST", lib.GetBaseUrl()+"/admin/groups/"+strconv.Itoa(int(group.Id))+"/permissions", strings.NewReader(json))
	if err != nil {
		t.Fatalf("Error creating POST request: %s", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)

	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatalf("Error sending POST request: %s", err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	groupPermissions, err := database.GetGroupPermissionsByGroupId(nil, group.Id)
	if err != nil {
		t.Fatalf("Error getting group permissions: %s", err)
	}

	assert.Equal(t, 2, len(groupPermissions))

	found := false
	for _, gp := range groupPermissions {
		if gp.PermissionId == perm1.Id {
			found = true
			break
		}
	}
	assert.True(t, found)

	found = false
	for _, gp := range groupPermissions {
		if gp.PermissionId == perm3.Id {
			found = true
			break
		}
	}
	assert.True(t, found)
}

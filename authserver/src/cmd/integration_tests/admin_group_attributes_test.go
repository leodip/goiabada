package integrationtests

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminGroupAttributes_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	group := &entities.Group{
		GroupIdentifier:      "g-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	attribute := &entities.GroupAttribute{
		GroupId:              group.Id,
		Key:                  "attr-key-" + gofakeit.UUID(),
		Value:                "attr-value-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err = database.CreateGroupAttribute(nil, attribute)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("td:contains('" + attribute.Key + "')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("td:contains('" + attribute.Value + "')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupAttributes_Post_Remove(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	group := &entities.Group{
		GroupIdentifier:      "g-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	attribute := &entities.GroupAttribute{
		GroupId:              group.Id,
		Key:                  "attr-key-" + gofakeit.UUID(),
		Value:                "attr-value-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err = database.CreateGroupAttribute(nil, attribute)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	destUrl = lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes/remove/" + strconv.Itoa(int(attribute.Id))

	req, err := http.NewRequest("POST", destUrl, strings.NewReader(""))
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

	data := unmarshalToMap(t, resp)

	assert.Equal(t, true, data["Success"])

	attributes, err := database.GetGroupAttributesByGroupId(nil, group.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 0, len(attributes))
}

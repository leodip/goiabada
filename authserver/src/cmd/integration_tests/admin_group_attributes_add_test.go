package integrationtests

import (
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminGroupAttributesAdd_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	group := &entities.Group{
		GroupIdentifier:      "test-group-" + strconv.Itoa(gofakeit.Number(1000, 9999)),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes/add"
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

	elem := doc.Find("input[name='attributeKey']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='attributeValue']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='includeInAccessToken']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='includeInIdToken']")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupAttributesAdd_Post_AttributeKeyIsRequired(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	group := &entities.Group{
		GroupIdentifier:      "test-group-" + strconv.Itoa(gofakeit.Number(1000, 9999)),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes/add"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := map[string][]string{
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("div.text-error p:contains('Attribute key is required')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupAttributesAdd_Post_AttributeValueIsTooLong(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	group := &entities.Group{
		GroupIdentifier:      "test-group-" + strconv.Itoa(gofakeit.Number(1000, 9999)),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes/add"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := map[string][]string{
		"attributeKey":       {"test-attribute"},
		"attributeValue":     {gofakeit.Sentence(300)},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("div.text-error p:contains('The attribute value cannot exceed a maximum length of')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupAttributesAdd_Post(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	group := &entities.Group{
		GroupIdentifier:      "test-group-" + strconv.Itoa(gofakeit.Number(1000, 9999)),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes/add"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := map[string][]string{
		"attributeKey":         {"test-attribute"},
		"attributeValue":       {"test-value"},
		"includeInAccessToken": {"on"},
		"includeInIdToken":     {"on"},
		"gorilla.csrf.Token":   {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)

	redirectLocation := resp.Header.Get("Location")
	assert.Contains(t, redirectLocation, "/admin/groups/"+strconv.Itoa(int(group.Id))+"/attributes")

	groupAttributes, err := database.GetGroupAttributesByGroupId(nil, group.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 1, len(groupAttributes))
	assert.Equal(t, "test-attribute", groupAttributes[0].Key)
	assert.Equal(t, "test-value", groupAttributes[0].Value)
	assert.True(t, groupAttributes[0].IncludeInAccessToken)
	assert.True(t, groupAttributes[0].IncludeInIdToken)
}

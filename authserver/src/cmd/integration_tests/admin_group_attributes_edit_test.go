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

func TestAdminGroupAttributesEdit_Get(t *testing.T) {
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
		Key:                  ("k-" + gofakeit.UUID())[:32],
		Value:                "attr-value-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err = database.CreateGroupAttribute(nil, attribute)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes/edit/" + strconv.Itoa(int(attribute.Id))
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
	assert.Equal(t, attribute.Key, elem.AttrOr("value", ""))

	elem = doc.Find("input[name='attributeValue']")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, attribute.Value, elem.AttrOr("value", ""))

	elem = doc.Find("input[name='includeInAccessToken'][checked]")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='includeInIdToken'][checked]")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupAttributesEdit_Post_AttributeValueIsTooLong(t *testing.T) {
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
		Key:                  ("k-" + gofakeit.UUID())[:32],
		Value:                "attr-value-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err = database.CreateGroupAttribute(nil, attribute)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes/edit/" + strconv.Itoa(int(attribute.Id))
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := map[string][]string{
		"attributeKey":         {"test-attribute-9988"},
		"attributeValue":       {gofakeit.Sentence(300)},
		"includeInAccessToken": {"off"},
		"includeInIdToken":     {"off"},
		"gorilla.csrf.Token":   {csrf},
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

func TestAdminGroupAttributesEdit_Post(t *testing.T) {
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
		Key:                  ("k-" + gofakeit.UUID())[:32],
		Value:                "attr-value-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err = database.CreateGroupAttribute(nil, attribute)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes/edit/" + strconv.Itoa(int(attribute.Id))
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := map[string][]string{
		"attributeKey":         {"test-attribute-9988"},
		"attributeValue":       {"test-value-7766"},
		"includeInAccessToken": {"off"},
		"includeInIdToken":     {"off"},
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
	assert.Equal(t, "test-attribute-9988", groupAttributes[0].Key)
	assert.Equal(t, "test-value-7766", groupAttributes[0].Value)
	assert.False(t, groupAttributes[0].IncludeInAccessToken)
	assert.False(t, groupAttributes[0].IncludeInIdToken)
}

func TestAdminGroupAttributesEdit_Post_Sanitize(t *testing.T) {
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
		Key:                  ("k-" + gofakeit.UUID())[:32],
		Value:                "attr-value-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err = database.CreateGroupAttribute(nil, attribute)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/attributes/edit/" + strconv.Itoa(int(attribute.Id))
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := map[string][]string{
		"attributeKey":         {"test-attribute-9988"},
		"attributeValue":       {"some <script>alert('xss')</script> value"},
		"includeInAccessToken": {"off"},
		"includeInIdToken":     {"off"},
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
	assert.Equal(t, "test-attribute-9988", groupAttributes[0].Key)
	assert.Equal(t, "some  value", groupAttributes[0].Value)
	assert.False(t, groupAttributes[0].IncludeInAccessToken)
	assert.False(t, groupAttributes[0].IncludeInIdToken)
}

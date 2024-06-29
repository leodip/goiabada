package integrationtests

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminGroupDelete_Get(t *testing.T) {
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

	// add 2 members to group

	userGroup := &entities.UserGroup{
		UserId:  1,
		GroupId: group.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatal(err)
	}

	userGroup = &entities.UserGroup{
		UserId:  2,
		GroupId: group.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/delete"
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

	elem := doc.Find("tbody td:contains('" + group.GroupIdentifier + "')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("tbody td:contains('Count of members')").Next()
	assert.Contains(t, elem.Text(), "2")
}

func TestAdminGroupDelete_Post(t *testing.T) {
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

	// add 2 members to group

	userGroup := &entities.UserGroup{
		UserId:  1,
		GroupId: group.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatal(err)
	}

	userGroup = &entities.UserGroup{
		UserId:  2,
		GroupId: group.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/delete"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"groupIdentifier":    {group.GroupIdentifier},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	group, err = database.GetGroupById(nil, group.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, group)

	// make sure users were not deleted

	user, err := database.GetUserById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, user)

	user, err = database.GetUserById(nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, user)
}

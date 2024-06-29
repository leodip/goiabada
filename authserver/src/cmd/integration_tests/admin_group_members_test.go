package integrationtests

import (
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminGroupMembers_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	group := &entities.Group{
		GroupIdentifier:      "group-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	// add 100 members to the group
	for i := 0; i < 100; i++ {

		user := &entities.User{
			Subject:    uuid.New(),
			GivenName:  gofakeit.FirstName(),
			FamilyName: gofakeit.LastName(),
			Email:      "someone." + gofakeit.UUID() + "@example.com",
		}
		err = database.CreateUser(nil, user)
		if err != nil {
			t.Fatal(err)
		}

		userGroup := &entities.UserGroup{
			UserId:  user.Id,
			GroupId: group.Id,
		}
		err = database.CreateUserGroup(nil, userGroup)
		if err != nil {
			t.Fatal(err)
		}
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/members"
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
	elem := doc.Find("td a[href^='/admin/users/']")
	assert.Equal(t, 10, elem.Length())

	// click page 2

	destUrl = lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/members?page=2"
	resp, err = httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem = doc.Find("td a[href^='/admin/users/']")
	assert.Equal(t, 10, elem.Length())
}

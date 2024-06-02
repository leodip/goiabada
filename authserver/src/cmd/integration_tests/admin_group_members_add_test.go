package integrationtests

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminGroupMembersAdd_Get(t *testing.T) {
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

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/members/add"
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

	elem := doc.Find("h1 span:contains('" + group.GroupIdentifier + "')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupMembersSearch_Get(t *testing.T) {
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

	random := strconv.Itoa(gofakeit.Number(1000, 9999))

	user1 := &entities.User{
		Subject:    uuid.New(),
		GivenName:  "John",
		FamilyName: "Doe",
		Email:      "john." + random + "@example.com",
	}
	err = database.CreateUser(nil, user1)
	if err != nil {
		t.Fatal(err)
	}

	user2 := &entities.User{
		Subject:    uuid.New(),
		GivenName:  "Mary",
		FamilyName: "Jane",
		Email:      "mary_jane" + random + "@example.com",
	}
	err = database.CreateUser(nil, user2)
	if err != nil {
		t.Fatal(err)
	}

	// add 2 members to group

	userGroup := &entities.UserGroup{
		UserId:  user1.Id,
		GroupId: group.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatal(err)
	}

	userGroup = &entities.UserGroup{
		UserId:  user2.Id,
		GroupId: group.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/members/search?query=" + random
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	type userResult struct {
		Id           int64
		Subject      string
		Username     string
		Email        string
		GivenName    string
		MiddleName   string
		FamilyName   string
		AddedToGroup bool
	}

	type searchResult struct {
		Users []userResult
	}

	assert.Equal(t, 200, resp.StatusCode)

	// unmarshall json response to searchResult struct
	var result searchResult
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 2, len(result.Users))
	assert.Equal(t, user1.Id, result.Users[0].Id)
	assert.Equal(t, user1.Subject.String(), result.Users[0].Subject)
	assert.Equal(t, user1.Email, result.Users[0].Email)
	assert.Equal(t, user1.GivenName, result.Users[0].GivenName)
	assert.Equal(t, user1.FamilyName, result.Users[0].FamilyName)
	assert.Equal(t, true, result.Users[0].AddedToGroup)

	assert.Equal(t, user2.Id, result.Users[1].Id)
	assert.Equal(t, user2.Subject.String(), result.Users[1].Subject)
	assert.Equal(t, user2.Email, result.Users[1].Email)
	assert.Equal(t, user2.GivenName, result.Users[1].GivenName)
	assert.Equal(t, user2.FamilyName, result.Users[1].FamilyName)
	assert.Equal(t, true, result.Users[1].AddedToGroup)
}

func TestAdminGroupMembersAdd_Post(t *testing.T) {
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

	random := strconv.Itoa(gofakeit.Number(1000, 9999))

	user1 := &entities.User{
		Subject:    uuid.New(),
		GivenName:  "John",
		FamilyName: "Doe",
		Email:      "john." + random + "@example.com",
	}
	err = database.CreateUser(nil, user1)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/members/add"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	// add user to group

	formData := map[string][]string{
		"gorilla.csrf.Token": {csrf},
	}

	destUrl = lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/members/add?groupId=" +
		strconv.Itoa(int(group.Id)) + "&userId=" + strconv.Itoa(int(user1.Id))

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	// check if user was added to group

	userGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, user1.Id, group.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, userGroup)
	assert.Equal(t, user1.Id, userGroup.UserId)
	assert.Equal(t, group.Id, userGroup.GroupId)
}

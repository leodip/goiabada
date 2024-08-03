package integrationtests

import (
	"strconv"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestAdminGroupMembersRemove_Post(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	group := &models.Group{
		GroupIdentifier:      "g-" + gofakeit.UUID(),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err := database.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	user1 := &models.User{
		Subject:    uuid.New(),
		GivenName:  "John",
		FamilyName: "Doe",
		Email:      "john." + gofakeit.UUID() + "@example.com",
	}
	err = database.CreateUser(nil, user1)
	if err != nil {
		t.Fatal(err)
	}

	userGroup := &models.UserGroup{
		UserId:  user1.Id,
		GroupId: group.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatal(err)
	}

	// load page
	destUrl := lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/members"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	// remove member from group

	destUrl = lib.GetBaseUrl() + "/admin/groups/" + strconv.Itoa(int(group.Id)) + "/members/remove/" + strconv.Itoa(int(user1.Id))
	resp, err = httpClient.PostForm(destUrl, map[string][]string{
		"gorilla.csrf.Token": {csrf},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	data := unmarshalToMap(t, resp)

	assert.Equal(t, true, data["Success"])

	// check if user was removed from group

	userGroup, err = database.GetUserGroupByUserIdAndGroupId(nil, user1.Id, group.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, userGroup)
}

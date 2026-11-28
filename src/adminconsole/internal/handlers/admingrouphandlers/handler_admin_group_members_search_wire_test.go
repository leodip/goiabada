package admingrouphandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
)

// memberSearchJSON is the answer of the member search as the add-members script reads it,
// user.Id among its keys, written out by hand from what the handler sent before #482 respelled
// the Go names. The keys are the contract with a script that may still be open in a browser
// across a deploy, so they do not follow a field's Go name (#482 decision 7).
const memberSearchJSON = `{"Users":[{"Id":7,"Subject":"5e0b1c9a-sub","Username":"ana","Email":"ana@example.com","GivenName":"Ana","MiddleName":"Maria","FamilyName":"Silva","FullName":"Ana Maria Silva","AddedToGroup":true},{"Id":8,"Subject":"9c1d2e3f-sub","Username":"yamada","Email":"yamada@example.com","GivenName":"太郎","MiddleName":"","FamilyName":"山田","FullName":"山田太郎","AddedToGroup":false}]}` + "\n"

// memberSearchAPI answers the two calls the member search makes: the group, and two users the
// search found: one already a member, named in Latin letters, and one named in kanji, whose full
// name core/personname writes family name first (#662).
type memberSearchAPI struct{}

func (memberSearchAPI) AddUserToGroup(context.Context, string, int64, int64) error {
	panic("the member search adds no one")
}

func (memberSearchAPI) GetGroupByID(_ context.Context, _ string, groupID int64) (*api.GroupResponse, error) {
	return &api.GroupResponse{ID: groupID}, nil
}

func (memberSearchAPI) SearchUsersWithGroupAnnotation(context.Context, string, string, int64, int, int) ([]api.UserWithGroupMembershipResponse, int, error) {
	user := api.UserWithGroupMembershipResponse{InGroup: true}
	user.ID = 7
	user.Subject = "5e0b1c9a-sub"
	user.Username = "ana"
	user.Email = "ana@example.com"
	user.GivenName = "Ana"
	user.MiddleName = "Maria"
	user.FamilyName = "Silva"
	kanji := api.UserWithGroupMembershipResponse{}
	kanji.ID = 8
	kanji.Subject = "9c1d2e3f-sub"
	kanji.Username = "yamada"
	kanji.Email = "yamada@example.com"
	kanji.GivenName = "太郎"
	kanji.FamilyName = "山田"
	return []api.UserWithGroupMembershipResponse{user, kanji}, 2, nil
}

func TestHandleMembersSearchGet_SendsTheKeysTheScriptReads(t *testing.T) {
	handler := HandleMembersSearchGet(render.New(fstest.MapFS{}, nil), memberSearchAPI{})
	req := handlertest.Request(http.MethodGet, "/admin/groups/3/members/search?query=ana",
		handlertest.WithAccessToken(), handlertest.WithPathValue("groupId", "3"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, memberSearchJSON, rr.Body.String())
}

// TestUserResult_EveryFieldDeclaresItsKey holds each field of a search result to an explicit json
// tag with the key the script reads, so the key no longer rests on the Go name.
func TestUserResult_EveryFieldDeclaresItsKey(t *testing.T) {
	assert.Equal(t,
		[]string{"Id", "Subject", "Username", "Email", "GivenName", "MiddleName", "FamilyName", "FullName", "AddedToGroup"},
		jsonTags(t, reflect.TypeOf(UserResult{})))
}

func jsonTags(t *testing.T, structType reflect.Type) []string {
	t.Helper()
	tags := make([]string, 0, structType.NumField())
	for i := range structType.NumField() {
		field := structType.Field(i)
		tag, ok := field.Tag.Lookup("json")
		assert.True(t, ok, "%s.%s declares no json tag, so its Go name is the key sent", structType.Name(), field.Name)
		tags = append(tags, tag)
	}
	return tags
}

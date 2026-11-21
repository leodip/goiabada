package adminresourcehandlers

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

// permissionUserSearchJSON is the answer of the user search as the grant-permission script reads
// it, user.Id among its keys, written out by hand from what the handler sent before #482
// respelled the Go names. The keys are the contract with a script that may still be open in a
// browser across a deploy, so they do not follow a field's Go name (#482 decision 7).
const permissionUserSearchJSON = `{"Users":[{"Id":7,"Subject":"5e0b1c9a-sub","Username":"ana","Email":"ana@example.com","GivenName":"Ana","MiddleName":"Maria","FamilyName":"Silva","HasPermission":true}]}` + "\n"

// permissionUserSearchAPI answers the three calls the user search makes: the resource, its one
// permission, and one user the search found, already holding it.
type permissionUserSearchAPI struct{}

func (permissionUserSearchAPI) GetPermissionsByResource(_ context.Context, _ string, resourceID int64) ([]api.PermissionResponse, error) {
	return []api.PermissionResponse{{ID: 11, ResourceID: resourceID}}, nil
}

func (permissionUserSearchAPI) GetResourceByID(_ context.Context, _ string, resourceID int64) (*api.ResourceResponse, error) {
	return &api.ResourceResponse{ID: resourceID}, nil
}

func (permissionUserSearchAPI) GetUserPermissions(context.Context, string, int64) (*api.UserResponse, []api.PermissionResponse, error) {
	panic("the user search reads no user's permissions")
}

func (permissionUserSearchAPI) GetUsersByPermission(context.Context, string, int64, int, int) ([]api.UserResponse, int, error) {
	panic("the user search lists no holders")
}

func (permissionUserSearchAPI) SearchUsersWithPermissionAnnotation(context.Context, string, int64, string, int, int) ([]api.UserWithPermissionResponse, int, error) {
	user := api.UserWithPermissionResponse{HasPermission: true}
	user.ID = 7
	user.Subject = "5e0b1c9a-sub"
	user.Username = "ana"
	user.Email = "ana@example.com"
	user.GivenName = "Ana"
	user.MiddleName = "Maria"
	user.FamilyName = "Silva"
	return []api.UserWithPermissionResponse{user}, 1, nil
}

func (permissionUserSearchAPI) UpdateUserPermissions(context.Context, string, int64, *api.UpdateUserPermissionsRequest) error {
	panic("the user search grants nothing")
}

func TestHandleUsersWithPermissionSearchGet_SendsTheKeysTheScriptReads(t *testing.T) {
	handler := HandleUsersWithPermissionSearchGet(render.New(fstest.MapFS{}, nil), permissionUserSearchAPI{})
	req := handlertest.Request(http.MethodGet, "/admin/resources/5/users-with-permission/search/11?query=ana",
		handlertest.WithAccessToken(),
		handlertest.WithPathValue("resourceId", "5"), handlertest.WithPathValue("permissionId", "11"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, permissionUserSearchJSON, rr.Body.String())
}

// TestUserResult_EveryFieldDeclaresItsKey holds each field of a search result to an explicit json
// tag with the key the script reads, so the key no longer rests on the Go name.
func TestUserResult_EveryFieldDeclaresItsKey(t *testing.T) {
	assert.Equal(t,
		[]string{"Id", "Subject", "Username", "Email", "GivenName", "MiddleName", "FamilyName", "HasPermission"},
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

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	neturl "net/url"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIUsersSearch_AnnotatePermission_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	res := createResource(t)
	perm := createPermission(t, res.Id)

	// Create three users; grant permission to two
	randSuffix := fake.LetterN(6)
	u1 := &record.User{Subject: fake.UUID(), Enabled: true, Username: "annperm1-" + randSuffix, Email: "annperm1-" + randSuffix + "@test.com", GivenName: "A1", FamilyName: "T"}
	u2 := &record.User{Subject: fake.UUID(), Enabled: true, Username: "annperm2-" + randSuffix, Email: "annperm2-" + randSuffix + "@test.com", GivenName: "A2", FamilyName: "T"}
	u3 := &record.User{Subject: fake.UUID(), Enabled: true, Username: "annperm3-" + randSuffix, Email: "annperm3-" + randSuffix + "@test.com", GivenName: "A3", FamilyName: "T"}
	assert.NoError(t, database.CreateUser(context.Background(), nil, u1))
	assert.NoError(t, database.CreateUser(context.Background(), nil, u2))
	assert.NoError(t, database.CreateUser(context.Background(), nil, u3))
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, u1.Id)
		_ = database.DeleteUser(context.Background(), nil, u2.Id)
		_ = database.DeleteUser(context.Background(), nil, u3.Id)
	}()

	assignPermissionToUser(t, u1.Id, perm.Id)
	assignPermissionToUser(t, u3.Id, perm.Id)

	// Use query parameter to filter to our test users (search matches on email, username, given_name, etc.)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/search?query=annperm&annotatePermissionId=" + strconv.FormatInt(perm.Id, 10) + "&page=1&size=200"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var apiResp api.SearchUsersWithPermissionAnnotationResponse
	err := json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)

	// Find our users and verify HasPermission
	var seen1, seen2, seen3 bool
	for _, u := range apiResp.Users {
		switch u.Email {
		case u1.Email:
			seen1 = true
			assert.True(t, u.HasPermission)
		case u2.Email:
			seen2 = true
			assert.False(t, u.HasPermission)
		case u3.Email:
			seen3 = true
			assert.True(t, u.HasPermission)
		}
	}
	assert.True(t, seen1 || seen2 || seen3, "Expected to see at least one created user in the page")
}

func TestAPIUsersSearch_AnnotatePermission_InvalidParam(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/search?annotatePermissionId=abc"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid annotatePermissionId value", errResp.ErrorDescription)
}

func TestAPIUsersSearch_AnnotatePermission_PermissionNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	missingId := int64(fake.Number(8_000_000, 8_999_999))
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/search?annotatePermissionId=" + strconv.FormatInt(missingId, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Permission not found", errResp.ErrorDescription)
}

func TestAPIUsersSearch_AnnotatePermission_Unauthorized(t *testing.T) {
	res := createResource(t)
	perm := createPermission(t, res.Id)
	u := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/search?annotatePermissionId=" + neturl.QueryEscape(strconv.FormatInt(perm.Id, 10))
	httpClient := createHttpClient(t)
	req, _ := http.NewRequest("GET", u, nil)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIUsersSearch_AnnotatePermission_ConflictWithGroupAnnotation(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	res := createResource(t)
	perm := createPermission(t, res.Id)

	// Create a group to reference
	grp := createTestGroup(t)
	defer func() { _ = database.DeleteGroup(context.Background(), nil, grp.Id) }()

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/search?annotatePermissionId=" + strconv.FormatInt(perm.Id, 10) + "&annotateGroupMembership=" + strconv.FormatInt(grp.Id, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "annotateGroupMembership and annotatePermissionId cannot be used together", errResp.ErrorDescription)
}

// Annotating against a permission on the authserver resource is answered as against any other,
// whether a built-in or one identified userinfo. The endpoint refused userinfo with 400 until #449,
// when the row stopped meaning anything and was deleted; an administrator may create one of that
// name, and it is an ordinary permission.
func TestAPIUsersSearch_AnnotatePermission_AnAuthServerPermission(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	authRes, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, authRes, "the seed creates the authserver resource")
	perms, err := database.GetPermissionsByResourceId(context.Background(), nil, authRes.Id)
	require.NoError(t, err)
	var manageAccount *record.Permission
	for i := range perms {
		if perms[i].PermissionIdentifier == builtin.ManageAccountPermissionIdentifier {
			manageAccount = &perms[i]
		}
	}
	require.NotNil(t, manageAccount, "the seed writes the manage-account permission")
	userinfoNamed := createTestPermission(t, authRes.Id, "userinfo", "Created by an administrator")
	t.Cleanup(func() { _ = database.DeletePermission(context.Background(), nil, userinfoNamed.Id) })

	for _, perm := range []*record.Permission{manageAccount, userinfoNamed} {
		t.Run(perm.PermissionIdentifier, func(t *testing.T) {
			randSuffix := fake.LetterN(8)
			holder := &record.User{Subject: fake.UUID(), Enabled: true, Username: "annauth-" + randSuffix, Email: "annauth-" + randSuffix + "@test.com", GivenName: "A", FamilyName: "T"}
			other := &record.User{Subject: fake.UUID(), Enabled: true, Username: "annauth-other-" + randSuffix, Email: "annauth-other-" + randSuffix + "@test.com", GivenName: "B", FamilyName: "T"}
			require.NoError(t, database.CreateUser(context.Background(), nil, holder))
			require.NoError(t, database.CreateUser(context.Background(), nil, other))
			t.Cleanup(func() {
				_ = database.DeleteUser(context.Background(), nil, holder.Id)
				_ = database.DeleteUser(context.Background(), nil, other.Id)
			})
			assignPermissionToUser(t, holder.Id, perm.Id)

			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/search?query=" + randSuffix + "&annotatePermissionId=" + strconv.FormatInt(perm.Id, 10) + "&page=1&size=200"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			var apiResp api.SearchUsersWithPermissionAnnotationResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&apiResp))
			annotated := map[string]bool{}
			for _, u := range apiResp.Users {
				annotated[u.Email] = u.HasPermission
			}
			assert.Equal(t, map[string]bool{holder.Email: true, other.Email: false}, annotated)
		})
	}
}

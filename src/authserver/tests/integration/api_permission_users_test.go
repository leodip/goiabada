package integrationtests

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test GET /api/v1/admin/permissions/{permissionId}/users success path
func TestAPIPermissionUsersGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	res := createResource(t)
	perm := createPermission(t, res.Id)

	// Create three users; assign permission to two
	randSuffix := fake.LetterN(6)
	u1 := &models.User{Subject: fake.UUID(), Enabled: true, Username: "permuser1-" + randSuffix, Email: "permuser1-" + randSuffix + "@test.com", GivenName: "U1", FamilyName: "T"}
	u2 := &models.User{Subject: fake.UUID(), Enabled: true, Username: "permuser2-" + randSuffix, Email: "permuser2-" + randSuffix + "@test.com", GivenName: "U2", FamilyName: "T"}
	u3 := &models.User{Subject: fake.UUID(), Enabled: true, Username: "permuser3-" + randSuffix, Email: "permuser3-" + randSuffix + "@test.com", GivenName: "U3", FamilyName: "T"}
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

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/" + strconv.FormatInt(perm.Id, 10) + "/users?page=1&size=200"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var apiResp api.GetUsersByPermissionResponse
	err := json.NewDecoder(resp.Body).Decode(&apiResp)
	assert.NoError(t, err)

	// Total should be at least 2; ensure u1 and u3 appear; u2 does not
	assert.GreaterOrEqual(t, apiResp.Total, 2)
	var seen1, seen3, seen2 bool
	for _, u := range apiResp.Users {
		if u.Email == u1.Email {
			seen1 = true
		}
		if u.Email == u3.Email {
			seen3 = true
		}
		if u.Email == u2.Email {
			seen2 = true
		}
	}
	assert.True(t, seen1, "u1 should be included")
	assert.True(t, seen3, "u3 should be included")
	assert.False(t, seen2, "u2 should not be included")
}

func TestAPIPermissionUsersGet_InvalidPermissionId(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/invalid/users"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid permission ID format", errResp.ErrorDescription)
}

func TestAPIPermissionUsersGet_PermissionNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	missingId := int64(fake.Number(7_000_000, 7_999_999))
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/" + strconv.FormatInt(missingId, 10) + "/users"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Permission not found", errResp.ErrorDescription)
}

// A permission on the authserver resource lists its holders as any other does, whether a built-in
// or one identified userinfo. The endpoint refused userinfo with 400 until #449, when the row
// stopped meaning anything and was deleted; an administrator may create one of that name, and it
// is an ordinary permission.
func TestAPIPermissionUsersGet_AnAuthServerPermission(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	authRes, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, authRes, "the seed creates the authserver resource")
	perms, err := database.GetPermissionsByResourceId(context.Background(), nil, authRes.Id)
	require.NoError(t, err)
	var manageAccount *models.Permission
	for i := range perms {
		if perms[i].PermissionIdentifier == constants.ManageAccountPermissionIdentifier {
			manageAccount = &perms[i]
		}
	}
	require.NotNil(t, manageAccount, "the seed writes the manage-account permission")
	userinfoNamed := createTestPermission(t, authRes.Id, "userinfo", "Created by an administrator")
	t.Cleanup(func() { _ = database.DeletePermission(context.Background(), nil, userinfoNamed.Id) })

	for _, perm := range []*models.Permission{manageAccount, userinfoNamed} {
		t.Run(perm.PermissionIdentifier, func(t *testing.T) {
			randSuffix := fake.LetterN(8)
			holder := &models.User{Subject: fake.UUID(), Enabled: true, Username: "permauth-" + randSuffix, Email: "permauth-" + randSuffix + "@test.com", GivenName: "P", FamilyName: "T"}
			require.NoError(t, database.CreateUser(context.Background(), nil, holder))
			t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, holder.Id) })
			assignPermissionToUser(t, holder.Id, perm.Id)

			// Every page, since a built-in can have more holders than one page carries by the time
			// the suite reaches this test.
			var emails []string
			for page := 1; ; page++ {
				url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/" + strconv.FormatInt(perm.Id, 10) + "/users?page=" + strconv.Itoa(page) + "&size=200"
				resp := makeAPIRequest(t, "GET", url, accessToken, nil)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				var apiResp api.GetUsersByPermissionResponse
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&apiResp))
				_ = resp.Body.Close()
				for _, u := range apiResp.Users {
					emails = append(emails, u.Email)
				}
				if len(apiResp.Users) == 0 || page*200 >= apiResp.Total {
					break
				}
			}
			assert.Contains(t, emails, holder.Email, "the holder is listed")
		})
	}
}

func TestAPIPermissionUsersGet_Unauthorized(t *testing.T) {
	res := createResource(t)
	perm := createPermission(t, res.Id)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/permissions/" + strconv.FormatInt(perm.Id, 10) + "/users"
	req, _ := http.NewRequest("GET", url, nil)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

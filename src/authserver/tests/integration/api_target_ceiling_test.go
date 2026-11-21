package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The target ceiling on users and groups: a user holding one of the six administrative
// permissions, directly or through any of its groups, and a group holding one, are administrators,
// and only an authserver:manage token writes to one in any way (#402 decisions 1, 2, 4 and 5).
//
// Each write runs three ways: manage-users against an administrator, made one directly and through
// a group, is refused 403 MANAGE_SCOPE_REQUIRED with the insufficient_scope challenge, changes
// nothing and leaves exactly one administrator_change_refused row under ceiling "target"; the same
// token against an ordinary target succeeds; and authserver:manage succeeds against an
// administrator. Deleting a group and changing an administrative group's members are the grant
// ceiling's (api_membership_ceiling_test.go).

// targetFixture is one target and what a write acts on beside it.
type targetFixture struct {
	userID  int64
	groupID int64
	// rowID is the attribute, session, consent or ordinary group the write names in its path.
	rowID int64
	// before is a value read before the write, which the write would change.
	before string
	// ordinaryPermissionID is a permission on a resource of the test's own, administrative to
	// nobody.
	ordinaryPermissionID int64
}

// targetCeilingWrite is one of the writes the target ceiling guards.
type targetCeilingWrite struct {
	name   string
	method string
	route  string
	kind   string
	// prepare puts in place what the write acts on.
	prepare func(t *testing.T, f *targetFixture)
	send    func(t *testing.T, token string, f *targetFixture) (*http.Response, string)
	// changed reports whether the write's effect is in the store.
	changed func(t *testing.T, f *targetFixture) bool
}

func storedUser(t *testing.T, userID int64) *record.User {
	t.Helper()
	user, err := database.GetUserByID(context.Background(), nil, userID)
	require.NoError(t, err)
	return user
}

func updateStoredUser(t *testing.T, userID int64, change func(user *record.User)) {
	t.Helper()
	user := storedUser(t, userID)
	change(user)
	require.NoError(t, database.UpdateUser(context.Background(), nil, user))
}

func userPermissionIDs(t *testing.T, userID int64) []int64 {
	t.Helper()
	rows, err := database.GetUserPermissionsByUserID(context.Background(), nil, userID)
	require.NoError(t, err)
	ids := []int64{}
	for _, row := range rows {
		ids = append(ids, row.PermissionID)
	}
	return ids
}

func userGroupIDs(t *testing.T, userID int64) []int64 {
	t.Helper()
	rows, err := database.GetUserGroupsByUserID(context.Background(), nil, userID)
	require.NoError(t, err)
	ids := []int64{}
	for _, row := range rows {
		ids = append(ids, row.GroupID)
	}
	return ids
}

func groupPermissionIDs(t *testing.T, groupID int64) []int64 {
	t.Helper()
	rows, err := database.GetGroupPermissionsByGroupID(context.Background(), nil, groupID)
	require.NoError(t, err)
	ids := []int64{}
	for _, row := range rows {
		ids = append(ids, row.PermissionID)
	}
	return ids
}

func noPrepare(t *testing.T, f *targetFixture) {}

// sendPicture uploads a picture under its own request id.
func sendPicture(t *testing.T, accessToken string, userID int64) (*http.Response, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("picture", "picture.png")
	require.NoError(t, err)
	_, err = io.Copy(part, bytes.NewReader(createTestPNGImage(64, 64)))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+fmt.Sprintf("/api/v1/admin/users/%d/profile-picture", userID), &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+accessToken)
	requestID := "target-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestID)

	resp, err := createHTTPClient(t).Do(req)
	require.NoError(t, err)
	return resp, requestID
}

func hasPicture(t *testing.T, userID int64) bool {
	t.Helper()
	has, err := database.UserHasProfilePicture(context.Background(), nil, userID)
	require.NoError(t, err)
	return has
}

var userTargetCeilingWrites = []targetCeilingWrite{
	{
		name: "PUT users enabled", method: http.MethodPut, route: "/api/v1/admin/users/{id}/enabled", kind: "user",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/enabled", f.userID), map[string]any{"enabled": false})
		},
		changed: func(t *testing.T, f *targetFixture) bool { return !storedUser(t, f.userID).Enabled },
	},
	{
		name: "PUT users profile", method: http.MethodPut, route: "/api/v1/admin/users/{id}/profile", kind: "user",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/profile", f.userID), map[string]any{"givenName": "Changed"})
		},
		changed: func(t *testing.T, f *targetFixture) bool { return storedUser(t, f.userID).GivenName == "Changed" },
	},
	{
		name: "PUT users address", method: http.MethodPut, route: "/api/v1/admin/users/{id}/address", kind: "user",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/address", f.userID), map[string]any{"addressLine1": "1 Long Road"})
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			return storedUser(t, f.userID).AddressLine1 == "1 Long Road"
		},
	},
	{
		name: "PUT users email", method: http.MethodPut, route: "/api/v1/admin/users/{id}/email", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) { f.before = uniqueEmail("taken-over@target.test") },
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/email", f.userID),
				map[string]any{"email": f.before, "emailVerified": true})
		},
		changed: func(t *testing.T, f *targetFixture) bool { return storedUser(t, f.userID).Email == f.before },
	},
	{
		name: "POST users email verification code", method: http.MethodPost, route: "/api/v1/admin/users/{id}/email/verification-code", kind: "user",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/email/verification-code", f.userID), nil)
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			return len(storedUser(t, f.userID).EmailVerificationCodeEncrypted) > 0
		},
	},
	{
		name: "PUT users phone", method: http.MethodPut, route: "/api/v1/admin/users/{id}/phone", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) {
			updateStoredUser(t, f.userID, func(user *record.User) { user.PhoneNumber = "5550100" })
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/phone", f.userID),
				map[string]any{"phoneCountryUniqueId": "", "phoneNumber": ""})
		},
		changed: func(t *testing.T, f *targetFixture) bool { return storedUser(t, f.userID).PhoneNumber == "" },
	},
	{
		name: "PUT users password", method: http.MethodPut, route: "/api/v1/admin/users/{id}/password", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) { f.before = storedUser(t, f.userID).PasswordHash },
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/password", f.userID),
				map[string]any{"newPassword": "Correct-Horse-Battery-Staple-9"})
		},
		changed: func(t *testing.T, f *targetFixture) bool { return storedUser(t, f.userID).PasswordHash != f.before },
	},
	{
		name: "PUT users otp", method: http.MethodPut, route: "/api/v1/admin/users/{id}/otp", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) {
			updateStoredUser(t, f.userID, func(user *record.User) {
				user.OTPEnabled = true
				user.OTPSecretEncrypted = encryptOTPSecretForTest(t, "JBSWY3DPEHPK3PXP")
			})
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/otp", f.userID), map[string]any{"enabled": false})
		},
		changed: func(t *testing.T, f *targetFixture) bool { return !storedUser(t, f.userID).OTPEnabled },
	},
	{
		name: "POST users profile picture", method: http.MethodPost, route: "/api/v1/admin/users/{id}/profile-picture", kind: "user",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendPicture(t, token, f.userID)
		},
		changed: func(t *testing.T, f *targetFixture) bool { return hasPicture(t, f.userID) },
	},
	{
		name: "DELETE users profile picture", method: http.MethodDelete, route: "/api/v1/admin/users/{id}/profile-picture", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) {
			require.NoError(t, database.CreateUserProfilePicture(context.Background(), nil, &record.UserProfilePicture{
				UserID: f.userID, Picture: createTestPNGImage(8, 8), ContentType: "image/png",
			}))
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d/profile-picture", f.userID), nil)
		},
		changed: func(t *testing.T, f *targetFixture) bool { return !hasPicture(t, f.userID) },
	},
	{
		name: "DELETE users", method: http.MethodDelete, route: "/api/v1/admin/users/{id}", kind: "user",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d", f.userID), nil)
		},
		changed: func(t *testing.T, f *targetFixture) bool { return storedUser(t, f.userID) == nil },
	},
	{
		name: "POST user attributes", method: http.MethodPost, route: "/api/v1/admin/user-attributes", kind: "user",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPost, "/api/v1/admin/user-attributes",
				map[string]any{"userId": f.userID, "key": "tier", "value": "gold"})
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			attributes, err := database.GetUserAttributesByUserID(context.Background(), nil, f.userID)
			require.NoError(t, err)
			return len(attributes) > 0
		},
	},
	{
		name: "PUT user attributes", method: http.MethodPut, route: "/api/v1/admin/user-attributes/{id}", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) {
			f.rowID = createTestUserAttribute(t, f.userID, "tier", "gold").ID
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/user-attributes/%d", f.rowID),
				map[string]any{"key": "tier", "value": "platinum"})
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			attribute, err := database.GetUserAttributeByID(context.Background(), nil, f.rowID)
			require.NoError(t, err)
			return attribute.Value == "platinum"
		},
	},
	{
		name: "DELETE user attributes", method: http.MethodDelete, route: "/api/v1/admin/user-attributes/{id}", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) {
			f.rowID = createTestUserAttribute(t, f.userID, "tier", "gold").ID
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/user-attributes/%d", f.rowID), nil)
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			attribute, err := database.GetUserAttributeByID(context.Background(), nil, f.rowID)
			require.NoError(t, err)
			return attribute == nil
		},
	},
	{
		name: "DELETE user sessions", method: http.MethodDelete, route: "/api/v1/admin/user-sessions/{id}", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) {
			now := time.Now().UTC()
			session := &record.UserSession{
				SessionIdentifier: fake.UUID(), Started: now, LastAccessed: now, AuthTime: now, PasswordAuthTime: now,
				AuthMethods: "pwd", ACRLevel: "urn:goiabada:level1", IPAddress: "192.0.2.1", UserID: f.userID,
			}
			require.NoError(t, database.CreateUserSession(context.Background(), nil, session))
			f.rowID = session.ID
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/user-sessions/%d", f.rowID), nil)
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			session, err := database.GetUserSessionByID(context.Background(), nil, f.rowID)
			require.NoError(t, err)
			return session == nil
		},
	},
	{
		name: "DELETE user consents", method: http.MethodDelete, route: "/api/v1/admin/user-consents/{id}", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) {
			client := createTestClient(t, "target-consent-"+strings.ToLower(fake.LetterN(8)))
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
			consent := &record.UserConsent{
				ClientID: client.ID, UserID: f.userID, Scope: "openid",
				GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
			}
			require.NoError(t, database.CreateUserConsent(context.Background(), nil, consent))
			f.rowID = consent.ID
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/user-consents/%d", f.rowID), nil)
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			consent, err := database.GetUserConsentByID(context.Background(), nil, f.rowID)
			require.NoError(t, err)
			return consent == nil
		},
	},
	{
		// The user holds a live refresh token with a client and no consent (#135 decision 2).
		name: "DELETE users connected clients", method: http.MethodDelete,
		route: "/api/v1/admin/users/{id}/connected-clients/{clientId}", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) {
			client := createTestClient(t, "target-connected-"+strings.ToLower(fake.LetterN(8)))
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
			holdRefreshToken(t, storedUser(t, f.userID), client, false, time.Now().UTC().Add(time.Hour))
			f.rowID = client.ID
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete,
				fmt.Sprintf("/api/v1/admin/users/%d/connected-clients/%d", f.userID, f.rowID), nil)
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			tokens, err := database.GetRefreshTokensByUserID(context.Background(), nil, f.userID)
			require.NoError(t, err)
			require.Len(t, tokens, 1)
			return tokens[0].Revoked
		},
	},
	{
		// Joining an ordinary group, keeping every membership the user has: nothing administrative
		// changes, so the grant ceiling lets it through and the target ceiling judges it.
		name: "PUT users groups", method: http.MethodPut, route: "/api/v1/admin/users/{id}/groups", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) { f.rowID = ordinaryGroup(t) },
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			current := userGroupIDs(t, f.userID)
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/groups", f.userID),
				map[string]any{"groupIds": append(append([]int64{}, current...), f.rowID), "expectedGroupIds": current})
		},
		changed: func(t *testing.T, f *targetFixture) bool { return memberOf(t, f.userID, f.rowID) },
	},
	{
		// Granting an ordinary permission, keeping every permission the user holds.
		name: "PUT users permissions", method: http.MethodPut, route: "/api/v1/admin/users/{id}/permissions", kind: "user",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			current := userPermissionIDs(t, f.userID)
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/permissions", f.userID),
				map[string]any{"permissionIDs": append(append([]int64{}, current...), f.ordinaryPermissionID), "expectedPermissionIds": current})
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			for _, id := range userPermissionIDs(t, f.userID) {
				if id == f.ordinaryPermissionID {
					return true
				}
			}
			return false
		},
	},
	{
		name: "POST group members of an ordinary group", method: http.MethodPost, route: "/api/v1/admin/groups/{id}/members", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) { f.rowID = ordinaryGroup(t) },
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPost, fmt.Sprintf("/api/v1/admin/groups/%d/members", f.rowID), map[string]any{"userId": f.userID})
		},
		changed: func(t *testing.T, f *targetFixture) bool { return memberOf(t, f.userID, f.rowID) },
	},
	{
		name: "DELETE group member of an ordinary group", method: http.MethodDelete, route: "/api/v1/admin/groups/{id}/members/{userId}", kind: "user",
		prepare: func(t *testing.T, f *targetFixture) {
			f.rowID = ordinaryGroup(t)
			joinGroup(t, f.userID, f.rowID)
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/groups/%d/members/%d", f.rowID, f.userID), nil)
		},
		changed: func(t *testing.T, f *targetFixture) bool { return !memberOf(t, f.userID, f.rowID) },
	},
}

var groupTargetCeilingWrites = []targetCeilingWrite{
	{
		name: "PUT groups", method: http.MethodPut, route: "/api/v1/admin/groups/{id}", kind: "group",
		prepare: func(t *testing.T, f *targetFixture) { f.before = "renamed-" + strings.ToLower(fake.LetterN(10)) },
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/groups/%d", f.groupID),
				map[string]any{"groupIdentifier": f.before, "description": "Renamed"})
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			group, err := database.GetGroupByID(context.Background(), nil, f.groupID)
			require.NoError(t, err)
			return group.GroupIdentifier == f.before
		},
	},
	{
		name: "POST group attributes", method: http.MethodPost, route: "/api/v1/admin/group-attributes", kind: "group",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPost, "/api/v1/admin/group-attributes",
				map[string]any{"groupId": f.groupID, "key": "tier", "value": "gold"})
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			attributes, err := database.GetGroupAttributesByGroupID(context.Background(), nil, f.groupID)
			require.NoError(t, err)
			return len(attributes) > 0
		},
	},
	{
		name: "PUT group attributes", method: http.MethodPut, route: "/api/v1/admin/group-attributes/{id}", kind: "group",
		prepare: func(t *testing.T, f *targetFixture) {
			f.rowID = createTestGroupAttribute(t, f.groupID, "tier", "gold").ID
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/group-attributes/%d", f.rowID),
				map[string]any{"key": "tier", "value": "platinum"})
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			attribute, err := database.GetGroupAttributeByID(context.Background(), nil, f.rowID)
			require.NoError(t, err)
			return attribute.Value == "platinum"
		},
	},
	{
		name: "DELETE group attributes", method: http.MethodDelete, route: "/api/v1/admin/group-attributes/{id}", kind: "group",
		prepare: func(t *testing.T, f *targetFixture) {
			f.rowID = createTestGroupAttribute(t, f.groupID, "tier", "gold").ID
		},
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			return sendAdmin(t, token, http.MethodDelete, fmt.Sprintf("/api/v1/admin/group-attributes/%d", f.rowID), nil)
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			attribute, err := database.GetGroupAttributeByID(context.Background(), nil, f.rowID)
			require.NoError(t, err)
			return attribute == nil
		},
	},
	{
		// Granting an ordinary permission, keeping every permission the group holds.
		name: "PUT groups permissions", method: http.MethodPut, route: "/api/v1/admin/groups/{id}/permissions", kind: "group",
		prepare: noPrepare,
		send: func(t *testing.T, token string, f *targetFixture) (*http.Response, string) {
			current := groupPermissionIDs(t, f.groupID)
			return sendAdmin(t, token, http.MethodPut, fmt.Sprintf("/api/v1/admin/groups/%d/permissions", f.groupID),
				map[string]any{"permissionIDs": append(append([]int64{}, current...), f.ordinaryPermissionID), "expectedPermissionIds": current})
		},
		changed: func(t *testing.T, f *targetFixture) bool {
			for _, id := range groupPermissionIDs(t, f.groupID) {
				if id == f.ordinaryPermissionID {
					return true
				}
			}
			return false
		},
	},
}

// ordinaryPermission is a permission on a resource of the test's own.
func ordinaryPermission(t *testing.T) int64 {
	t.Helper()
	resource := createTestResource(t, "target-res-"+strings.ToLower(fake.LetterN(8)), "Target ceiling")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.ID) })
	return createTestPermission(t, resource.ID, "read", "Read").ID
}

// administratorUser is a fresh user holding the administrative permission identifier, directly or,
// when throughGroup, through a group it belongs to. Either way it also holds manage-account, as
// every user does.
func administratorUser(t *testing.T, identifier string, throughGroup bool) int64 {
	t.Helper()
	userID := newMembershipUser(t)
	require.NoError(t, database.CreateUserPermission(context.Background(), nil,
		&record.UserPermission{UserID: userID, PermissionID: authServerPermissionID(t, builtin.ManageAccountPermissionIdentifier)}))
	administrative := authServerPermissionID(t, identifier)
	if throughGroup {
		joinGroup(t, userID, newGroupHolding(t, administrative))
	} else {
		require.NoError(t, database.CreateUserPermission(context.Background(), nil, &record.UserPermission{UserID: userID, PermissionID: administrative}))
	}
	return userID
}

// ordinaryUser is a fresh user holding manage-account and belonging to an ordinary group.
func ordinaryUser(t *testing.T) int64 {
	t.Helper()
	userID := newMembershipUser(t)
	require.NoError(t, database.CreateUserPermission(context.Background(), nil,
		&record.UserPermission{UserID: userID, PermissionID: authServerPermissionID(t, builtin.ManageAccountPermissionIdentifier)}))
	joinGroup(t, userID, ordinaryGroup(t))
	return userID
}

// assertRefusedByTheTargetCeiling holds one answered request to decision 4's refusal and decision
// 5's one record under ceiling "target".
func assertRefusedByTheTargetCeiling(t *testing.T, resp *http.Response, requestID, readerToken string,
	caller *record.Client, write targetCeilingWrite, targetID int64) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var envelope struct {
		ErrorCode        string `json:"error_code"`
		ErrorDescription string `json:"error_description"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	assert.Equal(t, "MANAGE_SCOPE_REQUIRED", envelope.ErrorCode)
	assert.Contains(t, envelope.ErrorDescription, "authserver:manage")
	challenge := resp.Header.Get("WWW-Authenticate")
	assert.True(t, strings.HasPrefix(challenge, `Bearer realm="`), "a Bearer challenge with its realm: %q", challenge)
	assert.Contains(t, challenge, `error="insufficient_scope"`)
	assert.Contains(t, challenge, `scope="authserver:manage"`)

	rows := refusalRows(t, readerToken, requestID)
	require.Len(t, rows, 1, "exactly one administrator_change_refused row for the refused request")
	row := rows[0]
	assert.Equal(t, caller.ClientIdentifier, row["logged_in_user"], "the caller is the token's sub")
	assert.Equal(t, write.method, row["method"])
	assert.Equal(t, write.route, row["route"])
	assert.Equal(t, "target", row["ceiling"])
	assert.Equal(t, write.kind, row["target_kind"])
	assert.InDelta(t, float64(targetID), row["target_id"], 0)
	assertUserIDNamesAUserTarget(t, row, write.kind, targetID)
	assert.NotContains(t, row, "permission_ids")
}

func TestTargetCeiling_AGranularTokenCannotWriteToAnAdministratorUser(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageUsersPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	ordinary := ordinaryPermission(t)

	for i, write := range userTargetCeilingWrites {
		// Each write meets a different administrative permission, directly and through a group.
		for _, variant := range []struct {
			name         string
			identifier   string
			throughGroup bool
		}{
			{"directly", administrativePermissionIdentifiers[i%len(administrativePermissionIdentifiers)], false},
			{"through a group", administrativePermissionIdentifiers[(i+3)%len(administrativePermissionIdentifiers)], true},
		} {
			t.Run(write.name+"/"+variant.name+"/"+variant.identifier, func(t *testing.T) {
				f := &targetFixture{userID: administratorUser(t, variant.identifier, variant.throughGroup), ordinaryPermissionID: ordinary}
				write.prepare(t, f)

				resp, requestID := write.send(t, granularToken, f)

				assertRefusedByTheTargetCeiling(t, resp, requestID, manageToken, caller, write, f.userID)
				assert.False(t, write.changed(t, f), "the refused request changed nothing")
			})
		}
	}
}

func TestTargetCeiling_AGranularTokenCannotWriteToAnAdministrativeGroup(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageUsersPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	ordinary := ordinaryPermission(t)

	for i, write := range groupTargetCeilingWrites {
		identifier := administrativePermissionIdentifiers[i%len(administrativePermissionIdentifiers)]
		t.Run(write.name+"/"+identifier, func(t *testing.T) {
			f := &targetFixture{groupID: newGroupHolding(t, authServerPermissionID(t, identifier)), ordinaryPermissionID: ordinary}
			write.prepare(t, f)

			resp, requestID := write.send(t, granularToken, f)

			assertRefusedByTheTargetCeiling(t, resp, requestID, manageToken, caller, write, f.groupID)
			assert.False(t, write.changed(t, f), "the refused request changed nothing")
		})
	}
}

func TestTargetCeiling_AGranularTokenStillWritesToOrdinaryUsersAndGroups(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	granularToken, caller := createClientWithGranularScope(t, builtin.ManageUsersPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.ID) })
	ordinary := ordinaryPermission(t)

	for _, write := range append(append([]targetCeilingWrite{}, userTargetCeilingWrites...), groupTargetCeilingWrites...) {
		t.Run(write.name, func(t *testing.T) {
			f := &targetFixture{ordinaryPermissionID: ordinary}
			if write.kind == "group" {
				f.groupID = ordinaryGroup(t)
			} else {
				f.userID = ordinaryUser(t)
			}
			write.prepare(t, f)

			resp, requestID := write.send(t, granularToken, f)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Less(t, resp.StatusCode, 300, "manage-account and a custom authserver permission make nobody an administrator: %s", body)
			assert.True(t, write.changed(t, f))
			assert.Empty(t, refusalRows(t, manageToken, requestID))
		})
	}
}

func TestTargetCeiling_AManageTokenWritesToAdministrators(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	ordinary := ordinaryPermission(t)

	for _, write := range append(append([]targetCeilingWrite{}, userTargetCeilingWrites...), groupTargetCeilingWrites...) {
		t.Run(write.name, func(t *testing.T) {
			f := &targetFixture{ordinaryPermissionID: ordinary}
			if write.kind == "group" {
				f.groupID = newGroupHolding(t, authServerPermissionID(t, builtin.ManagePermissionIdentifier))
			} else {
				f.userID = administratorUser(t, builtin.ManagePermissionIdentifier, false)
			}
			write.prepare(t, f)

			resp, requestID := write.send(t, manageToken, f)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Less(t, resp.StatusCode, 300, string(body))
			assert.True(t, write.changed(t, f))
			assert.Empty(t, refusalRows(t, manageToken, requestID))
		})
	}
}

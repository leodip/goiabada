package user

import (
	"testing"

	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
)

// =============================================================================
// Tests for UserHasScopePermission
//
// This is the authorization gate: handler_authorize.go and
// handler_auth_completed.go use it (via FilterOutScopesWhereUserIsNotAuthorized)
// to decide which scopes end up in a token, and token_validator.go uses it
// directly for the ROPC and client_credentials flows. A regression here is a
// privilege escalation, so the tests below pin both the grant paths and the
// deny-by-default paths.
// =============================================================================

// expectUserLoaded sets up the four calls UserHasScopePermission always makes
// before it even looks at the scope string: fetch the user, then load its
// permissions, groups, and the groups' permissions.
func expectUserLoaded(mockDB *mocks_data.Database, user *models.User, times int) {
	mockDB.On("GetUserById", mock.Anything, user.Id).Return(user, nil).Times(times)
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Times(times)
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Times(times)
	mockDB.On("GroupsLoadPermissions", mock.Anything, mock.Anything).Return(nil).Times(times)
}

func TestUserHasScopePermission_GrantedViaDirectUserPermission(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{
		Id:          1,
		Permissions: []models.Permission{{Id: 5, PermissionIdentifier: "read"}},
	}
	expectUserLoaded(mockDB, user, 1)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(1, "backend-svc:read")

	assert.NoError(t, err)
	assert.True(t, result)
}

func TestUserHasScopePermission_GrantedViaGroupPermission(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	// The user has no permission of its own; the grant comes from group membership.
	user := &models.User{
		Id:          1,
		Permissions: []models.Permission{},
		Groups: []models.Group{
			{
				Id:              7,
				GroupIdentifier: "site-admins",
				Permissions:     []models.Permission{{Id: 5, PermissionIdentifier: "read"}},
			},
		},
	}
	expectUserLoaded(mockDB, user, 1)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(1, "backend-svc:read")

	assert.NoError(t, err)
	assert.True(t, result)
}

func TestUserHasScopePermission_GrantedViaSecondGroup(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	// Ensures the group loop does not stop at the first group.
	user := &models.User{
		Id:          1,
		Permissions: []models.Permission{},
		Groups: []models.Group{
			{Id: 6, GroupIdentifier: "readers", Permissions: []models.Permission{{Id: 99, PermissionIdentifier: "other"}}},
			{Id: 7, GroupIdentifier: "writers", Permissions: []models.Permission{{Id: 5, PermissionIdentifier: "read"}}},
		},
	}
	expectUserLoaded(mockDB, user, 1)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(1, "backend-svc:read")

	assert.NoError(t, err)
	assert.True(t, result)
}

func TestUserHasScopePermission_DeniedWhenNeitherUserNorGroupHasIt(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{
		Id:          1,
		Permissions: []models.Permission{{Id: 99, PermissionIdentifier: "other"}},
		Groups: []models.Group{
			{Id: 7, Permissions: []models.Permission{{Id: 98, PermissionIdentifier: "another"}}},
		},
	}
	expectUserLoaded(mockDB, user, 1)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(1, "backend-svc:read")

	assert.NoError(t, err)
	assert.False(t, result)
}

// A permission identifier such as "read" is only unique within its resource.
// Matching is done on permission Id precisely so that holding "read" on one
// resource does not grant "read" on another. This test guards that.
func TestUserHasScopePermission_DeniedWhenIdentifierMatchesButResourceDiffers(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	// The user holds "read" (Id 77) on some other resource.
	user := &models.User{
		Id:          1,
		Permissions: []models.Permission{{Id: 77, PermissionIdentifier: "read", ResourceId: 20}},
	}
	expectUserLoaded(mockDB, user, 1)

	// On backend-svc, "read" is a different row (Id 5).
	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read", ResourceId: 10}}, nil).Once()

	result, err := pc.UserHasScopePermission(1, "backend-svc:read")

	assert.NoError(t, err)
	assert.False(t, result, "holding the same permission identifier on a different resource must not grant access")
}

func TestUserHasScopePermission_UserNotFound(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	mockDB.On("GetUserById", mock.Anything, int64(42)).Return(nil, nil).Once()

	result, err := pc.UserHasScopePermission(42, "backend-svc:read")

	assert.NoError(t, err)
	assert.False(t, result, "a missing user must be denied")
}

// The scope string is only parsed after the user and its groups are loaded, so
// these malformed-scope cases still expect the four load calls.
func TestUserHasScopePermission_MalformedScope(t *testing.T) {
	testCases := []struct {
		name  string
		scope string
	}{
		{"no separator", "backendsvc"},
		{"too many separators", "backend-svc:read:extra"},
		{"empty scope", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			pc := NewPermissionChecker(mockDB)

			user := &models.User{Id: 1}
			expectUserLoaded(mockDB, user, 1)

			result, err := pc.UserHasScopePermission(1, tc.scope)

			assert.False(t, result)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid scope format")
		})
	}
}

// A bare ":" splits into exactly two (empty) parts, so it passes the format
// check and falls through to a lookup for the resource named "". That must be
// denied rather than treated as a wildcard.
func TestUserHasScopePermission_SeparatorOnlyScopeIsDenied(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{Id: 1}
	expectUserLoaded(mockDB, user, 1)
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "").Return(nil, nil).Once()

	result, err := pc.UserHasScopePermission(1, ":")

	assert.NoError(t, err)
	assert.False(t, result)
}

// Both of these fail closed: the current code returns (false, nil) because the
// bare `err` it returns is nil at that point. These tests pin the deny outcome
// so that a future refactor cannot silently turn it into a grant.
func TestUserHasScopePermission_DeniedWhenResourceDoesNotExist(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{Id: 1}
	expectUserLoaded(mockDB, user, 1)
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "ghost").Return(nil, nil).Once()

	result, err := pc.UserHasScopePermission(1, "ghost:read")

	assert.NoError(t, err)
	assert.False(t, result, "an unknown resource must be denied")
}

func TestUserHasScopePermission_DeniedWhenPermissionIdentifierNotOnResource(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{Id: 1}
	expectUserLoaded(mockDB, user, 1)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(1, "backend-svc:delete")

	assert.NoError(t, err)
	assert.False(t, result, "a permission identifier not defined on the resource must be denied")
}

// Every database call in UserHasScopePermission must surface its error rather
// than being swallowed into a plain deny.
func TestUserHasScopePermission_DatabaseErrorsPropagate(t *testing.T) {
	dbErr := errors.New("database is down")
	user := &models.User{Id: 1}
	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}

	testCases := []struct {
		name  string
		setup func(mockDB *mocks_data.Database)
	}{
		{
			name: "GetUserById fails",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetUserById", mock.Anything, int64(1)).Return(nil, dbErr).Once()
			},
		},
		{
			name: "UserLoadPermissions fails",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetUserById", mock.Anything, int64(1)).Return(user, nil).Once()
				mockDB.On("UserLoadPermissions", mock.Anything, user).Return(dbErr).Once()
			},
		},
		{
			name: "UserLoadGroups fails",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetUserById", mock.Anything, int64(1)).Return(user, nil).Once()
				mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
				mockDB.On("UserLoadGroups", mock.Anything, user).Return(dbErr).Once()
			},
		},
		{
			name: "GroupsLoadPermissions fails",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetUserById", mock.Anything, int64(1)).Return(user, nil).Once()
				mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
				mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Once()
				mockDB.On("GroupsLoadPermissions", mock.Anything, mock.Anything).Return(dbErr).Once()
			},
		},
		{
			name: "GetResourceByResourceIdentifier fails",
			setup: func(mockDB *mocks_data.Database) {
				expectUserLoaded(mockDB, user, 1)
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(nil, dbErr).Once()
			},
		},
		{
			name: "GetPermissionsByResourceId fails",
			setup: func(mockDB *mocks_data.Database) {
				expectUserLoaded(mockDB, user, 1)
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(resource, nil).Once()
				mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(10)).Return(nil, dbErr).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			pc := NewPermissionChecker(mockDB)
			tc.setup(mockDB)

			result, err := pc.UserHasScopePermission(1, "backend-svc:read")

			assert.Error(t, err)
			assert.False(t, result, "an error must never produce a grant")
		})
	}
}

// =============================================================================
// Tests for FilterOutScopesWhereUserIsNotAuthorized
//
// This is what strips scopes a user is not entitled to before a token is
// issued. OIDC scopes and offline_access are intentionally exempt from the
// permission check; everything else must be verified.
// =============================================================================

func TestFilterOutScopes_NilUser(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized("backend-svc:read", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user is nil")
	assert.Equal(t, "", result)
}

// OIDC and offline_access scopes are returned without any database lookup.
// NewDatabase(t) asserts no unexpected calls, so this also proves no lookup happens.
func TestFilterOutScopes_OidcAndOfflineAccessBypassPermissionCheck(t *testing.T) {
	testCases := []struct {
		name  string
		scope string
		want  string
	}{
		{"openid", "openid", "openid"},
		{"profile", "profile", "profile"},
		{"email", "email", "email"},
		{"address", "address", "address"},
		{"phone", "phone", "phone"},
		{"groups", "groups", "groups"},
		{"attributes", "attributes", "attributes"},
		{"offline_access", "offline_access", "offline_access"},
		{"offline_access is matched case-insensitively", "OFFLINE_ACCESS", "OFFLINE_ACCESS"},
		{"all id token scopes together", "openid profile email", "openid profile email"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			pc := NewPermissionChecker(mockDB)

			result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(tc.scope, &models.User{Id: 1})

			assert.NoError(t, err)
			assert.Equal(t, tc.want, result)
		})
	}
}

func TestFilterOutScopes_EmptyScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized("", &models.User{Id: 1})

	assert.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestFilterOutScopes_KeepsAuthorizedStripsUnauthorized(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	// The user holds "read" (Id 5) but not "write" (Id 6).
	user := &models.User{
		Id:          1,
		Permissions: []models.Permission{{Id: 5, PermissionIdentifier: "read"}},
	}
	// Two resource scopes means UserHasScopePermission runs twice.
	expectUserLoaded(mockDB, user, 2)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(resource, nil).Times(2)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(10)).Return([]models.Permission{
		{Id: 5, PermissionIdentifier: "read"},
		{Id: 6, PermissionIdentifier: "write"},
	}, nil).Times(2)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized("backend-svc:read backend-svc:write", user)

	assert.NoError(t, err)
	assert.Equal(t, "backend-svc:read", result, "the unauthorized scope must be dropped")
}

func TestFilterOutScopes_PreservesOrderAndMixesOidcWithResourceScopes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{
		Id:          1,
		Permissions: []models.Permission{{Id: 5, PermissionIdentifier: "read"}},
	}
	expectUserLoaded(mockDB, user, 2)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "backend-svc").Return(resource, nil).Times(2)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(10)).Return([]models.Permission{
		{Id: 5, PermissionIdentifier: "read"},
		{Id: 6, PermissionIdentifier: "write"},
	}, nil).Times(2)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(
		"openid backend-svc:write profile backend-svc:read offline_access", user)

	assert.NoError(t, err)
	assert.Equal(t, "openid profile backend-svc:read offline_access", result)
}

// Extra whitespace produces empty elements, which are skipped. The result is
// also trimmed, so no leading or trailing space survives.
func TestFilterOutScopes_HandlesExtraWhitespace(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized("  openid   profile  ", &models.User{Id: 1})

	assert.NoError(t, err)
	assert.Equal(t, "openid profile", result)
}

// The filter does not deduplicate. Callers normalize upstream via
// AuthContext.SetScope, so this pins current behavior rather than asserting
// that duplicates are desirable.
func TestFilterOutScopes_DoesNotDeduplicate(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized("openid openid", &models.User{Id: 1})

	assert.NoError(t, err)
	assert.Equal(t, "openid openid", result)
}

func TestFilterOutScopes_MalformedScopeElementReturnsError(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized("openid not-a-valid-scope", &models.User{Id: 1})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scope format")
	assert.Equal(t, "", result, "a malformed element must not yield a partial scope string")
}

func TestFilterOutScopes_DatabaseErrorPropagates(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	mockDB.On("GetUserById", mock.Anything, int64(1)).Return(nil, errors.New("database is down")).Once()

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized("backend-svc:read", &models.User{Id: 1})

	assert.Error(t, err)
	assert.Equal(t, "", result)
}

// A user that exists as an argument but not in the database yields no scopes,
// rather than passing the resource scope through unchecked.
func TestFilterOutScopes_StripsEverythingWhenUserNotInDatabase(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	mockDB.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil).Once()

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized("backend-svc:read", &models.User{Id: 1})

	assert.NoError(t, err)
	assert.Equal(t, "", result)
}

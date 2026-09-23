package permissions

import (
	"context"
	"testing"

	"errors"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
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
	mockDB.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil).Times(times)
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Times(times)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Times(times)
	mockDB.On("GroupsLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(times)
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
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(context.Background(), 1, "backend-svc:read")

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
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(context.Background(), 1, "backend-svc:read")

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
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(context.Background(), 1, "backend-svc:read")

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
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(context.Background(), 1, "backend-svc:read")

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
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read", ResourceId: 10}}, nil).Once()

	result, err := pc.UserHasScopePermission(context.Background(), 1, "backend-svc:read")

	assert.NoError(t, err)
	assert.False(t, result, "holding the same permission identifier on a different resource must not grant access")
}

func TestUserHasScopePermission_UserNotFound(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(42)).Return(nil, nil).Once()

	result, err := pc.UserHasScopePermission(context.Background(), 42, "backend-svc:read")

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

			result, err := pc.UserHasScopePermission(context.Background(), 1, tc.scope)

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
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "").Return(nil, nil).Once()

	result, err := pc.UserHasScopePermission(context.Background(), 1, ":")

	assert.NoError(t, err)
	assert.False(t, result)
}

// Both of these fail closed with (false, nil). They used to reach that answer by
// accident, returning an `err` that happened to be nil at that point; ResolveScope
// now answers each as an outcome and the checker denies it by rule (#425). These
// tests pin the deny outcome so that a refactor cannot silently turn it into a grant.
func TestUserHasScopePermission_DeniedWhenResourceDoesNotExist(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{Id: 1}
	expectUserLoaded(mockDB, user, 1)
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "ghost").Return(nil, nil).Once()

	result, err := pc.UserHasScopePermission(context.Background(), 1, "ghost:read")

	assert.NoError(t, err)
	assert.False(t, result, "an unknown resource must be denied")
}

func TestUserHasScopePermission_DeniedWhenPermissionIdentifierNotOnResource(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{Id: 1}
	expectUserLoaded(mockDB, user, 1)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(
		[]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.UserHasScopePermission(context.Background(), 1, "backend-svc:delete")

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
				mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, dbErr).Once()
			},
		},
		{
			name: "UserLoadPermissions fails",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil).Once()
				mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(dbErr).Once()
			},
		},
		{
			name: "UserLoadGroups fails",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil).Once()
				mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
				mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(dbErr).Once()
			},
		},
		{
			name: "GroupsLoadPermissions fails",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil).Once()
				mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
				mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()
				mockDB.On("GroupsLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(dbErr).Once()
			},
		},
		{
			name: "GetResourceByResourceIdentifier fails",
			setup: func(mockDB *mocks_data.Database) {
				expectUserLoaded(mockDB, user, 1)
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(nil, dbErr).Once()
			},
		},
		{
			name: "GetPermissionsByResourceId fails",
			setup: func(mockDB *mocks_data.Database) {
				expectUserLoaded(mockDB, user, 1)
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
				mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(nil, dbErr).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			pc := NewPermissionChecker(mockDB)
			tc.setup(mockDB)

			result, err := pc.UserHasScopePermission(context.Background(), 1, "backend-svc:read")

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

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), "backend-svc:read", nil)

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
		{"all id token scopes together", "openid profile email", "openid profile email"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			pc := NewPermissionChecker(mockDB)

			result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), tc.scope, &models.User{Id: 1})

			assert.NoError(t, err)
			assert.Equal(t, tc.want, result)
		})
	}
}

func TestFilterOutScopes_EmptyScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), "", &models.User{Id: 1})

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
	// Two resource scopes resolve twice, but the user and their grants load once.
	expectUserLoaded(mockDB, user, 1)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Times(2)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return([]models.Permission{
		{Id: 5, PermissionIdentifier: "read"},
		{Id: 6, PermissionIdentifier: "write"},
	}, nil).Times(2)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), "backend-svc:read backend-svc:write", user)

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
	expectUserLoaded(mockDB, user, 1)

	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Times(2)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return([]models.Permission{
		{Id: 5, PermissionIdentifier: "read"},
		{Id: 6, PermissionIdentifier: "write"},
	}, nil).Times(2)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(),
		"openid backend-svc:write profile backend-svc:read offline_access", user)

	assert.NoError(t, err)
	assert.Equal(t, "openid profile backend-svc:read offline_access", result)
}

// Extra whitespace produces empty elements, which are skipped. The result is
// also trimmed, so no leading or trailing space survives.
func TestFilterOutScopes_HandlesExtraWhitespace(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), "  openid   profile  ", &models.User{Id: 1})

	assert.NoError(t, err)
	assert.Equal(t, "openid profile", result)
}

// The filter does not deduplicate. Callers normalize upstream via
// AuthContext.SetScope, so this pins current behavior rather than asserting
// that duplicates are desirable.
func TestFilterOutScopes_DoesNotDeduplicate(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), "openid openid", &models.User{Id: 1})

	assert.NoError(t, err)
	assert.Equal(t, "openid openid", result)
}

func TestFilterOutScopes_MalformedScopeElementReturnsError(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), "openid not-a-valid-scope", &models.User{Id: 1})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scope format")
	assert.Equal(t, "", result, "a malformed element must not yield a partial scope string")
}

// Every read the filter makes surfaces its error rather than being swallowed into
// a strip, and no partial scope string comes back with it.
func TestFilterOutScopes_DatabaseErrorPropagates(t *testing.T) {
	dbErr := errors.New("database is down")
	user := &models.User{Id: 1}
	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	stubResolved := func(mockDB *mocks_data.Database) {
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).
			Return([]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()
	}

	testCases := []struct {
		name  string
		setup func(mockDB *mocks_data.Database)
	}{
		{
			name: "GetResourceByResourceIdentifier fails",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(nil, dbErr).Once()
			},
		},
		{
			name: "GetPermissionsByResourceId fails",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
				mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(nil, dbErr).Once()
			},
		},
		{
			name: "GetUserById fails",
			setup: func(mockDB *mocks_data.Database) {
				stubResolved(mockDB)
				mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, dbErr).Once()
			},
		},
		{
			name: "UserLoadPermissions fails",
			setup: func(mockDB *mocks_data.Database) {
				stubResolved(mockDB)
				mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil).Once()
				mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(dbErr).Once()
			},
		},
		{
			name: "UserLoadGroups fails",
			setup: func(mockDB *mocks_data.Database) {
				stubResolved(mockDB)
				mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil).Once()
				mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
				mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(dbErr).Once()
			},
		},
		{
			name: "GroupsLoadPermissions fails",
			setup: func(mockDB *mocks_data.Database) {
				stubResolved(mockDB)
				mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil).Once()
				mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
				mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()
				mockDB.On("GroupsLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(dbErr).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			pc := NewPermissionChecker(mockDB)
			tc.setup(mockDB)

			result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), "openid backend-svc:read", &models.User{Id: 1})

			assert.ErrorIs(t, err, dbErr)
			assert.Equal(t, "", result)
		})
	}
}

// A user that exists as an argument but not in the database yields no resource
// scopes, rather than passing them through unchecked or on the strength of the
// caller's copy of the row. The row is read once however many scopes resolve.
func TestFilterOutScopes_StripsEveryResourceScopeWhenUserNotInDatabase(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").
		Return(&models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}, nil).Times(2)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return([]models.Permission{
		{Id: 5, PermissionIdentifier: "read"},
		{Id: 6, PermissionIdentifier: "write"},
	}, nil).Times(2)
	mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, nil).Once()

	// The caller's copy still claims both grants; only the database's answer counts.
	callersCopy := &models.User{Id: 1, Permissions: []models.Permission{{Id: 5}, {Id: 6}}}
	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(),
		"openid backend-svc:read backend-svc:write offline_access", callersCopy)

	assert.NoError(t, err)
	assert.Equal(t, "openid offline_access", result)
}

// The one-load property (#425): several resource scopes across two resources,
// with an unknown resource and an unknown permission among them, read the user and
// their grants exactly once. Each loader is registered .Once(), so a per-scope
// reload fails on the second call.
func TestFilterOutScopes_LoadsTheUserAndGrantsOnce(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	dbRow := &models.User{Id: 1}
	mockDB.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(dbRow, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, dbRow).Run(func(args mock.Arguments) {
		args.Get(2).(*models.User).Permissions = []models.Permission{{Id: 5}}
	}).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, dbRow).Run(func(args mock.Arguments) {
		args.Get(2).(*models.User).Groups = []models.Group{{Id: 7}}
	}).Return(nil).Once()
	mockDB.On("GroupsLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(2).([]models.Group)[0].Permissions = []models.Permission{{Id: 21}}
	}).Return(nil).Once()

	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").
		Return(&models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}, nil).Times(3)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return([]models.Permission{
		{Id: 5, PermissionIdentifier: "read"},
		{Id: 6, PermissionIdentifier: "write"},
	}, nil).Times(3)
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "billing-api").
		Return(&models.Resource{Id: 20, ResourceIdentifier: "billing-api"}, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(20)).Return([]models.Permission{
		{Id: 21, PermissionIdentifier: "read"},
	}, nil).Once()
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "ghost").Return(nil, nil).Once()

	// The caller's struct is never loaded onto: the grants land on the fresh row.
	callersCopy := &models.User{Id: 1}
	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(),
		"openid backend-svc:read ghost:read backend-svc:write billing-api:read backend-svc:delete", callersCopy)

	assert.NoError(t, err)
	assert.Equal(t, "openid backend-svc:read billing-api:read", result)
	assert.Empty(t, callersCopy.Permissions, "the caller's struct must not be mutated")
	assert.Empty(t, callersCopy.Groups, "the caller's struct must not be mutated")
	mockDB.AssertExpectations(t)
}

// A scope naming no resource, or no permission on one, is stripped on its own
// lookup: nothing reads the user when no scope resolves.
func TestFilterOutScopes_UnresolvedScopesNeverReadTheUser(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "ghost").Return(nil, nil).Once()
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").
		Return(&models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).
		Return([]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), "openid ghost:read backend-svc:delete", &models.User{Id: 1})

	assert.NoError(t, err)
	assert.Equal(t, "openid", result)
	mockDB.AssertNotCalled(t, "GetUserById", mock.Anything, mock.Anything, mock.Anything)
}

// RFC 6749 section 3.3 makes scope values case-sensitive, so OFFLINE_ACCESS is not
// offline_access and is not exempt: it is a bare word where a resource:permission
// scope belongs, answered as any other malformed element, with no read at all. It
// used to be case-folded through as offline access (#425).
func TestFilterOutScopes_UppercaseOfflineAccessIsNotExempt(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	result, err := pc.FilterOutScopesWhereUserIsNotAuthorized(context.Background(), "openid OFFLINE_ACCESS", &models.User{Id: 1})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scope format")
	assert.Equal(t, "", result)
}

// =============================================================================
// Tests for ResolveScope
//
// The one resolver the checker and both protocol validators share. The validators'
// own tests reach it through their rejection wording; these own its outcomes.
// =============================================================================

func TestResolveScope_Outcomes(t *testing.T) {
	resource := &models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}
	onResource := []models.Permission{
		{Id: 5, PermissionIdentifier: "read", ResourceId: 10},
		{Id: 6, PermissionIdentifier: "write", ResourceId: 10},
	}

	testCases := []struct {
		name          string
		scope         string
		setup         func(mockDB *mocks_data.Database)
		want          ScopeOutcome
		wantResource  string
		wantPerm      string
		wantPermRowId int64
	}{
		{name: "no separator", scope: "backendsvc", want: ScopeMalformed},
		{name: "two separators", scope: "backend-svc:read:extra", want: ScopeMalformed},
		{name: "empty", scope: "", want: ScopeMalformed},
		{
			name:  "unknown resource",
			scope: "ghost:read",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "ghost").Return(nil, nil).Once()
			},
			want: ScopeResourceUnknown, wantResource: "ghost", wantPerm: "read",
		},
		{
			name:  "unknown permission on a known resource",
			scope: "backend-svc:delete",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
				mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(onResource, nil).Once()
			},
			want: ScopePermissionUnknown, wantResource: "backend-svc", wantPerm: "delete",
		},
		{
			name:  "resolved carries the row",
			scope: "backend-svc:write",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(resource, nil).Once()
				mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(onResource, nil).Once()
			},
			want: ScopeOK, wantResource: "backend-svc", wantPerm: "write", wantPermRowId: 6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// A strict mock with no stubs is the proof that a malformed scope reads nothing.
			mockDB := mocks_data.NewDatabase(t)
			if tc.setup != nil {
				tc.setup(mockDB)
			}

			resolution, err := ResolveScope(context.Background(), mockDB, tc.scope)

			assert.NoError(t, err)
			assert.Equal(t, tc.want, resolution.Outcome)
			assert.Equal(t, tc.wantResource, resolution.ResourceIdentifier)
			assert.Equal(t, tc.wantPerm, resolution.PermissionIdentifier)
			if tc.want == ScopeOK {
				if assert.NotNil(t, resolution.Permission) {
					assert.Equal(t, tc.wantPermRowId, resolution.Permission.Id)
				}
			} else {
				assert.Nil(t, resolution.Permission)
			}
		})
	}
}

// IsResourceScope is the shape alone, exactly one ':', and it is the rule ResolveScope refuses by:
// every row the predicate rejects is also resolved against a strict mock with no stubs, and must
// come back ScopeMalformed without a read. The accepted shapes reaching the lookups are
// TestResolveScope_Outcomes' rows. The refresh arm relies on the two agreeing: a value this
// rejects is answered there as a scope this server does not issue, and one it accepts goes on to
// the permission check (#425).
func TestIsResourceScope(t *testing.T) {
	testCases := []struct {
		name  string
		scope string
		want  bool
	}{
		{name: "resource and permission", scope: "backend-svc:read", want: true},
		{name: "the built-in userinfo scope", scope: "authserver:userinfo", want: true},
		{name: "a resource scope containing the offline text", scope: "res:offline_access_read", want: true},
		{name: "separator only, two empty halves", scope: ":", want: true},
		{name: "uppercase offline access", scope: "OFFLINE_ACCESS", want: false},
		{name: "offline_access itself", scope: "offline_access", want: false},
		{name: "a claim scope", scope: "openid", want: false},
		{name: "two separators", scope: "backend-svc:read:extra", want: false},
		{name: "empty", scope: "", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsResourceScope(tc.scope))

			if tc.want {
				return
			}
			resolution, err := ResolveScope(context.Background(), mocks_data.NewDatabase(t), tc.scope)
			assert.NoError(t, err)
			assert.Equal(t, ScopeMalformed, resolution.Outcome)
		})
	}
}

// A database failure is an error and never an outcome: a caller reading only the
// outcome would otherwise deny a legitimate scope for the length of a fault.
func TestResolveScope_DatabaseErrorsPropagate(t *testing.T) {
	dbErr := errors.New("database is down")

	t.Run("resource lookup", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").Return(nil, dbErr).Once()

		_, err := ResolveScope(context.Background(), mockDB, "backend-svc:read")

		assert.ErrorIs(t, err, dbErr)
	})

	t.Run("permission lookup", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").
			Return(&models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}, nil).Once()
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).Return(nil, dbErr).Once()

		_, err := ResolveScope(context.Background(), mockDB, "backend-svc:read")

		assert.ErrorIs(t, err, dbErr)
	})
}

// TestUserHasScopePermission_CarriesTheCallersContextToEveryRead is the cascade half of #386's
// seam 4. The checker holds no request and takes one context, so the only thing to establish is
// that it hands THAT context to each of its reads rather than manufacturing one; a handler above
// it has already been shown to supply the request's own.
//
// The sentinel is a value on the context, not a request id, because nothing here has a request.
// A read that received context.Background() matches nothing and the strict mock reports an
// unexpected call, which is how this fails for its stated reason.
func TestUserHasScopePermission_CarriesTheCallersContextToEveryRead(t *testing.T) {
	type marker struct{}
	ctx := context.WithValue(context.Background(), marker{}, "the caller's own")
	callersContext := mock.MatchedBy(func(got context.Context) bool {
		return got.Value(marker{}) == "the caller's own"
	})

	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{Id: 1, Permissions: []models.Permission{{Id: 5, PermissionIdentifier: "read"}}}
	mockDB.On("GetUserById", callersContext, mock.Anything, user.Id).Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", callersContext, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", callersContext, mock.Anything, user).Return(nil).Once()
	mockDB.On("GroupsLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").
		Return(&models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).
		Return([]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	granted, err := pc.UserHasScopePermission(ctx, 1, "backend-svc:read")

	assert.NoError(t, err)
	assert.True(t, granted)
	mockDB.AssertExpectations(t)
}

// The scope filter reaches the database through the resolver and its one grant load, so the
// context it was given has to survive both hops as well. An OIDC scope is answered without any read
// at all, which is the reject arm: nothing to carry, nothing to get wrong.
func TestFilterOutScopesWhereUserIsNotAuthorized_CarriesTheCallersContextAndSkipsOidcScopes(t *testing.T) {
	type marker struct{}
	ctx := context.WithValue(context.Background(), marker{}, "the caller's own")
	callersContext := mock.MatchedBy(func(got context.Context) bool {
		return got.Value(marker{}) == "the caller's own"
	})

	mockDB := mocks_data.NewDatabase(t)
	pc := NewPermissionChecker(mockDB)

	user := &models.User{Id: 1, Permissions: []models.Permission{{Id: 5, PermissionIdentifier: "read"}}}
	mockDB.On("GetUserById", callersContext, mock.Anything, user.Id).Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", callersContext, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", callersContext, mock.Anything, user).Return(nil).Once()
	mockDB.On("GroupsLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend-svc").
		Return(&models.Resource{Id: 10, ResourceIdentifier: "backend-svc"}, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).
		Return([]models.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Once()

	filtered, err := pc.FilterOutScopesWhereUserIsNotAuthorized(ctx, "openid backend-svc:read", user)

	assert.NoError(t, err)
	assert.Equal(t, "openid backend-svc:read", filtered)
	mockDB.AssertExpectations(t)
}

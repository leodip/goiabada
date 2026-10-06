package permissions

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
)

// The six administrative scopes, written out rather than read from the set, so a scope added to it
// or dropped from it fails here (#402 decision 2, #499 decision 2).
var administrativeScopes = []string{
	"authserver:manage",
	"authserver:admin-read",
	"authserver:manage-users",
	"authserver:manage-clients",
	"authserver:manage-settings",
	"authserver:browser-sessions",
}

func TestIsAdministrativeScope_TheSixOnTheAuthServerResource(t *testing.T) {
	for _, scope := range administrativeScopes {
		assert.True(t, IsAdministrativeScope(scope), scope)
	}
}

func TestIsAdministrativeScope_NothingElse(t *testing.T) {
	for _, scope := range []string{
		"authserver:manage-account",
		"authserver:custom-report",
		"other:manage",
		"other:admin-read",
		"manage",
		"authserver",
		"authserver:",
		":manage",
		"Authserver:manage",
		"authserver:Manage",
		"authserver:manage ",
		" authserver:manage",
		"authserver:manage authserver:admin-read",
		"authserver:manage:x",
		"openid",
		"",
	} {
		assert.False(t, IsAdministrativeScope(scope), "%q", scope)
	}
}

// Every administrative scope names a built-in authserver permission, so the set cannot name a row
// the seed never writes.
func TestIsAdministrativeScope_EveryOneIsBuiltIn(t *testing.T) {
	builtIn := builtin.AuthServerPermissionIdentifiers()
	count := 0
	for _, identifier := range builtIn {
		if IsAdministrativeScope(builtin.AuthServerResourceIdentifier + ":" + identifier) {
			count++
		}
	}
	assert.Equal(t, len(administrativeScopes), count)
}

// authServerRows is the authserver resource's permissions as the seed writes them, plus a custom
// one an operator added, each at an id unrelated to its position.
func authServerRows() []record.Permission {
	return []record.Permission{
		{Id: 41, PermissionIdentifier: "manage-account", ResourceId: 3},
		{Id: 42, PermissionIdentifier: "manage", ResourceId: 3},
		{Id: 43, PermissionIdentifier: "admin-read", ResourceId: 3},
		{Id: 44, PermissionIdentifier: "manage-users", ResourceId: 3},
		{Id: 45, PermissionIdentifier: "manage-clients", ResourceId: 3},
		{Id: 46, PermissionIdentifier: "manage-settings", ResourceId: 3},
		{Id: 47, PermissionIdentifier: "browser-sessions", ResourceId: 3},
		{Id: 48, PermissionIdentifier: "custom-report", ResourceId: 3},
	}
}

func TestAdministrativePermissions_MapsEachAdministrativeRowToItsScope(t *testing.T) {
	database := datamocks.NewDatabase(t)
	tx := &sql.Tx{}
	database.On("GetResourceByResourceIdentifier", mock.Anything, tx, "authserver").
		Return(&record.Resource{Id: 3, ResourceIdentifier: "authserver"}, nil).Once()
	database.On("GetPermissionsByResourceId", mock.Anything, tx, int64(3)).Return(authServerRows(), nil).Once()

	administrative, err := AdministrativePermissions(context.Background(), database, tx)

	require.NoError(t, err)
	assert.Equal(t, map[int64]string{
		42: "authserver:manage",
		43: "authserver:admin-read",
		44: "authserver:manage-users",
		45: "authserver:manage-clients",
		46: "authserver:manage-settings",
		47: "authserver:browser-sessions",
	}, administrative)
}

// A nil transaction reads outside any, as every caller outside a transaction passes.
func TestAdministrativePermissions_ReadsOutsideAnyTransactionOnNil(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "authserver").
		Return(&record.Resource{Id: 3, ResourceIdentifier: "authserver"}, nil).Once()
	database.On("GetPermissionsByResourceId", mock.Anything, (*sql.Tx)(nil), int64(3)).
		Return(slices.Clone(authServerRows()[:2]), nil).Once()

	administrative, err := AdministrativePermissions(context.Background(), database, nil)

	require.NoError(t, err)
	assert.Equal(t, map[int64]string{42: "authserver:manage"}, administrative)
}

func TestAdministrativePermissions_AMissingResourceIsAnError(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "authserver").Return(nil, nil).Once()

	administrative, err := AdministrativePermissions(context.Background(), database, nil)

	require.Error(t, err)
	assert.Nil(t, administrative)
}

func TestAdministrativePermissions_ReadFailuresAreErrors(t *testing.T) {
	t.Run("resource", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		cause := errors.New("resource read failed")
		database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "authserver").Return(nil, cause).Once()

		administrative, err := AdministrativePermissions(context.Background(), database, nil)

		require.ErrorIs(t, err, cause)
		assert.Nil(t, administrative)
	})
	t.Run("permissions", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		cause := errors.New("permissions read failed")
		database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "authserver").
			Return(&record.Resource{Id: 3, ResourceIdentifier: "authserver"}, nil).Once()
		database.On("GetPermissionsByResourceId", mock.Anything, (*sql.Tx)(nil), int64(3)).Return(nil, cause).Once()

		administrative, err := AdministrativePermissions(context.Background(), database, nil)

		require.ErrorIs(t, err, cause)
		assert.Nil(t, administrative)
	})
}

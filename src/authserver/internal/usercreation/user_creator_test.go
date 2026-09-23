package usercreation

import (
	"context"
	"database/sql"
	"testing"

	"errors"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// These tests own UserCreator.CreateUser at the unit tier: the user row and its account
// permission land in one transaction opened through RunInTransaction, the permission insert
// names the id the user insert assigned, a failed insert hands its error to the helper and
// inserts no permission, and a missing account permission is refused before any transaction
// opens. What reaches the tables on a real engine is the registration and admin-create
// integration paths' to show.

// txSentinel is the transaction the shared stub hands the body. It is non-nil and the mock
// database never dereferences it, which is the whole of what it has to be: an expectation
// written against txSentinel matches a call the body made and no call made before or after the
// transaction, where the creator passes nil. A nil here -- which is what the BeginTransaction stubs
// it replaced handed over, and what this package's own copy of the stub handed over until #198
// -- makes those two indistinguishable, so a sweep moved back outside the transaction would
// pass on call count alone. mocks_data.ExpectRunInTransaction now refuses a nil outright, so
// what was this package's convention is the shared stub's rule (#422).
var txSentinel = &sql.Tx{}

const accountPermissionId = int64(31)

// expectAccountPermissionLookup registers the two reads that precede the transaction: the
// authserver resource and its permissions.
func expectAccountPermissionLookup(db *mocks_data.Database, permissions []models.Permission) {
	db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, constants.AuthServerResourceIdentifier).
		Return(&models.Resource{Id: 3}, nil).Once()
	db.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(3)).Return(permissions, nil).Once()
}

func accountPermissions() []models.Permission {
	return []models.Permission{
		{Id: 30, PermissionIdentifier: constants.ManageAccountPermissionIdentifier + "-lookalike"},
		{Id: accountPermissionId, PermissionIdentifier: constants.ManageAccountPermissionIdentifier},
	}
}

func TestUserCreator_CreateUser_WritesTheUserAndItsAccountPermissionInOneTransaction(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	expectAccountPermissionLookup(db, accountPermissions())

	var calls []string
	stub := mocks_data.ExpectRunInTransaction(db, txSentinel)
	db.On("CreateUser", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(2).(*models.User)
		created.Id = 77 // stand in for the generated primary key
		calls = append(calls, "user row")
	}).Return(nil).Once()
	db.On("CreateUserPermission", mock.Anything, mock.Anything, mock.MatchedBy(func(up *models.UserPermission) bool {
		return up.UserId == 77 && up.PermissionId == accountPermissionId
	})).Run(func(mock.Arguments) { calls = append(calls, "permission row") }).Return(nil).Once()

	user, err := NewUserCreator(db).CreateUser(context.Background(), &CreateUserInput{
		Email:         "ada@example.com",
		EmailVerified: true,
		PasswordHash:  "hash",
		GivenName:     "Ada",
		FamilyName:    "Lovelace",
	})
	require.NoError(t, err)
	require.NotNil(t, user)

	assert.Equal(t, []string{"user row", "permission row"}, calls,
		"the permission insert follows the user insert, inside the same transaction, and names the id it assigned")
	assert.NoError(t, stub.BodyErr, "the body asked the helper to commit")
	assert.Equal(t, int64(77), user.Id)
	assert.True(t, user.Enabled)
	assert.Equal(t, "ada@example.com", user.Email)
	assert.True(t, user.EmailVerified)
	assert.Equal(t, "hash", user.PasswordHash)
	assert.Equal(t, "Ada", user.GivenName)
	assert.Equal(t, "Lovelace", user.FamilyName)
	assert.NotEmpty(t, user.Subject)
	require.Len(t, user.Permissions, 1)
	assert.Equal(t, accountPermissionId, user.Permissions[0].Id)
}

func TestUserCreator_CreateUser_AFailedUserInsertReachesTheHelperAndWritesNoPermission(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	expectAccountPermissionLookup(db, accountPermissions())

	boom := errors.New("the engine refused the insert")
	stub := mocks_data.ExpectRunInTransaction(db, txSentinel)
	db.On("CreateUser", mock.Anything, mock.Anything, mock.Anything).Return(boom).Once()

	user, err := NewUserCreator(db).CreateUser(context.Background(), &CreateUserInput{Email: "ada@example.com"})

	require.ErrorIs(t, err, boom)
	assert.Nil(t, user, "no user is returned alongside an error")
	assert.ErrorIs(t, stub.BodyErr, boom, "the body handed the failure to the helper, which rolls back")
	db.AssertNotCalled(t, "CreateUserPermission", mock.Anything, mock.Anything, mock.Anything)
}

func TestUserCreator_CreateUser_ATransactionThatCannotOpenIsReported(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	expectAccountPermissionLookup(db, accountPermissions())

	boom := errors.New("cannot begin")
	mocks_data.ExpectRunInTransactionRefused(db, boom)

	user, err := NewUserCreator(db).CreateUser(context.Background(), &CreateUserInput{Email: "ada@example.com"})

	require.ErrorIs(t, err, boom)
	assert.Nil(t, user)
	db.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything, mock.Anything)
}

func TestUserCreator_CreateUser_RefusesWithoutTheAccountPermissionBeforeAnyTransaction(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	expectAccountPermissionLookup(db, []models.Permission{
		{Id: 30, PermissionIdentifier: "something-else"},
	})

	user, err := NewUserCreator(db).CreateUser(context.Background(), &CreateUserInput{Email: "ada@example.com"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to find the account permission")
	assert.Nil(t, user)
	db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// A lookup answers (nil, nil) for a row that is not there. The creator used to read the id off
// that nil and panic; it refuses instead, naming the resource, before any other read and before
// any transaction opens (#425).
func TestUserCreator_CreateUser_RefusesWhenTheAuthServerResourceIsMissing(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, constants.AuthServerResourceIdentifier).
		Return(nil, nil).Once()

	user, err := NewUserCreator(db).CreateUser(context.Background(), &CreateUserInput{Email: "ada@example.com"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to find the "+constants.AuthServerResourceIdentifier+" resource")
	assert.Nil(t, user)
	db.AssertNotCalled(t, "GetPermissionsByResourceId", mock.Anything, mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// TestUserCreator_CreateUser_TheBodyIsSafeToRerun is the property RunInTransaction relies on: a
// second run of the body, as after a deadlock, inserts the user again and names the id THAT
// insert assigned, not the one the rolled-back attempt left on the model.
func TestUserCreator_CreateUser_TheBodyIsSafeToRerun(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	expectAccountPermissionLookup(db, accountPermissions())

	// A stub that runs the body twice, as the helper does after a deadlock on the first attempt.
	// The shared stub in mocks_data runs the body once, so this one stays local; it hands over
	// txSentinel for the same reason the shared one refuses a nil.
	db.EXPECT().RunInTransaction(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error {
		if err := fn(txSentinel); err != nil {
			return err
		}
		return fn(txSentinel)
	}).Once()

	ids := []int64{77, 78}
	var permissionUserIds []int64
	db.On("CreateUser", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(2).(*models.User).Id = ids[0]
		ids = ids[1:]
	}).Return(nil).Twice()
	db.On("CreateUserPermission", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		permissionUserIds = append(permissionUserIds, args.Get(2).(*models.UserPermission).UserId)
	}).Return(nil).Twice()

	user, err := NewUserCreator(db).CreateUser(context.Background(), &CreateUserInput{Email: "ada@example.com"})
	require.NoError(t, err)

	assert.Equal(t, []int64{77, 78}, permissionUserIds,
		"each attempt's permission row names the id that attempt's user insert assigned")
	assert.Equal(t, int64(78), user.Id, "the caller sees the id of the attempt that committed")
}

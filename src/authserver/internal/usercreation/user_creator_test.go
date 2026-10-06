package usercreation

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"errors"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// These tests own Creator.CreateUser at the unit tier: the user row and its account
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
// pass on call count alone. datamocks.ExpectRunInTransaction now refuses a nil outright, so
// what was this package's convention is the shared stub's rule (#422).
var txSentinel = &sql.Tx{}

const accountPermissionId = int64(31)

// expectAccountPermissionLookup registers the two reads that precede the transaction: the
// authserver resource and its permissions.
func expectAccountPermissionLookup(db *datamocks.Database, permissions []record.Permission) {
	db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, builtin.AuthServerResourceIdentifier).
		Return(&record.Resource{Id: 3}, nil).Once()
	db.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(3)).Return(permissions, nil).Once()
}

func accountPermissions() []record.Permission {
	return []record.Permission{
		{Id: 30, PermissionIdentifier: builtin.ManageAccountPermissionIdentifier + "-lookalike"},
		{Id: accountPermissionId, PermissionIdentifier: builtin.ManageAccountPermissionIdentifier},
	}
}

func TestCreator_CreateUser_WritesTheUserAndItsAccountPermissionInOneTransaction(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectAccountPermissionLookup(db, accountPermissions())

	var calls []string
	stub := datamocks.ExpectRunInTransaction(db, txSentinel)
	db.On("CreateUser", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(2).(*record.User)
		created.Id = 77 // stand in for the generated primary key
		calls = append(calls, "user row")
	}).Return(nil).Once()
	db.On("CreateUserPermission", mock.Anything, mock.Anything, mock.MatchedBy(func(up *record.UserPermission) bool {
		return up.UserId == 77 && up.PermissionId == accountPermissionId
	})).Run(func(mock.Arguments) { calls = append(calls, "permission row") }).Return(nil).Once()

	user, err := New(db).CreateUser(context.Background(), &Input{
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

func TestCreator_CreateUser_AFailedUserInsertReachesTheHelperAndWritesNoPermission(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectAccountPermissionLookup(db, accountPermissions())

	boom := errors.New("the engine refused the insert")
	stub := datamocks.ExpectRunInTransaction(db, txSentinel)
	db.On("CreateUser", mock.Anything, mock.Anything, mock.Anything).Return(boom).Once()

	user, err := New(db).CreateUser(context.Background(), &Input{Email: "ada@example.com"})

	require.ErrorIs(t, err, boom)
	assert.Nil(t, user, "no user is returned alongside an error")
	assert.ErrorIs(t, stub.BodyErr, boom, "the body handed the failure to the helper, which rolls back")
	db.AssertNotCalled(t, "CreateUserPermission", mock.Anything, mock.Anything, mock.Anything)
}

func TestCreator_CreateUser_ATransactionThatCannotOpenIsReported(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectAccountPermissionLookup(db, accountPermissions())

	boom := errors.New("cannot begin")
	datamocks.ExpectRunInTransactionRefused(db, boom)

	user, err := New(db).CreateUser(context.Background(), &Input{Email: "ada@example.com"})

	require.ErrorIs(t, err, boom)
	assert.Nil(t, user)
	db.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything, mock.Anything)
}

func TestCreator_CreateUser_RefusesWithoutTheAccountPermissionBeforeAnyTransaction(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectAccountPermissionLookup(db, []record.Permission{
		{Id: 30, PermissionIdentifier: "something-else"},
	})

	user, err := New(db).CreateUser(context.Background(), &Input{Email: "ada@example.com"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to find the account permission")
	assert.Nil(t, user)
	db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// A lookup answers (nil, nil) for a row that is not there. The creator used to read the id off
// that nil and panic; it refuses instead, naming the resource, before any other read and before
// any transaction opens (#425).
func TestCreator_CreateUser_RefusesWhenTheAuthServerResourceIsMissing(t *testing.T) {
	db := datamocks.NewDatabase(t)
	db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, builtin.AuthServerResourceIdentifier).
		Return(nil, nil).Once()

	user, err := New(db).CreateUser(context.Background(), &Input{Email: "ada@example.com"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to find the "+builtin.AuthServerResourceIdentifier+" resource")
	assert.Nil(t, user)
	db.AssertNotCalled(t, "GetPermissionsByResourceId", mock.Anything, mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// TestCreator_CreateUser_TheBodyIsSafeToRerun is the property RunInTransaction relies on: a
// second run of the body, as after a deadlock, inserts the user again and names the id THAT
// insert assigned, not the one the rolled-back attempt left on the model.
func TestCreator_CreateUser_TheBodyIsSafeToRerun(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectAccountPermissionLookup(db, accountPermissions())

	// A stub that runs the body twice, as the helper does after a deadlock on the first attempt.
	// The shared stub in datamocks runs the body once, so this one stays local; it hands over
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
		args.Get(2).(*record.User).Id = ids[0]
		ids = ids[1:]
	}).Return(nil).Twice()
	db.On("CreateUserPermission", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		permissionUserIds = append(permissionUserIds, args.Get(2).(*record.UserPermission).UserId)
	}).Return(nil).Twice()

	user, err := New(db).CreateUser(context.Background(), &Input{Email: "ada@example.com"})
	require.NoError(t, err)

	assert.Equal(t, []int64{77, 78}, permissionUserIds,
		"each attempt's permission row names the id that attempt's user insert assigned")
	assert.Equal(t, int64(78), user.Id, "the caller sees the id of the attempt that committed")
}

// CreateUserInTransaction is for a caller that writes other rows beside the account and must
// commit them together (activation, #207): every read and both inserts run on the caller's
// transaction, and it opens none of its own, which would commit the account alone.
func TestCreator_CreateUserInTransaction_RunsEverythingOnTheCallersTransaction(t *testing.T) {
	db := datamocks.NewDatabase(t)
	db.On("GetResourceByResourceIdentifier", mock.Anything, txSentinel, builtin.AuthServerResourceIdentifier).
		Return(&record.Resource{Id: 3}, nil).Once()
	db.On("GetPermissionsByResourceId", mock.Anything, txSentinel, int64(3)).Return(accountPermissions(), nil).Once()

	var calls []string
	db.On("CreateUser", mock.Anything, txSentinel, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(2).(*record.User).Id = 77
		calls = append(calls, "user row")
	}).Return(nil).Once()
	db.On("CreateUserPermission", mock.Anything, txSentinel, mock.MatchedBy(func(up *record.UserPermission) bool {
		return up.UserId == 77 && up.PermissionId == accountPermissionId
	})).Run(func(mock.Arguments) { calls = append(calls, "permission row") }).Return(nil).Once()

	user, err := New(db).CreateUserInTransaction(context.Background(), txSentinel, &Input{
		Email:         "ada@example.com",
		EmailVerified: true,
		PasswordHash:  "hash",
	})
	require.NoError(t, err)
	require.NotNil(t, user)

	assert.Equal(t, []string{"user row", "permission row"}, calls)
	assert.Equal(t, int64(77), user.Id)
	assert.True(t, user.Enabled)
	assert.True(t, user.EmailVerified)
	assert.Equal(t, "hash", user.PasswordHash)
	require.Len(t, user.Permissions, 1)
	assert.Equal(t, accountPermissionId, user.Permissions[0].Id)
	db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// A failed insert is the caller's to roll back, so it is returned as it is and nothing after it
// is written.
func TestCreator_CreateUserInTransaction_AFailedUserInsertIsReturnedAndWritesNoPermission(t *testing.T) {
	db := datamocks.NewDatabase(t)
	db.On("GetResourceByResourceIdentifier", mock.Anything, txSentinel, builtin.AuthServerResourceIdentifier).
		Return(&record.Resource{Id: 3}, nil).Once()
	db.On("GetPermissionsByResourceId", mock.Anything, txSentinel, int64(3)).Return(accountPermissions(), nil).Once()

	boom := errors.New("the engine refused the insert")
	db.On("CreateUser", mock.Anything, txSentinel, mock.Anything).Return(boom).Once()

	user, err := New(db).CreateUserInTransaction(context.Background(), txSentinel, &Input{Email: "ada@example.com"})

	require.ErrorIs(t, err, boom)
	assert.Nil(t, user)
	db.AssertNotCalled(t, "CreateUserPermission", mock.Anything, mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// A nil transaction would make every write commit on its own, which is the one thing a caller
// choosing this method is avoiding, so it is refused before anything is read or written.
func TestCreator_CreateUserInTransaction_RefusesANilTransaction(t *testing.T) {
	db := datamocks.NewDatabase(t)

	user, err := New(db).CreateUserInTransaction(context.Background(), nil, &Input{Email: "ada@example.com"})

	require.Error(t, err)
	assert.Nil(t, user)
	db.AssertNotCalled(t, "GetResourceByResourceIdentifier", mock.Anything, mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// A user the administrator creates with a set-password email is inserted already holding the code
// that answers the emailed link, so no write after the insert stores it (#471 decision 4).
func TestCreator_CreateUser_InsertsTheResetCodeTheInputCarries(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectAccountPermissionLookup(db, accountPermissions())

	issuedAt := time.Date(2026, 10, 6, 12, 30, 0, 0, time.UTC)
	var inserted record.User
	datamocks.ExpectRunInTransaction(db, txSentinel)
	db.On("CreateUser", mock.Anything, txSentinel, mock.Anything).Run(func(args mock.Arguments) {
		inserted = *args.Get(2).(*record.User)
	}).Return(nil).Once()
	db.On("CreateUserPermission", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()

	user, err := New(db).CreateUser(context.Background(), &Input{
		Email:                       "ada@example.com",
		ForgotPasswordCodeEncrypted: []byte("ciphertext"),
		ForgotPasswordCodeHash:      "the-code-hash",
		ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: issuedAt, Valid: true},
	})
	require.NoError(t, err)

	assert.Equal(t, []byte("ciphertext"), inserted.ForgotPasswordCodeEncrypted)
	assert.Equal(t, "the-code-hash", inserted.ForgotPasswordCodeHash)
	assert.Equal(t, sql.NullTime{Time: issuedAt, Valid: true}, inserted.ForgotPasswordCodeIssuedAt)
	assert.Equal(t, "the-code-hash", user.ForgotPasswordCodeHash, "the returned user is the row inserted")
}

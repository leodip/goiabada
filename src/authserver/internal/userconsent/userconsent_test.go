package userconsent

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	consentUserId   = int64(7)
	consentClientId = int64(3)
)

// consentTx is the transaction the shared stub hands the body. It is non-nil, and every statement is
// matched on it rather than on mock.Anything, so a read or a write moved back outside the
// transaction fails the test that names it.
var consentTx = &sql.Tx{}

func TestRecord_CreatesAConsentWhenNoneIsStored(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	stub := mocks_data.ExpectRunInTransaction(db, consentTx)
	db.On("GetConsentByUserIdAndClientId", mock.Anything, consentTx, consentUserId, consentClientId).Return(nil, nil).Once()

	var created *models.UserConsent
	db.On("CreateUserConsent", mock.Anything, consentTx, mock.Anything).
		Run(func(args mock.Arguments) {
			created = args.Get(2).(*models.UserConsent)
			created.Id = 11
		}).
		Return(nil).Once()

	before := time.Now().UTC()
	consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid profile")
	require.NoError(t, err)
	require.NoError(t, stub.BodyErr)

	assert.Same(t, created, consent, "the row returned is the row written")
	assert.Equal(t, int64(11), consent.Id)
	assert.Equal(t, consentUserId, consent.UserId)
	assert.Equal(t, consentClientId, consent.ClientId)
	assert.Equal(t, "openid profile", consent.Scope)
	require.True(t, consent.GrantedAt.Valid, "a new consent records when it was granted")
	assert.False(t, consent.GrantedAt.Time.Before(before))
	assert.Equal(t, time.UTC, consent.GrantedAt.Time.Location())
	db.AssertNotCalled(t, "UpdateUserConsent", mock.Anything, mock.Anything, mock.Anything)
}

// A save replaces the stored scope whole, and it is the save's time that the row records: the
// account's consents page shows GrantedAt, and a consent the user submitted again is a consent
// granted again (#115). The scope the row had is gone, which is what unticking a scope means.
func TestRecord_ReplacesAStoredConsentWholeAndRefreshesItsDate(t *testing.T) {
	grantedAt := sql.NullTime{Time: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), Valid: true}
	stored := &models.UserConsent{
		Id: 5, UserId: consentUserId, ClientId: consentClientId, Scope: "openid profile email", GrantedAt: grantedAt,
	}
	db := mocks_data.NewDatabase(t)
	stub := mocks_data.ExpectRunInTransaction(db, consentTx)
	db.On("GetConsentByUserIdAndClientId", mock.Anything, consentTx, consentUserId, consentClientId).Return(stored, nil).Once()
	db.On("UpdateUserConsent", mock.Anything, consentTx, stored).Return(nil).Once()

	before := time.Now().UTC()
	consent, err := Record(context.Background(), db, consentUserId, consentClientId, "email")
	require.NoError(t, err)
	require.NoError(t, stub.BodyErr)

	assert.Same(t, stored, consent)
	assert.Equal(t, int64(5), consent.Id, "the stored row is rewritten, not a second one created")
	assert.Equal(t, "email", consent.Scope, "the scope is replaced, not appended to")
	require.True(t, consent.GrantedAt.Valid)
	assert.False(t, consent.GrantedAt.Time.Before(before), "a rewrite records this save's time, not the first grant's")
	assert.True(t, consent.GrantedAt.Time.After(grantedAt.Time))
	assert.Equal(t, time.UTC, consent.GrantedAt.Time.Location())
	db.AssertNotCalled(t, "CreateUserConsent", mock.Anything, mock.Anything, mock.Anything)
}

// Two first saves for one pair can both read no consent, and the second insert then loses on the key,
// which on PostgreSQL aborts its transaction. The save runs once more, and the second attempt reads
// the row the winner committed and rewrites it, so the last writer's scope is the one that stays
// (#249). What is returned is the attempt that committed.
func TestRecord_ASaveThatLosesTheKeyRunsOnceMoreAndRewritesTheWinnersRow(t *testing.T) {
	lostTheKey := errs.Errorf("%w: another save created the consent first", data.ErrUniqueViolation)

	db := mocks_data.NewDatabase(t)
	first := mocks_data.ExpectRunInTransaction(db, consentTx)
	second := mocks_data.ExpectRunInTransaction(db, consentTx)
	winners := &models.UserConsent{Id: 5, UserId: consentUserId, ClientId: consentClientId, Scope: "openid"}
	db.On("GetConsentByUserIdAndClientId", mock.Anything, consentTx, consentUserId, consentClientId).Return(nil, nil).Once()
	db.On("GetConsentByUserIdAndClientId", mock.Anything, consentTx, consentUserId, consentClientId).Return(winners, nil).Once()
	db.On("CreateUserConsent", mock.Anything, consentTx, mock.Anything).Return(lostTheKey).Once()
	db.On("UpdateUserConsent", mock.Anything, consentTx, winners).Return(nil).Once()

	consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid email")

	require.NoError(t, err, "a loser on the key is rerun, and the rerun finds the row")
	assert.ErrorIs(t, first.BodyErr, data.ErrUniqueViolation, "the first attempt rolled back")
	assert.NoError(t, second.BodyErr)
	assert.Same(t, winners, consent, "the row returned is the one the committed attempt rewrote")
	assert.Equal(t, "openid email", consent.Scope, "the rerun's scope, which is the last writer's")
	db.AssertExpectations(t)
	db.AssertNumberOfCalls(t, "CreateUserConsent", 1)
}

// The retry is bounded at two attempts: a third collision would mean a writer that keeps creating
// the row this one keeps failing to read, which is a fault and not a race.
func TestRecord_ASecondLossIsAFaultAndIsNotRetriedAgain(t *testing.T) {
	lostTheKey := errs.Errorf("%w: another save created the consent first", data.ErrUniqueViolation)

	db := mocks_data.NewDatabase(t)
	mocks_data.ExpectRunInTransaction(db, consentTx)
	mocks_data.ExpectRunInTransaction(db, consentTx)
	db.On("GetConsentByUserIdAndClientId", mock.Anything, consentTx, consentUserId, consentClientId).Return(nil, nil).Twice()
	db.On("CreateUserConsent", mock.Anything, consentTx, mock.Anything).Return(lostTheKey).Twice()

	consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid")

	assert.ErrorIs(t, err, data.ErrUniqueViolation)
	assert.Nil(t, consent)
	db.AssertExpectations(t)
}

func TestRecord_Failures(t *testing.T) {
	boom := errors.New("boom")

	t.Run("the read failing writes nothing", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		stub := mocks_data.ExpectRunInTransaction(db, consentTx)
		db.On("GetConsentByUserIdAndClientId", mock.Anything, consentTx, consentUserId, consentClientId).Return(nil, boom).Once()

		consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid")
		assert.ErrorIs(t, err, boom)
		assert.ErrorIs(t, stub.BodyErr, boom, "the transaction rolled back")
		assert.Nil(t, consent)
		db.AssertNotCalled(t, "CreateUserConsent", mock.Anything, mock.Anything, mock.Anything)
		db.AssertNotCalled(t, "UpdateUserConsent", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("the create failing returns no row and is not retried", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		stub := mocks_data.ExpectRunInTransaction(db, consentTx)
		db.On("GetConsentByUserIdAndClientId", mock.Anything, consentTx, consentUserId, consentClientId).Return(nil, nil).Once()
		db.On("CreateUserConsent", mock.Anything, consentTx, mock.Anything).Return(boom).Once()

		consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid")
		assert.ErrorIs(t, err, boom)
		assert.ErrorIs(t, stub.BodyErr, boom)
		assert.Nil(t, consent)
	})

	t.Run("the update failing returns no row and is not retried", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		stub := mocks_data.ExpectRunInTransaction(db, consentTx)
		db.On("GetConsentByUserIdAndClientId", mock.Anything, consentTx, consentUserId, consentClientId).
			Return(&models.UserConsent{Id: 5, UserId: consentUserId, ClientId: consentClientId}, nil).Once()
		db.On("UpdateUserConsent", mock.Anything, consentTx, mock.Anything).Return(boom).Once()

		consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid")
		assert.ErrorIs(t, err, boom)
		assert.ErrorIs(t, stub.BodyErr, boom)
		assert.Nil(t, consent)
	})

	t.Run("a commit the engine refuses returns no row, though the body ran to the end", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		mocks_data.ExpectRunInTransactionThenFail(db, consentTx, boom)
		db.On("GetConsentByUserIdAndClientId", mock.Anything, consentTx, consentUserId, consentClientId).Return(nil, nil).Once()
		db.On("CreateUserConsent", mock.Anything, consentTx, mock.Anything).Return(nil).Once()

		consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid")
		assert.ErrorIs(t, err, boom)
		assert.Nil(t, consent, "a consent that was not committed is not reported as saved")
	})

	t.Run("a transaction that cannot open writes nothing", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		mocks_data.ExpectRunInTransactionRefused(db, boom)

		consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid")
		assert.ErrorIs(t, err, boom)
		assert.Nil(t, consent)
		db.AssertNotCalled(t, "GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

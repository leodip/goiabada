package oauth

import (
	"database/sql"
	"errors"
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// These tests own seam 1 at the unit tier: the order of Rotate's statements, the guard
// refusing before any write, both compare-and-set refusals, and that a failure at any step
// commits nothing. They observe the rotator through mocks_data.Database, so what they can
// see is which calls were made, with which arguments, in which order, and that nothing was
// committed. What they cannot see is whether the resulting SQL composes against a real
// engine, which is signing_key_rotator_test.go at the data tier, on all four.
//
// mocks_data.NewDatabase(t) fails the test on any call that was not set up, so "the delete
// never ran" is asserted by the absence of an expectation as much as by AssertNotCalled.

// rotatorTx is an opaque non-nil transaction. The rotator only ever hands it back to the
// database, so its contents are irrelevant and its identity is the whole point: every call
// below asserts it was passed this exact transaction rather than nil.
var rotatorTx = &sql.Tx{}

// newTestRotator builds a rotator at the smallest key size crypto/rsa will still generate.
// The replacement key is generated on every path now, including every refusal, so at 4096
// each of the cases below would pay about 300ms for material most of them never store.
func newTestRotator(database *mocks_data.Database) *SigningKeyRotator {
	rotator := NewSigningKeyRotator(database)
	rotator.keySizeBits = 1024
	return rotator
}

func keyPairInState(id int64, state string) models.KeyPair {
	return models.KeyPair{
		Id:            id,
		State:         state,
		KeyIdentifier: "kid-" + state,
		Type:          "RSA",
		Algorithm:     "RS256",
	}
}

// fullKeySet is the ordinary starting point: one key in each state.
func fullKeySet() []models.KeyPair {
	return []models.KeyPair{
		keyPairInState(1, enums.KeyStateCurrent.String()),
		keyPairInState(2, enums.KeyStateNext.String()),
		keyPairInState(3, enums.KeyStatePrevious.String()),
	}
}

func TestSigningKeyRotator_Rotate_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	var calls []string
	record := func(name string) func(mock.Arguments) {
		return func(mock.Arguments) { calls = append(calls, name) }
	}

	database.On("BeginTransaction").Return(rotatorTx, nil).Once().
		Run(record("BeginTransaction"))
	database.On("GetAllSigningKeys", rotatorTx).Return(fullKeySet(), nil).Once().
		Run(record("GetAllSigningKeys"))
	database.On("DeleteKeyPair", rotatorTx, int64(3)).Return(nil).Once().
		Run(record("DeleteKeyPair"))
	database.On("UpdateKeyPairState", rotatorTx, int64(1),
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).
		Return(true, nil).Once().Run(record("demote"))
	database.On("UpdateKeyPairState", rotatorTx, int64(2),
		enums.KeyStateNext.String(), enums.KeyStateCurrent.String()).
		Return(true, nil).Once().Run(record("promote"))

	var created *models.KeyPair
	database.On("CreateKeyPair", rotatorTx, mock.Anything).Return(nil).Once().
		Run(func(args mock.Arguments) {
			calls = append(calls, "CreateKeyPair")
			created = args.Get(1).(*models.KeyPair)
		})
	database.On("CommitTransaction", rotatorTx).Return(nil).Once().
		Run(record("CommitTransaction"))
	database.On("RollbackTransaction", rotatorTx).Return(nil).Maybe()

	err := newTestRotator(database).Rotate()
	require.NoError(t, err)

	// The delete precedes the demotion, which the unique index on key_pairs (state)
	// requires: demoting while the old previous row is still there is two previous rows
	// within one statement. The rest of the order is decision 1's.
	assert.Equal(t, []string{
		"BeginTransaction",
		"GetAllSigningKeys",
		"DeleteKeyPair",
		"demote",
		"promote",
		"CreateKeyPair",
		"CommitTransaction",
	}, calls)

	require.NotNil(t, created)
	assert.Equal(t, enums.KeyStateNext.String(), created.State)
	assert.Equal(t, "RSA", created.Type)
	assert.Equal(t, "RS256", created.Algorithm)
	assert.NotEmpty(t, created.KeyIdentifier)
	assert.NotEmpty(t, created.PrivateKeyPEM)
	assert.NotEmpty(t, created.PublicKeyPEM)
	assert.NotEmpty(t, created.PublicKeyASN1_DER)
	assert.NotEmpty(t, created.PublicKeyJWK)
	// The private key is stored encrypted (#83), so the PEM header must not survive.
	assert.NotContains(t, string(created.PrivateKeyPEM), "PRIVATE KEY")
}

// TestSigningKeyRotator_Rotate_SucceedsWithNoPreviousKey covers the first rotation after
// seeding, where there is nothing to delete.
func TestSigningKeyRotator_Rotate_SucceedsWithNoPreviousKey(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("BeginTransaction").Return(rotatorTx, nil).Once()
	database.On("GetAllSigningKeys", rotatorTx).Return([]models.KeyPair{
		keyPairInState(1, enums.KeyStateCurrent.String()),
		keyPairInState(2, enums.KeyStateNext.String()),
	}, nil).Once()
	database.On("UpdateKeyPairState", rotatorTx, int64(1),
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).Return(true, nil).Once()
	database.On("UpdateKeyPairState", rotatorTx, int64(2),
		enums.KeyStateNext.String(), enums.KeyStateCurrent.String()).Return(true, nil).Once()
	database.On("CreateKeyPair", rotatorTx, mock.Anything).Return(nil).Once()
	database.On("CommitTransaction", rotatorTx).Return(nil).Once()
	database.On("RollbackTransaction", rotatorTx).Return(nil).Maybe()

	require.NoError(t, newTestRotator(database).Rotate())
	database.AssertNotCalled(t, "DeleteKeyPair", mock.Anything, mock.Anything)
}

// TestSigningKeyRotator_Rotate_GuardRefusesBeforeAnyWrite is the defect this change exists
// to fix. The guard used to run after the delete, so a deployment with no next key lost the
// key that signs its live tokens and was then refused anyway (#251).
func TestSigningKeyRotator_Rotate_GuardRefusesBeforeAnyWrite(t *testing.T) {
	testCases := []struct {
		name string
		keys []models.KeyPair
	}{
		{
			name: "no next key",
			keys: []models.KeyPair{
				keyPairInState(1, enums.KeyStateCurrent.String()),
				keyPairInState(3, enums.KeyStatePrevious.String()),
			},
		},
		{
			name: "no current key",
			keys: []models.KeyPair{
				keyPairInState(2, enums.KeyStateNext.String()),
				keyPairInState(3, enums.KeyStatePrevious.String()),
			},
		},
		{
			name: "no keys at all",
			keys: []models.KeyPair{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			database.On("BeginTransaction").Return(rotatorTx, nil).Once()
			database.On("GetAllSigningKeys", rotatorTx).Return(tc.keys, nil).Once()
			database.On("RollbackTransaction", rotatorTx).Return(nil).Once()

			err := newTestRotator(database).Rotate()

			assert.ErrorIs(t, err, ErrKeySetIncomplete)
			// The previous key survives the refusal. This is the assertion the old
			// handler could not have made.
			database.AssertNotCalled(t, "DeleteKeyPair", mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "UpdateKeyPairState",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "CreateKeyPair", mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
		})
	}
}

// TestSigningKeyRotator_Rotate_LosesTheDemotion is the losing rotation: it read a snapshot
// another rotation has already acted on, so its compare-and-set transitions nothing. The
// delete it has already issued rolls back with it, which is the property the whole
// transaction exists for.
func TestSigningKeyRotator_Rotate_LosesTheDemotion(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("BeginTransaction").Return(rotatorTx, nil).Once()
	database.On("GetAllSigningKeys", rotatorTx).Return(fullKeySet(), nil).Once()
	database.On("DeleteKeyPair", rotatorTx, int64(3)).Return(nil).Once()
	database.On("UpdateKeyPairState", rotatorTx, int64(1),
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).
		Return(false, nil).Once()
	database.On("RollbackTransaction", rotatorTx).Return(nil).Once()

	err := newTestRotator(database).Rotate()

	assert.ErrorIs(t, err, ErrRotationInProgress)
	// A false compare-and-set is not an error, so the promotion must not have been
	// attempted and nothing may commit.
	database.AssertNotCalled(t, "UpdateKeyPairState", rotatorTx, int64(2),
		enums.KeyStateNext.String(), enums.KeyStateCurrent.String())
	database.AssertNotCalled(t, "CreateKeyPair", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
}

// TestSigningKeyRotator_Rotate_LosesThePromotion is the same refusal one statement later:
// another rotation promoted the next key between this one's read and its own write.
func TestSigningKeyRotator_Rotate_LosesThePromotion(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("BeginTransaction").Return(rotatorTx, nil).Once()
	database.On("GetAllSigningKeys", rotatorTx).Return(fullKeySet(), nil).Once()
	database.On("DeleteKeyPair", rotatorTx, int64(3)).Return(nil).Once()
	database.On("UpdateKeyPairState", rotatorTx, int64(1),
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).
		Return(true, nil).Once()
	database.On("UpdateKeyPairState", rotatorTx, int64(2),
		enums.KeyStateNext.String(), enums.KeyStateCurrent.String()).
		Return(false, nil).Once()
	database.On("RollbackTransaction", rotatorTx).Return(nil).Once()

	err := newTestRotator(database).Rotate()

	assert.ErrorIs(t, err, ErrRotationInProgress)
	database.AssertNotCalled(t, "CreateKeyPair", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
}

// TestSigningKeyRotator_Rotate_RollsBackOnFailureAtEveryStep injects a failure at each
// database call in turn and asserts nothing commits. On postgres a failed statement aborts
// the whole transaction and every later command in it is refused with SQLSTATE 25P02
// (decision 4), which is why each of these must return at once rather than carry on.
func TestSigningKeyRotator_Rotate_RollsBackOnFailureAtEveryStep(t *testing.T) {
	failure := errors.New("engine failure")

	testCases := []struct {
		name  string
		setUp func(database *mocks_data.Database)
	}{
		{
			name: "GetAllSigningKeys",
			setUp: func(database *mocks_data.Database) {
				database.On("GetAllSigningKeys", rotatorTx).
					Return([]models.KeyPair(nil), failure).Once()
			},
		},
		{
			name: "DeleteKeyPair",
			setUp: func(database *mocks_data.Database) {
				database.On("GetAllSigningKeys", rotatorTx).Return(fullKeySet(), nil).Once()
				database.On("DeleteKeyPair", rotatorTx, int64(3)).Return(failure).Once()
			},
		},
		{
			name: "UpdateKeyPairState demote",
			setUp: func(database *mocks_data.Database) {
				database.On("GetAllSigningKeys", rotatorTx).Return(fullKeySet(), nil).Once()
				database.On("DeleteKeyPair", rotatorTx, int64(3)).Return(nil).Once()
				database.On("UpdateKeyPairState", rotatorTx, int64(1),
					enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).
					Return(false, failure).Once()
			},
		},
		{
			name: "UpdateKeyPairState promote",
			setUp: func(database *mocks_data.Database) {
				database.On("GetAllSigningKeys", rotatorTx).Return(fullKeySet(), nil).Once()
				database.On("DeleteKeyPair", rotatorTx, int64(3)).Return(nil).Once()
				database.On("UpdateKeyPairState", rotatorTx, int64(1),
					enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).
					Return(true, nil).Once()
				database.On("UpdateKeyPairState", rotatorTx, int64(2),
					enums.KeyStateNext.String(), enums.KeyStateCurrent.String()).
					Return(false, failure).Once()
			},
		},
		{
			name: "CreateKeyPair",
			setUp: func(database *mocks_data.Database) {
				database.On("GetAllSigningKeys", rotatorTx).Return(fullKeySet(), nil).Once()
				database.On("DeleteKeyPair", rotatorTx, int64(3)).Return(nil).Once()
				database.On("UpdateKeyPairState", rotatorTx, int64(1),
					enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).
					Return(true, nil).Once()
				database.On("UpdateKeyPairState", rotatorTx, int64(2),
					enums.KeyStateNext.String(), enums.KeyStateCurrent.String()).
					Return(true, nil).Once()
				database.On("CreateKeyPair", rotatorTx, mock.Anything).Return(failure).Once()
			},
		},
		{
			name: "unparseable key state",
			setUp: func(database *mocks_data.Database) {
				database.On("GetAllSigningKeys", rotatorTx).Return([]models.KeyPair{
					keyPairInState(1, "not-a-state"),
				}, nil).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			database.On("BeginTransaction").Return(rotatorTx, nil).Once()
			tc.setUp(database)
			database.On("RollbackTransaction", rotatorTx).Return(nil).Once()

			err := newTestRotator(database).Rotate()

			require.Error(t, err)
			// A genuine failure is neither refusal: the handler maps anything that is
			// not a sentinel to a 500, and reporting a race that did not happen would
			// tell an operator to stop retrying for the wrong reason.
			assert.NotErrorIs(t, err, ErrRotationInProgress)
			assert.NotErrorIs(t, err, ErrKeySetIncomplete)
			database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
		})
	}
}

// TestSigningKeyRotator_Rotate_CommitFailureIsReported closes the last step. There is
// nothing to roll back that the deferred rollback will not handle, but the error must
// still reach the caller rather than reporting a rotation that did not land.
func TestSigningKeyRotator_Rotate_CommitFailureIsReported(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	failure := errors.New("commit failed")

	database.On("BeginTransaction").Return(rotatorTx, nil).Once()
	database.On("GetAllSigningKeys", rotatorTx).Return(fullKeySet(), nil).Once()
	database.On("DeleteKeyPair", rotatorTx, int64(3)).Return(nil).Once()
	database.On("UpdateKeyPairState", rotatorTx, int64(1),
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).Return(true, nil).Once()
	database.On("UpdateKeyPairState", rotatorTx, int64(2),
		enums.KeyStateNext.String(), enums.KeyStateCurrent.String()).Return(true, nil).Once()
	database.On("CreateKeyPair", rotatorTx, mock.Anything).Return(nil).Once()
	database.On("CommitTransaction", rotatorTx).Return(failure).Once()
	database.On("RollbackTransaction", rotatorTx).Return(nil).Once()

	assert.ErrorIs(t, newTestRotator(database).Rotate(), failure)
}

// TestSigningKeyRotator_Rotate_BeginTransactionFailureIsReported also pins that the key
// material is generated before the transaction opens: nothing else is called.
func TestSigningKeyRotator_Rotate_BeginTransactionFailureIsReported(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	failure := errors.New("cannot begin")

	database.On("BeginTransaction").Return((*sql.Tx)(nil), failure).Once()

	assert.ErrorIs(t, newTestRotator(database).Rotate(), failure)
	database.AssertNotCalled(t, "RollbackTransaction", mock.Anything)
	database.AssertNotCalled(t, "GetAllSigningKeys", mock.Anything)
}

// TestSigningKeyRotator_Rotate_GeneratesTheKeyBeforeOpeningTheTransaction is the only
// direct observation of §4C's first ordering rule. A key size crypto/rsa refuses makes the
// generation fail, and BeginTransaction is then never reached: move the generation inside
// the transaction and this test sees a transaction opened for a rotation that could never
// have written anything. The rule exists because a 4096-bit generation is the slow step by
// three orders of magnitude, and holding a transaction open across it is what made the
// window wide enough to hit (#251).
func TestSigningKeyRotator_Rotate_GeneratesTheKeyBeforeOpeningTheTransaction(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	rotator := NewSigningKeyRotator(database)
	rotator.keySizeBits = 512 // crypto/rsa refuses anything under 1024

	err := rotator.Rotate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to generate a private key")
	database.AssertNotCalled(t, "BeginTransaction")
}

// TestNewSigningKeyRotator_UsesFourThousandNinetySixBits pins the production key size,
// which no exported surface carries. The tests above all lower it, so without this nothing
// would notice it changing.
func TestNewSigningKeyRotator_UsesFourThousandNinetySixBits(t *testing.T) {
	assert.Equal(t, 4096, NewSigningKeyRotator(mocks_data.NewDatabase(t)).keySizeBits)
}

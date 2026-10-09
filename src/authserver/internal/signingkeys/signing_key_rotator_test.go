package signingkeys

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/uuid/uuidtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// These tests own seam 1 at the unit tier: the order of Rotate's statements, the guard
// refusing before any write, both compare-and-set refusals, and that a failure at any step
// commits nothing. They observe the rotator through datamocks.Database, so what they can
// see is which calls were made, with which arguments, in which order, and that nothing was
// committed. What they cannot see is whether the resulting SQL composes against a real
// engine, which is signing_key_rotator_test.go at the data tier, on all four.
//
// datamocks.NewDatabase(t) fails the test on any call that was not set up, so "the delete
// never ran" is asserted by the absence of an expectation as much as by AssertNotCalled.

// rotatorTx is an opaque non-nil transaction. The rotator only ever hands it back to the
// database, so its contents are irrelevant and its identity is the whole point: every call
// below asserts it was passed this exact transaction rather than nil.
var rotatorTx = &sql.Tx{}

// newTestRotator builds a rotator at the smallest key size crypto/rsa will still generate.
// The replacement key is generated on every path now, including every refusal, so at 4096
// each of the cases below would pay about 300ms for material most of them never store.
func newTestRotator(database *datamocks.Database) *Rotator {
	rotator := NewRotator(database, testDataCipher)
	rotator.keySizeBits = 1024
	return rotator
}

func keyPairInState(id int64, state string) record.KeyPair {
	return record.KeyPair{
		Id:            id,
		State:         state,
		KeyIdentifier: "kid-" + state,
		Type:          "RSA",
		Algorithm:     "RS256",
	}
}

// fullKeySet is the ordinary starting point: one key in each state.
func fullKeySet() []record.KeyPair {
	return []record.KeyPair{
		keyPairInState(1, record.KeyStateCurrent.String()),
		keyPairInState(2, record.KeyStateNext.String()),
		keyPairInState(3, record.KeyStatePrevious.String()),
	}
}

func TestRotator_Rotate_Success(t *testing.T) {
	database := datamocks.NewDatabase(t)

	var calls []string
	recordCall := func(name string) func(mock.Arguments) {
		return func(mock.Arguments) { calls = append(calls, name) }
	}

	stub := datamocks.ExpectRunInTransaction(database, rotatorTx)
	database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return(fullKeySet(), nil).Once().
		Run(recordCall("GetAllSigningKeys"))
	database.On("DeleteKeyPair", mock.Anything, rotatorTx, int64(3)).Return(nil).Once().
		Run(recordCall("DeleteKeyPair"))
	database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(1),
		record.KeyStateCurrent.String(), record.KeyStatePrevious.String()).
		Return(true, nil).Once().Run(recordCall("demote"))
	database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(2),
		record.KeyStateNext.String(), record.KeyStateCurrent.String()).
		Return(true, nil).Once().Run(recordCall("promote"))

	var created *record.KeyPair
	database.On("CreateKeyPair", mock.Anything, rotatorTx, mock.Anything).Return(nil).Once().
		Run(func(args mock.Arguments) {
			calls = append(calls, "CreateKeyPair")
			created = args.Get(2).(*record.KeyPair)
		})

	err := newTestRotator(database).Rotate(context.Background())
	require.NoError(t, err)

	// The delete precedes the demotion, which the unique index on key_pairs (state)
	// requires: demoting while the old previous row is still there is two previous rows
	// within one statement. The rest of the order is decision 1's. The body returned nil
	// to the helper, which is the commit.
	assert.Equal(t, []string{
		"GetAllSigningKeys",
		"DeleteKeyPair",
		"demote",
		"promote",
		"CreateKeyPair",
	}, calls)
	require.NoError(t, stub.BodyErr)

	require.NotNil(t, created)
	assert.Equal(t, record.KeyStateNext.String(), created.State)
	assert.Equal(t, "RSA", created.Type)
	assert.Equal(t, "RS256", created.Algorithm)
	// The kid is a canonical v4 the generator produced, not merely a non-empty string: it is
	// published in the JWKS and every token header names it, so a malformed or duplicated one
	// would make a signed token unverifiable (#278).
	parsedKid, err := uuidtest.Parse(created.KeyIdentifier)
	require.NoError(t, err)
	assert.Equal(t, created.KeyIdentifier, parsedKid)
	assert.NotEmpty(t, created.PrivateKeyPEM)
	// The replacement key comes from NewKeyPair, so it carries RFC 7468's label (#424).
	assert.True(t, strings.HasPrefix(string(created.PublicKeyPEM), "-----BEGIN PUBLIC KEY-----\n"),
		"the replacement key's public PEM is not labelled PUBLIC KEY")
	assert.NotEmpty(t, created.PublicKeyASN1_DER)
	assert.NotEmpty(t, created.PublicKeyJWK)
	// The private key is stored encrypted (#83), so the PEM header must not survive, and it is
	// sealed under the cipher the rotator was built with, so that cipher opens it (#434).
	assert.NotContains(t, string(created.PrivateKeyPEM), "PRIVATE KEY")
	_, err = ParsePrivateKey(testDataCipher, created)
	assert.NoError(t, err, "the replacement key does not open under the rotator's cipher")
}

// TestRotator_Rotate_SucceedsWithNoPreviousKey covers the first rotation after
// seeding, where there is nothing to delete.
func TestRotator_Rotate_SucceedsWithNoPreviousKey(t *testing.T) {
	database := datamocks.NewDatabase(t)

	datamocks.ExpectRunInTransaction(database, rotatorTx)
	database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return([]record.KeyPair{
		keyPairInState(1, record.KeyStateCurrent.String()),
		keyPairInState(2, record.KeyStateNext.String()),
	}, nil).Once()
	database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(1),
		record.KeyStateCurrent.String(), record.KeyStatePrevious.String()).Return(true, nil).Once()
	database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(2),
		record.KeyStateNext.String(), record.KeyStateCurrent.String()).Return(true, nil).Once()
	database.On("CreateKeyPair", mock.Anything, rotatorTx, mock.Anything).Return(nil).Once()

	require.NoError(t, newTestRotator(database).Rotate(context.Background()))
	database.AssertNotCalled(t, "DeleteKeyPair", mock.Anything, mock.Anything, mock.Anything)
}

// TestRotator_Rotate_GuardRefusesBeforeAnyWrite is the defect this change exists
// to fix. The guard used to run after the delete, so a deployment with no next key lost the
// key that signs its live tokens and was then refused anyway (#251).
func TestRotator_Rotate_GuardRefusesBeforeAnyWrite(t *testing.T) {
	testCases := []struct {
		name string
		keys []record.KeyPair
	}{
		{
			name: "no next key",
			keys: []record.KeyPair{
				keyPairInState(1, record.KeyStateCurrent.String()),
				keyPairInState(3, record.KeyStatePrevious.String()),
			},
		},
		{
			name: "no current key",
			keys: []record.KeyPair{
				keyPairInState(2, record.KeyStateNext.String()),
				keyPairInState(3, record.KeyStatePrevious.String()),
			},
		},
		{
			name: "no keys at all",
			keys: []record.KeyPair{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			stub := datamocks.ExpectRunInTransaction(database, rotatorTx)
			database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return(tc.keys, nil).Once()

			err := newTestRotator(database).Rotate(context.Background())

			require.ErrorIs(t, err, ErrKeySetIncomplete)
			require.ErrorIs(t, stub.BodyErr, ErrKeySetIncomplete, "the refusal reaches the helper, which rolls back")
			// The previous key survives the refusal. This is the assertion the old
			// handler could not have made.
			database.AssertNotCalled(t, "DeleteKeyPair", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "UpdateKeyPairState", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "CreateKeyPair", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestRotator_Rotate_LosesTheDemotion is the losing rotation: it read a snapshot
// another rotation has already acted on, so its compare-and-set transitions nothing. The
// delete it has already issued rolls back with it, which is the property the whole
// transaction exists for.
func TestRotator_Rotate_LosesTheDemotion(t *testing.T) {
	database := datamocks.NewDatabase(t)

	stub := datamocks.ExpectRunInTransaction(database, rotatorTx)
	database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return(fullKeySet(), nil).Once()
	database.On("DeleteKeyPair", mock.Anything, rotatorTx, int64(3)).Return(nil).Once()
	database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(1),
		record.KeyStateCurrent.String(), record.KeyStatePrevious.String()).
		Return(false, nil).Once()

	err := newTestRotator(database).Rotate(context.Background())

	require.ErrorIs(t, err, ErrRotationInProgress)
	// A false compare-and-set is not an error, so the promotion must not have been
	// attempted and nothing may commit: the body hands the refusal to the helper, which
	// rolls the delete back with it.
	database.AssertNotCalled(t, "UpdateKeyPairState", mock.Anything, rotatorTx, int64(2),
		record.KeyStateNext.String(), record.KeyStateCurrent.String())
	database.AssertNotCalled(t, "CreateKeyPair", mock.Anything, mock.Anything, mock.Anything)
	assert.ErrorIs(t, stub.BodyErr, ErrRotationInProgress)
}

// TestRotator_Rotate_LosesThePromotion is the same refusal one statement later:
// another rotation promoted the next key between this one's read and its own write.
func TestRotator_Rotate_LosesThePromotion(t *testing.T) {
	database := datamocks.NewDatabase(t)

	stub := datamocks.ExpectRunInTransaction(database, rotatorTx)
	database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return(fullKeySet(), nil).Once()
	database.On("DeleteKeyPair", mock.Anything, rotatorTx, int64(3)).Return(nil).Once()
	database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(1),
		record.KeyStateCurrent.String(), record.KeyStatePrevious.String()).
		Return(true, nil).Once()
	database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(2),
		record.KeyStateNext.String(), record.KeyStateCurrent.String()).
		Return(false, nil).Once()

	err := newTestRotator(database).Rotate(context.Background())

	require.ErrorIs(t, err, ErrRotationInProgress)
	database.AssertNotCalled(t, "CreateKeyPair", mock.Anything, mock.Anything, mock.Anything)
	assert.ErrorIs(t, stub.BodyErr, ErrRotationInProgress)
}

// TestRotator_Rotate_RollsBackOnFailureAtEveryStep injects a failure at each
// database call in turn and asserts nothing commits. On postgres a failed statement aborts
// the whole transaction and every later command in it is refused with SQLSTATE 25P02
// (decision 4), which is why each of these must return at once rather than carry on.
func TestRotator_Rotate_RollsBackOnFailureAtEveryStep(t *testing.T) {
	failure := errors.New("engine failure")

	testCases := []struct {
		name  string
		setUp func(database *datamocks.Database)
	}{
		{
			name: "GetAllSigningKeys",
			setUp: func(database *datamocks.Database) {
				database.On("GetAllSigningKeys", mock.Anything, rotatorTx).
					Return([]record.KeyPair(nil), failure).Once()
			},
		},
		{
			name: "DeleteKeyPair",
			setUp: func(database *datamocks.Database) {
				database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return(fullKeySet(), nil).Once()
				database.On("DeleteKeyPair", mock.Anything, rotatorTx, int64(3)).Return(failure).Once()
			},
		},
		{
			name: "UpdateKeyPairState demote",
			setUp: func(database *datamocks.Database) {
				database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return(fullKeySet(), nil).Once()
				database.On("DeleteKeyPair", mock.Anything, rotatorTx, int64(3)).Return(nil).Once()
				database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(1),
					record.KeyStateCurrent.String(), record.KeyStatePrevious.String()).
					Return(false, failure).Once()
			},
		},
		{
			name: "UpdateKeyPairState promote",
			setUp: func(database *datamocks.Database) {
				database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return(fullKeySet(), nil).Once()
				database.On("DeleteKeyPair", mock.Anything, rotatorTx, int64(3)).Return(nil).Once()
				database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(1),
					record.KeyStateCurrent.String(), record.KeyStatePrevious.String()).
					Return(true, nil).Once()
				database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(2),
					record.KeyStateNext.String(), record.KeyStateCurrent.String()).
					Return(false, failure).Once()
			},
		},
		{
			name: "CreateKeyPair",
			setUp: func(database *datamocks.Database) {
				database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return(fullKeySet(), nil).Once()
				database.On("DeleteKeyPair", mock.Anything, rotatorTx, int64(3)).Return(nil).Once()
				database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(1),
					record.KeyStateCurrent.String(), record.KeyStatePrevious.String()).
					Return(true, nil).Once()
				database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(2),
					record.KeyStateNext.String(), record.KeyStateCurrent.String()).
					Return(true, nil).Once()
				database.On("CreateKeyPair", mock.Anything, rotatorTx, mock.Anything).Return(failure).Once()
			},
		},
		{
			name: "unparseable key state",
			setUp: func(database *datamocks.Database) {
				database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return([]record.KeyPair{
					keyPairInState(1, "not-a-state"),
				}, nil).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			stub := datamocks.ExpectRunInTransaction(database, rotatorTx)
			tc.setUp(database)

			err := newTestRotator(database).Rotate(context.Background())

			require.Error(t, err)
			// A genuine failure is neither refusal: the handler maps anything that is
			// not a sentinel to a 500, and reporting a race that did not happen would
			// tell an operator to stop retrying for the wrong reason.
			require.NotErrorIs(t, err, ErrRotationInProgress)
			require.NotErrorIs(t, err, ErrKeySetIncomplete)
			// The failure reached the helper from the body, so the helper rolled back.
			require.Error(t, stub.BodyErr)
			assert.Equal(t, err, stub.BodyErr, "the body's error is returned to the caller unchanged")
		})
	}
}

// TestRotator_Rotate_CommitFailureIsReported closes the last step. There is
// nothing to roll back that the deferred rollback will not handle, but the error must
// still reach the caller rather than reporting a rotation that did not land.
func TestRotator_Rotate_CommitFailureIsReported(t *testing.T) {
	database := datamocks.NewDatabase(t)
	failure := errors.New("commit failed")

	datamocks.ExpectRunInTransactionThenFail(database, rotatorTx, failure)
	database.On("GetAllSigningKeys", mock.Anything, rotatorTx).Return(fullKeySet(), nil).Once()
	database.On("DeleteKeyPair", mock.Anything, rotatorTx, int64(3)).Return(nil).Once()
	database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(1),
		record.KeyStateCurrent.String(), record.KeyStatePrevious.String()).Return(true, nil).Once()
	database.On("UpdateKeyPairState", mock.Anything, rotatorTx, int64(2),
		record.KeyStateNext.String(), record.KeyStateCurrent.String()).Return(true, nil).Once()
	database.On("CreateKeyPair", mock.Anything, rotatorTx, mock.Anything).Return(nil).Once()

	assert.ErrorIs(t, newTestRotator(database).Rotate(context.Background()), failure)
}

// TestRotator_Rotate_ATransactionThatCannotOpenIsReported is the helper failing
// before the body runs. It also pins that the key material is generated before the
// transaction opens: nothing else is called.
func TestRotator_Rotate_ATransactionThatCannotOpenIsReported(t *testing.T) {
	database := datamocks.NewDatabase(t)
	failure := errors.New("cannot begin")

	datamocks.ExpectRunInTransactionRefused(database, failure)

	require.ErrorIs(t, newTestRotator(database).Rotate(context.Background()), failure)
	database.AssertNotCalled(t, "GetAllSigningKeys", mock.Anything, mock.Anything)
}

// TestRotator_Rotate_GeneratesTheKeyBeforeOpeningTheTransaction is the only
// direct observation of §4C's first ordering rule. A key size crypto/rsa refuses makes the
// generation fail, and RunInTransaction is then never reached: move the generation inside
// the transaction and this test sees a transaction opened for a rotation that could never
// have written anything. The rule exists because a 4096-bit generation is the slow step by
// three orders of magnitude, and holding a transaction open across it is what made the
// window wide enough to hit (#251).
func TestRotator_Rotate_GeneratesTheKeyBeforeOpeningTheTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)

	rotator := NewRotator(database, testDataCipher)
	rotator.keySizeBits = 512 // crypto/rsa refuses anything under 1024

	err := rotator.Rotate(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to generate a private key")
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// TestNewRotator_UsesFourThousandNinetySixBits pins the production key size,
// which no exported surface carries. The tests above all lower it, so without this nothing
// would notice it changing.
func TestNewRotator_UsesFourThousandNinetySixBits(t *testing.T) {
	assert.Equal(t, 4096, NewRotator(datamocks.NewDatabase(t), testDataCipher).keySizeBits)
}

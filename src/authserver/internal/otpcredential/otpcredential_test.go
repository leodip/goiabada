package otpcredential

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// otpTx is an opaque non-nil transaction, the handle the stub hands the body. The mocks never
// dereference it; it only has to be the same pointer every write inside the transaction carries,
// so a write that slipped back to the pool would arrive with a nil tx and fail as an unexpected
// call.
var otpTx = &sql.Tx{}

const (
	otpUserId = int64(42)
	// A real base32 TOTP seed, so otp.MatchStep does its actual HMAC rather than short-circuiting
	// on an unparseable secret.
	otpSeed = "JBSWY3DPEHPK3PXP"
)

// enrollableUser is a user part way through enrolling: no authenticator yet.
func enrollableUser() *models.User {
	return &models.User{Id: otpUserId, Enabled: true}
}

// enrolledUser is a user with otpSeed already established, which is the state VerifyStored reads.
func enrolledUser(t *testing.T) *models.User {
	t.Helper()

	u := &models.User{Id: otpUserId, Enabled: true, OTPEnabled: true}
	require.NoError(t, setSecret(u, otpSeed))
	return u
}

// codeFor returns a passcode the given seed produces at now, which is what a user reads off their
// authenticator app.
func codeFor(t *testing.T, seed string, now time.Time) string {
	t.Helper()

	code, err := totp.GenerateCode(seed, now)
	require.NoError(t, err)
	return code
}

// Seam 2, the establish half. The user write, the generation advance and the pending clear are one
// transaction, in that order, and the generation the caller gets is the committing attempt's
// read-back rather than anything computed here (#242 decision 2, #247).
func TestEstablish_WritesTheUserTheGenerationAndTheClearInOneTransaction(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	user := enrollableUser()

	var calls []string
	mocks_data.ExpectRunInTransaction(database, otpTx, func(edge string) { calls = append(calls, edge) })

	database.EXPECT().UpdateUser(mock.Anything, otpTx, mock.MatchedBy(func(u *models.User) bool {
		// otp_enabled is on and the seed is stored encrypted, both of which were the caller's
		// two lines before #387 folded them in here. There is no plaintext column any more:
		// migration 000048 dropped users.otp_secret (#98).
		if !u.OTPEnabled || len(u.OTPSecretEncrypted) == 0 {
			return false
		}
		if bytes.Contains(u.OTPSecretEncrypted, []byte(otpSeed)) {
			return false
		}
		stored, err := storedSecret(u)
		return err == nil && stored == otpSeed
	})).RunAndReturn(func(context.Context, *sql.Tx, *models.User) error {
		calls = append(calls, "update")
		return nil
	}).Once()

	database.EXPECT().IncrementUserOtpConfigGeneration(mock.Anything, otpTx, otpUserId).
		RunAndReturn(func(context.Context, *sql.Tx, int64) (int64, error) {
			calls = append(calls, "increment")
			return 9, nil
		}).Once()

	database.EXPECT().ClearPendingOTPEnrollment(mock.Anything, otpTx, otpUserId).
		RunAndReturn(func(context.Context, *sql.Tx, int64) error {
			calls = append(calls, "clear")
			return nil
		}).Once()

	generation, err := Establish(context.Background(), database, user, otpSeed)

	require.NoError(t, err)
	assert.EqualValues(t, 9, generation,
		"the caller gets the value the increment read back: the browser ceremony overwrites the "+
			"pre-enrollment snapshot with it, and computing N+1 here would launder a concurrent change into it")
	assert.Equal(t, []string{"begin", "update", "increment", "clear", "commit"}, calls,
		"all three writes belong to one transaction; committed separately, an authenticator can be "+
			"on with the counter unmoved and every live session still satisfied (#242 decision 2)")
	assert.True(t, user.OTPEnabled)
}

// The rollback arm of the same property. A failing write hands its error to the helper, which is
// what "nothing committed" looks like one layer up, and the caller gets no generation.
func TestEstablish_AFailedWriteRollsTheWholeTransactionBack(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	writeErr := errors.New("update refused")

	stub := mocks_data.ExpectRunInTransaction(database, otpTx)
	database.EXPECT().UpdateUser(mock.Anything, otpTx, mock.Anything).Return(writeErr).Once()

	generation, err := Establish(context.Background(), database, enrollableUser(), otpSeed)

	require.ErrorIs(t, err, writeErr)
	assert.Zero(t, generation)
	assert.ErrorIs(t, stub.BodyErr, writeErr,
		"the body must hand the error to the helper rather than swallow it, because that is what "+
			"makes the pending enrolment survive a failed enable (#247)")
	database.AssertNotCalled(t, "IncrementUserOtpConfigGeneration", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "ClearPendingOTPEnrollment", mock.Anything, mock.Anything, mock.Anything)
}

// A commit the engine refuses after every statement landed is still a failed establish: the caller
// is told, and is not handed a generation the database never committed.
func TestEstablish_ACommitFailureYieldsNoGeneration(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	commitErr := errors.New("commit refused")

	mocks_data.ExpectRunInTransactionThenFail(database, otpTx, commitErr)
	database.EXPECT().UpdateUser(mock.Anything, otpTx, mock.Anything).Return(nil).Once()
	database.EXPECT().IncrementUserOtpConfigGeneration(mock.Anything, otpTx, otpUserId).Return(11, nil).Once()
	database.EXPECT().ClearPendingOTPEnrollment(mock.Anything, otpTx, otpUserId).Return(nil).Once()

	generation, err := Establish(context.Background(), database, enrollableUser(), otpSeed)

	require.ErrorIs(t, err, commitErr)
	assert.Zero(t, generation, "a generation from an attempt that did not commit must not reach the ceremony")
}

// A transaction that never opens: the body never runs, so no write is attempted and the helper's
// error is what the caller sees.
func TestEstablish_ARefusedTransactionWritesNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	beginErr := errors.New("cannot begin")

	mocks_data.ExpectRunInTransactionRefused(database, beginErr)

	generation, err := Establish(context.Background(), database, enrollableUser(), otpSeed)

	require.ErrorIs(t, err, beginErr)
	assert.Zero(t, generation)
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
}

// Seam 2, the remove half. The clear, the disable, the step reset and the counter advance are one
// transaction, in decision 10's order: otp_enabled cleared before the marker (#111 decisions 4,
// 10 and 13).
func TestRemove_ClearsDisablesResetsAndAdvancesInOneTransaction(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	user := enrolledUser(t)

	var calls []string
	mocks_data.ExpectRunInTransaction(database, otpTx, func(edge string) { calls = append(calls, edge) })

	database.EXPECT().UpdateUser(mock.Anything, otpTx, mock.MatchedBy(func(u *models.User) bool {
		return !u.OTPEnabled && len(u.OTPSecretEncrypted) == 0
	})).RunAndReturn(func(context.Context, *sql.Tx, *models.User) error {
		calls = append(calls, "update")
		return nil
	}).Once()

	database.EXPECT().ResetUserOTPStep(mock.Anything, otpTx, otpUserId).
		RunAndReturn(func(context.Context, *sql.Tx, int64) error {
			calls = append(calls, "reset")
			return nil
		}).Once()

	database.EXPECT().IncrementUserOtpConfigGeneration(mock.Anything, otpTx, otpUserId).
		RunAndReturn(func(context.Context, *sql.Tx, int64) (int64, error) {
			calls = append(calls, "increment")
			return 4, nil
		}).Once()

	require.NoError(t, Remove(context.Background(), database, user))

	assert.Equal(t, []string{"begin", "update", "reset", "increment", "commit"}, calls,
		"the disable and the marker reset commit together: separately, an enrollment landing between "+
			"them leaves a consumed code claimable again (#111 decision 13)")
	assert.False(t, user.OTPEnabled)
	assert.Empty(t, user.OTPSecretEncrypted, "the seed goes with the authenticator")
}

// The counter advance is not best-effort. A removal that commits without it is exactly the state
// the re-prompt exists to prevent, so its error is returned and the transaction rolls back.
func TestRemove_AFailedGenerationAdvanceFailsTheRemoval(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	incrementErr := errors.New("increment refused")

	stub := mocks_data.ExpectRunInTransaction(database, otpTx)
	database.EXPECT().UpdateUser(mock.Anything, otpTx, mock.Anything).Return(nil).Once()
	database.EXPECT().ResetUserOTPStep(mock.Anything, otpTx, otpUserId).Return(nil).Once()
	database.EXPECT().IncrementUserOtpConfigGeneration(mock.Anything, otpTx, otpUserId).
		Return(0, incrementErr).Once()

	err := Remove(context.Background(), database, enrolledUser(t))

	require.ErrorIs(t, err, incrementErr)
	assert.ErrorIs(t, stub.BodyErr, incrementErr)
}

// Seam 3, the three-arm table, against the authenticator the user has enrolled. requireOTPEnabled
// is true on every call from here: this claim asserts a factor, and that assertion is only true of
// an enrolled authenticator (#111 decision 10).
func TestVerifyStored(t *testing.T) {
	now := time.Now().UTC()

	t.Run("a code the enrolled seed produces matches and claims its step", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().
			TryConsumeUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, true).
			Return(true, nil).Once()

		result, err := VerifyStored(context.Background(), database, enrolledUser(t), codeFor(t, otpSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeMatched, result.Outcome)
		assert.EqualValues(t, now.Unix()/otp.StepSeconds, result.Step,
			"the step reported is the one the passcode matched, which is what the replay record names")
	})

	t.Run("a wrong code is refused without claiming anything", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		result, err := VerifyStored(context.Background(), database, enrolledUser(t), "000000", now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeWrong, result.Outcome)
		assert.Zero(t, result.Step, "nothing matched, so there is no step to name")
		// One matcher per parameter, or testify compares argument lists that can never be equal
		// and the assertion passes whatever happened (#421).
		database.AssertNotCalled(t, "TryConsumeUserOTPStep",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a step already spent is reported as a replay, with the step", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().
			TryConsumeUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, true).
			Return(false, nil).Once()

		result, err := VerifyStored(context.Background(), database, enrolledUser(t), codeFor(t, otpSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeReplayed, result.Outcome,
			"a replay is a refusal distinct from a wrong code: every caller raises "+
				"AuditOTPCodeReplayDetected on it, and two of the three raise nothing on a wrong code")
		assert.EqualValues(t, now.Unix()/otp.StepSeconds, result.Step)
	})

	t.Run("a failing claim is an error rather than a refusal", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		claimErr := errors.New("claim refused")
		database.EXPECT().
			TryConsumeUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, true).
			Return(false, claimErr).Once()

		result, err := VerifyStored(context.Background(), database, enrolledUser(t), codeFor(t, otpSeed, now), now)

		require.ErrorIs(t, err, claimErr)
		assert.Equal(t, OutcomeWrong, result.Outcome,
			"the zero value is a refusal, so a caller that read the result past the error would "+
				"refuse the passcode rather than authenticate on it")
	})

	t.Run("a stored seed that will not decrypt is an error", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		user := enrolledUser(t)
		user.OTPSecretEncrypted = []byte("not ciphertext this cipher produced")

		_, err := VerifyStored(context.Background(), database, user, codeFor(t, otpSeed, now), now)

		require.Error(t, err, "a seed this server cannot read is a 500, not a wrong passcode")
	})
}

// Seam 3 again, against a seed the caller holds: the browser's off AuthContext.OTPKeyURL, the
// account API's off the pending enrolment the server issued. requireOTPEnabled is false on every
// call from here, because enrolment establishes the authenticator rather than asserts it and
// otp_enabled is still off until Establish writes it (#111 decision 10).
func TestVerifySupplied(t *testing.T) {
	now := time.Now().UTC()
	const suppliedSeed = "ZP2Z5KXRBAPPHWXEHH65PY5H7EKLVHRZ"

	t.Run("a code the supplied seed produces matches, and the stored seed is not consulted", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().
			TryConsumeUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, false).
			Return(true, nil).Once()

		// Enrolled with a different seed on purpose: the supplied one is what decides this, which
		// is the whole difference between the two entry points.
		result, err := VerifySupplied(context.Background(), database, enrolledUser(t), suppliedSeed,
			codeFor(t, suppliedSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeMatched, result.Outcome)
	})

	t.Run("a code from the stored seed does not verify against the supplied one", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		result, err := VerifySupplied(context.Background(), database, enrolledUser(t), suppliedSeed,
			codeFor(t, otpSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeWrong, result.Outcome)
		database.AssertNotCalled(t, "TryConsumeUserOTPStep",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a step already spent is reported as a replay", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().
			TryConsumeUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, false).
			Return(false, nil).Once()

		result, err := VerifySupplied(context.Background(), database, enrollableUser(), suppliedSeed,
			codeFor(t, suppliedSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeReplayed, result.Outcome)
		assert.EqualValues(t, now.Unix()/otp.StepSeconds, result.Step)
	})
}

// The seed's encryption at rest, which was models.User's TestUser_OTPSecret until #387 took the
// three methods off the persistence record. Same four claims (#82).
func TestSeedAtRest(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // the key TestMain installed
	const secret = "JBSWY3DPEHPK3PXP"

	u := &models.User{}
	require.NoError(t, setSecret(u, secret))

	// The encrypted value must be populated without containing the seed verbatim. There is no
	// plaintext column to check: migration 000048 dropped users.otp_secret (#98).
	require.NotEmpty(t, u.OTPSecretEncrypted, "OTPSecretEncrypted is empty after setSecret")
	assert.False(t, bytes.Contains(u.OTPSecretEncrypted, []byte(secret)),
		"the encrypted OTP secret contains the plaintext seed")

	got, err := storedSecret(u)
	require.NoError(t, err)
	assert.Equal(t, secret, got)

	// With a different cipher key the stored value must not decrypt.
	require.NoError(t, encryption.InitDataCipher([]byte("fedcba9876543210fedcba9876543210")))
	_, err = storedSecret(u)
	assert.Error(t, err, "storedSecret with a different cipher key: expected an error")
	require.NoError(t, encryption.InitDataCipher(key)) // restore, for every other case in this package

	// A user with no encrypted secret returns an empty string, no error.
	got, err = storedSecret(&models.User{})
	require.NoError(t, err)
	assert.Empty(t, got)

	// clearSecret removes the stored seed.
	clearSecret(u)
	assert.Empty(t, u.OTPSecretEncrypted, "clearSecret left data behind")
	got, err = storedSecret(u)
	require.NoError(t, err)
	assert.Empty(t, got)
}

package otpcredential

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/otp"
	"github.com/leodip/goiabada/authserver/internal/record"
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

// otpReadGeneration is the otp_config_generation every user below was read at, which the two
// compare-and-sets must hand the database as what they expect.
const otpReadGeneration = int64(5)

// enrollableUser is a user part way through enrolling: no authenticator yet.
func enrollableUser() *record.User {
	return &record.User{Id: otpUserId, Enabled: true, OtpConfigGeneration: otpReadGeneration}
}

// enrolledUser is a user with otpSeed already established, which is the state VerifyStored reads.
func enrolledUser(t *testing.T) *record.User {
	t.Helper()

	encrypted, err := encryptSecret(testDataCipher, otpSeed)
	require.NoError(t, err)
	return &record.User{Id: otpUserId, Enabled: true, OTPEnabled: true, OTPSecretEncrypted: encrypted,
		OtpConfigGeneration: otpReadGeneration}
}

// isEncryptedOTPSeed reports whether stored is otpSeed encrypted at rest: never the plaintext, and
// decrypting back to it.
func isEncryptedOTPSeed(stored []byte) bool {
	if len(stored) == 0 || bytes.Contains(stored, []byte(otpSeed)) {
		return false
	}
	plain, err := testDataCipher.Decrypt(stored)
	return err == nil && plain == otpSeed
}

// codeFor returns a passcode the given seed produces at now, which is what a user reads off their
// authenticator app.
func codeFor(t *testing.T, seed string, now time.Time) string {
	t.Helper()

	code, err := totp.GenerateCode(seed, now)
	require.NoError(t, err)
	return code
}

// Seam 2, the establish half. The compare-and-set, the generation advance and the pending clear are
// one transaction, in that order, and the generation the caller gets is the committing attempt's
// read-back rather than anything computed here (#242 decision 2, #247). The compare-and-set expects
// OTP off at the generation the user was read with (#471 decision 2).
func TestEstablish_WritesTheAuthenticatorTheGenerationAndTheClearInOneTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := enrollableUser()

	var calls []string
	datamocks.ExpectRunInTransaction(database, otpTx, func(edge string) { calls = append(calls, edge) })

	// The seed is stored encrypted, which was the caller's line before #387 folded it in here.
	// There is no plaintext column any more: migration 000048 dropped users.otp_secret (#98).
	database.EXPECT().TryEstablishUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration,
		mock.MatchedBy(isEncryptedOTPSeed)).
		RunAndReturn(func(context.Context, *sql.Tx, int64, int64, []byte) (bool, error) {
			calls = append(calls, "establish")
			return true, nil
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

	generation, established, err := Establish(context.Background(), database, testDataCipher, user, otpSeed)

	require.NoError(t, err)
	assert.True(t, established)
	assert.EqualValues(t, 9, generation,
		"the caller gets the value the increment read back: the browser ceremony overwrites the "+
			"pre-enrollment snapshot with it, and computing N+1 here would launder a concurrent change into it")
	assert.Equal(t, []string{"begin", "establish", "increment", "clear", "commit"}, calls,
		"all three writes belong to one transaction; committed separately, an authenticator can be "+
			"on with the counter unmoved and every live session still satisfied (#242 decision 2)")
	assert.True(t, user.OTPEnabled)
	assert.True(t, isEncryptedOTPSeed(user.OTPSecretEncrypted), "the user carries what landed")
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
}

// An establish whose compare-and-set matched nothing changes nothing else: the generation does not
// advance for an authenticator this request did not install, the pending enrolment stays for the
// one that may yet be, and the caller is told so without an error, to answer from a re-read (#471
// decision 2).
func TestEstablish_ALostCompareAndSetWritesNothingElse(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := enrollableUser()

	stub := datamocks.ExpectRunInTransaction(database, otpTx)
	database.EXPECT().TryEstablishUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration, mock.Anything).
		Return(false, nil).Once()

	generation, established, err := Establish(context.Background(), database, testDataCipher, user, otpSeed)

	require.NoError(t, err, "a lost compare-and-set is an answer, not a fault")
	assert.False(t, established)
	assert.Zero(t, generation)
	require.NoError(t, stub.BodyErr)
	database.AssertNotCalled(t, "IncrementUserOtpConfigGeneration", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "ClearPendingOTPEnrollment", mock.Anything, mock.Anything, mock.Anything)
	assert.False(t, user.OTPEnabled, "the user must not claim an authenticator that was never stored")
	assert.Empty(t, user.OTPSecretEncrypted)
}

// The rollback arm of the same property. A failing write hands its error to the helper, which is
// what "nothing committed" looks like one layer up, and the caller gets no generation.
func TestEstablish_AFailedWriteRollsTheWholeTransactionBack(t *testing.T) {
	database := datamocks.NewDatabase(t)
	writeErr := errors.New("update refused")

	stub := datamocks.ExpectRunInTransaction(database, otpTx)
	database.EXPECT().TryEstablishUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration, mock.Anything).
		Return(false, writeErr).Once()

	generation, established, err := Establish(context.Background(), database, testDataCipher, enrollableUser(), otpSeed)

	require.ErrorIs(t, err, writeErr)
	assert.False(t, established)
	assert.Zero(t, generation)
	require.ErrorIs(t, stub.BodyErr, writeErr,
		"the body must hand the error to the helper rather than swallow it, because that is what "+
			"makes the pending enrolment survive a failed enable (#247)")
	database.AssertNotCalled(t, "IncrementUserOtpConfigGeneration", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "ClearPendingOTPEnrollment", mock.Anything, mock.Anything, mock.Anything)
}

// A commit the engine refuses after every statement landed is still a failed establish: the caller
// is told, and is not handed a generation the database never committed.
func TestEstablish_ACommitFailureYieldsNoGeneration(t *testing.T) {
	database := datamocks.NewDatabase(t)
	commitErr := errors.New("commit refused")

	datamocks.ExpectRunInTransactionThenFail(database, otpTx, commitErr)
	database.EXPECT().TryEstablishUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration, mock.Anything).
		Return(true, nil).Once()
	database.EXPECT().IncrementUserOtpConfigGeneration(mock.Anything, otpTx, otpUserId).Return(11, nil).Once()
	database.EXPECT().ClearPendingOTPEnrollment(mock.Anything, otpTx, otpUserId).Return(nil).Once()

	user := enrollableUser()
	generation, established, err := Establish(context.Background(), database, testDataCipher, user, otpSeed)

	require.ErrorIs(t, err, commitErr)
	assert.False(t, established)
	assert.Zero(t, generation, "a generation from an attempt that did not commit must not reach the ceremony")
	assert.False(t, user.OTPEnabled)
}

// A transaction that never opens: the body never runs, so no write is attempted and the helper's
// error is what the caller sees.
func TestEstablish_ARefusedTransactionWritesNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	beginErr := errors.New("cannot begin")

	datamocks.ExpectRunInTransactionRefused(database, beginErr)

	generation, established, err := Establish(context.Background(), database, testDataCipher, enrollableUser(), otpSeed)

	require.ErrorIs(t, err, beginErr)
	assert.False(t, established)
	assert.Zero(t, generation)
	database.AssertNotCalled(t, "TryEstablishUserOTP",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// Seam 2, the remove half. The compare-and-set, the step reset, the counter advance and the
// lowering of the user's sessions are one transaction, in decision 10's order: otp_enabled cleared
// before the marker (#111 decisions 4, 10 and 13, #542 decision 1). The compare-and-set expects
// OTP on at the generation the user was read with (#471 decision 2).
func TestRemove_ClearsDisablesResetsAndAdvancesInOneTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := enrolledUser(t)

	var calls []string
	datamocks.ExpectRunInTransaction(database, otpTx, func(edge string) { calls = append(calls, edge) })

	database.EXPECT().TryRemoveUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration).
		RunAndReturn(func(context.Context, *sql.Tx, int64, int64) (bool, error) {
			calls = append(calls, "remove")
			return true, nil
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

	// The password's method is what the sessions keep: pwd and otp are the only two there are.
	database.EXPECT().LowerUserSessionsToPassword(mock.Anything, otpTx, otpUserId, "pwd").
		RunAndReturn(func(context.Context, *sql.Tx, int64, string) error {
			calls = append(calls, "lower")
			return nil
		}).Once()

	removed, err := Remove(context.Background(), database, user)
	require.NoError(t, err)
	assert.True(t, removed)

	assert.Equal(t, []string{"begin", "remove", "reset", "increment", "lower", "commit"}, calls,
		"the disable and the marker reset commit together: separately, an enrollment landing between "+
			"them leaves a consumed code claimable again (#111 decision 13); and the sessions are "+
			"lowered with them, so none still names the authenticator once it is gone (#542)")
	assert.False(t, user.OTPEnabled)
	assert.Empty(t, user.OTPSecretEncrypted, "the seed goes with the authenticator")
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
}

// A removal whose compare-and-set matched nothing changes nothing else: the marker belongs to an
// authenticator this request did not remove, and the generation must not advance for it (#471
// decision 2).
func TestRemove_ALostCompareAndSetWritesNothingElse(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := enrolledUser(t)

	stub := datamocks.ExpectRunInTransaction(database, otpTx)
	database.EXPECT().TryRemoveUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration).
		Return(false, nil).Once()

	removed, err := Remove(context.Background(), database, user)

	require.NoError(t, err, "a lost compare-and-set is an answer, not a fault")
	assert.False(t, removed)
	require.NoError(t, stub.BodyErr)
	database.AssertNotCalled(t, "ResetUserOTPStep", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "IncrementUserOtpConfigGeneration", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "LowerUserSessionsToPassword", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assert.True(t, user.OTPEnabled, "the user must not report a removal that did not happen")
}

// A lowering that fails fails the removal: committed without it, the authenticator is gone and a
// session still claims it, which is the state the lowering exists to prevent. What the lowering
// leaves each session claiming is the statement's, and the data tier holds it on all four engines.
func TestRemove_AFailedLoweringFailsTheRemoval(t *testing.T) {
	writeErr := errors.New("session write refused")
	database := datamocks.NewDatabase(t)
	user := enrolledUser(t)
	stub := datamocks.ExpectRunInTransaction(database, otpTx)
	database.EXPECT().TryRemoveUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration).Return(true, nil).Once()
	database.EXPECT().ResetUserOTPStep(mock.Anything, otpTx, otpUserId).Return(nil).Once()
	database.EXPECT().IncrementUserOtpConfigGeneration(mock.Anything, otpTx, otpUserId).Return(6, nil).Once()
	database.EXPECT().LowerUserSessionsToPassword(mock.Anything, otpTx, otpUserId, "pwd").Return(writeErr).Once()

	removed, err := Remove(context.Background(), database, user)

	require.ErrorIs(t, err, writeErr)
	assert.False(t, removed)
	require.ErrorIs(t, stub.BodyErr, writeErr)
	assert.True(t, user.OTPEnabled, "the user must not report a removal that rolled back")
}

// The counter advance is not best-effort. A removal that commits without it is exactly the state
// the re-prompt exists to prevent, so its error is returned and the transaction rolls back.
func TestRemove_AFailedGenerationAdvanceFailsTheRemoval(t *testing.T) {
	database := datamocks.NewDatabase(t)
	incrementErr := errors.New("increment refused")

	stub := datamocks.ExpectRunInTransaction(database, otpTx)
	database.EXPECT().TryRemoveUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration).Return(true, nil).Once()
	database.EXPECT().ResetUserOTPStep(mock.Anything, otpTx, otpUserId).Return(nil).Once()
	database.EXPECT().IncrementUserOtpConfigGeneration(mock.Anything, otpTx, otpUserId).
		Return(0, incrementErr).Once()

	removed, err := Remove(context.Background(), database, enrolledUser(t))

	require.ErrorIs(t, err, incrementErr)
	assert.False(t, removed)
	assert.ErrorIs(t, stub.BodyErr, incrementErr)
}

// Seam 3, the three-arm table, against the authenticator the user has enrolled. Every claim from
// here is the verification claim at the generation the user was read with: it asserts a factor,
// and that assertion is only true of the authenticator the passcode was checked against (#111
// decision 10, #471 decision 3).
func TestVerifyStored(t *testing.T) {
	now := time.Now().UTC()

	t.Run("a code the enrolled seed produces matches and claims its step", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().
			TryConsumeEnrolledUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, otpReadGeneration).
			Return(true, nil).Once()

		result, err := VerifyStored(context.Background(), database, testDataCipher, enrolledUser(t), codeFor(t, otpSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeMatched, result.Outcome)
		assert.Equal(t, now.Unix()/otp.StepSeconds, result.Step,
			"the step reported is the one the passcode matched, which is what the replay record names")
	})

	t.Run("a wrong code is refused without claiming anything", func(t *testing.T) {
		database := datamocks.NewDatabase(t)

		result, err := VerifyStored(context.Background(), database, testDataCipher, enrolledUser(t), "000000", now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeWrong, result.Outcome)
		assert.Zero(t, result.Step, "nothing matched, so there is no step to name")
		// One matcher per parameter, or testify compares argument lists that can never be equal
		// and the assertion passes whatever happened (#421).
		database.AssertNotCalled(t, "TryConsumeEnrolledUserOTPStep",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a step already spent is reported as a replay, with the step", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().
			TryConsumeEnrolledUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, otpReadGeneration).
			Return(false, nil).Once()

		result, err := VerifyStored(context.Background(), database, testDataCipher, enrolledUser(t), codeFor(t, otpSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeReplayed, result.Outcome,
			"a replay is a refusal distinct from a wrong code: every caller raises "+
				"EventOTPCodeReplayDetected on it, and two of the three raise nothing on a wrong code")
		assert.Equal(t, now.Unix()/otp.StepSeconds, result.Step)
	})

	t.Run("a failing claim is an error rather than a refusal", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		claimErr := errors.New("claim refused")
		database.EXPECT().
			TryConsumeEnrolledUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, otpReadGeneration).
			Return(false, claimErr).Once()

		result, err := VerifyStored(context.Background(), database, testDataCipher, enrolledUser(t), codeFor(t, otpSeed, now), now)

		require.ErrorIs(t, err, claimErr)
		assert.Equal(t, OutcomeWrong, result.Outcome,
			"the zero value is a refusal, so a caller that read the result past the error would "+
				"refuse the passcode rather than authenticate on it")
	})

	t.Run("a stored seed that will not decrypt is an error", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		user := enrolledUser(t)
		user.OTPSecretEncrypted = []byte("not ciphertext this cipher produced")

		_, err := VerifyStored(context.Background(), database, testDataCipher, user, codeFor(t, otpSeed, now), now)

		require.Error(t, err, "a seed this server cannot read is a 500, not a wrong passcode")
	})
}

// Seam 3 again, against a seed the caller holds: the browser's off AuthContext.OTPKeyURL, the
// account API's off the pending enrolment the server issued. Every claim from here is the enrolment
// claim, naming no authenticator state, because enrolment establishes the authenticator rather than
// asserts it and otp_enabled is still off until Establish writes it (#111 decision 10).
func TestVerifySupplied(t *testing.T) {
	now := time.Now().UTC()
	const suppliedSeed = "ZP2Z5KXRBAPPHWXEHH65PY5H7EKLVHRZ"

	t.Run("a code the supplied seed produces matches, and the stored seed is not consulted", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().
			TryConsumeUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything).
			Return(true, nil).Once()

		// Enrolled with a different seed on purpose: the supplied one is what decides this, which
		// is the whole difference between the two entry points.
		result, err := VerifySupplied(context.Background(), database, enrolledUser(t), suppliedSeed,
			codeFor(t, suppliedSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeMatched, result.Outcome)
	})

	t.Run("a code from the stored seed does not verify against the supplied one", func(t *testing.T) {
		database := datamocks.NewDatabase(t)

		result, err := VerifySupplied(context.Background(), database, enrolledUser(t), suppliedSeed,
			codeFor(t, otpSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeWrong, result.Outcome)
		database.AssertNotCalled(t, "TryConsumeUserOTPStep",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a step already spent is reported as a replay", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().
			TryConsumeUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything).
			Return(false, nil).Once()

		result, err := VerifySupplied(context.Background(), database, enrollableUser(), suppliedSeed,
			codeFor(t, suppliedSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeReplayed, result.Outcome)
		assert.Equal(t, now.Unix()/otp.StepSeconds, result.Step)
	})
}

// The seed's encryption at rest, which was record.User's TestUser_OTPSecret until #387 took the
// three methods off the persistence record (#82).
func TestSeedAtRest(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"

	encrypted, err := encryptSecret(testDataCipher, secret)
	require.NoError(t, err)
	u := &record.User{OTPSecretEncrypted: encrypted}

	// The encrypted value must be populated without containing the seed verbatim. There is no
	// plaintext column to check: migration 000048 dropped users.otp_secret (#98).
	require.NotEmpty(t, u.OTPSecretEncrypted, "encryptSecret returned nothing")
	assert.False(t, bytes.Contains(u.OTPSecretEncrypted, []byte(secret)),
		"the encrypted OTP secret contains the plaintext seed")

	got, err := storedSecret(testDataCipher, u)
	require.NoError(t, err)
	assert.Equal(t, secret, got)

	// Under a second cipher with another key the stored value must not decrypt. A cipher of its
	// own, where this used to swap the process-wide key and restore it after (#434).
	otherCipher, err := encryption.NewDataCipher([]byte("fedcba9876543210fedcba9876543210"))
	require.NoError(t, err)
	_, err = storedSecret(otherCipher, u)
	require.Error(t, err, "storedSecret with a different cipher key: expected an error")

	// A user with no encrypted secret returns an empty string, no error.
	got, err = storedSecret(testDataCipher, &record.User{})
	require.NoError(t, err)
	assert.Empty(t, got)
}

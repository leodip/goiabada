package otpcredential

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The consecutive-failure count NIST SP 800-63B section 3.2.2 bases its disable on
// (#489): VerifyStored advances it on every attempt it refuses, an authenticator at the
// limit answers as a wrong code with no write at all, and Establish clears it in the
// transaction that rebinds. The count's own statements -- the claim clearing it beside
// the step, the increment stopping at the limit -- are the data tier's, and
// tests/data/user_otp_consecutive_failures_test.go holds them against the real schema.
func TestVerifyStoredCountsConsecutiveFailures(t *testing.T) {
	now := time.Now().UTC()

	t.Run("a wrong code advances the count", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().
			IncrementUserOtpConsecutiveFailures(mock.Anything, (*sql.Tx)(nil), otpUserId, otpReadGeneration).
			Return(false, nil).Once()

		result, err := VerifyStored(context.Background(), database, testDataCipher, enrolledUser(t), "000000", now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeWrong, result.Outcome)
		assert.False(t, result.Disabled, "a refusal short of the limit disables nothing")
		database.AssertNotCalled(t, "TryConsumeEnrolledUserOTPStep",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	// The statement is bound to the authenticator the code was checked against, the generation
	// read with the seed, so the expectation names otpReadGeneration rather than anything: a
	// refusal in flight across a replacement charges nothing to the replacement (#489).
	for _, arm := range []struct {
		name    string
		code    func() string
		replay  bool
		outcome VerifyOutcome
	}{
		{name: "a wrong code", code: func() string { return "000000" }, outcome: OutcomeWrong},
		{name: "a replayed code", code: func() string { return codeFor(t, otpSeed, now) }, replay: true,
			outcome: OutcomeReplayed},
	} {
		t.Run(arm.name+" that reaches the limit reports the disable", func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			if arm.replay {
				database.EXPECT().
					TryConsumeEnrolledUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, otpReadGeneration).
					Return(false, nil).Once()
			}
			database.EXPECT().
				IncrementUserOtpConsecutiveFailures(mock.Anything, (*sql.Tx)(nil), otpUserId, otpReadGeneration).
				Return(true, nil).Once()

			result, err := VerifyStored(context.Background(), database, testDataCipher, enrolledUser(t), arm.code(), now)

			require.NoError(t, err)
			assert.Equal(t, arm.outcome, result.Outcome, "the submitter is answered as for any refused code")
			assert.True(t, result.Disabled, "the call that reached the limit reports it, so its caller audits it")
		})

		t.Run(arm.name+" whose count cannot be written is an error, not a refusal", func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			writeErr := errors.New("increment failed")
			if arm.replay {
				database.EXPECT().
					TryConsumeEnrolledUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, otpReadGeneration).
					Return(false, nil).Once()
			}
			database.EXPECT().
				IncrementUserOtpConsecutiveFailures(mock.Anything, (*sql.Tx)(nil), otpUserId, otpReadGeneration).
				Return(false, writeErr).Once()

			result, err := VerifyStored(context.Background(), database, testDataCipher, enrolledUser(t), arm.code(), now)

			require.ErrorIs(t, err, writeErr,
				"a refusal the count missed must not be answered as counted: the caller fails the request")
			assert.Equal(t, VerifyResult{}, result)
		})
	}

	t.Run("a replayed code advances the count: a failed attempt is a failed attempt", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().
			TryConsumeEnrolledUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, otpReadGeneration).
			Return(false, nil).Once()
		database.EXPECT().
			IncrementUserOtpConsecutiveFailures(mock.Anything, (*sql.Tx)(nil), otpUserId, otpReadGeneration).
			Return(false, nil).Once()

		result, err := VerifyStored(context.Background(), database, testDataCipher, enrolledUser(t), codeFor(t, otpSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeReplayed, result.Outcome)
		assert.False(t, result.Disabled)
	})

	t.Run("a matched code advances nothing: the claim's own statement clears", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().
			TryConsumeEnrolledUserOTPStep(mock.Anything, (*sql.Tx)(nil), otpUserId, mock.Anything, otpReadGeneration).
			Return(true, nil).Once()

		result, err := VerifyStored(context.Background(), database, testDataCipher, enrolledUser(t), codeFor(t, otpSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeMatched, result.Outcome)
		database.AssertNotCalled(t, "IncrementUserOtpConsecutiveFailures",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("an authenticator at the limit is disabled and writes nothing", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		user := enrolledUser(t)
		user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit

		result, err := VerifyStored(context.Background(), database, testDataCipher, user, codeFor(t, otpSeed, now), now)

		require.NoError(t, err)
		assert.Equal(t, OutcomeWrong, result.Outcome,
			"the refusal is indistinguishable from a wrong code, for the replay's reason (#111)")
		assert.Zero(t, result.Step)
		database.AssertNotCalled(t, "TryConsumeEnrolledUserOTPStep",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "IncrementUserOtpConsecutiveFailures",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

// The rebind clears the count, inside the establish's transaction: at
// record.OtpConsecutiveFailureLimit the authenticator is disabled until it is rebound,
// and rebinding is a fresh enrolment (NIST SP 800-63B section 3.2.2, #489).
func TestEstablish_ClearsTheConsecutiveFailuresCountInTheRebind(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := enrollableUser()

	var calls []string
	datamocks.ExpectRunInTransaction(database, otpTx, func(edge string) { calls = append(calls, edge) })

	database.EXPECT().TryEstablishUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration, mock.Anything).
		Return(true, nil).Once()
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
	database.EXPECT().ClearUserOtpConsecutiveFailures(mock.Anything, otpTx, otpUserId).
		RunAndReturn(func(context.Context, *sql.Tx, int64) error {
			calls = append(calls, "clear-count")
			return nil
		}).Once()

	_, established, err := Establish(context.Background(), database, testDataCipher, user, otpSeed)

	require.NoError(t, err)
	assert.True(t, established)
	assert.Equal(t, []string{"begin", "increment", "clear", "clear-count", "commit"}, calls,
		"the rebind's clear belongs to the establish's transaction: a count left standing would "+
			"disable the enrolment that exists to clear it (#489)")
}

// A clear the engine refuses fails the establish: the transaction rolls back, nothing is reported
// as established, and the caller gets the error. Committed without it, the fresh authenticator would
// carry the count that disabled the one it replaces (#489).
func TestEstablish_AFailedCountClearEstablishesNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := enrollableUser()
	clearErr := errors.New("clear failed")

	stub := datamocks.ExpectRunInTransaction(database, otpTx)
	database.EXPECT().TryEstablishUserOTP(mock.Anything, otpTx, otpUserId, otpReadGeneration, mock.Anything).
		Return(true, nil).Once()
	database.EXPECT().IncrementUserOtpConfigGeneration(mock.Anything, otpTx, otpUserId).Return(9, nil).Once()
	database.EXPECT().ClearPendingOTPEnrollment(mock.Anything, otpTx, otpUserId).Return(nil).Once()
	database.EXPECT().ClearUserOtpConsecutiveFailures(mock.Anything, otpTx, otpUserId).Return(clearErr).Once()

	generation, established, err := Establish(context.Background(), database, testDataCipher, user, otpSeed)

	require.ErrorIs(t, err, clearErr)
	require.ErrorIs(t, stub.BodyErr, clearErr, "the body hands the error to the helper, which rolls back")
	assert.False(t, established)
	assert.Zero(t, generation)
	assert.False(t, user.OTPEnabled, "the user carries nothing that did not commit")
}

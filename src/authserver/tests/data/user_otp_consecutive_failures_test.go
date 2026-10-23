package datatests

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The consecutive-failure count that disables an enrolled authenticator at
// record.OtpConsecutiveFailureLimit, NIST SP 800-63B section 3.2.2's limit (#489).
//
// Three writers move it, and this file pins each against the real schema:
//
//   - IncrementUserOtpConsecutiveFailures advances it, and stops at the limit, where the
//     row no longer matches, so grinding a disabled authenticator moves nothing; it reports
//     the one call that reached the limit, moves nothing for an authenticator removed or
//     replaced since the read, and leaves updated_at alone;
//   - the verification claim (TryConsumeEnrolledUserOTPStep) clears it, in the same
//     statement that claims the step, and refuses while it stands at the limit;
//   - ClearUserOtpConsecutiveFailures returns it to 0, the rebind's clear, which only
//     runs inside a transaction.
func TestOtpConsecutiveFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("the limit is NIST's 100", func(t *testing.T) {
		// A literal rather than the constant, which every other case reads: raising the
		// limit must fail somewhere. NIST SP 800-63B section 3.2.2 allows no more than 100.
		assert.Equal(t, 100, record.OtpConsecutiveFailureLimit)
	})

	t.Run("the increment advances, reports the 100th call alone, and stops at the limit", func(t *testing.T) {
		read := otpStateUser(t, true)

		for i := 1; i < 100; i++ {
			disabled, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
			require.NoError(t, err, "increment %d", i)
			require.False(t, disabled, "increment %d of 100 disables nothing", i)
		}
		disabled, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
		require.NoError(t, err, "increment 100")
		assert.True(t, disabled, "the 100th consecutive failure disables the authenticator")

		disabled, err = database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
		require.NoError(t, err, "one increment beyond the limit is not an error: the row no longer matches")
		assert.False(t, disabled, "the disable is reported once, not again for every code after it")

		assert.EqualValues(t, 100, reloadUser(t, read.Id).OtpConsecutiveFailures,
			"the count must stop at the limit rather than keep rising")
	})

	t.Run("concurrent refusals at the limit report the disable exactly once", func(t *testing.T) {
		read := otpStateUser(t, true)
		start := record.OtpConsecutiveFailureLimit - raceCallers/2
		for i := 0; i < start; i++ {
			_, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
			require.NoError(t, err)
		}

		reported := raceOnce(t, raceCallers, func(int) (bool, error) {
			return database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
		})

		assert.Equal(t, 1, reported, "exactly one of the racing refusals moved the count to the limit")
		assert.EqualValues(t, record.OtpConsecutiveFailureLimit, reloadUser(t, read.Id).OtpConsecutiveFailures,
			"no refusal below the limit is lost, and none carries the count past it")
	})

	t.Run("the increment charges nothing to an authenticator other than the one read", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			moved func(t *testing.T, read *record.User)
		}{
			{"the authenticator was removed", func(t *testing.T, read *record.User) {
				removed, err := database.TryRemoveUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration)
				require.NoError(t, err)
				require.True(t, removed)
			}},
			{"the authenticator was replaced", func(t *testing.T, read *record.User) {
				advanceGenerationUnder(t, read.Id)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				read := otpStateUser(t, true)
				tc.moved(t, read)

				disabled, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
				require.NoError(t, err, "a row that no longer matches is not an error")
				assert.False(t, disabled)
				assert.EqualValues(t, 0, reloadUser(t, read.Id).OtpConsecutiveFailures,
					"a code checked against one authenticator is never counted against another")
			})
		}
	})

	t.Run("the increment leaves updated_at alone", func(t *testing.T) {
		read := otpStateUser(t, true)

		_, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
		require.NoError(t, err)

		after := reloadUser(t, read.Id)
		require.EqualValues(t, 1, after.OtpConsecutiveFailures)
		assert.True(t, read.UpdatedAt.Time.Equal(after.UpdatedAt.Time),
			"a refused code is not an edit of the account: updated_at is %v and was %v",
			after.UpdatedAt.Time, read.UpdatedAt.Time)
	})

	t.Run("the verification claim clears the count beside the step it claims", func(t *testing.T) {
		read := otpStateUser(t, true)
		_, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
		require.NoError(t, err)

		claimed, err := database.TryConsumeEnrolledUserOTPStep(ctx, nil, read.Id, nowStep(), read.OtpConfigGeneration)
		require.NoError(t, err)
		require.True(t, claimed, "a fresh step at the generation read must claim")

		user, err := database.GetUserById(ctx, nil, read.Id)
		require.NoError(t, err)
		assert.EqualValues(t, 0, user.OtpConsecutiveFailures,
			"a successful verification disregards the attempts before it (NIST SP 800-63B 3.2.2)")
	})

	t.Run("the verification claim refuses while the count stands at the limit", func(t *testing.T) {
		read := otpStateUser(t, true)
		for i := 0; i < record.OtpConsecutiveFailureLimit; i++ {
			_, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
			require.NoError(t, err)
		}

		claimed, err := database.TryConsumeEnrolledUserOTPStep(ctx, nil, read.Id, nowStep(), read.OtpConfigGeneration)
		require.NoError(t, err)
		assert.False(t, claimed,
			"at the limit the authenticator is disabled: even a fresh code claims nothing until it is rebound")

		user, err := database.GetUserById(ctx, nil, read.Id)
		require.NoError(t, err)
		assert.EqualValues(t, record.OtpConsecutiveFailureLimit, user.OtpConsecutiveFailures,
			"a refused claim must not clear the count it refused on")
	})

	t.Run("the rebind's clear runs in a transaction and returns the count to 0", func(t *testing.T) {
		read := otpStateUser(t, true)
		for i := 0; i < record.OtpConsecutiveFailureLimit; i++ {
			_, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
			require.NoError(t, err)
		}

		require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			return database.ClearUserOtpConsecutiveFailures(ctx, tx, read.Id)
		}), "the clear is Establish's rebind clear, and must commit in the establish's transaction")

		user, err := database.GetUserById(ctx, nil, read.Id)
		require.NoError(t, err)
		assert.EqualValues(t, 0, user.OtpConsecutiveFailures,
			"a rebound authenticator starts at no failed attempts against it")
	})

	t.Run("the clear refuses to run outside a transaction and leaves the count", func(t *testing.T) {
		read := otpStateUser(t, true)
		for i := 0; i < record.OtpConsecutiveFailureLimit; i++ {
			_, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id, read.OtpConfigGeneration)
			require.NoError(t, err)
		}

		require.Error(t, database.ClearUserOtpConsecutiveFailures(ctx, nil, read.Id),
			"a clear that could commit apart from the rebind must be refused")

		assert.EqualValues(t, record.OtpConsecutiveFailureLimit, reloadUser(t, read.Id).OtpConsecutiveFailures,
			"the refused clear writes nothing")
	})
}

// TestUpdateUser_DoesNotClobberOtpConsecutiveFailures is the users-table half of the dont-update
// tag, the sibling of TestUpdateUser_DoesNotClobberOtpConfigGeneration. A whole-row write from a
// model read before the count reached the limit must not write the earlier count back, which
// would silently unlock a disabled authenticator (#489).
func TestUpdateUser_DoesNotClobberOtpConsecutiveFailures(t *testing.T) {
	ctx := context.Background()
	stale := otpStateUser(t, true)
	require.EqualValues(t, 0, stale.OtpConsecutiveFailures)

	for i := 0; i < record.OtpConsecutiveFailureLimit; i++ {
		_, err := database.IncrementUserOtpConsecutiveFailures(ctx, nil, stale.Id, stale.OtpConfigGeneration)
		require.NoError(t, err)
	}

	stale.GivenName = "edited-" + stale.GivenName
	require.NoError(t, database.UpdateUser(ctx, nil, stale), "UpdateUser")

	after := reloadUser(t, stale.Id)
	assert.EqualValues(t, record.OtpConsecutiveFailureLimit, after.OtpConsecutiveFailures,
		"UpdateUser must not carry otp_consecutive_failures; is the dont-update tag missing?")
	assert.Equal(t, stale.GivenName, after.GivenName, "the rest of the update must still apply")
}

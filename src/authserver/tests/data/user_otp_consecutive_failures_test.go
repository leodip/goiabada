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
//     row no longer matches, so grinding a disabled authenticator moves nothing;
//   - the verification claim (TryConsumeEnrolledUserOTPStep) clears it, in the same
//     statement that claims the step, and refuses while it stands at the limit;
//   - ClearUserOtpConsecutiveFailures returns it to 0, the rebind's clear, which only
//     runs inside a transaction.
func TestOtpConsecutiveFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("the increment advances and stops at the limit", func(t *testing.T) {
		read := otpStateUser(t, true)

		for i := 0; i < record.OtpConsecutiveFailureLimit; i++ {
			require.NoError(t, database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id),
				"increment %d", i+1)
		}
		require.NoError(t, database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id),
			"one increment beyond the limit is not an error: the row no longer matches")

		user, err := database.GetUserById(ctx, nil, read.Id)
		require.NoError(t, err, "read the user back")
		assert.EqualValues(t, record.OtpConsecutiveFailureLimit, user.OtpConsecutiveFailures,
			"the count must stop at the limit rather than keep rising")
	})

	t.Run("the verification claim clears the count beside the step it claims", func(t *testing.T) {
		read := otpStateUser(t, true)
		require.NoError(t, database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id))

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
			require.NoError(t, database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id))
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
			require.NoError(t, database.IncrementUserOtpConsecutiveFailures(ctx, nil, read.Id))
		}

		require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			return database.ClearUserOtpConsecutiveFailures(ctx, tx, read.Id)
		}), "the clear is Establish's rebind clear, and must commit in the establish's transaction")

		user, err := database.GetUserById(ctx, nil, read.Id)
		require.NoError(t, err)
		assert.EqualValues(t, 0, user.OtpConsecutiveFailures,
			"a rebound authenticator starts at no failed attempts against it")
	})
}

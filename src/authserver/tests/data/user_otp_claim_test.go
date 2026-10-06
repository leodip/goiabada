package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/leodip/goiabada/authserver/internal/otpcredential"
)

// The step claim of an enrolled user's passcode, bound to the authenticator the passcode was
// checked against (#471 decision 3, #144's verification half).
//
// The claim used to match while otp_enabled was on, whatever authenticator that now meant: a
// passcode checked against a secret that was removed, and another established in its place,
// between the read and the claim, still claimed its step and asserted otp. It now matches only at
// the otp_config_generation read with the secret, which every establish and remove advances.

func TestTryConsumeEnrolledUserOTPStep(t *testing.T) {
	ctx := context.Background()

	t.Run("lands while OTP is on at the generation read", func(t *testing.T) {
		read := otpStateUser(t, true)
		step := nowStep()

		claimed, err := database.TryConsumeEnrolledUserOTPStep(ctx, nil, read.Id, step, read.OtpConfigGeneration)
		if err != nil || !claimed {
			t.Fatalf("TryConsumeEnrolledUserOTPStep: claimed=%v err=%v, want true and no error", claimed, err)
		}
		if got := reloadUser(t, read.Id).LastOTPStep; got != step {
			t.Errorf("last_otp_step = %d, want %d", got, step)
		}
	})

	t.Run("refuses an authenticator whose generation moved since it was read", func(t *testing.T) {
		read := otpStateUser(t, true)
		advanceGenerationUnder(t, read.Id)
		moved := reloadUser(t, read.Id)

		claimed, err := database.TryConsumeEnrolledUserOTPStep(ctx, nil, read.Id, nowStep(), read.OtpConfigGeneration)
		if err != nil {
			t.Fatalf("TryConsumeEnrolledUserOTPStep failed: %v", err)
		}
		if claimed {
			t.Error("a passcode checked against an authenticator read before it was replaced claimed its step")
		}
		if got := reloadUser(t, read.Id).LastOTPStep; got != moved.LastOTPStep {
			t.Errorf("last_otp_step = %d, want %d: a refused claim must leave the marker", got, moved.LastOTPStep)
		}
	})

	t.Run("refuses OTP off at the generation read", func(t *testing.T) {
		read := otpStateUser(t, true)
		// The narrow removal alone, which turns otp_enabled off and leaves the generation where it
		// was, so only the otp_enabled term can refuse the claim below.
		removed, err := database.TryRemoveUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration)
		if err != nil || !removed {
			t.Fatalf("the removal must land: removed=%v err=%v", removed, err)
		}
		if got := reloadUser(t, read.Id).OtpConfigGeneration; got != read.OtpConfigGeneration {
			t.Fatalf("OtpConfigGeneration = %d, want %d: the removal alone must not move it", got, read.OtpConfigGeneration)
		}

		claimed, err := database.TryConsumeEnrolledUserOTPStep(ctx, nil, read.Id, nowStep(), read.OtpConfigGeneration)
		if err != nil {
			t.Fatalf("TryConsumeEnrolledUserOTPStep failed: %v", err)
		}
		if claimed {
			t.Error("a verification claim landed on an account whose authenticator is off")
		}
		if got := reloadUser(t, read.Id).LastOTPStep; got != 0 {
			t.Errorf("last_otp_step = %d, want 0: a refused claim must leave the marker", got)
		}
	})

	t.Run("refuses a step at or below the one stored", func(t *testing.T) {
		read := otpStateUser(t, true)
		step := nowStep()
		claimed, err := database.TryConsumeEnrolledUserOTPStep(ctx, nil, read.Id, step, read.OtpConfigGeneration)
		if err != nil || !claimed {
			t.Fatalf("the first claim must land: claimed=%v err=%v", claimed, err)
		}

		for _, replayed := range []int64{step, step - 1} {
			again, err := database.TryConsumeEnrolledUserOTPStep(ctx, nil, read.Id, replayed, read.OtpConfigGeneration)
			if err != nil {
				t.Fatalf("claim of step %d errored instead of being refused: %v", replayed, err)
			}
			if again {
				t.Errorf("step %d was claimed with %d already stored", replayed, step)
			}
		}
	})

	t.Run("of overlapping claims from one read exactly one lands", func(t *testing.T) {
		skipOnSQLite(t)

		read := otpStateUser(t, true)
		base := nowStep()
		for round := 0; round < raceRounds; round++ {
			step := base + int64(round) + 1
			won := raceOnce(t, raceCallers, func(int) (bool, error) {
				return database.TryConsumeEnrolledUserOTPStep(ctx, nil, read.Id, step, read.OtpConfigGeneration)
			})
			if won != 1 {
				t.Fatalf("round %d: %d claims of step %d landed from one read, want exactly 1", round, won, step)
			}
		}
	})

	t.Run("refuses user id 0", func(t *testing.T) {
		if _, err := database.TryConsumeEnrolledUserOTPStep(ctx, nil, 0, nowStep(), 0); err == nil {
			t.Error("expected an error consuming an OTP step for user id 0")
		}
	})
}

// TestVerifyStored_RefusesAPasscodeCheckedAgainstAReplacedAuthenticator is #144's verification half
// end to end: the request reads the user and its secret, the authenticator is removed and another
// established in its place, and the passcode the request checked against the first secret is then
// refused rather than asserting otp for an authenticator that no longer exists.
//
// The removal returns the consumed-step marker to 0 and the replacement turns otp_enabled back on,
// so a claim bound to otp_enabled alone lands here; only the generation term refuses it.
func TestVerifyStored_RefusesAPasscodeCheckedAgainstAReplacedAuthenticator(t *testing.T) {
	ctx := context.Background()
	const firstSeed = "ZP2Z5KXRBAPPHWXEHH65PY5H7EKLVHRZ"
	const replacementSeed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

	enrolled := func(t *testing.T) int64 {
		t.Helper()
		user := otpStateUser(t, false)
		_, established, err := otpcredential.Establish(ctx, database, dataCipher, user, firstSeed)
		if err != nil || !established {
			t.Fatalf("the first authenticator must establish: established=%v err=%v", established, err)
		}
		return user.Id
	}
	codeFor := func(t *testing.T, seed string, now time.Time) string {
		t.Helper()
		code, err := totp.GenerateCode(seed, now)
		if err != nil {
			t.Fatalf("totp.GenerateCode: %v", err)
		}
		return code
	}

	t.Run("the authenticator read is still the one enrolled", func(t *testing.T) {
		read := reloadUser(t, enrolled(t))
		now := time.Now().UTC()

		result, err := otpcredential.VerifyStored(ctx, database, dataCipher, read, codeFor(t, firstSeed, now), now)
		if err != nil {
			t.Fatalf("VerifyStored failed: %v", err)
		}
		if result.Outcome != otpcredential.OutcomeMatched {
			t.Errorf("Outcome = %v, want OutcomeMatched", result.Outcome)
		}
	})

	t.Run("the authenticator read was replaced under the request", func(t *testing.T) {
		userId := enrolled(t)
		read := reloadUser(t, userId)

		removed, err := otpcredential.Remove(ctx, database, reloadUser(t, userId))
		if err != nil || !removed {
			t.Fatalf("the removal must land: removed=%v err=%v", removed, err)
		}
		_, established, err := otpcredential.Establish(ctx, database, dataCipher, reloadUser(t, userId), replacementSeed)
		if err != nil || !established {
			t.Fatalf("the replacement must establish: established=%v err=%v", established, err)
		}
		replaced := reloadUser(t, userId)
		if !replaced.OTPEnabled || replaced.LastOTPStep != 0 {
			t.Fatalf("the replaced row reads otp_enabled=%v last_otp_step=%d, want true and 0",
				replaced.OTPEnabled, replaced.LastOTPStep)
		}

		now := time.Now().UTC()
		result, err := otpcredential.VerifyStored(ctx, database, dataCipher, read, codeFor(t, firstSeed, now), now)
		if err != nil {
			t.Fatalf("VerifyStored failed: %v", err)
		}
		if result.Outcome == otpcredential.OutcomeMatched {
			t.Error("a passcode checked against the removed authenticator was accepted as a second factor")
		}
		if got := reloadUser(t, userId).LastOTPStep; got != 0 {
			t.Errorf("last_otp_step = %d, want 0: the refused claim must not spend a step of the replacement", got)
		}

		// The replacement itself verifies from a read of it.
		result, err = otpcredential.VerifyStored(ctx, database, dataCipher, replaced, codeFor(t, replacementSeed, now), now)
		if err != nil {
			t.Fatalf("VerifyStored of the replacement failed: %v", err)
		}
		if result.Outcome != otpcredential.OutcomeMatched {
			t.Errorf("the replacement's own passcode: Outcome = %v, want OutcomeMatched", result.Outcome)
		}
	})
}

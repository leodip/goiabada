package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// Establishing and removing an authenticator as compare-and-sets on the authenticator (#471
// decision 2, #144's enrolment half).
//
// Both wrote back, through UpdateUser, the whole row the request read at its start, so a disable
// or a password change made in between was undone, and two overlapping enrolments both succeeded,
// the later secret replacing the earlier. Each now writes the seed and otp_enabled alone, and only
// while OTP is still in the state the request read at the otp_config_generation it read: the
// generation term is what sees an enable and a disable landing entirely between the read and the
// write, which otp_enabled alone would not.

// otpStateUser seeds an enabled user whose authenticator is on or off, with a seed when on, and
// returns the row as a request would read it at its start.
func otpStateUser(t *testing.T, otpEnabled bool) *record.User {
	t.Helper()
	seeded := enabledTestUser(t, func(user *record.User) {
		user.OTPEnabled = otpEnabled
		user.OTPSecretEncrypted = nil
		if otpEnabled {
			user.OTPSecretEncrypted = []byte("the-enrolled-seed-" + fake.LetterN(12))
		}
	})
	return reloadUser(t, seeded.Id)
}

// disableAndChangePasswordUnder makes the two concurrent changes no OTP write may undo: an
// administrator's disable and a password change, each through its own narrow write. It returns the
// hash the change stored.
func disableAndChangePasswordUnder(t *testing.T, userId int64) string {
	t.Helper()
	ctx := context.Background()
	disabled, err := database.TrySetUserEnabled(ctx, nil, userId, true, false)
	if err != nil || !disabled {
		t.Fatalf("the concurrent disable must take effect: disabled=%v err=%v", disabled, err)
	}
	newHash := "changed-under-the-otp-write-" + fake.Password(32)
	if err = database.SetUserPasswordHash(ctx, nil, userId, newHash); err != nil {
		t.Fatalf("the concurrent password change must take effect: %v", err)
	}
	return newHash
}

// advanceGenerationUnder moves otp_config_generation on without touching otp_enabled, which is
// what an enable and a disable landing between the read and the write leave behind.
func advanceGenerationUnder(t *testing.T, userId int64) {
	t.Helper()
	tx, err := database.BeginTransaction(context.Background())
	if err != nil {
		t.Fatalf("BeginTransaction: %v", err)
	}
	if _, err = database.IncrementUserOtpConfigGeneration(context.Background(), tx, userId); err != nil {
		_ = database.RollbackTransaction(context.Background(), tx)
		t.Fatalf("IncrementUserOtpConfigGeneration: %v", err)
	}
	if err = database.CommitTransaction(context.Background(), tx); err != nil {
		t.Fatalf("CommitTransaction: %v", err)
	}
}

func TestTryEstablishUserOTP(t *testing.T) {
	ctx := context.Background()

	t.Run("lands while OTP is off at the generation read, and a disable and a password change survive", func(t *testing.T) {
		read := otpStateUser(t, false)
		newHash := disableAndChangePasswordUnder(t, read.Id)
		moved := reloadUser(t, read.Id)

		seed := []byte("the-new-seed-" + fake.LetterN(16))
		established, err := database.TryEstablishUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration, seed)
		if err != nil || !established {
			t.Fatalf("TryEstablishUserOTP: established=%v err=%v, want true and no error", established, err)
		}

		after := reloadUser(t, read.Id)
		expected := *moved
		expected.OTPEnabled = true
		expected.OTPSecretEncrypted = seed
		compareUsers(t, &expected, after)
		if after.Enabled {
			t.Error("the establish re-enabled an account an administrator disabled under it")
		}
		if after.PasswordHash != newHash {
			t.Error("the establish put back a password hash replaced under it")
		}
		if after.OtpConfigGeneration != moved.OtpConfigGeneration {
			t.Errorf("OtpConfigGeneration = %d, want %d: the advance is the caller's, in the same transaction",
				after.OtpConfigGeneration, moved.OtpConfigGeneration)
		}
	})

	t.Run("refuses an authenticator already on at the generation read", func(t *testing.T) {
		read := otpStateUser(t, true)

		established, err := database.TryEstablishUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration,
			[]byte("a-second-seed-"+fake.LetterN(16)))
		if err != nil {
			t.Fatalf("TryEstablishUserOTP failed: %v", err)
		}
		if established {
			t.Error("a second authenticator was installed over the first")
		}
		compareUsers(t, read, reloadUser(t, read.Id))
	})

	t.Run("refuses OTP off at a generation that moved since it was read", func(t *testing.T) {
		read := otpStateUser(t, false)
		advanceGenerationUnder(t, read.Id)
		moved := reloadUser(t, read.Id)

		established, err := database.TryEstablishUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration,
			[]byte("a-stale-seed-"+fake.LetterN(16)))
		if err != nil {
			t.Fatalf("TryEstablishUserOTP failed: %v", err)
		}
		if established {
			t.Error("an enrolment read before an enable and a disable landed was installed over them")
		}
		after := reloadUser(t, read.Id)
		compareUsers(t, moved, after)
		if after.OtpConfigGeneration != moved.OtpConfigGeneration {
			t.Errorf("OtpConfigGeneration = %d, want %d", after.OtpConfigGeneration, moved.OtpConfigGeneration)
		}
	})

	t.Run("of overlapping enrolments from one read exactly one lands, and its seed is the one stored", func(t *testing.T) {
		skipOnSQLite(t)

		for round := 0; round < raceRounds; round++ {
			read := otpStateUser(t, false)
			seeds := make([][]byte, raceCallers)
			for i := range seeds {
				seeds[i] = []byte("racing-seed-" + fake.LetterN(16))
			}
			landed := make([]bool, raceCallers)
			won := raceOnce(t, raceCallers, func(i int) (bool, error) {
				established, err := database.TryEstablishUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration, seeds[i])
				landed[i] = established
				return established, err
			})
			if won != 1 {
				t.Fatalf("round %d: %d enrolments landed from one read, want exactly 1", round, won)
			}
			winner := 0
			for i := range landed {
				if landed[i] {
					winner = i
				}
			}
			if got := reloadUser(t, read.Id).OTPSecretEncrypted; string(got) != string(seeds[winner]) {
				t.Fatalf("round %d: the stored seed is not the winner's", round)
			}
		}
	})

	t.Run("refuses user id 0 and an empty seed", func(t *testing.T) {
		if _, err := database.TryEstablishUserOTP(ctx, nil, 0, 0, []byte("x")); err == nil {
			t.Error("expected an error establishing OTP for user id 0")
		}
		if _, err := database.TryEstablishUserOTP(ctx, nil, 1, 0, nil); err == nil {
			t.Error("expected an error establishing an empty seed")
		}
	})
}

func TestTryRemoveUserOTP(t *testing.T) {
	ctx := context.Background()

	t.Run("lands while OTP is on at the generation read, and a disable and a password change survive", func(t *testing.T) {
		read := otpStateUser(t, true)
		newHash := disableAndChangePasswordUnder(t, read.Id)
		moved := reloadUser(t, read.Id)

		removed, err := database.TryRemoveUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration)
		if err != nil || !removed {
			t.Fatalf("TryRemoveUserOTP: removed=%v err=%v, want true and no error", removed, err)
		}

		after := reloadUser(t, read.Id)
		expected := *moved
		expected.OTPEnabled = false
		expected.OTPSecretEncrypted = nil
		compareUsers(t, &expected, after)
		if len(after.OTPSecretEncrypted) != 0 {
			t.Error("the seed must go with the authenticator")
		}
		if after.Enabled {
			t.Error("the removal re-enabled an account an administrator disabled under it")
		}
		if after.PasswordHash != newHash {
			t.Error("the removal put back a password hash replaced under it")
		}
		if after.OtpConfigGeneration != moved.OtpConfigGeneration {
			t.Errorf("OtpConfigGeneration = %d, want %d", after.OtpConfigGeneration, moved.OtpConfigGeneration)
		}
	})

	t.Run("refuses an authenticator already off at the generation read", func(t *testing.T) {
		read := otpStateUser(t, false)

		removed, err := database.TryRemoveUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration)
		if err != nil {
			t.Fatalf("TryRemoveUserOTP failed: %v", err)
		}
		if removed {
			t.Error("a removal reported success on an account with no authenticator")
		}
		compareUsers(t, read, reloadUser(t, read.Id))
	})

	t.Run("refuses an authenticator replaced since it was read", func(t *testing.T) {
		read := otpStateUser(t, true)
		// The authenticator read was removed and another established in its place: still on,
		// another seed, the generation moved.
		replaced := reloadUser(t, read.Id)
		replaced.OTPSecretEncrypted = []byte("the-replacement-seed-" + fake.LetterN(12))
		if err := database.UpdateUser(ctx, nil, replaced); err != nil {
			t.Fatalf("Failed to replace the authenticator: %v", err)
		}
		advanceGenerationUnder(t, read.Id)
		moved := reloadUser(t, read.Id)

		removed, err := database.TryRemoveUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration)
		if err != nil {
			t.Fatalf("TryRemoveUserOTP failed: %v", err)
		}
		if removed {
			t.Error("a removal read before the authenticator was replaced removed the replacement")
		}
		compareUsers(t, moved, reloadUser(t, read.Id))
	})

	t.Run("of overlapping removals from one read exactly one lands", func(t *testing.T) {
		skipOnSQLite(t)

		for round := 0; round < raceRounds; round++ {
			read := otpStateUser(t, true)
			won := raceOnce(t, raceCallers, func(int) (bool, error) {
				return database.TryRemoveUserOTP(ctx, nil, read.Id, read.OtpConfigGeneration)
			})
			if won != 1 {
				t.Fatalf("round %d: %d removals landed from one read, want exactly 1", round, won)
			}
		}
	})

	t.Run("refuses user id 0", func(t *testing.T) {
		if _, err := database.TryRemoveUserOTP(ctx, nil, 0, 0); err == nil {
			t.Error("expected an error removing OTP for user id 0")
		}
	})
}

// The compare-and-sets inside the operations that own them: a lost one writes nothing else either,
// so the generation does not advance, a pending enrolment is not cleared and the consumed-step
// marker is not reset for an authenticator this request did not change.
func TestOtpCredential_ALostCompareAndSetWritesNothing(t *testing.T) {
	ctx := context.Background()
	const enrolledSeed = "ZP2Z5KXRBAPPHWXEHH65PY5H7EKLVHRZ"

	t.Run("establish", func(t *testing.T) {
		read := otpStateUser(t, false)
		now := time.Now().UTC().Truncate(time.Microsecond)
		pending := encryptedKeyURL(t, "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
		installed, err := database.TryInstallPendingOTPEnrollment(ctx, nil, read.Id, pending, now, now.Add(-15*time.Minute))
		if err != nil || !installed {
			t.Fatalf("the pending enrolment must install: installed=%v err=%v", installed, err)
		}
		read = reloadUser(t, read.Id)

		// Another enrolment wins from the same read.
		winning := reloadUser(t, read.Id)
		_, established, err := otpcredential.Establish(ctx, database, dataCipher, winning, enrolledSeed)
		if err != nil || !established {
			t.Fatalf("the first enrolment must land: established=%v err=%v", established, err)
		}
		won := reloadUser(t, read.Id)

		generation, established, err := otpcredential.Establish(ctx, database, dataCipher, read, enrolledSeed)
		if err != nil {
			t.Fatalf("Establish failed: %v", err)
		}
		if established || generation != 0 {
			t.Errorf("the losing enrolment reported established=%v generation=%d, want false and 0", established, generation)
		}
		after := reloadUser(t, read.Id)
		compareUsers(t, won, after)
		if after.OtpConfigGeneration != won.OtpConfigGeneration {
			t.Errorf("OtpConfigGeneration = %d, want %d: a lost enrolment must not advance it",
				after.OtpConfigGeneration, won.OtpConfigGeneration)
		}
	})

	t.Run("establish leaves the pending enrolment when it loses", func(t *testing.T) {
		read := otpStateUser(t, false)
		advanceGenerationUnder(t, read.Id)
		now := time.Now().UTC().Truncate(time.Microsecond)
		pending := encryptedKeyURL(t, "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
		installed, err := database.TryInstallPendingOTPEnrollment(ctx, nil, read.Id, pending, now, now.Add(-15*time.Minute))
		if err != nil || !installed {
			t.Fatalf("the pending enrolment must install: installed=%v err=%v", installed, err)
		}

		_, established, err := otpcredential.Establish(ctx, database, dataCipher, read, enrolledSeed)
		if err != nil || established {
			t.Fatalf("Establish from a stale generation: established=%v err=%v, want false and no error", established, err)
		}
		if got := reloadUser(t, read.Id).OtpEnrollmentSecretEncrypted; string(got) != string(pending) {
			t.Error("a lost enrolment cleared a pending enrolment it did not complete")
		}
	})

	t.Run("remove", func(t *testing.T) {
		read := otpStateUser(t, true)
		consumed, err := database.TryConsumeUserOTPStep(ctx, nil, read.Id, 1000, true)
		if err != nil || !consumed {
			t.Fatalf("the step claim must land: consumed=%v err=%v", consumed, err)
		}
		advanceGenerationUnder(t, read.Id)
		moved := reloadUser(t, read.Id)

		removed, err := otpcredential.Remove(ctx, database, read)
		if err != nil {
			t.Fatalf("Remove failed: %v", err)
		}
		if removed {
			t.Error("a removal read before the authenticator changed reported success")
		}
		after := reloadUser(t, read.Id)
		compareUsers(t, moved, after)
		if after.OtpConfigGeneration != moved.OtpConfigGeneration {
			t.Errorf("OtpConfigGeneration = %d, want %d: a lost removal must not advance it",
				after.OtpConfigGeneration, moved.OtpConfigGeneration)
		}
		if after.LastOTPStep != moved.LastOTPStep {
			t.Errorf("LastOTPStep = %d, want %d: a lost removal must not reset the marker",
				after.LastOTPStep, moved.LastOTPStep)
		}
	})
}

package datatests

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// The administrator's two email writes, and the reset code both email changes clear (#471).
//
// The administrator's email change and verification code generation each wrote back, through
// UpdateUser, the whole row the request read at its start, so a disable, a password change or an
// OTP change made in between was undone. SetUserEmail now writes the address group alone; the code
// generation stores only while the account still holds the address the request read, since it
// reports that address. Both email changes, the administrator's and the account's own, also clear
// any outstanding reset code: a code belongs to the address it was mailed to, and a link mailed to
// the previous address, an administrator's setup email to a mistyped address included, must stop
// setting the account's password.

// stressedRead is a user read as a request would read it at its start, then moved under it: an
// administrator's disable, a password change and an OTP change, each through a write of its own.
// It returns the read and the row as the concurrent changes left it.
func stressedRead(t *testing.T, seed func(user *record.User)) (read *record.User, moved *record.User, newHash string) {
	t.Helper()
	ctx := context.Background()
	seeded := enabledTestUser(t, seed)

	read, err := database.GetUserById(ctx, nil, seeded.Id)
	if err != nil || read == nil {
		t.Fatalf("Failed to read the user: user=%v err=%v", read, err)
	}

	disabled, err := database.TrySetUserEnabled(ctx, nil, read.Id, true, false)
	if err != nil || !disabled {
		t.Fatalf("the concurrent disable must take effect: disabled=%v err=%v", disabled, err)
	}
	newHash = "changed-under-the-save-" + fake.Password(32)
	if err = database.SetUserPasswordHash(ctx, nil, read.Id, newHash); err != nil {
		t.Fatalf("the concurrent password change must take effect: %v", err)
	}
	changeOTPUnder(t, read.Id)

	moved, err = database.GetUserById(ctx, nil, read.Id)
	if err != nil || moved == nil {
		t.Fatalf("Failed to reload the user: user=%v err=%v", moved, err)
	}
	if moved.Enabled || moved.PasswordHash != newHash || moved.OTPEnabled == read.OTPEnabled ||
		moved.OtpConfigGeneration == read.OtpConfigGeneration {
		t.Fatal("the concurrent changes did not land, so the case would prove nothing")
	}
	return read, moved, newHash
}

// assertConcurrentChangesSurvived holds the three columns groups no email write may touch to what
// the concurrent changes left in them.
func assertConcurrentChangesSurvived(t *testing.T, moved, after *record.User, newHash string) {
	t.Helper()
	if after.Enabled {
		t.Error("the write re-enabled an account an administrator disabled under it")
	}
	if after.PasswordHash != newHash {
		t.Error("the write put back a password hash replaced under it")
	}
	if after.OTPEnabled != moved.OTPEnabled || string(after.OTPSecretEncrypted) != string(moved.OTPSecretEncrypted) {
		t.Error("the write reversed an OTP change made under it")
	}
	if after.OtpConfigGeneration != moved.OtpConfigGeneration {
		t.Errorf("OtpConfigGeneration = %d, want %d", after.OtpConfigGeneration, moved.OtpConfigGeneration)
	}
	if after.AuthStateGeneration != moved.AuthStateGeneration {
		t.Errorf("AuthStateGeneration = %d, want %d", after.AuthStateGeneration, moved.AuthStateGeneration)
	}
}

func TestSetUserEmail_ConcurrentDisablePasswordAndOTPChangesSurvive(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verified bool
	}{
		// The fixture's flag starts opposite to what the save writes, so a skipped column shows.
		{"saved verified", true},
		{"saved unverified", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			read, moved, newHash := stressedRead(t, func(user *record.User) { user.EmailVerified = !tc.verified })
			if len(moved.EmailVerificationCodeEncrypted) == 0 || !moved.EmailVerificationCodeIssuedAt.Valid {
				t.Fatal("the fixture must hold a pending verification code, or its clear proves nothing")
			}

			newEmail := "admin_set_" + fake.Email()
			beforeSave := time.Now().UTC().Truncate(time.Second)
			read.Email = newEmail
			read.EmailVerified = tc.verified
			if err := database.SetUserEmail(ctx, nil, read); err != nil {
				t.Fatalf("SetUserEmail failed: %v", err)
			}

			after, err := database.GetUserById(ctx, nil, read.Id)
			if err != nil || after == nil {
				t.Fatalf("Failed to reload the saved user: user=%v err=%v", after, err)
			}

			// Its own columns landed, the pending verification code with its issued-at is gone, and
			// every other column holds what the concurrent changes left.
			expected := *moved
			expected.Email = newEmail
			expected.EmailVerified = tc.verified
			expected.EmailVerificationCodeEncrypted = nil
			expected.EmailVerificationCodeIssuedAt = sql.NullTime{}
			compareUsers(t, &expected, after)
			if after.EmailVerificationCodeIssuedAt.Valid {
				t.Error("the verification code's issued-at must be cleared with the code")
			}
			assertConcurrentChangesSurvived(t, moved, after, newHash)

			if !after.UpdatedAt.Valid || after.UpdatedAt.Time.Before(beforeSave) {
				t.Errorf("updated_at = %v, want a time not before %v", after.UpdatedAt, beforeSave)
			}
			if diff := read.UpdatedAt.Time.Sub(after.UpdatedAt.Time).Abs(); !read.UpdatedAt.Valid || diff > time.Microsecond {
				t.Errorf("the saved user's UpdatedAt = %v, want the stored %v", read.UpdatedAt, after.UpdatedAt)
			}
		})
	}
}

// emailChange is one of the two email changes, each from the user as its request read it.
type emailChange struct {
	name   string
	change func(t *testing.T, read *record.User, toEmail string)
}

var emailChanges = []emailChange{
	{
		name: "the administrator's",
		change: func(t *testing.T, read *record.User, toEmail string) {
			t.Helper()
			read.Email = toEmail
			read.EmailVerified = true
			if err := database.SetUserEmail(context.Background(), nil, read); err != nil {
				t.Fatalf("SetUserEmail failed: %v", err)
			}
		},
	},
	{
		name: "the account's own",
		change: func(t *testing.T, read *record.User, toEmail string) {
			t.Helper()
			changed, err := database.TrySetUserEmail(context.Background(), nil, read.Id, read.Email, read.EmailVerified, toEmail)
			if err != nil || !changed {
				t.Fatalf("TrySetUserEmail: changed=%v err=%v, want true and no error", changed, err)
			}
		},
	},
}

// TestEmailChanges_ClearAnOutstandingResetCode is decision 6 of #471 at the row: after either
// email change the reset code, its hash and its issued-at are gone, so the link mailed to the
// previous address finds no account.
func TestEmailChanges_ClearAnOutstandingResetCode(t *testing.T) {
	for _, c := range emailChanges {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			user, hash := createUserWithResetCode(t)
			read, err := database.GetUserById(ctx, nil, user.Id)
			if err != nil || read == nil {
				t.Fatalf("Failed to read the user: user=%v err=%v", read, err)
			}
			if found, findErr := database.GetUserByForgotPasswordCodeHash(ctx, nil, hash); findErr != nil || found == nil {
				t.Fatalf("the fixture's code must be findable before the change: found=%v err=%v", found, findErr)
			}

			c.change(t, read, "moved_"+fake.Email())

			after, err := database.GetUserById(ctx, nil, user.Id)
			if err != nil || after == nil {
				t.Fatalf("Failed to reload the user: user=%v err=%v", after, err)
			}
			if len(after.ForgotPasswordCodeEncrypted) != 0 {
				t.Error("the reset code must be cleared: it was mailed to the previous address")
			}
			if after.ForgotPasswordCodeIssuedAt.Valid {
				t.Error("the reset code's issued-at must be cleared with it")
			}
			if after.ForgotPasswordCodeHash != "" {
				t.Errorf("ForgotPasswordCodeHash = %q, want the dormant ''", after.ForgotPasswordCodeHash)
			}
			found, err := database.GetUserByForgotPasswordCodeHash(ctx, nil, hash)
			if err != nil {
				t.Fatalf("lookup by the cleared hash failed: %v", err)
			}
			if found != nil {
				t.Error("the link mailed to the previous address still finds the account")
			}
		})
	}
}

func TestSetUserEmail_Refusals(t *testing.T) {
	t.Run("user id 0", func(t *testing.T) {
		if err := database.SetUserEmail(context.Background(), nil, &record.User{Email: fake.Email()}); err == nil {
			t.Error("expected an error setting the email of user id 0")
		}
	})

	t.Run("a taken address is ErrUniqueViolation", func(t *testing.T) {
		first := createTestUser(t)
		defer func() { _ = database.DeleteUser(context.Background(), nil, first.Id) }()
		second := createTestUser(t)
		defer func() { _ = database.DeleteUser(context.Background(), nil, second.Id) }()

		second.Email = first.Email
		err := database.SetUserEmail(context.Background(), nil, second)
		if err == nil {
			t.Fatal("a user was moved onto a taken email; users.email is supposed to be unique")
		}
		if !errors.Is(err, data.ErrUniqueViolation) {
			t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false for SetUserEmail on this engine, "+
				"so the administrator's email PUT cannot answer 409 here; err = %v", err)
		}
	})
}

// TestTryIssueEmailVerificationCode pins the administrator's code generation: it stores the code
// and its issued-at and unverifies the address, only while the account holds the address the
// request read, and writes nothing else.
func TestTryIssueEmailVerificationCode(t *testing.T) {
	ctx := context.Background()

	t.Run("the account still holds the address read", func(t *testing.T) {
		user := seedEmailState(t, true, []byte("an-older-ciphertext"), issuedAgo(time.Minute))

		now := time.Now().UTC().Truncate(time.Microsecond)
		code := []byte("fresh-ciphertext-" + fake.LetterN(16))
		stored, err := database.TryIssueEmailVerificationCode(ctx, nil, user.Id, user.Email, code, now)
		if err != nil || !stored {
			t.Fatalf("TryIssueEmailVerificationCode: stored=%v err=%v, want true and no error", stored, err)
		}

		after, err := database.GetUserById(ctx, nil, user.Id)
		if err != nil {
			t.Fatalf("Failed to reload user: %v", err)
		}
		expected := *user
		expected.EmailVerified = false
		expected.EmailVerificationCodeEncrypted = code
		expected.EmailVerificationCodeIssuedAt = sql.NullTime{Time: now, Valid: true}
		compareUsers(t, &expected, after)
	})

	t.Run("the address moved since it was read", func(t *testing.T) {
		user := seedEmailState(t, true, []byte("the-pending-ciphertext"), issuedAgo(time.Minute))
		readEmail := user.Email

		// Another request moves the address while this one is issuing.
		changed, err := database.TrySetUserEmail(ctx, nil, user.Id, user.Email, user.EmailVerified, "moved_"+fake.Email())
		if err != nil || !changed {
			t.Fatalf("the concurrent email change must take effect: changed=%v err=%v", changed, err)
		}
		moved, err := database.GetUserById(ctx, nil, user.Id)
		if err != nil {
			t.Fatalf("Failed to reload user: %v", err)
		}

		now := time.Now().UTC()
		stored, err := database.TryIssueEmailVerificationCode(ctx, nil, user.Id, readEmail,
			[]byte("fresh-ciphertext-"+fake.LetterN(16)), now)
		if err != nil {
			t.Fatalf("TryIssueEmailVerificationCode failed: %v", err)
		}
		if stored {
			t.Error("a code was stored for an address the account no longer holds")
		}

		after, err := database.GetUserById(ctx, nil, user.Id)
		if err != nil {
			t.Fatalf("Failed to reload user: %v", err)
		}
		compareUsers(t, moved, after)
	})

	t.Run("a concurrent disable, password change and OTP change survive", func(t *testing.T) {
		read, moved, newHash := stressedRead(t, func(user *record.User) { user.EmailVerified = true })

		now := time.Now().UTC().Truncate(time.Microsecond)
		code := []byte("fresh-ciphertext-" + fake.LetterN(16))
		stored, err := database.TryIssueEmailVerificationCode(ctx, nil, read.Id, read.Email, code, now)
		if err != nil || !stored {
			t.Fatalf("TryIssueEmailVerificationCode: stored=%v err=%v, want true and no error", stored, err)
		}

		after, err := database.GetUserById(ctx, nil, read.Id)
		if err != nil || after == nil {
			t.Fatalf("Failed to reload the user: user=%v err=%v", after, err)
		}
		expected := *moved
		expected.EmailVerified = false
		expected.EmailVerificationCodeEncrypted = code
		expected.EmailVerificationCodeIssuedAt = sql.NullTime{Time: now, Valid: true}
		compareUsers(t, &expected, after)
		assertConcurrentChangesSurvived(t, moved, after, newHash)
	})

	t.Run("refuses user id 0 and an empty code", func(t *testing.T) {
		now := time.Now().UTC()
		if _, err := database.TryIssueEmailVerificationCode(ctx, nil, 0, "a@example.com", []byte("x"), now); err == nil {
			t.Error("expected an error issuing a code for user id 0")
		}
		if _, err := database.TryIssueEmailVerificationCode(ctx, nil, 1, "a@example.com", nil, now); err == nil {
			t.Error("expected an error issuing an empty code")
		}
	})
}

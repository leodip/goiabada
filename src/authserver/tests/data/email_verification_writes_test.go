package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// The three conditional writes behind the self-service email change, the verification send and
// the verification check (#404). Each replaced a read of the user row, a decision in Go, and a
// write that did not repeat the decision, so concurrent requests from one read all acted on it:
// every send passed the cooldown and mailed a code, and every email change notified the previous
// address. The sequential cases pin each predicate one condition at a time; the concurrent ones
// are what a read-then-unconditional-write cannot pass.

// seedEmailState puts a fresh user in the verification state a case starts from, and returns the
// row as stored.
func seedEmailState(t *testing.T, verified bool, code []byte, issuedAt sql.NullTime) *models.User {
	t.Helper()
	user := createTestUser(t)
	user.EmailVerified = verified
	user.EmailVerificationCodeEncrypted = code
	user.EmailVerificationCodeIssuedAt = issuedAt
	if err := database.UpdateUser(context.Background(), nil, user); err != nil {
		t.Fatalf("Failed to seed the user's verification state: %v", err)
	}
	stored, err := database.GetUserById(context.Background(), nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload the seeded user: %v", err)
	}
	return stored
}

func issuedAgo(d time.Duration) sql.NullTime {
	return sql.NullTime{Time: time.Now().UTC().Add(-d).Truncate(time.Microsecond), Valid: true}
}

// raceOnce starts callers goroutines on one barrier, so they reach the row together, and returns
// how many reported a win. A caller that errored is reported through t and counts as no win: a
// lock-wait timeout is a 500 in production, and the request does nothing.
//
// Overlap can be made likely but not forced, as TestTryConsumeForgotPasswordCode_ConcurrentCallers
// ProduceOneWinner says of itself, so a green run detects a broken predicate probabilistically.
func raceOnce(t *testing.T, callers int, call func(i int) (bool, error)) int {
	t.Helper()
	start := make(chan struct{})
	wins := make([]bool, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			wins[i], errs[i] = call(i)
		}(i)
	}
	close(start)
	wg.Wait()

	won := 0
	for i := range wins {
		if errs[i] != nil {
			t.Logf("caller %d errored, counted as no win: %v", i, errs[i])
			continue
		}
		if wins[i] {
			won++
		}
	}
	return won
}

func skipOnSQLite(t *testing.T) {
	t.Helper()
	if dbType() == data.SQLite {
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so callers queue " +
			"rather than contend; the test would pass without ever creating overlap")
	}
}

const (
	raceCallers = 8
	raceRounds  = 5
)

// TestTrySetUserEmail_RefusesARowThatMovedSinceItWasRead is the predicate one condition at a time:
// another address, or the same address with the verified flag the other way, matches nothing and
// writes nothing.
func TestTrySetUserEmail_RefusesARowThatMovedSinceItWasRead(t *testing.T) {
	for _, tc := range []struct {
		name         string
		fromEmail    func(user *models.User) string
		fromVerified bool
	}{
		{"the address moved", func(*models.User) string { return "elsewhere_" + fake.Email() }, true},
		{"the verified flag moved", func(user *models.User) string { return user.Email }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := seedEmailState(t, true, []byte("pending"), issuedAgo(time.Minute))

			changed, err := database.TrySetUserEmail(context.Background(), nil, user.Id, tc.fromEmail(user), tc.fromVerified,
				"changed_"+fake.Email())
			if err != nil {
				t.Fatalf("TrySetUserEmail failed: %v", err)
			}
			if changed {
				t.Error("TrySetUserEmail changed a row that no longer holds what the caller read")
			}

			after, err := database.GetUserById(context.Background(), nil, user.Id)
			if err != nil {
				t.Fatalf("Failed to reload user: %v", err)
			}
			compareUsers(t, user, after)
		})
	}
}

// TestTrySetUserEmail_ConcurrentChangesFromOneReadProduceOneWinner is the notice's bound: of
// concurrent changes made from one read of a verified address, exactly one changes the row, so
// exactly one notifies the previous address.
func TestTrySetUserEmail_ConcurrentChangesFromOneReadProduceOneWinner(t *testing.T) {
	skipOnSQLite(t)

	for round := 0; round < raceRounds; round++ {
		user := seedEmailState(t, true, nil, sql.NullTime{})

		won := raceOnce(t, raceCallers, func(i int) (bool, error) {
			return database.TrySetUserEmail(context.Background(), nil, user.Id, user.Email, true,
				fmt.Sprintf("race_%d_%d_%s", round, i, fake.Email()))
		})
		if won != 1 {
			t.Fatalf("round %d: %d of %d concurrent changes from one read changed the row, want exactly 1",
				round, won, raceCallers)
		}
	}
}

// TestTryStoreEmailVerificationCode pins the send's claim: it stores the code and its issued-at
// only on an unverified account still holding the address, with no code issued inside the
// cooldown, and writes nothing else.
func TestTryStoreEmailVerificationCode(t *testing.T) {
	const cooldown = 5 * time.Minute

	for _, tc := range []struct {
		name      string
		verified  bool
		issuedAt  sql.NullTime
		moveEmail bool
		want      bool
	}{
		{"no code ever issued", false, sql.NullTime{}, false, true},
		{"the last code issued before the cooldown", false, issuedAgo(cooldown + time.Minute), false, true},
		{"the last code issued inside the cooldown", false, issuedAgo(time.Minute), false, false},
		{"the address already verified", true, sql.NullTime{}, false, false},
		{"the address moved since it was read", false, sql.NullTime{}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := seedEmailState(t, tc.verified, nil, tc.issuedAt)
			email := user.Email
			if tc.moveEmail {
				email = "elsewhere_" + fake.Email()
			}

			now := time.Now().UTC().Truncate(time.Microsecond)
			code := []byte("fresh-ciphertext-" + fake.LetterN(16))
			stored, err := database.TryStoreEmailVerificationCode(context.Background(), nil, user.Id, email, code,
				now, now.Add(-cooldown))
			if err != nil {
				t.Fatalf("TryStoreEmailVerificationCode failed: %v", err)
			}
			if stored != tc.want {
				t.Fatalf("stored = %v, want %v", stored, tc.want)
			}

			after, err := database.GetUserById(context.Background(), nil, user.Id)
			if err != nil {
				t.Fatalf("Failed to reload user: %v", err)
			}
			expected := *user
			if tc.want {
				expected.EmailVerificationCodeEncrypted = code
				expected.EmailVerificationCodeIssuedAt = sql.NullTime{Time: now, Valid: true}
			}
			// Every other column is as it was, and a refused claim moved nothing.
			compareUsers(t, &expected, after)
		})
	}

	t.Run("refuses user id 0 and an empty code", func(t *testing.T) {
		now := time.Now().UTC()
		if _, err := database.TryStoreEmailVerificationCode(context.Background(), nil, 0, "a@example.com",
			[]byte("x"), now, now); err == nil {
			t.Error("expected an error storing a code for user id 0")
		}
		if _, err := database.TryStoreEmailVerificationCode(context.Background(), nil, 1, "a@example.com",
			nil, now, now); err == nil {
			t.Error("expected an error storing an empty code")
		}
	})
}

// TestTryStoreEmailVerificationCode_ConcurrentSendsProduceOneWinner is the cooldown's bound under
// concurrency: of concurrent sends on one account, exactly one stores a code, so exactly one
// mails one. The send it replaced let all of them through, at whatever address the account held.
func TestTryStoreEmailVerificationCode_ConcurrentSendsProduceOneWinner(t *testing.T) {
	skipOnSQLite(t)

	for round := 0; round < raceRounds; round++ {
		user := seedEmailState(t, false, nil, sql.NullTime{})

		won := raceOnce(t, raceCallers, func(i int) (bool, error) {
			now := time.Now().UTC()
			return database.TryStoreEmailVerificationCode(context.Background(), nil, user.Id, user.Email,
				[]byte(fmt.Sprintf("ciphertext-%d-%d", round, i)), now, now.Add(-5*time.Minute))
		})
		if won != 1 {
			t.Fatalf("round %d: %d of %d concurrent sends stored a code, want exactly 1", round, won, raceCallers)
		}
	}
}

// TestTryVerifyUserEmail pins the verification's write: it verifies only an unverified account
// still holding the address with the compared ciphertext still pending, clears the code, keeps
// the issued-at for the resend cooldown, and writes nothing else.
func TestTryVerifyUserEmail(t *testing.T) {
	pending := []byte("the-pending-ciphertext")

	t.Run("the code compared is still pending", func(t *testing.T) {
		user := seedEmailState(t, false, pending, issuedAgo(time.Minute))

		verified, err := database.TryVerifyUserEmail(context.Background(), nil, user.Id, user.Email, pending)
		if err != nil || !verified {
			t.Fatalf("TryVerifyUserEmail: verified=%v err=%v, want true and no error", verified, err)
		}

		after, err := database.GetUserById(context.Background(), nil, user.Id)
		if err != nil {
			t.Fatalf("Failed to reload user: %v", err)
		}
		expected := *user
		expected.EmailVerified = true
		expected.EmailVerificationCodeEncrypted = nil
		// The issued-at stays: compareUsers holds it to the seeded value.
		compareUsers(t, &expected, after)
	})

	for _, tc := range []struct {
		name      string
		verified  bool
		stored    []byte
		compared  []byte
		moveEmail bool
	}{
		{"a new send replaced the code", false, []byte("a-newer-ciphertext"), pending, false},
		{"an email change cleared the code", false, nil, pending, false},
		{"the address moved since it was read", false, pending, pending, true},
		{"the address is already verified", true, pending, pending, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := seedEmailState(t, tc.verified, tc.stored, issuedAgo(time.Minute))
			email := user.Email
			if tc.moveEmail {
				email = "elsewhere_" + fake.Email()
			}

			verified, err := database.TryVerifyUserEmail(context.Background(), nil, user.Id, email, tc.compared)
			if err != nil {
				t.Fatalf("TryVerifyUserEmail failed: %v", err)
			}
			if verified {
				t.Error("TryVerifyUserEmail verified a row whose pending code is not the one compared")
			}

			after, err := database.GetUserById(context.Background(), nil, user.Id)
			if err != nil {
				t.Fatalf("Failed to reload user: %v", err)
			}
			compareUsers(t, user, after)
		})
	}

	t.Run("refuses user id 0 and an empty code", func(t *testing.T) {
		if _, err := database.TryVerifyUserEmail(context.Background(), nil, 0, "a@example.com", []byte("x")); err == nil {
			t.Error("expected an error verifying user id 0")
		}
		if _, err := database.TryVerifyUserEmail(context.Background(), nil, 1, "a@example.com", nil); err == nil {
			t.Error("expected an error verifying against an empty code")
		}
	})
}

// TestTryVerifyUserEmail_AConcurrentDisableSurvives is the hazard the narrow write exists for: the
// verification read the user while it was enabled, an administrator disabled it, and the
// full-row UpdateUser of that read re-enabled it. The conditional write writes neither column.
func TestTryVerifyUserEmail_AConcurrentDisableSurvives(t *testing.T) {
	pending := []byte("the-pending-ciphertext")
	user := seedEmailState(t, false, pending, issuedAgo(time.Minute))
	if !user.Enabled {
		enabled, err := database.TrySetUserEnabled(context.Background(), nil, user.Id, false, true)
		if err != nil || !enabled {
			t.Fatalf("the fixture must start enabled: enabled=%v err=%v", enabled, err)
		}
	}

	disabled, err := database.TrySetUserEnabled(context.Background(), nil, user.Id, true, false)
	if err != nil || !disabled {
		t.Fatalf("the concurrent disable must take effect: disabled=%v err=%v", disabled, err)
	}

	verified, err := database.TryVerifyUserEmail(context.Background(), nil, user.Id, user.Email, pending)
	if err != nil || !verified {
		t.Fatalf("TryVerifyUserEmail: verified=%v err=%v, want true and no error", verified, err)
	}

	after, err := database.GetUserById(context.Background(), nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if after.Enabled {
		t.Error("the verification re-enabled an account an administrator disabled under it")
	}
	if !after.EmailVerified {
		t.Error("the address must be verified")
	}
}

// TestTryVerifyUserEmail_ConcurrentSubmissionsProduceOneWinner: of concurrent submissions of one
// code, exactly one verifies the address and spends the code.
func TestTryVerifyUserEmail_ConcurrentSubmissionsProduceOneWinner(t *testing.T) {
	skipOnSQLite(t)

	pending := []byte("the-pending-ciphertext")
	for round := 0; round < raceRounds; round++ {
		user := seedEmailState(t, false, pending, issuedAgo(time.Minute))

		won := raceOnce(t, raceCallers, func(int) (bool, error) {
			return database.TryVerifyUserEmail(context.Background(), nil, user.Id, user.Email, pending)
		})
		if won != 1 {
			t.Fatalf("round %d: %d of %d concurrent submissions of one code verified, want exactly 1",
				round, won, raceCallers)
		}
	}
}

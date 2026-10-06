package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// The three narrow writes behind the profile, address and phone saves, self-service and
// administrator alike (#471). Each replaced a full-row UpdateUser of the user the request read at
// its start, which wrote back every column of that read: an administrator's disable made in
// between was undone after its revocation sweep had run, a password changed or reset in between
// was put back so the old one worked again, and an OTP enable or disable in between was reversed.
// Each case reads the row as a request would, makes those three changes through writes of their
// own, then saves from the stale read, and asserts that the save's own columns landed and that
// every other column holds what the concurrent changes left there.

// columnGroupWrite is one of the three saves: the state the fixture starts from where the case
// needs one, what the save changes on the user it is given, and the narrow write that stores it.
type columnGroupWrite struct {
	name  string
	seed  func(user *record.User)
	apply func(user *record.User)
	write func(ctx context.Context, user *record.User) error
}

var birthDateSaved = time.Date(1815, time.December, 10, 0, 0, 0, 0, time.UTC)

// columnGroupWrites holds each save twice: once setting every column of its group to a value no
// fixture user holds, and once clearing every one of them, so a column the write skips shows as
// the fixture's value either way. A username is unique, so each call draws its own.
func columnGroupWrites() []columnGroupWrite {
	savedUsername := "saved_" + fake.LetterN(10)
	clearedUsername := "cleared_" + fake.LetterN(10)
	return []columnGroupWrite{
		{
			name: "profile set",
			apply: func(user *record.User) {
				user.Username = savedUsername
				user.GivenName = "Ada"
				user.MiddleName = "King"
				user.FamilyName = "Lovelace"
				user.Nickname = "Countess"
				user.Website = "https://saved.example.com/ada"
				user.Gender = "female"
				user.BirthDate = sql.NullTime{Time: birthDateSaved, Valid: true}
				user.ZoneInfoCountryName = "United Kingdom"
				user.ZoneInfo = "Europe/London"
				user.Locale = "en-GB"
			},
			write: func(ctx context.Context, user *record.User) error { return database.SetUserProfile(ctx, nil, user) },
		},
		{
			name: "profile cleared",
			apply: func(user *record.User) {
				user.Username = clearedUsername
				user.GivenName = ""
				user.MiddleName = ""
				user.FamilyName = ""
				user.Nickname = ""
				user.Website = ""
				user.Gender = ""
				user.BirthDate = sql.NullTime{}
				user.ZoneInfoCountryName = ""
				user.ZoneInfo = ""
				user.Locale = ""
			},
			write: func(ctx context.Context, user *record.User) error { return database.SetUserProfile(ctx, nil, user) },
		},
		{
			name: "address set",
			apply: func(user *record.User) {
				user.AddressLine1 = "12 Saved Street"
				user.AddressLine2 = "Flat 3"
				user.AddressLocality = "Savedtown"
				user.AddressRegion = "Savedshire"
				user.AddressPostalCode = "SV1 2AB"
				user.AddressCountry = "GBR"
			},
			write: func(ctx context.Context, user *record.User) error { return database.SetUserAddress(ctx, nil, user) },
		},
		{
			name: "address cleared",
			apply: func(user *record.User) {
				user.AddressLine1 = ""
				user.AddressLine2 = ""
				user.AddressLocality = ""
				user.AddressRegion = ""
				user.AddressPostalCode = ""
				user.AddressCountry = ""
			},
			write: func(ctx context.Context, user *record.User) error { return database.SetUserAddress(ctx, nil, user) },
		},
		{
			name: "phone set",
			// The fixture draws the flag at random; it starts opposite to what the save writes.
			seed: func(user *record.User) { user.PhoneNumberVerified = false },
			apply: func(user *record.User) {
				user.PhoneNumberCountryUniqueId = "PRT_0"
				user.PhoneNumberCountryCallingCode = "+351"
				user.PhoneNumber = "912 345 678"
				user.PhoneNumberVerified = true
			},
			write: func(ctx context.Context, user *record.User) error { return database.SetUserPhone(ctx, nil, user) },
		},
		{
			name: "phone cleared",
			seed: func(user *record.User) { user.PhoneNumberVerified = true },
			apply: func(user *record.User) {
				user.PhoneNumberCountryUniqueId = ""
				user.PhoneNumberCountryCallingCode = ""
				user.PhoneNumber = ""
				user.PhoneNumberVerified = false
			},
			write: func(ctx context.Context, user *record.User) error { return database.SetUserPhone(ctx, nil, user) },
		},
	}
}

// enabledTestUser seeds a user that is enabled, which createTestUser draws at random, so the
// concurrent disable has something to disable, starting from seed's state when it is given one.
func enabledTestUser(t *testing.T, seed func(user *record.User)) *record.User {
	t.Helper()
	user := createTestUser(t)
	if seed != nil {
		seed(user)
		if err := database.UpdateUser(context.Background(), nil, user); err != nil {
			t.Fatalf("Failed to seed the user's starting state: %v", err)
		}
	}
	if !user.Enabled {
		enabled, err := database.TrySetUserEnabled(context.Background(), nil, user.Id, false, true)
		if err != nil || !enabled {
			t.Fatalf("the fixture must start enabled: enabled=%v err=%v", enabled, err)
		}
	}
	return user
}

// changeOTPUnder flips the user's OTP on or off with a new secret, and advances the generation,
// the three columns establishing or removing an authenticator moves. It writes them from a fresh
// read, so it stands for an OTP change that completed while the save's request was in flight.
func changeOTPUnder(t *testing.T, userId int64) {
	t.Helper()
	fresh, err := database.GetUserById(context.Background(), nil, userId)
	if err != nil || fresh == nil {
		t.Fatalf("Failed to read the user for the OTP change: user=%v err=%v", fresh, err)
	}
	fresh.OTPEnabled = !fresh.OTPEnabled
	fresh.OTPSecretEncrypted = []byte("otp-changed-under-the-save-" + fake.LetterN(12))
	err = database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		if updateErr := database.UpdateUser(context.Background(), tx, fresh); updateErr != nil {
			return updateErr
		}
		_, incrementErr := database.IncrementUserOtpConfigGeneration(context.Background(), tx, userId)
		return incrementErr
	})
	if err != nil {
		t.Fatalf("Failed to change the user's OTP: %v", err)
	}
}

func TestColumnGroupWrites_ConcurrentDisablePasswordAndOTPChangesSurvive(t *testing.T) {
	for _, w := range columnGroupWrites() {
		t.Run(w.name, func(t *testing.T) {
			ctx := context.Background()
			seeded := enabledTestUser(t, w.seed)

			// The row as the save's request read it at its start.
			read, err := database.GetUserById(ctx, nil, seeded.Id)
			if err != nil || read == nil {
				t.Fatalf("Failed to read the user: user=%v err=%v", read, err)
			}

			// What other requests change while the save is in flight.
			disabled, err := database.TrySetUserEnabled(ctx, nil, read.Id, true, false)
			if err != nil || !disabled {
				t.Fatalf("the concurrent disable must take effect: disabled=%v err=%v", disabled, err)
			}
			newHash := "changed-under-the-save-" + fake.Password(32)
			if err = database.SetUserPasswordHash(ctx, nil, read.Id, newHash); err != nil {
				t.Fatalf("the concurrent password change must take effect: %v", err)
			}
			changeOTPUnder(t, read.Id)

			moved, err := database.GetUserById(ctx, nil, read.Id)
			if err != nil || moved == nil {
				t.Fatalf("Failed to reload the user: user=%v err=%v", moved, err)
			}
			if moved.Enabled || moved.PasswordHash != newHash || moved.OTPEnabled == read.OTPEnabled ||
				moved.OtpConfigGeneration == read.OtpConfigGeneration {
				t.Fatal("the concurrent changes did not land, so the case would prove nothing")
			}

			// The save, from the stale read.
			beforeSave := time.Now().UTC().Truncate(time.Second)
			w.apply(read)
			if err = w.write(ctx, read); err != nil {
				t.Fatalf("the save failed: %v", err)
			}

			after, err := database.GetUserById(ctx, nil, read.Id)
			if err != nil || after == nil {
				t.Fatalf("Failed to reload the saved user: user=%v err=%v", after, err)
			}

			// Its own columns landed, and every other column holds what the concurrent changes left.
			expected := *moved
			w.apply(&expected)
			compareUsers(t, &expected, after)
			if after.Enabled {
				t.Error("the save re-enabled an account an administrator disabled under it")
			}
			if after.PasswordHash != newHash {
				t.Error("the save put back a password hash replaced under it")
			}
			if after.OTPEnabled != moved.OTPEnabled || string(after.OTPSecretEncrypted) != string(moved.OTPSecretEncrypted) {
				t.Error("the save reversed an OTP change made under it")
			}
			if after.OtpConfigGeneration != moved.OtpConfigGeneration {
				t.Errorf("OtpConfigGeneration = %d, want %d", after.OtpConfigGeneration, moved.OtpConfigGeneration)
			}
			if after.AuthStateGeneration != moved.AuthStateGeneration {
				t.Errorf("AuthStateGeneration = %d, want %d", after.AuthStateGeneration, moved.AuthStateGeneration)
			}

			// It reports when the row changed, on the row and on the user the response is built from.
			if !after.UpdatedAt.Valid || after.UpdatedAt.Time.Before(beforeSave) {
				t.Errorf("updated_at = %v, want a time not before %v", after.UpdatedAt, beforeSave)
			}
			// The user handed in carries the stored value, to the microsecond every engine keeps
			// and either side of it, since some round and some truncate. The read's own updated_at
			// is from this same second, so nothing coarser would tell the two apart.
			if diff := read.UpdatedAt.Time.Sub(after.UpdatedAt.Time).Abs(); !read.UpdatedAt.Valid || diff > time.Microsecond {
				t.Errorf("the saved user's UpdatedAt = %v, want the stored %v", read.UpdatedAt, after.UpdatedAt)
			}
		})
	}
}

func TestColumnGroupWrites_RefuseUserIdZero(t *testing.T) {
	for _, w := range columnGroupWrites() {
		t.Run(w.name, func(t *testing.T) {
			user := &record.User{}
			w.apply(user)
			if err := w.write(context.Background(), user); err == nil {
				t.Error("expected an error saving user id 0")
			}
		})
	}
}

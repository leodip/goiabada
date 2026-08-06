// cmd/data_tests/user_test.go

package datatests

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
)

func TestCreateUser(t *testing.T) {
	user := createTestUser(t)

	if user.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !user.CreatedAt.Valid || user.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !user.UpdatedAt.Valid || user.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created user: %v", err)
	}

	compareUsers(t, user, retrievedUser)
}

func TestUpdateUser(t *testing.T) {
	user := createTestUser(t)

	// Update all fields
	user.Enabled = !user.Enabled
	user.Subject = uuid.New()
	user.Username = "updated_" + gofakeit.Username()
	user.GivenName = "Updated" + gofakeit.FirstName()
	user.MiddleName = "Updated" + gofakeit.MiddleName()
	user.FamilyName = "Updated" + gofakeit.LastName()
	user.Nickname = "Updated" + gofakeit.FirstName()
	user.Website = "https://updated" + gofakeit.DomainName()
	user.Gender = enums.GenderFemale.String()
	user.Email = "updated_" + gofakeit.Email()
	user.EmailVerified = !user.EmailVerified
	user.EmailVerificationCodeEncrypted = []byte(gofakeit.Password(true, true, true, true, false, 32))
	user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}
	user.ZoneInfoCountryName = gofakeit.Country()
	user.ZoneInfo = gofakeit.TimeZone()
	user.Locale = gofakeit.Language()
	user.BirthDate = sql.NullTime{Time: gofakeit.Date().Truncate(time.Microsecond), Valid: true}
	user.PhoneNumberCountryUniqueId = gofakeit.CountryAbr()
	user.PhoneNumberCountryCallingCode = fmt.Sprintf("+%s", gofakeit.Numerify("##"))
	user.PhoneNumber = gofakeit.Phone()
	user.PhoneNumberVerified = !user.PhoneNumberVerified
	user.PhoneNumberVerificationCodeEncrypted = []byte(gofakeit.Password(true, true, true, true, false, 32))
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}
	user.AddressLine1 = gofakeit.StreetName()
	user.AddressLine2 = gofakeit.StreetNumber()
	user.AddressLocality = gofakeit.City()
	user.AddressRegion = gofakeit.State()
	user.AddressPostalCode = gofakeit.Zip()
	user.AddressCountry = gofakeit.CountryAbr()
	user.PasswordHash = gofakeit.Password(true, true, true, true, false, 64)
	user.OTPSecret = gofakeit.UUID()
	user.OTPEnabled = !user.OTPEnabled
	user.ForgotPasswordCodeEncrypted = []byte(gofakeit.Password(true, true, true, true, false, 32))
	user.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}

	time.Sleep(timestampTick)

	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user: %v", err)
	}

	compareUsers(t, user, updatedUser)

	if !updatedUser.UpdatedAt.Time.After(updatedUser.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetUserById(t *testing.T) {
	user := createTestUser(t)

	retrievedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to get user by ID: %v", err)
	}

	compareUsers(t, user, retrievedUser)

	nonExistentUser, err := database.GetUserById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user, got: %v", err)
	}
	if nonExistentUser != nil {
		t.Errorf("Expected nil for non-existent user, got a user with ID: %d", nonExistentUser.Id)
	}
}

func TestGetUserByUsername(t *testing.T) {
	user := createTestUser(t)

	retrievedUser, err := database.GetUserByUsername(nil, user.Username)
	if err != nil {
		t.Fatalf("Failed to get user by username: %v", err)
	}

	compareUsers(t, user, retrievedUser)

	nonExistentUser, err := database.GetUserByUsername(nil, "non_existent_username")
	if err != nil {
		t.Errorf("Expected no error for non-existent user, got: %v", err)
	}
	if nonExistentUser != nil {
		t.Errorf("Expected nil for non-existent user, got a user with ID: %d", nonExistentUser.Id)
	}
}

func TestGetUserBySubject(t *testing.T) {
	user := createTestUser(t)

	retrievedUser, err := database.GetUserBySubject(nil, user.Subject.String())
	if err != nil {
		t.Fatalf("Failed to get user by subject: %v", err)
	}

	compareUsers(t, user, retrievedUser)

	nonExistentUser, err := database.GetUserBySubject(nil, uuid.New().String())
	if err != nil {
		t.Errorf("Expected no error for non-existent user, got: %v", err)
	}
	if nonExistentUser != nil {
		t.Errorf("Expected nil for non-existent user, got a user with ID: %d", nonExistentUser.Id)
	}
}

func TestGetUserByEmail(t *testing.T) {
	user := createTestUser(t)

	retrievedUser, err := database.GetUserByEmail(nil, user.Email)
	if err != nil {
		t.Fatalf("Failed to get user by email: %v", err)
	}

	compareUsers(t, user, retrievedUser)

	nonExistentUser, err := database.GetUserByEmail(nil, "non_existent_email@example.com")
	if err != nil {
		t.Errorf("Expected no error for non-existent user, got: %v", err)
	}
	if nonExistentUser != nil {
		t.Errorf("Expected nil for non-existent user, got a user with ID: %d", nonExistentUser.Id)
	}
}

func TestSearchUsersPaginated(t *testing.T) {
	// Create multiple users
	users := make([]*models.User, 5)
	for i := 0; i < 5; i++ {
		users[i] = createTestUser(t)
	}

	// Test search by username
	searchResults, total, err := database.SearchUsersPaginated(nil, users[0].Username, 1, 10)
	if err != nil {
		t.Fatalf("Failed to search users: %v", err)
	}
	if len(searchResults) != 1 {
		t.Errorf("Expected 1 search result, got %d", len(searchResults))
	}
	if total != 1 {
		t.Errorf("Expected total of 1, got %d", total)
	}

	// Test pagination
	allUsers, total, err := database.SearchUsersPaginated(nil, "", 1, 3)
	if err != nil {
		t.Fatalf("Failed to search all users: %v", err)
	}
	if len(allUsers) != 3 {
		t.Errorf("Expected 3 users on first page, got %d", len(allUsers))
	}
	if total < 5 {
		t.Errorf("Expected total of at least 5, got %d", total)
	}
}

func TestDeleteUser(t *testing.T) {
	user := createTestUser(t)

	err := database.DeleteUser(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}

	deletedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted user: %v", err)
	}
	if deletedUser != nil {
		t.Errorf("User still exists after deletion")
	}

	err = database.DeleteUser(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user, got: %v", err)
	}
}

func createTestUser(t *testing.T) *models.User {
	user := &models.User{
		Enabled:                              gofakeit.Bool(),
		Subject:                              uuid.New(),
		Username:                             gofakeit.Username(),
		GivenName:                            gofakeit.FirstName(),
		MiddleName:                           gofakeit.MiddleName(),
		FamilyName:                           gofakeit.LastName(),
		Nickname:                             gofakeit.FirstName(),
		Website:                              gofakeit.URL(),
		Gender:                               enums.GenderOther.String(),
		Email:                                gofakeit.Email(),
		EmailVerified:                        gofakeit.Bool(),
		EmailVerificationCodeEncrypted:       []byte(gofakeit.Password(true, true, true, true, false, 32)),
		EmailVerificationCodeIssuedAt:        sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ZoneInfoCountryName:                  gofakeit.Country(),
		ZoneInfo:                             gofakeit.TimeZone(),
		Locale:                               gofakeit.Language(),
		BirthDate:                            sql.NullTime{Time: gofakeit.Date().Truncate(time.Microsecond), Valid: true},
		PhoneNumberCountryUniqueId:           gofakeit.CountryAbr(),
		PhoneNumberCountryCallingCode:        fmt.Sprintf("+%s", gofakeit.Numerify("##")),
		PhoneNumber:                          gofakeit.Phone(),
		PhoneNumberVerified:                  gofakeit.Bool(),
		PhoneNumberVerificationCodeEncrypted: []byte(gofakeit.Password(true, true, true, true, false, 32)),
		PhoneNumberVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		AddressLine1:                         gofakeit.StreetName(),
		AddressLine2:                         gofakeit.StreetNumber(),
		AddressLocality:                      gofakeit.City(),
		AddressRegion:                        gofakeit.State(),
		AddressPostalCode:                    gofakeit.Zip(),
		AddressCountry:                       gofakeit.CountryAbr(),
		PasswordHash:                         gofakeit.Password(true, true, true, true, false, 64),
		OTPSecret:                            gofakeit.UUID(),
		OTPEnabled:                           gofakeit.Bool(),
		ForgotPasswordCodeEncrypted:          []byte(gofakeit.Password(true, true, true, true, false, 32)),
		ForgotPasswordCodeIssuedAt:           sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
	}

	err := database.CreateUser(nil, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	return user
}

func compareUsers(t *testing.T, expected, actual *models.User) {
	if actual.Id != expected.Id {
		t.Errorf("ID mismatch: expected %d, got %d", expected.Id, actual.Id)
	}
	if actual.Enabled != expected.Enabled {
		t.Errorf("Enabled mismatch: expected %v, got %v", expected.Enabled, actual.Enabled)
	}
	if actual.Subject != expected.Subject {
		t.Errorf("Subject mismatch: expected %s, got %s", expected.Subject, actual.Subject)
	}
	if actual.Username != expected.Username {
		t.Errorf("Username mismatch: expected %s, got %s", expected.Username, actual.Username)
	}
	if actual.GivenName != expected.GivenName {
		t.Errorf("GivenName mismatch: expected %s, got %s", expected.GivenName, actual.GivenName)
	}
	if actual.MiddleName != expected.MiddleName {
		t.Errorf("MiddleName mismatch: expected %s, got %s", expected.MiddleName, actual.MiddleName)
	}
	if actual.FamilyName != expected.FamilyName {
		t.Errorf("FamilyName mismatch: expected %s, got %s", expected.FamilyName, actual.FamilyName)
	}
	if actual.Nickname != expected.Nickname {
		t.Errorf("Nickname mismatch: expected %s, got %s", expected.Nickname, actual.Nickname)
	}
	if actual.Website != expected.Website {
		t.Errorf("Website mismatch: expected %s, got %s", expected.Website, actual.Website)
	}
	if actual.Gender != expected.Gender {
		t.Errorf("Gender mismatch: expected %s, got %s", expected.Gender, actual.Gender)
	}
	if actual.Email != expected.Email {
		t.Errorf("Email mismatch: expected %s, got %s", expected.Email, actual.Email)
	}
	if actual.EmailVerified != expected.EmailVerified {
		t.Errorf("EmailVerified mismatch: expected %v, got %v", expected.EmailVerified, actual.EmailVerified)
	}
	if string(actual.EmailVerificationCodeEncrypted) != string(expected.EmailVerificationCodeEncrypted) {
		t.Errorf("EmailVerificationCodeEncrypted mismatch")
	}
	if !actual.EmailVerificationCodeIssuedAt.Time.Equal(expected.EmailVerificationCodeIssuedAt.Time) {
		t.Errorf("EmailVerificationCodeIssuedAt mismatch: expected %v, got %v", expected.EmailVerificationCodeIssuedAt, actual.EmailVerificationCodeIssuedAt)
	}
	if actual.ZoneInfoCountryName != expected.ZoneInfoCountryName {
		t.Errorf("ZoneInfoCountryName mismatch: expected %s, got %s", expected.ZoneInfoCountryName, actual.ZoneInfoCountryName)
	}
	if actual.ZoneInfo != expected.ZoneInfo {
		t.Errorf("ZoneInfo mismatch: expected %s, got %s", expected.ZoneInfo, actual.ZoneInfo)
	}
	if actual.Locale != expected.Locale {
		t.Errorf("Locale mismatch: expected %s, got %s", expected.Locale, actual.Locale)
	}
	if !actual.BirthDate.Time.Equal(expected.BirthDate.Time) {
		t.Errorf("BirthDate mismatch: expected %v, got %v", expected.BirthDate, actual.BirthDate)
	}
	if actual.PhoneNumberCountryUniqueId != expected.PhoneNumberCountryUniqueId {
		t.Errorf("PhoneNumberCountryUniqueId mismatch: expected %s, got %s", expected.PhoneNumberCountryUniqueId, actual.PhoneNumberCountryUniqueId)
	}
	if actual.PhoneNumberCountryCallingCode != expected.PhoneNumberCountryCallingCode {
		t.Errorf("PhoneNumberCountryCallingCode mismatch: expected %s, got %s", expected.PhoneNumberCountryCallingCode, actual.PhoneNumberCountryCallingCode)
	}
	if actual.PhoneNumber != expected.PhoneNumber {
		t.Errorf("PhoneNumber mismatch: expected %s, got %s", expected.PhoneNumber, actual.PhoneNumber)
	}
	if actual.PhoneNumberVerified != expected.PhoneNumberVerified {
		t.Errorf("PhoneNumberVerified mismatch: expected %v, got %v", expected.PhoneNumberVerified, actual.PhoneNumberVerified)
	}
	if string(actual.PhoneNumberVerificationCodeEncrypted) != string(expected.PhoneNumberVerificationCodeEncrypted) {
		t.Errorf("PhoneNumberVerificationCodeEncrypted mismatch")
	}
	if !actual.PhoneNumberVerificationCodeIssuedAt.Time.Equal(expected.PhoneNumberVerificationCodeIssuedAt.Time) {
		t.Errorf("PhoneNumberVerificationCodeIssuedAt mismatch: expected %v, got %v", expected.PhoneNumberVerificationCodeIssuedAt, actual.PhoneNumberVerificationCodeIssuedAt)
	}
	if actual.AddressLine1 != expected.AddressLine1 {
		t.Errorf("AddressLine1 mismatch: expected %s, got %s", expected.AddressLine1, actual.AddressLine1)
	}
	if actual.AddressLine2 != expected.AddressLine2 {
		t.Errorf("AddressLine2 mismatch: expected %s, got %s", expected.AddressLine2, actual.AddressLine2)
	}
	if actual.AddressLocality != expected.AddressLocality {
		t.Errorf("AddressLocality mismatch: expected %s, got %s", expected.AddressLocality, actual.AddressLocality)
	}
	if actual.AddressRegion != expected.AddressRegion {
		t.Errorf("AddressRegion mismatch: expected %s, got %s", expected.AddressRegion, actual.AddressRegion)
	}
	if actual.AddressPostalCode != expected.AddressPostalCode {
		t.Errorf("AddressPostalCode mismatch: expected %s, got %s", expected.AddressPostalCode, actual.AddressPostalCode)
	}
	if actual.AddressCountry != expected.AddressCountry {
		t.Errorf("AddressCountry mismatch: expected %s, got %s", expected.AddressCountry, actual.AddressCountry)
	}
	if actual.PasswordHash != expected.PasswordHash {
		t.Errorf("PasswordHash mismatch: expected %s, got %s", expected.PasswordHash, actual.PasswordHash)
	}
	if actual.OTPSecret != expected.OTPSecret {
		t.Errorf("OTPSecret mismatch: expected %s, got %s", expected.OTPSecret, actual.OTPSecret)
	}
	if actual.OTPEnabled != expected.OTPEnabled {
		t.Errorf("OTPEnabled mismatch: expected %v, got %v", expected.OTPEnabled, actual.OTPEnabled)
	}
	if string(actual.ForgotPasswordCodeEncrypted) != string(expected.ForgotPasswordCodeEncrypted) {
		t.Errorf("ForgotPasswordCodeEncrypted mismatch")
	}
	if !actual.ForgotPasswordCodeIssuedAt.Time.Equal(expected.ForgotPasswordCodeIssuedAt.Time) {
		t.Errorf("ForgotPasswordCodeIssuedAt mismatch: expected %v, got %v", expected.ForgotPasswordCodeIssuedAt, actual.ForgotPasswordCodeIssuedAt)
	}
}

// TestUpdateUser_DoesNotClobberAuthStateGeneration pins decision 11(b) of #106.
//
// AuthStateGeneration is tagged fieldtag:"dont-update", so it is written on insert
// and an ordinary full-row UpdateUser must leave it alone. That matters because
// every credential handler loads the whole user and writes it back: without the
// tag, a request holding a model read before an increment would silently regress
// the generation and let a superseded credential work again.
//
// Keep this test. With the tag dropped the code still compiles and every other
// test still passes; the only symptom is a security boundary quietly ceasing to
// hold. The value 7 is deliberately nonzero, since 0 is the column default and a
// test written with 0 would pass with the field never assigned at all.
func TestUpdateUser_DoesNotClobberAuthStateGeneration(t *testing.T) {
	user := createTestUser(t)
	user.AuthStateGeneration = 7
	// Re-created rather than updated: writing it is exactly what UpdateUser must
	// not do, so the nonzero value has to arrive through an insert.
	user.Id = 0
	user.Subject = uuid.New()
	user.Username = "gen_" + gofakeit.LetterN(8)
	user.Email = gofakeit.LetterN(8) + "@example.com"
	if err := database.CreateUser(nil, user); err != nil {
		t.Fatalf("Failed to create user with a generation: %v", err)
	}

	created, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload created user: %v", err)
	}
	if created.AuthStateGeneration != 7 {
		t.Fatalf("CreateUser must persist auth_state_generation, got %d want 7",
			created.AuthStateGeneration)
	}

	// A stale model, carrying the pre-increment value, must not pull it back down.
	created.AuthStateGeneration = 0
	created.GivenName = "Changed"
	if err := database.UpdateUser(nil, created); err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	after, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload updated user: %v", err)
	}
	if after.AuthStateGeneration != 7 {
		t.Errorf("UpdateUser regressed auth_state_generation to %d, want 7 (is the dont-update tag missing?)",
			after.AuthStateGeneration)
	}
	if after.GivenName != "Changed" {
		t.Errorf("the rest of the update must still apply, GivenName = %q", after.GivenName)
	}
}

// TestIncrementUserAuthStateGeneration pins that the counter is monotonic and returns the
// value that actually landed. Two calls must yield 1 then 2, never the same number twice:
// the increment is a single statement so concurrent credential changes cannot both read
// the same value and write the same successor (#106).
func TestIncrementUserAuthStateGeneration(t *testing.T) {
	user := createTestUser(t)

	// Through a transaction, which the method requires. The increment and its read-back
	// are two statements, so outside one a concurrent increment could land between them
	// and this caller would be handed the other caller's generation.
	tx := beginTx(t)

	first, err := database.IncrementUserAuthStateGeneration(tx, user.Id)
	if err != nil {
		t.Fatalf("first increment failed: %v", err)
	}
	if first != 1 {
		t.Errorf("first increment returned %d, want 1", first)
	}

	second, err := database.IncrementUserAuthStateGeneration(tx, user.Id)
	if err != nil {
		t.Fatalf("second increment failed: %v", err)
	}
	if second != 2 {
		t.Errorf("second increment returned %d, want 2 (is the counter monotonic?)", second)
	}

	if err := database.CommitTransaction(tx); err != nil {
		t.Fatalf("CommitTransaction failed: %v", err)
	}

	reloaded, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if reloaded.AuthStateGeneration != 2 {
		t.Errorf("persisted generation = %d, want 2", reloaded.AuthStateGeneration)
	}

	// A nil transaction is refused rather than quietly allowed. Keep this: without it
	// the test would endorse exactly the unsafe usage the method exists to prevent.
	if _, err := database.IncrementUserAuthStateGeneration(nil, user.Id); err == nil {
		t.Error("expected an error incrementing the generation without a transaction")
	}

	tx2 := beginTx(t)
	if _, err := database.IncrementUserAuthStateGeneration(tx2, 0); err == nil {
		t.Error("expected an error incrementing the generation of user id 0")
	}
}

// TestSetUserPasswordHash checks the hash is written, the outstanding forgot-password code
// is cleared in the same statement, and no other column is touched.
//
// Clearing the code matters: a reset that left a usable code behind would let the same
// link be replayed. Not touching other columns is the point of the method existing at all,
// since the full-row UpdateUser is what lets a concurrent admin disable be undone (#106).
func TestSetUserPasswordHash(t *testing.T) {
	user := createTestUser(t)
	user.Enabled = true
	user.ForgotPasswordCodeEncrypted = []byte("PENDINGRESETCODE")
	user.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}
	if err := database.UpdateUser(nil, user); err != nil {
		t.Fatalf("Failed to seed a pending reset code: %v", err)
	}

	before, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}

	if err := database.SetUserPasswordHash(nil, user.Id, "newhash"); err != nil {
		t.Fatalf("SetUserPasswordHash failed: %v", err)
	}

	after, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}

	if after.PasswordHash != "newhash" {
		t.Errorf("PasswordHash = %q, want %q", after.PasswordHash, "newhash")
	}
	if len(after.ForgotPasswordCodeEncrypted) != 0 {
		t.Error("the forgot-password code must be cleared in the same statement")
	}
	if after.ForgotPasswordCodeIssuedAt.Valid {
		t.Error("the forgot-password issued-at must be cleared in the same statement")
	}
	if after.Enabled != before.Enabled {
		t.Errorf("Enabled changed from %v to %v; this method must touch nothing else", before.Enabled, after.Enabled)
	}
	if after.Email != before.Email || after.GivenName != before.GivenName {
		t.Error("unrelated profile columns changed; this method must touch nothing else")
	}

	if err := database.SetUserPasswordHash(nil, 0, "x"); err == nil {
		t.Error("expected an error setting the password hash of user id 0")
	}
}

// TestTrySetUserEnabled pins the compare-and-set in both directions. The disable
// direction's return value is what gates the revocation sweep in a later stage, so
// "returns true exactly once" is the property that stops a second disable of an
// already-disabled account sweeping and auditing again (#106).
func TestTrySetUserEnabled(t *testing.T) {
	user := createTestUser(t)
	user.Enabled = true
	if err := database.UpdateUser(nil, user); err != nil {
		t.Fatalf("Failed to enable the test user: %v", err)
	}

	// Disable: the first call transitions, the second does not.
	first, err := database.TrySetUserEnabled(nil, user.Id, true, false)
	if err != nil {
		t.Fatalf("first disable failed: %v", err)
	}
	if !first {
		t.Error("first disable should report the transition")
	}

	second, err := database.TrySetUserEnabled(nil, user.Id, true, false)
	if err != nil {
		t.Fatalf("second disable failed: %v", err)
	}
	if second {
		t.Error("second disable must report false; the account was already disabled")
	}

	reloaded, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if reloaded.Enabled {
		t.Error("user should be disabled")
	}

	// Enable: same property in the other direction. This is why the method covers both
	// rather than being a TryDisableUser, so enabling does not fall back to a full-row
	// update that could clobber a concurrent password change.
	firstEnable, err := database.TrySetUserEnabled(nil, user.Id, false, true)
	if err != nil {
		t.Fatalf("first enable failed: %v", err)
	}
	if !firstEnable {
		t.Error("first enable should report the transition")
	}

	secondEnable, err := database.TrySetUserEnabled(nil, user.Id, false, true)
	if err != nil {
		t.Fatalf("second enable failed: %v", err)
	}
	if secondEnable {
		t.Error("second enable must report false; the account was already enabled")
	}

	// A mismatched expectation is a no-op, not an error.
	mismatch, err := database.TrySetUserEnabled(nil, user.Id, false, false)
	if err != nil {
		t.Fatalf("mismatched expectation should not error: %v", err)
	}
	if mismatch {
		t.Error("a mismatched expected value must report false")
	}
	reloaded, err = database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if !reloaded.Enabled {
		t.Error("a mismatched expectation must leave the row alone")
	}

	if _, err := database.TrySetUserEnabled(nil, 0, true, false); err == nil {
		t.Error("expected an error setting enabled on user id 0")
	}
}

// createEnrolledTestUser returns a saved user with OTP on, which the consumed-step
// tests need explicitly: createTestUser randomises OTPEnabled, so a test relying on
// it would pass or fail by coin toss once requireOTPEnabled is in the predicate.
func createEnrolledTestUser(t *testing.T) *models.User {
	t.Helper()
	user := createTestUser(t)
	user.OTPEnabled = true
	if err := database.UpdateUser(nil, user); err != nil {
		t.Fatalf("Failed to enable OTP on the test user: %v", err)
	}
	return user
}

// nowStep is a plausible TOTP time step, the one the current wall clock falls in. The
// tests use realistic magnitudes rather than small integers because the column's
// meaning depends on it: decision 2 reads 0 as "nothing consumed" precisely because a
// step is Unix seconds divided by 30, so any real one is around 6e7, and a test built
// on steps 1, 2 and 3 would not exercise the same distinction.
func nowStep() int64 {
	return time.Now().UTC().Unix() / 30
}

// TestTryConsumeUserOTPStep is the claim table for #111: a TOTP code accepted once is
// never accepted again, because the accept and the record are one conditional UPDATE.
//
// The flag is false throughout, which is the enrollment sites' predicate;
// TestTryConsumeUserOTPStep_RequireOTPEnabled covers the verification sites' one.
func TestTryConsumeUserOTPStep(t *testing.T) {
	user := createEnrolledTestUser(t)
	step := nowStep()

	// A fresh row starts at 0, so the first claim of any real step transitions it.
	claimed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
	if err != nil {
		t.Fatalf("first claim failed: %v", err)
	}
	if !claimed {
		t.Error("the first claim of a step must report the transition")
	}

	reloaded, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if reloaded.LastOTPStep != step {
		t.Errorf("persisted last_otp_step = %d, want %d", reloaded.LastOTPStep, step)
	}

	// The same step again is the replay this whole issue exists to refuse.
	again, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
	if err != nil {
		t.Fatalf("replayed claim errored instead of being refused: %v", err)
	}
	if again {
		t.Error("claiming the same step twice must report false; that is a replay")
	}

	// A lower step is refused too. The marker is a high-water mark, so it also refuses
	// codes below it that were never used: decision 1 accepts that imprecision because
	// it only spans the 90 second acceptance window.
	lower, err := database.TryConsumeUserOTPStep(nil, user.Id, step-1, false)
	if err != nil {
		t.Fatalf("lower claim errored: %v", err)
	}
	if lower {
		t.Error("a step below the stored one must be refused")
	}

	// The next step is a different code and is accepted.
	higher, err := database.TryConsumeUserOTPStep(nil, user.Id, step+1, false)
	if err != nil {
		t.Fatalf("higher claim failed: %v", err)
	}
	if !higher {
		t.Error("a step above the stored one must be accepted")
	}

	// An unknown user is a refusal, not an error: no row transitioned, which is the
	// only thing the method reports. The caller cannot tell it from a replay, and the
	// doc comment says so.
	unknown, err := database.TryConsumeUserOTPStep(nil, 999999999, step, false)
	if err != nil {
		t.Errorf("an unknown user id must not error, got %v", err)
	}
	if unknown {
		t.Error("an unknown user id must report false")
	}

	if _, err := database.TryConsumeUserOTPStep(nil, 0, step, false); err == nil {
		t.Error("expected an error consuming an OTP step for user id 0")
	}
}

// TestResetUserOTPStep pins decision 4: disabling OTP returns the marker to 0, which
// is what makes a consumed step claimable again and what an operator relies on if a
// clock jump strands the marker in the future.
func TestResetUserOTPStep(t *testing.T) {
	user := createEnrolledTestUser(t)
	step := nowStep()

	claimed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
	if err != nil || !claimed {
		t.Fatalf("seeding a consumed step failed: claimed=%v err=%v", claimed, err)
	}

	if err := database.ResetUserOTPStep(nil, user.Id); err != nil {
		t.Fatalf("ResetUserOTPStep failed: %v", err)
	}

	reloaded, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if reloaded.LastOTPStep != 0 {
		t.Errorf("last_otp_step after reset = %d, want 0", reloaded.LastOTPStep)
	}

	// The consumed step is claimable again, which is the observable half of the reset.
	reclaimed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
	if err != nil {
		t.Fatalf("claim after reset failed: %v", err)
	}
	if !reclaimed {
		t.Error("a reset must make a previously consumed step claimable again")
	}

	// Resetting an already-reset user is a no-op rather than a failure: nothing gates
	// on a transition here, unlike TrySetUserEnabled's disable direction.
	if err := database.ResetUserOTPStep(nil, user.Id); err != nil {
		t.Errorf("resetting twice must not error, got %v", err)
	}

	if err := database.ResetUserOTPStep(nil, 0); err == nil {
		t.Error("expected an error resetting the OTP step of user id 0")
	}
}

// TestTryConsumeUserOTPStep_RequireOTPEnabled pins both directions of decision 10's
// flag.
//
// A verification claim asserts a factor, and that assertion is only true of an
// enrolled authenticator. Without the otp_enabled term, a browser request that loaded
// the user before a concurrent disable would still claim its step and be issued a
// token naming amr "otp" for an authenticator that had just been removed. Enrollment
// claims must not carry the term, because they run before the enable write.
//
// Keep this test. It is the only place either direction of the flag is observable:
// the interleaving it pins needs a request holding state loaded before a disable, so
// no endpoint can reach it, and hard-wiring the flag either way leaves every other
// case in the suite green.
func TestTryConsumeUserOTPStep_RequireOTPEnabled(t *testing.T) {
	user := createEnrolledTestUser(t)
	step := nowStep()

	// Enrolled: a verification claim transitions the row.
	claimed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, true)
	if err != nil {
		t.Fatalf("verification claim against an enrolled user failed: %v", err)
	}
	if !claimed {
		t.Error("a verification claim against an enrolled user must succeed")
	}

	// The authenticator is removed. Written through UpdateUser, which is what the
	// disable handlers do; it cannot touch last_otp_step, since the column is
	// dont-update.
	user.OTPEnabled = false
	if err := database.UpdateUser(nil, user); err != nil {
		t.Fatalf("Failed to disable OTP: %v", err)
	}

	// A verification claim is now refused, with no error: the step is newer than the
	// stored one, so only the otp_enabled term can be refusing it.
	afterDisable, err := database.TryConsumeUserOTPStep(nil, user.Id, step+1, true)
	if err != nil {
		t.Fatalf("verification claim after a disable errored instead of being refused: %v", err)
	}
	if afterDisable {
		t.Error("a verification claim must be refused once OTP is disabled (is the otp_enabled term missing?)")
	}

	// The same claim without the flag succeeds, which is what the enrollment sites
	// need: they claim while otp_enabled is still false.
	enrolling, err := database.TryConsumeUserOTPStep(nil, user.Id, step+1, false)
	if err != nil {
		t.Fatalf("enrollment claim failed: %v", err)
	}
	if !enrolling {
		t.Error("an enrollment claim must succeed with OTP disabled (is the flag hard-wired on?)")
	}
}

// TestResetUserOTPStep_DoesNotReopenConsumedStepToVerification is decision 10's hole
// and decision 4's remedy in one case.
//
// The reset makes a consumed step claimable again, which is exactly what an in-flight
// verification request holding pre-disable state would exploit if the claim did not
// bind to enrolment state. The flag is what closes it: after the disable the
// verification claim is refused even though the marker is back at 0.
func TestResetUserOTPStep_DoesNotReopenConsumedStepToVerification(t *testing.T) {
	user := createEnrolledTestUser(t)
	step := nowStep()

	consumed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, true)
	if err != nil || !consumed {
		t.Fatalf("seeding a consumed step failed: consumed=%v err=%v", consumed, err)
	}

	// A disable, in the order the handlers use: clear otp_enabled first, then reset.
	// Reversed, there is a window where the marker reads 0 while the authenticator
	// still reads enabled, and this test's claim would succeed.
	user.OTPEnabled = false
	if err := database.UpdateUser(nil, user); err != nil {
		t.Fatalf("Failed to disable OTP: %v", err)
	}
	if err := database.ResetUserOTPStep(nil, user.Id); err != nil {
		t.Fatalf("ResetUserOTPStep failed: %v", err)
	}

	replayed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, true)
	if err != nil {
		t.Fatalf("verification claim after reset errored instead of being refused: %v", err)
	}
	if replayed {
		t.Error("a reset must not reopen a consumed step to a verification claim")
	}

	// Re-enrolment, which is the point of the reset, still works with that same step.
	reenrolling, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
	if err != nil {
		t.Fatalf("re-enrolment claim failed: %v", err)
	}
	if !reenrolling {
		t.Error("a reset must let re-enrolment claim a previously consumed step")
	}
}

// TestTryConsumeUserOTPStep_EnlistsInTransactionAndFailsClosed covers the two
// questions a mock cannot answer, both forced by one rolled-back transaction.
//
// Enlistment: a method that ignored its tx and wrote through the pool instead would
// leave the claim behind after a rollback, and every other case here would still
// pass. No planned call site passes a tx, since the claim is a single statement, so
// this pins the interface contract rather than a current caller: honouring the
// supplied tx is what would make it safe for a later change to wrap the claim and the
// enrollment write together, and a claim that escaped would commit even when the
// enable rolled back.
//
// Failing closed: after the rollback the transaction is finished, so the driver
// returns an error rather than executing. The method must surface it as (false, err)
// so the caller responds 500. Collapsing a database fault into "not consumed" would
// refuse valid codes; collapsing it into "consumed" would accept replays for as long
// as the fault lasted.
func TestTryConsumeUserOTPStep_EnlistsInTransactionAndFailsClosed(t *testing.T) {
	user := createEnrolledTestUser(t)
	step := nowStep()

	tx := beginTx(t)
	claimed, err := database.TryConsumeUserOTPStep(tx, user.Id, step, false)
	if err != nil {
		t.Fatalf("claim inside a transaction failed: %v", err)
	}
	if !claimed {
		t.Fatal("claim inside a transaction should report the transition")
	}

	if err := database.RollbackTransaction(tx); err != nil {
		t.Fatalf("RollbackTransaction failed: %v", err)
	}

	reloaded, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if reloaded.LastOTPStep != 0 {
		t.Errorf("a rolled-back claim must not persist, last_otp_step = %d (did the method escape its transaction?)",
			reloaded.LastOTPStep)
	}

	// The step is free again, which is the same fact from the other side.
	afterRollback, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
	if err != nil {
		t.Fatalf("claim after rollback failed: %v", err)
	}
	if !afterRollback {
		t.Error("a rolled-back claim must leave the step claimable")
	}

	// The finished transaction is the forced fault.
	failed, err := database.TryConsumeUserOTPStep(tx, user.Id, step+1, false)
	if err == nil {
		t.Error("a claim through a finished transaction must return an error, not a benign false")
	}
	if failed {
		t.Error("a failed claim must never report true")
	}

	if err := database.ResetUserOTPStep(tx, user.Id); err == nil {
		t.Error("a reset through a finished transaction must return an error")
	}
}

// TestTryConsumeUserOTPStep_ConcurrentCallersProduceOneWinner is §2 goal 3: two
// concurrent submissions of one code yield at most one success.
//
// The sequential claim table cannot tell a conditional UPDATE from a read-then-write.
// A non-atomic implementation passes first/same/lower/higher perfectly and still lets
// two concurrent callers both win, which is the double-submit an attacker holding a
// phished code races for.
//
// Follows TestTryClaimCleanupRun_ConcurrentCallersProduceOneWinner, including its
// honesty: overlap can be made likely but not forced, so a green run detects a broken
// implementation probabilistically rather than certifying atomicity.
func TestTryConsumeUserOTPStep_ConcurrentCallersProduceOneWinner(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so callers queue " +
			"rather than contend; the test would pass without ever creating overlap")
	}

	const (
		callers = 8
		rounds  = 5
	)

	user := createEnrolledTestUser(t)
	base := nowStep()

	for round := 0; round < rounds; round++ {
		// A fresh step per round, so each round is a first claim rather than a replay.
		step := base + int64(round) + 1

		type outcome struct {
			claimed bool
			err     error
		}
		outcomes := make([]outcome, callers)

		// Every caller waits on the same barrier so they hit the row together. Each
		// takes its own pooled connection, since tx is nil.
		start := make(chan struct{})
		var wg sync.WaitGroup

		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				claimed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
				outcomes[i] = outcome{claimed: claimed, err: err}
			}(i)
		}

		close(start)
		wg.Wait()

		wins, failures := 0, 0
		for _, o := range outcomes {
			if o.err != nil {
				// A lock-wait timeout or deadlock is a legitimate outcome under
				// contention and counts as "did not claim". In production that is a
				// 500 and the code is refused, which is the correct response.
				failures++
				continue
			}
			if o.claimed {
				wins++
			}
		}

		if wins != 1 {
			t.Fatalf("round %d: expected exactly 1 winner among %d concurrent claims of step %d, got %d (%d errored)",
				round, callers, step, wins, failures)
		}
		if failures > 0 {
			t.Logf("round %d: 1 winner, %d lock contention errors (acceptable)", round, failures)
		}

		reloaded, err := database.GetUserById(nil, user.Id)
		if err != nil {
			t.Fatalf("round %d: Failed to reload user: %v", round, err)
		}
		if reloaded.LastOTPStep != step {
			t.Fatalf("round %d: last_otp_step = %d, want %d", round, reloaded.LastOTPStep, step)
		}
	}
}

// TestUpdateUser_DoesNotClobberLastOTPStep is §2 goal 4: the counter cannot be
// regressed by an ordinary whole-user write.
//
// last_otp_step is tagged fieldtag:"dont-update" per decision 2. The hazard is more
// direct than AuthStateGeneration's: the OTP enrollment handler claims a step and
// then writes the whole user back in the same request, so without the tag it would
// write its own pre-claim value over its own claim and leave the enrollment code
// replayable.
//
// Keep this test. Dropping or misspelling the tag still compiles and leaves every
// claim and migration case green. The claimed step is nonzero for the same reason
// TestUpdateUser_DoesNotClobberAuthStateGeneration's is: 0 is the column default, so
// a case written with 0 passes with the column never written at all.
func TestUpdateUser_DoesNotClobberLastOTPStep(t *testing.T) {
	user := createEnrolledTestUser(t)
	step := nowStep()

	// A model read before the claim, which is what a concurrent handler holds. Read
	// rather than reused, so its LastOTPStep is genuinely the pre-claim value.
	stale, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to load the pre-claim model: %v", err)
	}
	if stale.LastOTPStep != 0 {
		t.Fatalf("expected a fresh user to start at step 0, got %d", stale.LastOTPStep)
	}

	claimed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
	if err != nil || !claimed {
		t.Fatalf("seeding a consumed step failed: claimed=%v err=%v", claimed, err)
	}

	stale.GivenName = "Changed"
	if err := database.UpdateUser(nil, stale); err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	after, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload updated user: %v", err)
	}
	if after.LastOTPStep != step {
		t.Errorf("UpdateUser regressed last_otp_step to %d, want %d (is the dont-update tag missing?)",
			after.LastOTPStep, step)
	}
	if after.GivenName != "Changed" {
		t.Errorf("the rest of the update must still apply, GivenName = %q", after.GivenName)
	}
}

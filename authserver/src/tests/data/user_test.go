// cmd/data_tests/user_test.go

package datatests

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/models"
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
	user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().Truncate(time.Microsecond), Valid: true}
	user.ZoneInfoCountryName = gofakeit.Country()
	user.ZoneInfo = gofakeit.TimeZone()
	user.Locale = gofakeit.Language()
	user.BirthDate = sql.NullTime{Time: gofakeit.Date().Truncate(time.Microsecond), Valid: true}
	user.PhoneNumberCountryUniqueId = gofakeit.CountryAbr()
	user.PhoneNumberCountryCallingCode = fmt.Sprintf("+%s", gofakeit.Numerify("##"))
	user.PhoneNumber = gofakeit.Phone()
	user.PhoneNumberVerified = !user.PhoneNumberVerified
	user.PhoneNumberVerificationCodeEncrypted = []byte(gofakeit.Password(true, true, true, true, false, 32))
	user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().Truncate(time.Microsecond), Valid: true}
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
	user.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: time.Now().Truncate(time.Microsecond), Valid: true}

	time.Sleep(time.Millisecond * 100)

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
		EmailVerificationCodeIssuedAt:        sql.NullTime{Time: time.Now().Truncate(time.Microsecond), Valid: true},
		ZoneInfoCountryName:                  gofakeit.Country(),
		ZoneInfo:                             gofakeit.TimeZone(),
		Locale:                               gofakeit.Language(),
		BirthDate:                            sql.NullTime{Time: gofakeit.Date().Truncate(time.Microsecond), Valid: true},
		PhoneNumberCountryUniqueId:           gofakeit.CountryAbr(),
		PhoneNumberCountryCallingCode:        fmt.Sprintf("+%s", gofakeit.Numerify("##")),
		PhoneNumber:                          gofakeit.Phone(),
		PhoneNumberVerified:                  gofakeit.Bool(),
		PhoneNumberVerificationCodeEncrypted: []byte(gofakeit.Password(true, true, true, true, false, 32)),
		PhoneNumberVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().Truncate(time.Microsecond), Valid: true},
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
		ForgotPasswordCodeIssuedAt:           sql.NullTime{Time: time.Now().Truncate(time.Microsecond), Valid: true},
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

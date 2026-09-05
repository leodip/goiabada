// cmd/data_tests/user_test.go

package datatests

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
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

	// The search has to mean one thing on all four engines, and the term has to be data rather
	// than a pattern the caller of the admin API chooses. Neither was true before: the fold was
	// left to the column's collation, which compares case-sensitively on SQLite and PostgreSQL
	// and folds on MySQL and SQL Server, so the same search returned different rows per engine
	// (#283); and a term of "%" matched every user in the deployment (#95).
	//
	// Every subtest seeds its rows under one random tag carrying both cases, and asserts only
	// about rows it seeded. The shared test databases keep their users across runs, so a case
	// that counted every matching row would be decided by whatever an earlier test left behind.

	t.Run("the search folds case on every engine", func(t *testing.T) {
		// The tag begins "Tag", so it differs from both its own lowercase and its own uppercase
		// form whatever LetterN returns, which is what makes the two folding queries real.
		tag := "Tag" + gofakeit.LetterN(10)
		want := createSearchUser(t, tag, "u"+gofakeit.LetterN(12))

		for _, c := range []struct {
			name  string
			query string
		}{
			// The gate for both folding cases is LOWER() on the two sides of the predicate.
			// PostgreSQL is where they fail without it, since its collation folds nothing;
			// SQLite's LIKE folds ASCII on its own, and MySQL and SQL Server fold until the
			// collation moves.
			{"folded down", strings.ToLower(tag)},
			{"folded up", strings.ToUpper(tag)},
			// The exact spelling has always worked. Keep it: it is what says the folding was
			// added without trading the plain case away.
			{"exact", tag},
		} {
			t.Run(c.name, func(t *testing.T) {
				assertSearchFindsExactly(t, c.query, want.Id)
			})
		}
	})

	t.Run("a % in the term is matched literally", func(t *testing.T) {
		tag := "Tag" + gofakeit.LetterN(10)
		withPercent := createSearchUser(t, tag+"%x", "u"+gofakeit.LetterN(12))
		// Differs from the row above in exactly one character, the one under test, so it can
		// only be matched by reading "%" as a wildcard.
		createSearchUser(t, tag+"zx", "u"+gofakeit.LetterN(12))

		assertSearchFindsExactly(t, tag+"%x", withPercent.Id)
	})

	t.Run("a term of % stops matching every user", func(t *testing.T) {
		// #95 as reported: the term is the wildcard itself, so the search returns the whole
		// user table a page at a time.
		tag := "Tag" + gofakeit.LetterN(10)
		withPercent := createSearchUser(t, tag+"%x", "u"+gofakeit.LetterN(12))
		plain := createSearchUser(t, tag+"plain", "u"+gofakeit.LetterN(12))

		// Large enough that the whole result set fits on one page in a test database of any
		// plausible size, and the guard below turns an overflow into this test's own failure
		// rather than a silent pass: a "%" read as a wildcard matches every user there is.
		const pageSize = 2000
		users, total, err := database.SearchUsersPaginated(nil, "%", 1, pageSize)
		if err != nil {
			t.Fatalf("Failed to search users: %v", err)
		}
		if total > len(users) {
			t.Fatalf("A search for %%%% matched %d users, more than the %d this page holds: the term is being read as a wildcard", total, len(users))
		}
		ids := userIds(users)
		if !ids[withPercent.Id] {
			t.Errorf("Expected the user whose given name contains a literal %%%% to be found, got %d rows", len(users))
		}
		if ids[plain.Id] {
			t.Errorf("Expected a user with no %%%% in any searched column to be absent, but a term of %%%% matched it")
		}
	})

	t.Run("an _ in the term is matched literally", func(t *testing.T) {
		tag := "Tag" + gofakeit.LetterN(10)
		withUnderscore := createSearchUser(t, "g"+gofakeit.LetterN(12), tag+"a_b")
		// Again one character apart: "_" matches any single character until it is escaped.
		createSearchUser(t, "g"+gofakeit.LetterN(12), tag+"axb")

		assertSearchFindsExactly(t, tag+"a_b", withUnderscore.Id)
	})

	t.Run("a literal ! is findable", func(t *testing.T) {
		// "!" is the escape character the predicate declares, so the escaper has to double it.
		// Undoubled, the pattern reads "!e" as an escaped "e" and finds a row spelled without
		// the "!" instead of this one. An email local part may legally contain "!".
		tag := "Tag" + gofakeit.LetterN(10)
		withBang := createSearchUser(t, tag+"!e", "u"+gofakeit.LetterN(12))

		assertSearchFindsExactly(t, tag+"!e", withBang.Id)
	})

	t.Run("a [ in the term is matched literally", func(t *testing.T) {
		// SQL Server's LIKE has a third wildcard the other three do not, the [abc] character
		// class, so this case is only rejected there: unescaped, "[x]" matches a single "x" and
		// finds the second row instead of the first. On the other three "[" is already a
		// literal and both spellings pass, which is why the data tier has to run on all four.
		tag := "Tag" + gofakeit.LetterN(10)
		withClass := createSearchUser(t, tag+"[x]y", "u"+gofakeit.LetterN(12))
		createSearchUser(t, tag+"xy", "u"+gofakeit.LetterN(12))

		assertSearchFindsExactly(t, tag+"[x]y", withClass.Id)
	})
}

// createSearchUser creates a user with both of the columns the search cases vary, given_name and
// username. The other searched columns get values that cannot collide with a tag.
func createSearchUser(t *testing.T, givenName string, username string) *models.User {
	t.Helper()
	user := &models.User{
		Enabled:   true,
		Subject:   uuid.New(),
		Username:  username,
		GivenName: givenName,
		Email:     gofakeit.LetterN(12) + "@example.com",
	}
	if err := database.CreateUser(nil, user); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	return user
}

// assertSearchFindsExactly checks both halves of the query SearchUsersPaginated builds: the rows
// the page returns, and the total, which is a second set of predicates over the same columns and
// would otherwise go unasserted.
func assertSearchFindsExactly(t *testing.T, query string, wantId int64) {
	t.Helper()
	users, total, err := database.SearchUsersPaginated(nil, query, 1, 10)
	if err != nil {
		t.Fatalf("Failed to search users for %q: %v", query, err)
	}
	if total != 1 {
		t.Fatalf("Expected a total of 1 for %q, got %d", query, total)
	}
	if len(users) != 1 {
		t.Fatalf("Expected 1 user for %q, got %d", query, len(users))
	}
	if users[0].Id != wantId {
		t.Errorf("Expected user %d for %q, got %d", wantId, query, users[0].Id)
	}
}

func userIds(users []models.User) map[int64]bool {
	ids := make(map[int64]bool, len(users))
	for _, user := range users {
		ids[user.Id] = true
	}
	return ids
}

// A page is a slice of an order, so paging is only correct when that order is total.
// given_name is not unique, and ties are the norm rather than the exception here: every
// self-registered user has an empty given name, as does the seeded admin. Where a tie group
// straddles a page boundary and nothing breaks the tie, the database may arrange those rows one
// way for the page-1 query and another way for the page-2 query, so one user comes back on both
// pages and another is never returned at all. This pins the total order the fix establishes,
// given_name then id, which is what makes the pages a partition of the result set (#112).
func TestSearchUsersPaginated_TiedGivenNamesStillPageAsAPartition(t *testing.T) {
	// One given name shared by every user, which is the worst case: the entire result set is a
	// single tie group. The random suffix is what keeps the search matching only these rows.
	givenName := "TiedPage" + gofakeit.LetterN(10)

	const userCount = 7
	wantIds := make([]int64, 0, userCount)
	for i := 0; i < userCount; i++ {
		wantIds = append(wantIds, createUserWithGivenName(t, givenName).Id)
	}

	// Ids ascend with creation, so the order the fix establishes is the order they were made in.
	// Postgres is the engine that actually rearranges tied rows, so it is the one that catches a
	// missing tiebreaker; the others read these back in primary-key order anyway and the assertion
	// holds there either way. Running the data tier on all four is what makes the coverage real.
	const pageSize = 3
	gotIds := make([]int64, 0, userCount)
	for page := 1; page <= userCount; page++ {
		users, total, err := database.SearchUsersPaginated(nil, givenName, page, pageSize)
		if err != nil {
			t.Fatalf("Failed to search users on page %d: %v", page, err)
		}
		if total != userCount {
			t.Fatalf("Expected a total of %d on page %d, got %d", userCount, page, total)
		}
		if len(users) == 0 {
			break
		}
		if len(users) > pageSize {
			t.Fatalf("Expected at most %d users on page %d, got %d", pageSize, page, len(users))
		}
		for _, user := range users {
			gotIds = append(gotIds, user.Id)
		}
	}

	if len(gotIds) != len(wantIds) {
		t.Fatalf("Expected paging to return each of the %d users exactly once, got %d rows: %v",
			len(wantIds), len(gotIds), gotIds)
	}
	for i := range wantIds {
		if gotIds[i] != wantIds[i] {
			t.Fatalf("Expected the pages to concatenate into ascending id order %v, got %v",
				wantIds, gotIds)
		}
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

// createTestUser seeds a user on the package's shared handle. createTestUserOn takes the handle,
// which is what lets a test run against a fixture database of its own (#139 stage 8).
func createTestUser(t *testing.T) *models.User {
	return createTestUserOn(t, database)
}

func createTestUserOn(t *testing.T, db data.Database) *models.User {
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

	err := db.CreateUser(nil, user)
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

// codeHashOf is what the three issue sites store: an unsalted SHA-256 hex of the code
// that went into the link. The tests use real hashes rather than short literals because
// the column's meaning depends on the shape. The empty string reads as "no code
// outstanding" precisely
// because SHA-256 hex is always 64 characters, so a table built on "abc" would not
// exercise the same distinction (#112).
func codeHashOf(t *testing.T, code string) string {
	t.Helper()
	hash, err := hashutil.HashString(code)
	if err != nil {
		t.Fatalf("HashString: %v", err)
	}
	return hash
}

// createUserWithResetCode returns a saved user carrying an outstanding forgot-password
// code, plus the hash the reset link would find it by. createTestUser leaves the hash at
// its empty default, so an ordinary test user is a dormant row for these lookups.
func createUserWithResetCode(t *testing.T) (*models.User, string) {
	t.Helper()
	user := createTestUser(t)
	hash := codeHashOf(t, uuid.NewString())
	user.ForgotPasswordCodeEncrypted = []byte("PENDINGRESETCODE")
	user.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}
	user.ForgotPasswordCodeHash = hash
	if err := database.UpdateUser(nil, user); err != nil {
		t.Fatalf("Failed to seed an outstanding reset code: %v", err)
	}
	return user, hash
}

// TestGetUserByForgotPasswordCodeHash is the identity half of seam 2 for the reset flow:
// the link carries the code and no address, so this lookup is the only thing that says
// which user a reset link belongs to (#112).
//
// The dormant-row cases are the ones that matter. Every user with no outstanding code
// carries the empty string, so a lookup reaching the query with an empty hash would hand back
// somebody else's account.
func TestGetUserByForgotPasswordCodeHash(t *testing.T) {
	user, hash := createUserWithResetCode(t)

	// 1. The hash that was stored finds the row it was stored on.
	found, err := database.GetUserByForgotPasswordCodeHash(nil, hash)
	if err != nil {
		t.Fatalf("lookup by the stored hash failed: %v", err)
	}
	if found == nil {
		t.Fatal("the stored hash must find the user it was stored on")
	}
	if found.Id != user.Id {
		t.Errorf("found user id %d, want %d", found.Id, user.Id)
	}
	if found.ForgotPasswordCodeHash != hash {
		t.Errorf("round-tripped hash = %q, want %q", found.ForgotPasswordCodeHash, hash)
	}

	// 2. A hash no row carries is a miss, not an error. The handler renders the same
	// indistinguishable page for a miss as for a wrong code, so a spurious error here
	// would surface as a 500 and tell an attacker the difference.
	missing, err := database.GetUserByForgotPasswordCodeHash(nil, codeHashOf(t, uuid.NewString()))
	if err != nil {
		t.Errorf("a hash no row carries must not be an error, got: %v", err)
	}
	if missing != nil {
		t.Errorf("a hash no row carries must return nil, got user id %d", missing.Id)
	}
}

// TestGetUserByForgotPasswordCodeHash_EmptyNeverMatches is case 3 and case 4 of the
// table, and the pair is deliberate. Case 3 proves an empty hash finds nothing with several dormant
// rows in place; case 4 proves the same from the other side, that a real 64-hex hash
// still misses while those dormant rows exist. Without case 4 a lookup could be passing
// case 3 purely on the empty-code guard while the query itself matched dormant rows.
func TestGetUserByForgotPasswordCodeHash_EmptyNeverMatches(t *testing.T) {
	// Three users with no outstanding code, so the '' value is present several times
	// over. The plain (non-UNIQUE) index on this column is what makes that legal, and
	// this is the case that would find a UNIQUE one.
	dormant := make([]*models.User, 0, 3)
	for i := 0; i < 3; i++ {
		u := createTestUser(t)
		if u.ForgotPasswordCodeHash != "" {
			t.Fatalf("a fresh user must carry no code hash, got %q", u.ForgotPasswordCodeHash)
		}
		dormant = append(dormant, u)
	}

	// 3. The empty hash matches none of them.
	found, err := database.GetUserByForgotPasswordCodeHash(nil, "")
	if err != nil {
		t.Errorf("an empty hash must not be an error, got: %v", err)
	}
	if found != nil {
		t.Errorf("an empty hash matched user id %d; every user with no outstanding code carries '' and none of them may be findable",
			found.Id)
	}

	// 4. A real hash nobody holds still misses, with those same dormant rows present.
	found, err = database.GetUserByForgotPasswordCodeHash(nil, codeHashOf(t, "a code no user was ever issued"))
	if err != nil {
		t.Errorf("a hash no row carries must not be an error, got: %v", err)
	}
	if found != nil {
		t.Errorf("a hash no row carries matched user id %d", found.Id)
	}

	for _, u := range dormant {
		reloaded, err := database.GetUserById(nil, u.Id)
		if err != nil {
			t.Fatalf("Failed to reload a dormant user: %v", err)
		}
		if reloaded.ForgotPasswordCodeHash != "" {
			t.Errorf("a dormant user's hash changed to %q; nothing in this test writes it", reloaded.ForgotPasswordCodeHash)
		}
	}
}

// TestSetUserPasswordHash_ClearsCodeHash is case 5: setting a password makes the
// outstanding code's hash unfindable. The expiry check would still refuse a used code,
// but the row should not be locatable by that hash at all.
//
// The lookup runs before and after on purpose. Asserting only the "after" would pass with
// the clear reverted if the hash had never been findable to begin with.
func TestSetUserPasswordHash_ClearsCodeHash(t *testing.T) {
	user, hash := createUserWithResetCode(t)

	before, err := database.GetUserByForgotPasswordCodeHash(nil, hash)
	if err != nil || before == nil {
		t.Fatalf("the seeded hash must be findable before the password write: user=%v err=%v", before, err)
	}

	if err := database.SetUserPasswordHash(nil, user.Id, "newhash"); err != nil {
		t.Fatalf("SetUserPasswordHash failed: %v", err)
	}

	after, err := database.GetUserByForgotPasswordCodeHash(nil, hash)
	if err != nil {
		t.Fatalf("lookup after the password write failed: %v", err)
	}
	if after != nil {
		t.Errorf("the hash still finds user id %d after the password was set; SetUserPasswordHash must clear it in the same statement",
			after.Id)
	}

	reloaded, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if reloaded.ForgotPasswordCodeHash != "" {
		t.Errorf("forgot_password_code_hash = %q after the password write, want the dormant ''",
			reloaded.ForgotPasswordCodeHash)
	}
}

// TestGetUserByForgotPasswordCodeHash_Transaction is cases 6 and 7: the lookup runs on
// the caller's transaction, and a failure propagates as an error rather than as a benign
// "no such code".
//
// It reads only THROUGH the transaction while that transaction is open, never around it.
// A second connection reading the same row cannot run on all four engines: sqlite is
// limited to one connection (SetMaxOpenConns(1)) so the outside read would queue rather
// than fail, and SQL Server's READ COMMITTED takes shared row locks rather than reading a
// snapshot, so it would block. transaction_test.go documents both. The outside read here
// happens only after the transaction is finished, which needs no second connection.
func TestGetUserByForgotPasswordCodeHash_Transaction(t *testing.T) {
	hash := codeHashOf(t, uuid.NewString())

	// The user is created BEFORE the transaction opens. sqlite runs with
	// SetMaxOpenConns(1), so a pooled write while a transaction holds that one connection
	// waits for a connection that cannot be released until the transaction ends, and the
	// test hangs rather than failing.
	user := createTestUser(t)

	tx := beginTx(t)

	user.ForgotPasswordCodeHash = hash
	if err := database.UpdateUser(tx, user); err != nil {
		t.Fatalf("Failed to write the code hash inside the transaction: %v", err)
	}

	// 6. Visible through the transaction that wrote it. A method ignoring its tx would
	// query the pool, which cannot see this write.
	inTx, err := database.GetUserByForgotPasswordCodeHash(tx, hash)
	if err != nil {
		t.Fatalf("lookup through the writing transaction failed: %v", err)
	}
	if inTx == nil {
		t.Fatal("a row written in this transaction must be visible through it (did the lookup ignore its tx?)")
	}
	if inTx.Id != user.Id {
		t.Errorf("found user id %d through the transaction, want %d", inTx.Id, user.Id)
	}

	if err := database.RollbackTransaction(tx); err != nil {
		t.Fatalf("RollbackTransaction failed: %v", err)
	}

	// 7a. Rolled back, so nothing carries the hash any more.
	afterRollback, err := database.GetUserByForgotPasswordCodeHash(nil, hash)
	if err != nil {
		t.Fatalf("lookup after rollback failed: %v", err)
	}
	if afterRollback != nil {
		t.Errorf("a rolled-back write must leave no findable hash, found user id %d", afterRollback.Id)
	}

	// 7b. The finished transaction is the forced fault. A driver failure must not
	// collapse into "no such code": the reset flow reads that as a wrong code and
	// refuses, which is safe, but it is a 500 and the record must say so.
	failed, err := database.GetUserByForgotPasswordCodeHash(tx, hash)
	if err == nil {
		t.Error("a lookup through a finished transaction must return an error, not a benign nil")
	}
	if failed != nil {
		t.Error("a failed lookup must never return a user")
	}
}

// TestTryConsumeForgotPasswordCode is cases 16 to 19: the claim table for the conditional
// write that ends a password reset.
//
// The second call is the case the whole method turns on. The reset flow's "this code was
// validated" marker lives in a client-side encrypted session cookie, so clearing it in a
// response cannot invalidate a copy an attacker kept; what refuses the replay is that the
// claim's predicate no longer matches (#112).
func TestTryConsumeForgotPasswordCode(t *testing.T) {
	user, hash := createUserWithResetCode(t)

	// 16. The stored hash claims, writes the password, and clears all three code columns.
	claimed, err := database.TryConsumeForgotPasswordCode(nil, user.Id, hash, "firstpassword")
	if err != nil {
		t.Fatalf("the first claim failed: %v", err)
	}
	if !claimed {
		t.Fatal("the first claim of an outstanding code must report the transition")
	}

	after, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if after.PasswordHash != "firstpassword" {
		t.Errorf("PasswordHash = %q, want %q", after.PasswordHash, "firstpassword")
	}
	if len(after.ForgotPasswordCodeEncrypted) != 0 {
		t.Error("the encrypted code must be cleared in the same statement")
	}
	if after.ForgotPasswordCodeIssuedAt.Valid {
		t.Error("the issued-at must be cleared in the same statement")
	}
	if after.ForgotPasswordCodeHash != "" {
		t.Errorf("the code hash must be cleared in the same statement, got %q", after.ForgotPasswordCodeHash)
	}

	// 17. The same hash again claims nothing and leaves the first password standing.
	// Without the hash in the WHERE clause this returns true and overwrites it.
	replayed, err := database.TryConsumeForgotPasswordCode(nil, user.Id, hash, "replayedpassword")
	if err != nil {
		t.Fatalf("the replayed claim errored rather than reporting false: %v", err)
	}
	if replayed {
		t.Error("a second claim of a consumed code must report false")
	}

	afterReplay, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to reload user: %v", err)
	}
	if afterReplay.PasswordHash != "firstpassword" {
		t.Errorf("a replayed claim rewrote the password to %q; it must leave the first one in place",
			afterReplay.PasswordHash)
	}

	// 18. A real hash the row does not carry changes nothing either.
	other, otherHash := createUserWithResetCode(t)
	wrong, err := database.TryConsumeForgotPasswordCode(nil, other.Id, codeHashOf(t, uuid.NewString()), "wrongpassword")
	if err != nil {
		t.Fatalf("a claim with a non-matching hash errored: %v", err)
	}
	if wrong {
		t.Error("a claim with a hash the row does not carry must report false")
	}
	otherAfter, err := database.GetUserById(nil, other.Id)
	if err != nil {
		t.Fatalf("Failed to reload the second user: %v", err)
	}
	if otherAfter.PasswordHash == "wrongpassword" {
		t.Error("a claim with a non-matching hash wrote the password anyway")
	}
	if otherAfter.ForgotPasswordCodeHash != otherHash {
		t.Errorf("a claim with a non-matching hash cleared the outstanding one, got %q want %q",
			otherAfter.ForgotPasswordCodeHash, otherHash)
	}

	// 19. Both guards are errors rather than a benign false, and neither touches the row.
	// '' is the dormant value on every user with no code outstanding, so an empty
	// predicate would claim one of them and set a password on an account nobody asked to
	// reset.
	if _, err := database.TryConsumeForgotPasswordCode(nil, other.Id, "", "guardedpassword"); err == nil {
		t.Error("an empty code hash must return an error")
	}
	if _, err := database.TryConsumeForgotPasswordCode(nil, 0, otherHash, "guardedpassword"); err == nil {
		t.Error("a zero user id must return an error")
	}
	guarded, err := database.GetUserById(nil, other.Id)
	if err != nil {
		t.Fatalf("Failed to reload the second user: %v", err)
	}
	if guarded.PasswordHash == "guardedpassword" || guarded.ForgotPasswordCodeHash != otherHash {
		t.Error("a guarded call must not touch the row")
	}
}

// TestTryConsumeForgotPasswordCode_EnlistsInTransactionAndFailsClosed is case 20, and it
// is the property the sequential table above cannot reach.
//
// Stage 3 calls this method inside the transaction that also revokes the user's sessions
// and refresh tokens. A claim that ignored its tx would commit the new password and clear
// the reset code while that sweep rolled back, leaving the user with a new password and
// every stolen session still live.
func TestTryConsumeForgotPasswordCode_EnlistsInTransactionAndFailsClosed(t *testing.T) {
	user, hash := createUserWithResetCode(t)
	originalPassword := user.PasswordHash

	tx := beginTx(t)
	claimed, err := database.TryConsumeForgotPasswordCode(tx, user.Id, hash, "committedpassword")
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
	if reloaded.PasswordHash != originalPassword {
		t.Errorf("a rolled-back claim persisted the password (%q); did the method escape its transaction?",
			reloaded.PasswordHash)
	}
	if reloaded.ForgotPasswordCodeHash != hash {
		t.Errorf("a rolled-back claim cleared the outstanding code hash, got %q want %q",
			reloaded.ForgotPasswordCodeHash, hash)
	}

	// The code is claimable again, which is the same fact from the other side.
	afterRollback, err := database.TryConsumeForgotPasswordCode(nil, user.Id, hash, "secondpassword")
	if err != nil {
		t.Fatalf("claim after rollback failed: %v", err)
	}
	if !afterRollback {
		t.Error("a rolled-back claim must leave the code claimable")
	}

	// The finished transaction is the forced fault: an error, never a benign false.
	failed, err := database.TryConsumeForgotPasswordCode(tx, user.Id, hash, "faultedpassword")
	if err == nil {
		t.Error("a claim through a finished transaction must return an error, not a benign false")
	}
	if failed {
		t.Error("a failed claim must never report true")
	}
}

// TestTryConsumeForgotPasswordCode_ConcurrentCallersProduceOneWinner is case 21, and the
// only case that can refuse a read-then-unconditional-write: cases 16 to 19 are all
// sequential and such an implementation satisfies every one of them while still letting
// two concurrent submissions of one reset link both set a password.
//
// Follows TestTryConsumeUserOTPStep_ConcurrentCallersProduceOneWinner, including its
// honesty: overlap can be made likely but not forced, so a green run detects a broken
// implementation probabilistically rather than certifying atomicity. A lock-wait timeout
// counts as "did not claim", because in production it is a 500 and the reset is refused.
func TestTryConsumeForgotPasswordCode_ConcurrentCallersProduceOneWinner(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so callers queue " +
			"rather than contend; the test would pass without ever creating overlap")
	}

	const (
		callers = 8
		rounds  = 5
	)

	for round := 0; round < rounds; round++ {
		// A fresh user and a fresh code per round, so each round is a first claim.
		user, hash := createUserWithResetCode(t)

		type outcome struct {
			claimed  bool
			err      error
			password string
		}
		outcomes := make([]outcome, callers)

		// Every caller waits on the same barrier so they hit the row together, and each
		// carries a distinct candidate password so the winner is identifiable.
		start := make(chan struct{})
		var wg sync.WaitGroup

		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				password := fmt.Sprintf("password-%d-%d", round, i)
				<-start
				claimed, err := database.TryConsumeForgotPasswordCode(nil, user.Id, hash, password)
				outcomes[i] = outcome{claimed: claimed, err: err, password: password}
			}(i)
		}

		close(start)
		wg.Wait()

		wins, failures := 0, 0
		winner := ""
		for _, o := range outcomes {
			if o.err != nil {
				failures++
				continue
			}
			if o.claimed {
				wins++
				winner = o.password
			}
		}

		if wins != 1 {
			t.Fatalf("round %d: expected exactly 1 winner among %d concurrent claims, got %d (%d errored)",
				round, callers, wins, failures)
		}
		if failures > 0 {
			t.Logf("round %d: 1 winner, %d lock contention errors (acceptable)", round, failures)
		}

		reloaded, err := database.GetUserById(nil, user.Id)
		if err != nil {
			t.Fatalf("round %d: Failed to reload user: %v", round, err)
		}
		if reloaded.PasswordHash != winner {
			t.Fatalf("round %d: stored password = %q, want the winner's %q",
				round, reloaded.PasswordHash, winner)
		}
		if reloaded.ForgotPasswordCodeHash != "" {
			t.Fatalf("round %d: the winning claim must clear the code hash, got %q",
				round, reloaded.ForgotPasswordCodeHash)
		}
	}
}

// TestGetUserByEmailIsCaseSensitive holds the sign-in lookup to one meaning on four
// engines. RFC 5321 section 2.4 says "The local-part of a mailbox MUST BE treated as case
// sensitive", and MySQL and SQL Server did not: a row stored as Alice@x.com signed in there
// for alice@x.com and could not sign in at all on SQLite or PostgreSQL (#219, #221).
//
// The answer is not to make the lookup fold. Every write path stores
// strings.ToLower(strings.TrimSpace(...)), both credential paths look the lowercased
// address up, and a startup pass lowercases the legacy rows, so after #283 a stored address
// IS its own lowercase form and an exact lookup reaches it on every engine.
//
// Two of the cases below reach a fold no collation turns off, and both are the reason
// commondb.engineFoldedTheMatch exists:
//
//   - the padded address, which SQL Server compares equal to the unpadded one under every
//     collation it has, BIN2 included;
//   - the same address spelled in NFD, a base letter followed by a combining accent, which
//     MySQL and SQL Server compare equal to the NFC spelling and which SQLite and
//     PostgreSQL do not.
//
// Every non-ASCII character here is written as a hex escape on purpose. Typed literally, an
// editor or a tool that normalises the file would silently turn the NFD case into a
// comparison of a string with itself, and the test would pass having stopped testing.
func TestGetUserByEmailIsCaseSensitive(t *testing.T) {
	random := strings.ToLower(gofakeit.LetterN(6))
	lower := "case_email_" + random + "@case.local"
	upper := strings.ToUpper(lower)

	lowerUser := createUserWithEmail(t, lower)
	// A second address differing from the first only by case. idx_email is UNIQUE and
	// folded on MySQL and SQL Server before 000040, so this insert was refused there.
	upperUser := createUserWithEmail(t, upper)

	// The same address twice: once with a precomposed U+00E9, once with an ASCII e
	// followed by U+0301 COMBINING ACUTE ACCENT.
	nfcAddress := "case_jos\u00e9_" + random + "@case.local"
	nfdAddress := "case_jose\u0301_" + random + "@case.local"
	nfcUser := createUserWithEmail(t, nfcAddress)

	for _, tc := range []struct {
		name   string
		lookup string
		wantId int64
	}{
		{"the lowercase address resolves the lowercase user", lower, lowerUser.Id},
		{"the uppercase address resolves the uppercase user", upper, upperUser.Id},
		{"a mis-cased address resolves nothing", "Case_Email_" + strings.ToUpper(random) + "@case.local", 0},
		{"a trailing space resolves nothing, which SQL Server's padding would otherwise defeat", lower + " ", 0},
		{"the NFC spelling resolves the row stored in NFC", nfcAddress, nfcUser.Id},
		{"the NFD spelling resolves nothing, which MySQL's and SQL Server's normalisation fold would otherwise defeat", nfdAddress, 0},
	} {
		got, err := database.GetUserByEmail(nil, tc.lookup)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if tc.wantId == 0 {
			if got != nil {
				t.Errorf("%s: expected nil, got the user with id %d and email %q",
					tc.name, got.Id, got.Email)
			}
			continue
		}
		if got == nil {
			t.Fatalf("%s: expected the user with id %d, got nil", tc.name, tc.wantId)
		}
		if got.Id != tc.wantId {
			t.Errorf("%s: expected the user with id %d, got id %d (email %q)",
				tc.name, tc.wantId, got.Id, got.Email)
		}
	}
}

// TestGetUserBySubjectIsCaseSensitive is OpenID Connect Core section 2 in the data tier:
// "The sub value is a case-sensitive string". The subject is a UUID Goiabada generates, so
// case is not the exposure here; SQL Server's padding is, and it is reachable because
// nothing between a token's sub claim and this lookup trims. See
// commondb.engineFoldedTheMatch.
func TestGetUserBySubjectIsCaseSensitive(t *testing.T) {
	user := createTestUser(t)
	subject := user.Subject.String()

	for _, tc := range []struct {
		name   string
		lookup string
		wantId int64
	}{
		{"the subject as stored resolves the user", subject, user.Id},
		{"an upper-cased subject resolves nothing", strings.ToUpper(subject), 0},
		{"a trailing space resolves nothing, which SQL Server's padding would otherwise defeat", subject + " ", 0},
	} {
		got, err := database.GetUserBySubject(nil, tc.lookup)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if tc.wantId == 0 {
			if got != nil {
				t.Errorf("%s: expected nil, got the user with id %d and subject %q",
					tc.name, got.Id, got.Subject)
			}
			continue
		}
		if got == nil {
			t.Fatalf("%s: expected the user with id %d, got nil", tc.name, tc.wantId)
		}
		if got.Id != tc.wantId {
			t.Errorf("%s: expected the user with id %d, got id %d", tc.name, tc.wantId, got.Id)
		}
	}
}

// createUserWithEmail is the minimum a users row needs, at a chosen address.
func createUserWithEmail(t *testing.T, email string) *models.User {
	t.Helper()

	user := &models.User{
		Enabled:      true,
		Subject:      uuid.New(),
		Username:     "case_" + gofakeit.LetterN(10),
		Email:        email,
		PasswordHash: gofakeit.Password(true, true, true, true, false, 60),
	}
	if err := database.CreateUser(nil, user); err != nil {
		t.Fatalf("Failed to create a user at %q, which every engine must now accept: %v", email, err)
	}
	return user
}

package validators

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// assertLocalizedErrorCode asserts that err is an *i18n.LocalizedError carrying
// the expected code, matching the convention in email_validator_test.go.
func assertLocalizedErrorCode(t *testing.T, err error, expectedCode string) {
	t.Helper()
	assert.Error(t, err)
	locErr, ok := err.(*i18n.LocalizedError)
	assert.True(t, ok, "expected *i18n.LocalizedError, got %T", err)
	if ok {
		assert.Equal(t, expectedCode, locErr.Code)
	}
}

// =============================================================================
// Tests for ValidateName
//
// The shared name pattern is `^[\p{L}\s'-]{2,48}$`: Unicode letters, spaces,
// apostrophes and hyphens, 2 to 48 characters. An empty name is allowed, since
// given / middle / family names are all optional.
// =============================================================================

func TestValidateName_Accepted(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	testCases := []struct {
		name  string
		value string
	}{
		{"simple name", "Jane"},
		{"two characters is the minimum", "Jo"},
		{"hyphenated", "Mary-Jane"},
		{"apostrophe", "O'Brien"},
		{"space separated", "Mary Jane"},
		{"accented letters", "José"},
		{"cedilla", "Gonçalves"},
		{"non-latin script", "Ольга"},
		{"chinese characters", "李明"},
		{"exactly 48 characters", strings.Repeat("a", 48)},
		{"empty is allowed because the field is optional", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateName(tc.value, i18n.ErrCodeProfileGivenNameInvalid)

			assert.NoError(t, err)
		})
	}
}

// A name must contain at least one letter and may only use a literal space as a
// separator. That rules out a value made entirely of separators and any value
// spanning multiple lines.
func TestValidateName_RejectsWhitespaceOnlyAndControlCharacters(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	testCases := []struct {
		name  string
		value string
	}{
		{"two spaces only", "  "},
		{"many spaces only", strings.Repeat(" ", 10)},
		{"hyphens only", "--"},
		{"apostrophes only", "''"},
		{"mixed separators without a letter", " '- "},
		{"embedded newline", "Jane\nDoe"},
		{"embedded tab", "Jane\tDoe"},
		{"embedded carriage return", "Jane\rDoe"},
		{"trailing newline", "Jane\n"},
		{"leading newline", "\nJane"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateName(tc.value, i18n.ErrCodeProfileGivenNameInvalid)

			assertLocalizedErrorCode(t, err, i18n.ErrCodeProfileGivenNameInvalid)
		})
	}
}

// Padding with spaces is still accepted as long as a letter is present; the
// pattern is not a trimming rule.
func TestValidateName_AcceptsPaddedNames(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	for _, value := range []string{" Jane", "Jane ", "  Jane  "} {
		t.Run(value, func(t *testing.T) {
			err := validator.ValidateName(value, i18n.ErrCodeProfileGivenNameInvalid)

			assert.NoError(t, err)
		})
	}
}

// The subject on the input must resolve to a real user. A stale or forged
// subject is an error rather than a localized validation failure, and must not
// panic on the nil comparison that follows.
func TestValidateProfile_UnresolvableSubjectReturnsError(t *testing.T) {
	testCases := []struct {
		name           string
		usernameLookup func(mockDB *mocks_data.Database)
	}{
		{
			name:           "username is free",
			usernameLookup: func(mockDB *mocks_data.Database) {},
		},
		{
			name: "username is taken by another user",
			usernameLookup: func(mockDB *mocks_data.Database) {
				// Never reached: the subject check short circuits first.
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			validator := NewProfileValidator(mockDB)

			mockDB.On("GetUserBySubject", mock.Anything, "unknown-subject").Return(nil, nil).Once()
			tc.usernameLookup(mockDB)

			err := validator.ValidateProfile(&ValidateProfileInput{
				Username: "jdoe",
				Subject:  "unknown-subject",
			})

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "subject not found: unknown-subject")
			_, isLocalized := err.(*i18n.LocalizedError)
			assert.False(t, isLocalized, "an unresolvable subject is not a user-facing validation error")
		})
	}
}

func TestValidateName_Rejected(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	testCases := []struct {
		name  string
		value string
	}{
		{"single character", "J"},
		{"49 characters", strings.Repeat("a", 49)},
		{"contains a digit", "Jane2"},
		{"contains an underscore", "Jane_Doe"},
		{"contains punctuation", "Jane."},
		{"contains an at sign", "Jane@Doe"},
		{"leading digit", "1Jane"},
		{"emoji", "Jane😀"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateName(tc.value, i18n.ErrCodeProfileGivenNameInvalid)

			assertLocalizedErrorCode(t, err, i18n.ErrCodeProfileGivenNameInvalid)
		})
	}
}

// The caller chooses the error code so the localized message names the right
// field. ValidateName must return whichever code it was given.
func TestValidateName_ReturnsTheCallerSuppliedCode(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	codes := []string{
		i18n.ErrCodeProfileGivenNameInvalid,
		i18n.ErrCodeProfileMiddleNameInvalid,
		i18n.ErrCodeProfileFamilyNameInvalid,
	}

	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			err := validator.ValidateName("J", code)

			assertLocalizedErrorCode(t, err, code)
		})
	}
}

// =============================================================================
// Tests for ValidateProfile
// =============================================================================

func TestValidateProfile_EmptyInputIsValid(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	// With no username there is no database lookup at all; NewDatabase(t) would
	// fail the test if one happened.
	err := validator.ValidateProfile(&ValidateProfileInput{})

	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// Username
// -----------------------------------------------------------------------------

func TestValidateProfile_UsernameFormat(t *testing.T) {
	subject := uuid.New()

	testCases := []struct {
		name         string
		username     string
		expectedCode string
	}{
		{"letters only", "jdoe", ""},
		{"letters and digits", "jdoe2", ""},
		{"with underscore", "j_doe", ""},
		{"two characters is the minimum", "jd", ""},
		{"24 characters is the maximum", "j" + strings.Repeat("a", 23), ""},
		{"single character is too short", "j", i18n.ErrCodeProfileUsernameInvalid},
		{"25 characters is too long", "j" + strings.Repeat("a", 24), i18n.ErrCodeProfileUsernameInvalid},
		{"must not start with a digit", "2jdoe", i18n.ErrCodeProfileUsernameInvalid},
		{"must not start with an underscore", "_jdoe", i18n.ErrCodeProfileUsernameInvalid},
		{"no hyphen", "j-doe", i18n.ErrCodeProfileUsernameInvalid},
		{"no dot", "j.doe", i18n.ErrCodeProfileUsernameInvalid},
		{"no space", "j doe", i18n.ErrCodeProfileUsernameInvalid},
		{"no at sign", "j@doe", i18n.ErrCodeProfileUsernameInvalid},
		{"no accented letters", "josé", i18n.ErrCodeProfileUsernameInvalid},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			validator := NewProfileValidator(mockDB)

			// The format check runs after the uniqueness lookups, so both are
			// always reached when a username is present.
			user := &models.User{Id: 1, Subject: subject}
			mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(user, nil).Once()
			mockDB.On("GetUserByUsername", mock.Anything, tc.username).Return(nil, nil).Once()

			err := validator.ValidateProfile(&ValidateProfileInput{
				Username: tc.username,
				Subject:  subject.String(),
			})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedErrorCode(t, err, tc.expectedCode)
		})
	}
}

func TestValidateProfile_UsernameTakenByAnotherUser(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewProfileValidator(mockDB)

	subject := uuid.New()
	otherSubject := uuid.New()

	mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(
		&models.User{Id: 1, Subject: subject}, nil).Once()
	mockDB.On("GetUserByUsername", mock.Anything, "jdoe").Return(
		&models.User{Id: 2, Subject: otherSubject}, nil).Once()

	err := validator.ValidateProfile(&ValidateProfileInput{
		Username: "jdoe",
		Subject:  subject.String(),
	})

	assertLocalizedErrorCode(t, err, i18n.ErrCodeProfileUsernameTaken)
}

// Keeping your own username must not be reported as taken.
func TestValidateProfile_UsernameOwnedBySameUserIsAllowed(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewProfileValidator(mockDB)

	subject := uuid.New()
	user := &models.User{Id: 1, Subject: subject}

	mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(user, nil).Once()
	mockDB.On("GetUserByUsername", mock.Anything, "jdoe").Return(user, nil).Once()

	err := validator.ValidateProfile(&ValidateProfileInput{
		Username: "jdoe",
		Subject:  subject.String(),
	})

	assert.NoError(t, err)
}

func TestValidateProfile_UsernameLookupErrorsPropagate(t *testing.T) {
	subject := uuid.New()
	dbErr := errors.New("database is down")

	t.Run("GetUserBySubject fails", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		validator := NewProfileValidator(mockDB)

		mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(nil, dbErr).Once()

		err := validator.ValidateProfile(&ValidateProfileInput{
			Username: "jdoe",
			Subject:  subject.String(),
		})

		assert.Error(t, err)
		_, isLocalized := err.(*i18n.LocalizedError)
		assert.False(t, isLocalized, "a database failure is not a validation error")
	})

	t.Run("GetUserByUsername fails", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		validator := NewProfileValidator(mockDB)

		mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(
			&models.User{Id: 1, Subject: subject}, nil).Once()
		mockDB.On("GetUserByUsername", mock.Anything, "jdoe").Return(nil, dbErr).Once()

		err := validator.ValidateProfile(&ValidateProfileInput{
			Username: "jdoe",
			Subject:  subject.String(),
		})

		assert.Error(t, err)
		_, isLocalized := err.(*i18n.LocalizedError)
		assert.False(t, isLocalized)
	})
}

// -----------------------------------------------------------------------------
// Names, nickname, website
// -----------------------------------------------------------------------------

// ValidateProfile delegates to ValidateName for each of the three name fields,
// and must surface the code matching the field that actually failed.
func TestValidateProfile_NameFieldsReportTheirOwnCode(t *testing.T) {
	testCases := []struct {
		name         string
		input        ValidateProfileInput
		expectedCode string
	}{
		{
			name:         "given name",
			input:        ValidateProfileInput{GivenName: "J"},
			expectedCode: i18n.ErrCodeProfileGivenNameInvalid,
		},
		{
			name:         "middle name",
			input:        ValidateProfileInput{MiddleName: "Q1"},
			expectedCode: i18n.ErrCodeProfileMiddleNameInvalid,
		},
		{
			name:         "family name",
			input:        ValidateProfileInput{FamilyName: "Doe_"},
			expectedCode: i18n.ErrCodeProfileFamilyNameInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewProfileValidator(mocks_data.NewDatabase(t))

			err := validator.ValidateProfile(&tc.input)

			assertLocalizedErrorCode(t, err, tc.expectedCode)
		})
	}
}

// The given name is checked before the middle name, which is checked before the
// family name. That ordering decides which error the user sees first.
func TestValidateProfile_NameFieldsAreCheckedInOrder(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	err := validator.ValidateProfile(&ValidateProfileInput{
		GivenName:  "J",
		MiddleName: "Q1",
		FamilyName: "Doe_",
	})

	assertLocalizedErrorCode(t, err, i18n.ErrCodeProfileGivenNameInvalid)
}

func TestValidateProfile_ValidNamesPass(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	err := validator.ValidateProfile(&ValidateProfileInput{
		GivenName:  "Jane",
		MiddleName: "Mary-Anne",
		FamilyName: "O'Brien",
	})

	assert.NoError(t, err)
}

// The nickname uses the same pattern as the username.
func TestValidateProfile_Nickname(t *testing.T) {
	testCases := []struct {
		name         string
		nickname     string
		expectedCode string
	}{
		{"valid", "jd", ""},
		{"with digits and underscore", "jd_2", ""},
		{"24 characters", "j" + strings.Repeat("a", 23), ""},
		{"too short", "j", i18n.ErrCodeProfileNicknameInvalid},
		{"too long", "j" + strings.Repeat("a", 24), i18n.ErrCodeProfileNicknameInvalid},
		{"leading digit", "2jd", i18n.ErrCodeProfileNicknameInvalid},
		{"hyphen", "j-d", i18n.ErrCodeProfileNicknameInvalid},
		{"space", "j d", i18n.ErrCodeProfileNicknameInvalid},
		{"empty is allowed", "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewProfileValidator(mocks_data.NewDatabase(t))

			err := validator.ValidateProfile(&ValidateProfileInput{Nickname: tc.nickname})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedErrorCode(t, err, tc.expectedCode)
		})
	}
}

func TestValidateProfile_Website(t *testing.T) {
	testCases := []struct {
		name         string
		website      string
		expectedCode string
	}{
		{"https", "https://example.com", ""},
		{"http", "http://example.com", ""},
		{"no scheme", "example.com", ""},
		{"with www", "www.example.com", ""},
		{"with a path", "https://example.com/about", ""},
		{"with a subdomain", "https://blog.example.com", ""},
		{"with a hyphenated host", "https://my-site.example.com", ""},
		{"empty is allowed", "", ""},
		{"no dot", "https://example", i18n.ErrCodeProfileWebsiteInvalid},
		{"trailing dot only", "example.", i18n.ErrCodeProfileWebsiteInvalid},
		{"single-character tld", "example.c", i18n.ErrCodeProfileWebsiteInvalid},
		{"space inside", "https://exa mple.com", i18n.ErrCodeProfileWebsiteInvalid},
		{"unsupported scheme", "ftp://example.com", i18n.ErrCodeProfileWebsiteInvalid},
		{"just a word", "notaurl", i18n.ErrCodeProfileWebsiteInvalid},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewProfileValidator(mocks_data.NewDatabase(t))

			err := validator.ValidateProfile(&ValidateProfileInput{Website: tc.website})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedErrorCode(t, err, tc.expectedCode)
		})
	}
}

// The website length cap is 96 characters. Note that the format check runs
// first, so an over-long value must still be a well-formed URL to reach it.
func TestValidateProfile_WebsiteTooLong(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	// "https://" (8) + host + "/" + padding, over 96 characters in total.
	longWebsite := "https://example.com/" + strings.Repeat("a", 80)
	assert.Greater(t, len(longWebsite), 96)

	err := validator.ValidateProfile(&ValidateProfileInput{Website: longWebsite})

	assertLocalizedErrorCode(t, err, i18n.ErrCodeProfileWebsiteTooLong)

	locErr, ok := err.(*i18n.LocalizedError)
	assert.True(t, ok)
	if ok {
		assert.Equal(t, 96, locErr.Args["max"], "the message must carry the limit for interpolation")
	}
}

func TestValidateProfile_WebsiteAtTheLengthLimitIsAccepted(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	prefix := "https://example.com/"
	website := prefix + strings.Repeat("a", 96-len(prefix))
	assert.Len(t, website, 96)

	err := validator.ValidateProfile(&ValidateProfileInput{Website: website})

	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// Gender
// -----------------------------------------------------------------------------

func TestValidateProfile_Gender(t *testing.T) {
	testCases := []struct {
		name         string
		gender       string
		expectedCode string
	}{
		{"female", fmt.Sprintf("%d", int(enums.GenderFemale)), ""},
		{"male", fmt.Sprintf("%d", int(enums.GenderMale)), ""},
		{"other", fmt.Sprintf("%d", int(enums.GenderOther)), ""},
		{"empty is allowed", "", ""},
		{"not a number", "female", i18n.ErrCodeProfileGenderInvalid},
		{"out of range high", "3", i18n.ErrCodeProfileGenderInvalid},
		{"negative", "-1", i18n.ErrCodeProfileGenderInvalid},
		{"float", "1.5", i18n.ErrCodeProfileGenderInvalid},
		{"whitespace", " 1", i18n.ErrCodeProfileGenderInvalid},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewProfileValidator(mocks_data.NewDatabase(t))

			err := validator.ValidateProfile(&ValidateProfileInput{Gender: tc.gender})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedErrorCode(t, err, tc.expectedCode)
		})
	}
}

// -----------------------------------------------------------------------------
// Date of birth
// -----------------------------------------------------------------------------

func TestValidateProfile_DateOfBirthFormat(t *testing.T) {
	testCases := []struct {
		name         string
		dob          string
		expectedCode string
	}{
		{"valid date", "1990-05-15", ""},
		{"leap day", "2000-02-29", ""},
		{"empty is allowed", "", ""},
		{"slashes instead of hyphens", "1990/05/15", i18n.ErrCodeProfileDobInvalidFormat},
		{"day first", "15-05-1990", i18n.ErrCodeProfileDobInvalidFormat},
		{"missing day", "1990-05", i18n.ErrCodeProfileDobInvalidFormat},
		{"not a date", "not-a-date", i18n.ErrCodeProfileDobInvalidFormat},
		{"month 13", "1990-13-01", i18n.ErrCodeProfileDobInvalidFormat},
		{"day 32", "1990-01-32", i18n.ErrCodeProfileDobInvalidFormat},
		{"non-leap february 29", "1990-02-29", i18n.ErrCodeProfileDobInvalidFormat},
		{"includes a time", "1990-05-15T10:00:00Z", i18n.ErrCodeProfileDobInvalidFormat},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewProfileValidator(mocks_data.NewDatabase(t))

			err := validator.ValidateProfile(&ValidateProfileInput{DateOfBirth: tc.dob})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedErrorCode(t, err, tc.expectedCode)
		})
	}
}

func TestValidateProfile_DateOfBirthInTheFuture(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02")

	err := validator.ValidateProfile(&ValidateProfileInput{DateOfBirth: tomorrow})

	assertLocalizedErrorCode(t, err, i18n.ErrCodeProfileDobInFuture)
}

// The comparison is date-only and anchored in UTC, so the current UTC date is
// never treated as future-dated regardless of the server's timezone. This test
// is the regression guard for that: it fails whenever "today" is derived from
// local components again, but only during the hours where local and UTC dates
// differ, so read a failure here as a timezone-anchoring bug rather than flake.
func TestValidateProfile_DateOfBirthTodayIsAccepted(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	today := time.Now().UTC().Format("2006-01-02")

	err := validator.ValidateProfile(&ValidateProfileInput{DateOfBirth: today})

	assert.NoError(t, err)
}

// The local date is also accepted, whether it is the same day as UTC or the day
// before. This covers the other side of a timezone offset.
func TestValidateProfile_DateOfBirthLocalTodayIsAccepted(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	localToday := time.Now().Format("2006-01-02")

	err := validator.ValidateProfile(&ValidateProfileInput{DateOfBirth: localToday})

	assert.NoError(t, err)
}

func TestValidateProfile_DateOfBirthYesterdayIsAccepted(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")

	err := validator.ValidateProfile(&ValidateProfileInput{DateOfBirth: yesterday})

	assert.NoError(t, err)
}

// A date comfortably in the past is accepted regardless of timezone, so this
// case holds no matter where the server runs.
func TestValidateProfile_DateOfBirthWellInThePastIsAccepted(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	err := validator.ValidateProfile(&ValidateProfileInput{DateOfBirth: "1990-05-15"})

	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// Zone info and locale
//
// Both are checked against the generated catalogs, so the tests source their
// valid values from those catalogs rather than hardcoding one that a tzdata
// refresh could remove.
// -----------------------------------------------------------------------------

func TestValidateProfile_ZoneInfo(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	t.Run("a zone from the catalog is accepted", func(t *testing.T) {
		err := validator.ValidateProfile(&ValidateProfileInput{ZoneInfo: "America/Sao_Paulo"})

		assert.NoError(t, err)
	})

	t.Run("empty is allowed", func(t *testing.T) {
		err := validator.ValidateProfile(&ValidateProfileInput{ZoneInfo: ""})

		assert.NoError(t, err)
	})

	t.Run("rejections", func(t *testing.T) {
		for _, zone := range []string{"Not/AZone", "UTC+3", "america/sao_paulo", "Sao_Paulo"} {
			t.Run(zone, func(t *testing.T) {
				err := validator.ValidateProfile(&ValidateProfileInput{ZoneInfo: zone})

				assertLocalizedErrorCode(t, err, i18n.ErrCodeProfileZoneInfoInvalid)
			})
		}
	})
}

func TestValidateProfile_Locale(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	t.Run("a locale from the catalog is accepted", func(t *testing.T) {
		err := validator.ValidateProfile(&ValidateProfileInput{Locale: "pt-BR"})

		assert.NoError(t, err)
	})

	t.Run("empty is allowed", func(t *testing.T) {
		err := validator.ValidateProfile(&ValidateProfileInput{Locale: ""})

		assert.NoError(t, err)
	})

	t.Run("rejections", func(t *testing.T) {
		for _, locale := range []string{"xx-XX", "not-a-locale", "PT-br", "pt_BR"} {
			t.Run(locale, func(t *testing.T) {
				err := validator.ValidateProfile(&ValidateProfileInput{Locale: locale})

				assertLocalizedErrorCode(t, err, i18n.ErrCodeProfileLocaleInvalid)
			})
		}
	})
}

// -----------------------------------------------------------------------------
// A fully populated valid profile
// -----------------------------------------------------------------------------

func TestValidateProfile_FullyPopulatedValidProfile(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewProfileValidator(mockDB)

	subject := uuid.New()
	user := &models.User{Id: 1, Subject: subject}

	mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(user, nil).Once()
	mockDB.On("GetUserByUsername", mock.Anything, "jdoe").Return(user, nil).Once()

	err := validator.ValidateProfile(&ValidateProfileInput{
		Username:            "jdoe",
		GivenName:           "Jane",
		MiddleName:          "Mary",
		FamilyName:          "O'Brien",
		Nickname:            "jd",
		Website:             "https://example.com",
		Gender:              fmt.Sprintf("%d", int(enums.GenderFemale)),
		DateOfBirth:         "1990-05-15",
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
		Subject:             subject.String(),
	})

	assert.NoError(t, err)
}

// ZoneInfoCountryName is carried on the input but is not validated, so any
// value passes. Pinning that prevents a false assumption that it is checked.
func TestValidateProfile_ZoneInfoCountryNameIsNotValidated(t *testing.T) {
	validator := NewProfileValidator(mocks_data.NewDatabase(t))

	err := validator.ValidateProfile(&ValidateProfileInput{
		ZoneInfoCountryName: "Not A Real Country",
	})

	assert.NoError(t, err)
}

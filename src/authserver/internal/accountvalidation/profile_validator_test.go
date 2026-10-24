package accountvalidation

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"errors"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/gender"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// assertLocalizedError asserts that err is an *i18n.LocalizedError carrying the
// expected code and rendering the expected English sentence.
//
// The sentence is asserted as well as the code because a code assertion alone
// passes whatever the catalog happens to say: rewording an entry to describe a
// different rule leaves every such test green while the user reads the wrong
// instruction. Rewording validator.password.uppercase_required to ask for a
// lowercase character survived the whole suite before this landed (#230).
func assertLocalizedError(t *testing.T, err error, expectedCode string, expectedMessage string) {
	t.Helper()
	require.Error(t, err)
	var locErr *i18n.LocalizedError
	ok := errors.As(err, &locErr)
	assert.True(t, ok, "expected *i18n.LocalizedError, got %T", err)
	if ok {
		assert.Equal(t, expectedCode, locErr.Code)
		assert.Equal(t, expectedMessage, locErr.EnglishFallback())
	}
}

// The English sentence each validator.profile.* code renders, transcribed from
// src/core/i18n/catalogs/active.en.toml. The tables below are keyed by code and
// carry many rows per code, so the sentence is stated once here rather than
// repeated on every row; a code reaching a table without an entry here asserts
// against the empty string and fails.
//
// validator.profile.website_too_long and validator.profile.nickname_too_long are absent
// deliberately: they are the profile messages carrying an argument, so their sentences
// are asserted at the call site that knows the limit.
var profileErrorMessages = map[string]string{
	i18n.ErrCodeProfileGivenNameInvalid: "Please enter a valid given name. It should contain only letters, " +
		"with up to four accents or other marks stacked on each, spaces, hyphens, apostrophes, and middle dots, " +
		"and be between 1 and 48 characters in length.",
	i18n.ErrCodeProfileMiddleNameInvalid: "Please enter a valid middle name. It should contain only letters, " +
		"with up to four accents or other marks stacked on each, spaces, hyphens, apostrophes, and middle dots, " +
		"and be between 1 and 48 characters in length.",
	i18n.ErrCodeProfileFamilyNameInvalid: "Please enter a valid family name. It should contain only letters, " +
		"with up to four accents or other marks stacked on each, spaces, hyphens, apostrophes, and middle dots, " +
		"and be between 1 and 48 characters in length.",
	i18n.ErrCodeProfileUsernameInvalid: "Usernames must start with a letter and consist only of letters, " +
		"numbers, and underscores. They must be between 2 and 24 characters long.",
	i18n.ErrCodeProfileNicknameInvalid: "Nicknames cannot contain control characters, such as " +
		"tabs or line breaks.",
	i18n.ErrCodeProfileNicknameAngleBrackets: "The nickname cannot contain the characters < or >.",
	i18n.ErrCodeProfileUsernameTaken:         "Sorry, this username is already taken.",
	i18n.ErrCodeProfileWebsiteInvalid:        "Please enter a valid website URL.",
	i18n.ErrCodeProfileGenderInvalid:         "Gender is invalid.",
	i18n.ErrCodeProfileDobInvalidFormat:      "The date of birth is invalid. Please use the format YYYY-MM-DD.",
	i18n.ErrCodeProfileDobInFuture:           "The date of birth can't be in the future.",
	i18n.ErrCodeProfileZoneInfoInvalid:       "Unknown time zone.",
	i18n.ErrCodeProfileLocaleInvalid:         "Unknown language and region.",
}

// =============================================================================
// Tests for ValidateName
//
// A name is 1 to 48 characters, at least one of them a letter, made of Unicode
// letters, nonspacing and spacing marks (Mn, Mc) each after a letter or another
// mark, the literal space, the apostrophes ' and ’, the hyphen, the middle dots
// ・ and ·, the Tibetan tsheg ་ and the Hebrew geresh ׳, and the zero-width
// non-joiner and joiner between two letters. At most four nonspacing marks stand
// in a row, never the same one twice, counted with every composed letter
// decomposed (#669). An empty name is allowed, since given / middle / family
// names are all optional.
// =============================================================================

func TestValidateName_Accepted(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	testCases := []struct {
		name  string
		value string
	}{
		{"simple name", "Jane"},
		{"two characters", "Jo"},
		{"single latin letter", "J"},
		{"single chinese character", "王"},
		{"single korean character", "김"},
		{"hyphenated", "Mary-Jane"},
		{"apostrophe", "O'Brien"},
		{"space separated", "Mary Jane"},
		{"accented letters", "José"},
		{"cedilla", "Gonçalves"},
		{"non-latin script", "Ольга"},
		{"chinese characters", "李明"},
		{"exactly 48 characters", strings.Repeat("a", 48)},
		{"empty is allowed because the field is optional", ""},
		// #669 decision 1: the vowel signs, viramas and points a name is written with
		// are marks (Mn, Mc), each after a letter. One row per script of the issue.
		{"hindi with a spacing vowel sign", "\u0905\u092E\u093F\u0924"},                     // अमित
		{"hindi with a virama", "\u092A\u094D\u0930\u093F\u092F\u093E"},                     // प्रिया
		{"bengali", "\u09B8\u09CC\u09B0\u09AD"},                                             // সৌরভ
		{"tamil", "\u0BA4\u0BAE\u0BBF\u0BB4\u0BCD"},                                         // தமிழ்
		{"telugu", "\u0C05\u0C28\u0C3F\u0C32\u0C4D"},                                        // అనిల్
		{"kannada", "\u0C95\u0CBF\u0CB0\u0CA3\u0CCD"},                                       // ಕಿರಣ್
		{"sinhala", "\u0D9C\u0DD3\u0DAD\u0DCF"},                                             // ගීතා
		{"burmese, four marks with one stacked", "\u1000\u103B\u1031\u102C\u103A"},          // ကျော်
		{"thai", "\u0E1B\u0E23\u0E30\u0E22\u0E38\u0E17\u0E18\u0E4C"},                        // ประยุทธ์
		{"arabic with its vowel marks", "\u0645\u064F\u062D\u064E\u0645\u0651\u064E\u062F"}, // مُحَمَّد
		{"hebrew with its points", "\u05E9\u05C1\u05B8\u05DC\u05D5\u05B9\u05DD"},            // שָׁלוֹם
		{"latin typed decomposed", "Jose\u0301"},
		// #669 decision 3: the bound is more than four nonspacing marks in a row.
		{"hebrew with three marks on one letter", "\u05E9\u05BC\u05C1\u05B8"}, // שּׁ
		{"exactly four marks stacked on one letter", "a\u0301\u0302\u0303\u0304"},
		// #669 decision 4: five punctuation characters go wherever the apostrophe
		// and hyphen go.
		{"typographic apostrophe", "O\u2019Brien"},                                  // O’Brien
		{"katakana middle dot", "\u30B8\u30E7\u30F3\u30FB\u30B9\u30DF\u30B9"},       // ジョン・スミス
		{"catalan middle dot", "Marcel\u00B7l\u00ED"},                               // Marcel·lí
		{"tibetan tsheg", "\u0F56\u0F66\u0F9F\u0F53\u0F0B\u0F60\u0F5B\u0F72\u0F53"}, // བསྟན་འཛིན
		{"hebrew geresh", "\u05D2\u05F3\u05D5\u05DF"},                               // ג׳ון
		// #669 decision 5: the zero-width non-joiner and joiner between two letters.
		{"persian with a zero-width non-joiner", "\u0646\u06CC\u06A9\u200C\u0646\u0627\u0645"}, // نیک‌نام
		{"sinhala with a zero-width joiner after a virama", "\u0DC1\u0DCA\u200D\u0DBB\u0DD3"},  // ශ්‍රී
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
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	testCases := []struct {
		name  string
		value string
	}{
		{"single space only", " "},
		{"single hyphen only", "-"},
		{"single apostrophe only", "'"},
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

			assertLocalizedError(t, err, i18n.ErrCodeProfileGivenNameInvalid,
				profileErrorMessages[i18n.ErrCodeProfileGivenNameInvalid])
		})
	}
}

// Padding with spaces is still accepted as long as a letter is present; the
// pattern is not a trimming rule.
func TestValidateName_AcceptsPaddedNames(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

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
		usernameLookup func(mockDB *datamocks.Database)
	}{
		{
			name:           "username is free",
			usernameLookup: func(mockDB *datamocks.Database) {},
		},
		{
			name: "username is taken by another user",
			usernameLookup: func(mockDB *datamocks.Database) {
				// Never reached: the subject check short circuits first.
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			validator := NewProfileValidator(mockDB)

			mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "unknown-subject").Return(nil, nil).Once()
			tc.usernameLookup(mockDB)

			err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
				Username: "jdoe",
				Subject:  "unknown-subject",
			})

			require.Error(t, err)
			assert.Contains(t, err.Error(), "subject not found: unknown-subject")
			var localizedError *i18n.LocalizedError
			isLocalized := errors.As(err, &localizedError)
			assert.False(t, isLocalized, "an unresolvable subject is not a user-facing validation error")
		})
	}
}

func TestValidateName_Rejected(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	testCases := []struct {
		name  string
		value string
	}{
		{"49 characters", strings.Repeat("a", 49)},
		{"contains a digit", "Jane2"},
		{"contains an underscore", "Jane_Doe"},
		{"contains punctuation", "Jane."},
		{"contains an at sign", "Jane@Doe"},
		{"leading digit", "1Jane"},
		{"emoji", "Jane😀"},
		// Decision 3 of #275: the name shape is the only guard against markup in a
		// name once nothing sanitizes. One row per character, so relaxing the
		// pattern for either of them fails here with a reason attached.
		{"pins decision 3 of #275: less-than is refused by the name shape", "Ann<e"},
		{"pins decision 3 of #275: greater-than is refused by the name shape", "Ann>e"},
		// #669 decision 1: a mark is written on a letter, never alone, first or after
		// a separator, and an enclosing mark is never one.
		{"a mark alone", "\u0301"},
		{"marks alone", "\u0301\u0302"},
		{"a mark at the start", "\u0301Jane"},
		{"a mark after a space", "Mary \u0301Jane"},
		{"a mark after a hyphen", "Mary-\u0301Jane"},
		{"a mark after an apostrophe", "O'\u0301Brien"},
		{"an enclosing mark", "A\u20DD"},
		// #669 decision 3: more than four nonspacing marks in a row, or the same one
		// twice, counted decomposed.
		{"five marks stacked on one letter", "a\u0301\u0302\u0303\u0304\u0306"},
		{"a composed letter and four more marks, five decomposed", "\u00E0\u0301\u0302\u0303\u0304"},
		{"the same mark twice", "e\u0301\u0301"},
		{"a composed letter and its own mark again, a repeat decomposed", "\u00E9\u0301"},
		// #669 decision 4: every other punctuation character stays refused, and a name
		// still needs a letter.
		{"left single quotation mark", "\u2018Brien"},
		{"middle dots alone", "\u30FB\u00B7"},
		// #669 decision 5: a joiner stands between two letters and nowhere else, and
		// the other format characters stay refused.
		{"a joiner at the start", "\u200CJane"},
		{"a joiner at the end", "Jane\u200C"},
		{"a joiner after a space", "Mary \u200DJane"},
		{"a joiner before a space", "Mary\u200D Jane"},
		{"a joiner after a hyphen", "Mary-\u200DJane"},
		{"a joiner before a mark", "a\u200C\u0301"},
		{"two joiners", "Mary\u200C\u200CJane"},
		{"left-to-right mark", "Jane\u200EDoe"},
		{"right-to-left mark", "Jane\u200FDoe"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateName(tc.value, i18n.ErrCodeProfileGivenNameInvalid)

			assertLocalizedError(t, err, i18n.ErrCodeProfileGivenNameInvalid,
				profileErrorMessages[i18n.ErrCodeProfileGivenNameInvalid])
		})
	}
}

// The caller chooses the error code so the localized message names the right
// field. ValidateName must return whichever code it was given.
func TestValidateName_ReturnsTheCallerSuppliedCode(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	codes := []string{
		i18n.ErrCodeProfileGivenNameInvalid,
		i18n.ErrCodeProfileMiddleNameInvalid,
		i18n.ErrCodeProfileFamilyNameInvalid,
	}

	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			err := validator.ValidateName("J.", code)

			assertLocalizedError(t, err, code, profileErrorMessages[code])
		})
	}
}

// =============================================================================
// Tests for ValidateProfile
// =============================================================================

func TestValidateProfile_EmptyInputIsValid(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	// With no username there is no database lookup at all; NewDatabase(t) would
	// fail the test if one happened.
	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{})

	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// Username
// -----------------------------------------------------------------------------

func TestValidateProfile_UsernameFormat(t *testing.T) {
	subject := fake.UUID()

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
		// Decision 3 of #275: the username pattern is the only guard against
		// markup here once nothing sanitizes.
		{"pins decision 3 of #275: no less-than", "us<er", i18n.ErrCodeProfileUsernameInvalid},
		{"pins decision 3 of #275: no greater-than", "us>er", i18n.ErrCodeProfileUsernameInvalid},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			validator := NewProfileValidator(mockDB)

			// The format check runs after the uniqueness lookups, so both are
			// always reached when a username is present.
			user := &record.User{Id: 1, Subject: subject}
			mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, subject).Return(user, nil).Once()
			mockDB.On("GetUserByUsername", mock.Anything, mock.Anything, tc.username).Return(nil, nil).Once()

			err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
				Username: tc.username,
				Subject:  subject,
			})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedError(t, err, tc.expectedCode, profileErrorMessages[tc.expectedCode])
		})
	}
}

func TestValidateProfile_UsernameTakenByAnotherUser(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	validator := NewProfileValidator(mockDB)

	subject := fake.UUID()
	otherSubject := fake.UUID()

	mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, subject).Return(
		&record.User{Id: 1, Subject: subject}, nil).Once()
	mockDB.On("GetUserByUsername", mock.Anything, mock.Anything, "jdoe").Return(
		&record.User{Id: 2, Subject: otherSubject}, nil).Once()

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
		Username: "jdoe",
		Subject:  subject,
	})

	assertLocalizedError(t, err, i18n.ErrCodeProfileUsernameTaken,
		profileErrorMessages[i18n.ErrCodeProfileUsernameTaken])
}

// Keeping your own username must not be reported as taken.
func TestValidateProfile_UsernameOwnedBySameUserIsAllowed(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	validator := NewProfileValidator(mockDB)

	subject := fake.UUID()
	user := &record.User{Id: 1, Subject: subject}

	mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, subject).Return(user, nil).Once()
	mockDB.On("GetUserByUsername", mock.Anything, mock.Anything, "jdoe").Return(user, nil).Once()

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
		Username: "jdoe",
		Subject:  subject,
	})

	assert.NoError(t, err)
}

func TestValidateProfile_UsernameLookupErrorsPropagate(t *testing.T) {
	subject := fake.UUID()
	dbErr := errors.New("database is down")

	t.Run("GetUserBySubject fails", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewProfileValidator(mockDB)

		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, subject).Return(nil, dbErr).Once()

		err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
			Username: "jdoe",
			Subject:  subject,
		})

		require.Error(t, err)
		var localizedError *i18n.LocalizedError
		isLocalized := errors.As(err, &localizedError)
		assert.False(t, isLocalized, "a database failure is not a validation error")
	})

	t.Run("GetUserByUsername fails", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewProfileValidator(mockDB)

		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, subject).Return(
			&record.User{Id: 1, Subject: subject}, nil).Once()
		mockDB.On("GetUserByUsername", mock.Anything, mock.Anything, "jdoe").Return(nil, dbErr).Once()

		err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
			Username: "jdoe",
			Subject:  subject,
		})

		require.Error(t, err)
		var localizedError *i18n.LocalizedError
		isLocalized := errors.As(err, &localizedError)
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
			input:        ValidateProfileInput{GivenName: "J."},
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
			validator := NewProfileValidator(datamocks.NewDatabase(t))

			err := validator.ValidateProfile(context.Background(), &tc.input)

			assertLocalizedError(t, err, tc.expectedCode, profileErrorMessages[tc.expectedCode])
		})
	}
}

// The given name is checked before the middle name, which is checked before the
// family name. That ordering decides which error the user sees first.
func TestValidateProfile_NameFieldsAreCheckedInOrder(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
		GivenName:  "J.",
		MiddleName: "Q1",
		FamilyName: "Doe_",
	})

	assertLocalizedError(t, err, i18n.ErrCodeProfileGivenNameInvalid,
		profileErrorMessages[i18n.ErrCodeProfileGivenNameInvalid])
}

func TestValidateProfile_ValidNamesPass(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
		GivenName:  "Jane",
		MiddleName: "Mary-Anne",
		FamilyName: "O'Brien",
	})

	assert.NoError(t, err)
}

// The nickname is the OIDC nickname claim, a casual name that may or may not be the
// given name's (#632 item 4), so the value it stores is free text — "Amazing Grace",
// "Dr. G", "Jean-Luc", "D'Arcy", letters of any script — rather than a username's
// shape: preferred_username is the claim with a username's shape, and the username
// field fills it.
func TestValidateProfile_Nickname(t *testing.T) {
	testCases := []struct {
		name         string
		nickname     string
		expectedCode string
	}{
		{"valid", "jd", ""},
		{"with digits and underscore", "jd_2", ""},
		{"one character", "j", ""},
		{"leading digit", "2jd", ""},
		{"a space", "Amazing Grace", ""},
		{"a dot", "Dr. G", ""},
		{"a hyphen", "Jean-Luc", ""},
		{"an apostrophe", "D'Arcy", ""},
		{"letters beyond ASCII", "미키", ""},
		{"48 characters", "j" + strings.Repeat("a", 47), ""},
		{"the bound in UTF-16 code units, not characters", strings.Repeat("🙂", 24), ""},
		{"empty is allowed", "", ""},
		{"a control character: a tab", "ni	ck", i18n.ErrCodeProfileNicknameInvalid},
		{"a control character: a line break", "ni\nck", i18n.ErrCodeProfileNicknameInvalid},
		// C1 is control too, and its next line, U+0085, a mandatory break (UAX #14 class NL).
		{"a C1 control character: a next line", "Amazing\u0085Grace", i18n.ErrCodeProfileNicknameInvalid},
		{"a C1 control character: the first", "ni\u0080ck", i18n.ErrCodeProfileNicknameInvalid},
		{"a C1 control character: the last", "ni\u009fck", i18n.ErrCodeProfileNicknameInvalid},
		// A line or paragraph separator is a mandatory break too, which browsers honour.
		{"a line separator", "Amazing\u2028Grace", i18n.ErrCodeProfileNicknameInvalid},
		{"a paragraph separator", "Amazing\u2029Grace", i18n.ErrCodeProfileNicknameInvalid},
		// A bidi embedding, override or isolate makes the claim display reordered in a
		// relying party: "\u202Enimda" shows as "admin".
		{"a right-to-left override", "\u202Enimda", i18n.ErrCodeProfileNicknameInvalid},
		{"a left-to-right embedding", "\u202Aab", i18n.ErrCodeProfileNicknameInvalid},
		{"a pop directional formatting", "ab\u202C", i18n.ErrCodeProfileNicknameInvalid},
		{"a left-to-right isolate", "\u2066ab", i18n.ErrCodeProfileNicknameInvalid},
		{"a pop directional isolate", "ab\u2069", i18n.ErrCodeProfileNicknameInvalid},
		// The other format characters stay accepted: a joiner builds an emoji sequence and
		// writes some scripts, and a direction mark fixes the order a typed name shows in.
		{"a zero-width joiner in an emoji sequence", "👩\u200D💻", ""},
		{"a zero-width non-joiner", "می\u200Cخواهم", ""},
		{"a right-to-left mark", "Grace\u200F", ""},
		// Decision 3 of #275: with the username's pattern gone, the angle-bracket
		// rule is the only guard against markup here once nothing sanitizes.
		{"pins decision 3 of #275: no less-than", "ni<ck", i18n.ErrCodeProfileNicknameAngleBrackets},
		{"pins decision 3 of #275: no greater-than", "ni>ck", i18n.ErrCodeProfileNicknameAngleBrackets},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewProfileValidator(datamocks.NewDatabase(t))

			err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{Nickname: tc.nickname})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedError(t, err, tc.expectedCode, profileErrorMessages[tc.expectedCode])
		})
	}
}

// The nickname shares the name fields' bound, 48, measured in the UTF-16 code units
// every text bound uses, so a character outside the Basic Multilingual Plane counts
// two and reaches the bound in half as many characters.
func TestValidateProfile_NicknameTooLong(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	// 49 characters.
	longNickname := "j" + strings.Repeat("a", 48)

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{Nickname: longNickname})

	assertLocalizedError(t, err, i18n.ErrCodeProfileNicknameTooLong,
		"Please ensure the nickname is no longer than 48 characters.")

	// 25 characters, 50 UTF-16 code units.
	longNickname = strings.Repeat("🙂", 25)

	err = validator.ValidateProfile(context.Background(), &ValidateProfileInput{Nickname: longNickname})

	assertLocalizedError(t, err, i18n.ErrCodeProfileNicknameTooLong,
		"Please ensure the nickname is no longer than 48 characters.")
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
			validator := NewProfileValidator(datamocks.NewDatabase(t))

			err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{Website: tc.website})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedError(t, err, tc.expectedCode, profileErrorMessages[tc.expectedCode])
		})
	}
}

// The website length cap is 96 characters. Note that the format check runs
// first, so an over-long value must still be a well-formed URL to reach it.
func TestValidateProfile_WebsiteTooLong(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	// "https://" (8) + host + "/" + padding, over 96 characters in total.
	longWebsite := "https://example.com/" + strings.Repeat("a", 80)
	assert.Greater(t, len(longWebsite), 96)

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{Website: longWebsite})

	assertLocalizedError(t, err, i18n.ErrCodeProfileWebsiteTooLong,
		"Please ensure the website URL is no longer than 96 characters.")

	var locErr *i18n.LocalizedError
	ok := errors.As(err, &locErr)
	assert.True(t, ok)
	if ok {
		assert.Equal(t, 96, locErr.Args["max"], "the message must carry the limit for interpolation")
	}
}

func TestValidateProfile_WebsiteAtTheLengthLimitIsAccepted(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	prefix := "https://example.com/"
	website := prefix + strings.Repeat("a", 96-len(prefix))
	assert.Len(t, website, 96)

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{Website: website})

	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// Gender
// -----------------------------------------------------------------------------

// TestValidateProfile_Gender holds both spellings a profile PUT accepts (#443 decision 13): the
// digit the admin console's forms post and the word GET returns, so a client can write back what it
// read. The words are literals, the strings the OIDC gender claim carries, not read off
// gender.Gender.String, and the match is exact: a capital or a pad is no gender.
func TestValidateProfile_Gender(t *testing.T) {
	testCases := []struct {
		name         string
		gender       string
		expectedCode string
	}{
		{"the digit for female", "0", ""},
		{"the digit for male", "1", ""},
		{"the digit for other", "2", ""},
		{"the word female", "female", ""},
		{"the word male", "male", ""},
		{"the word other", "other", ""},
		{"empty is allowed", "", ""},
		{"a capitalized word", "Male", i18n.ErrCodeProfileGenderInvalid},
		{"an upper-case word", "FEMALE", i18n.ErrCodeProfileGenderInvalid},
		{"a padded word", " male", i18n.ErrCodeProfileGenderInvalid},
		{"no word", "x", i18n.ErrCodeProfileGenderInvalid},
		{"a word for no gender", "unknown", i18n.ErrCodeProfileGenderInvalid},
		{"out of range high", "3", i18n.ErrCodeProfileGenderInvalid},
		{"negative", "-1", i18n.ErrCodeProfileGenderInvalid},
		{"float", "1.5", i18n.ErrCodeProfileGenderInvalid},
		{"whitespace", " 1", i18n.ErrCodeProfileGenderInvalid},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewProfileValidator(datamocks.NewDatabase(t))

			err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{Gender: tc.gender})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedError(t, err, tc.expectedCode, profileErrorMessages[tc.expectedCode])
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
			validator := NewProfileValidator(datamocks.NewDatabase(t))

			err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{DateOfBirth: tc.dob})

			if tc.expectedCode == "" {
				assert.NoError(t, err)
				return
			}
			assertLocalizedError(t, err, tc.expectedCode, profileErrorMessages[tc.expectedCode])
		})
	}
}

// Two days ahead of UTC, not one. One day ahead is deliberately accepted now: with no
// timezone on the input the server cannot tell "tomorrow" from "today in UTC+14".
//
// This test used to use one day ahead and assert rejection, while
// TestValidateProfile_DateOfBirthLocalTodayIsAccepted asserted the same string was
// accepted. During the hour each day when the local and UTC dates differ those are the
// identical input with opposite expectations, so no implementation could satisfy both.
// TestValidateProfile_DateOfBirthTimezoneToleranceBoundary pins the resolution without
// depending on the clock.
func TestValidateProfile_DateOfBirthInTheFuture(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	dayAfterTomorrow := time.Now().UTC().AddDate(0, 0, 2).Format("2006-01-02")

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{DateOfBirth: dayAfterTomorrow})

	assertLocalizedError(t, err, i18n.ErrCodeProfileDobInFuture,
		profileErrorMessages[i18n.ErrCodeProfileDobInFuture])
}

// The tolerance boundary, expressed as offsets from the UTC date, so it holds at every
// hour and in every server timezone. The three tests around this one derive their input
// from time.Now() and therefore only exercise the interesting case for part of the day,
// which is why the original bug stayed hidden for three days and then failed in CI.
func TestValidateProfile_DateOfBirthTimezoneToleranceBoundary(t *testing.T) {
	utcNow := time.Now().UTC()

	testCases := []struct {
		name       string
		daysAhead  int
		wantReject bool
	}{
		{"the UTC date itself is accepted", 0, false},
		// Somebody's today, at any positive offset up to UTC+14.
		{"one day ahead of UTC is accepted", 1, false},
		// Nobody's today: offsets stop at UTC+14, so this cannot be a local date.
		{"two days ahead of UTC is rejected", 2, true},
		{"a year ahead is rejected", 365, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewProfileValidator(datamocks.NewDatabase(t))
			date := utcNow.AddDate(0, 0, tc.daysAhead).Format("2006-01-02")

			err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{DateOfBirth: date})

			if tc.wantReject {
				assertLocalizedError(t, err, i18n.ErrCodeProfileDobInFuture,
					profileErrorMessages[i18n.ErrCodeProfileDobInFuture])
				return
			}
			assert.NoError(t, err)
		})
	}
}

// The comparison is date-only and anchored in UTC, so the current UTC date is
// never treated as future-dated regardless of the server's timezone. This test
// is the regression guard for that: it fails whenever "today" is derived from
// local components again, but only during the hours where local and UTC dates
// differ, so read a failure here as a timezone-anchoring bug rather than flake.
func TestValidateProfile_DateOfBirthTodayIsAccepted(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	today := time.Now().UTC().Format("2006-01-02")

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{DateOfBirth: today})

	assert.NoError(t, err)
}

// The local date is also accepted, whether it is the same day as UTC or the day
// before. This covers the other side of a timezone offset.
func TestValidateProfile_DateOfBirthLocalTodayIsAccepted(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	localToday := time.Now().Format("2006-01-02")

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{DateOfBirth: localToday})

	assert.NoError(t, err)
}

func TestValidateProfile_DateOfBirthYesterdayIsAccepted(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{DateOfBirth: yesterday})

	assert.NoError(t, err)
}

// A date comfortably in the past is accepted regardless of timezone, so this
// case holds no matter where the server runs.
func TestValidateProfile_DateOfBirthWellInThePastIsAccepted(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{DateOfBirth: "1990-05-15"})

	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// Zone info and locale
//
// Both are checked against the generated catalogs, so the tests source their
// valid values from those catalogs rather than hardcoding one that a tzdata
// refresh could remove.
// -----------------------------------------------------------------------------

// The zone and its country name are validated as a pair: the pair must be a row of the
// timezones table, or both must be empty. Europe/Berlin is listed under several countries
// (Germany and Sweden among them), which is why a zone ID alone does not name a row.
func TestValidateProfile_ZoneInfo(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	accepted := []struct {
		name        string
		countryName string
		zone        string
	}{
		{"a matching pair", "Brazil", "America/Sao_Paulo"},
		{"one of the countries sharing a zone", "Germany", "Europe/Berlin"},
		{"another of the countries sharing a zone", "Sweden", "Europe/Berlin"},
		{"both empty", "", ""},
	}
	for _, tc := range accepted {
		t.Run("accepted/"+tc.name, func(t *testing.T) {
			err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
				ZoneInfoCountryName: tc.countryName,
				ZoneInfo:            tc.zone,
			})

			assert.NoError(t, err)
		})
	}

	refused := []struct {
		name        string
		countryName string
		zone        string
	}{
		{"a real country with another country's zone", "Brazil", "Europe/Berlin"},
		{"a zone with an empty name", "", "America/Sao_Paulo"},
		{"a name with an empty zone", "Brazil", ""},
		{"a name differing only in case", "brazil", "America/Sao_Paulo"},
		{"an unknown zone", "Brazil", "Not/AZone"},
		{"an offset that is not a zone", "Brazil", "UTC+3"},
		{"a zone differing only in case", "Brazil", "america/sao_paulo"},
		{"a partial zone", "Brazil", "Sao_Paulo"},
	}
	for _, tc := range refused {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
				ZoneInfoCountryName: tc.countryName,
				ZoneInfo:            tc.zone,
			})

			assertLocalizedError(t, err, i18n.ErrCodeProfileZoneInfoInvalid,
				profileErrorMessages[i18n.ErrCodeProfileZoneInfoInvalid])
		})
	}
}

func TestValidateProfile_Locale(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	t.Run("a locale from the catalog is accepted", func(t *testing.T) {
		err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{Locale: "pt-BR"})

		assert.NoError(t, err)
	})

	t.Run("empty is allowed", func(t *testing.T) {
		err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{Locale: ""})

		assert.NoError(t, err)
	})

	t.Run("rejections", func(t *testing.T) {
		for _, locale := range []string{"xx-XX", "not-a-locale", "PT-br", "pt_BR"} {
			t.Run(locale, func(t *testing.T) {
				err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{Locale: locale})

				assertLocalizedError(t, err, i18n.ErrCodeProfileLocaleInvalid,
					profileErrorMessages[i18n.ErrCodeProfileLocaleInvalid])
			})
		}
	})
}

// -----------------------------------------------------------------------------
// A fully populated valid profile
// -----------------------------------------------------------------------------

func TestValidateProfile_FullyPopulatedValidProfile(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	validator := NewProfileValidator(mockDB)

	subject := fake.UUID()
	user := &record.User{Id: 1, Subject: subject}

	mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, subject).Return(user, nil).Once()
	mockDB.On("GetUserByUsername", mock.Anything, mock.Anything, "jdoe").Return(user, nil).Once()

	err := validator.ValidateProfile(context.Background(), &ValidateProfileInput{
		Username:            "jdoe",
		GivenName:           "Jane",
		MiddleName:          "Mary",
		FamilyName:          "O'Brien",
		Nickname:            "jd",
		Website:             "https://example.com",
		Gender:              fmt.Sprintf("%d", int(gender.Female)),
		DateOfBirth:         "1990-05-15",
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
		Subject:             subject,
	})

	assert.NoError(t, err)
}

// A name's 48 is also counted in UTF-16 code units, what SQL Server's nvarchar(64) name columns
// hold. Thirty-three Deseret letters are 33 code points, within the shape's 48, but 66 units, past
// the column's 64: until the review before 1.7.0 the name passed here and the write failed on SQL
// Server with a database error. Forty-eight é, one unit each, are still a valid name.
func TestValidateName_CountsUTF16Units(t *testing.T) {
	validator := NewProfileValidator(datamocks.NewDatabase(t))

	require.NoError(t, validator.ValidateName(strings.Repeat("é", 48), i18n.ErrCodeProfileGivenNameInvalid))

	err := validator.ValidateName(strings.Repeat("\U00010400", 33), i18n.ErrCodeProfileGivenNameInvalid)
	var localized *i18n.LocalizedError
	require.ErrorAs(t, err, &localized)
	assert.Equal(t, i18n.ErrCodeProfileGivenNameInvalid, localized.Code)

	require.NoError(t, validator.ValidateName(strings.Repeat("\U00010400", 24), i18n.ErrCodeProfileGivenNameInvalid),
		"24 Deseret letters are 48 units, at the bound")
}

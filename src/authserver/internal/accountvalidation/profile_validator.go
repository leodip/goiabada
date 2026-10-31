package accountvalidation

import (
	"context"
	"database/sql"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/gender"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/timezones"
	"golang.org/x/text/unicode/norm"
)

// profileValidatorDatabase is what the account profile validator reads: the rows that decide
// whether a username is already somebody else's.
type profileValidatorDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	GetUserByUsername(ctx context.Context, tx *sql.Tx, username string) (*record.User, error)
}

type ProfileValidator struct {
	database profileValidatorDatabase
}

func NewProfileValidator(database profileValidatorDatabase) *ProfileValidator {
	return &ProfileValidator{
		database: database,
	}
}

type ValidateProfileInput struct {
	Username            string
	GivenName           string
	MiddleName          string
	FamilyName          string
	Nickname            string
	Website             string
	Gender              string
	DateOfBirth         string
	ZoneInfoCountryName string
	ZoneInfo            string
	Locale              string
	PageLanguage        *string
	Subject             string
}

// nameMaxLength is a name's bound, counted both in code points and in inputvalidation.TextLength's
// units.
const nameMaxLength = 48

// nameMaxStackedMarks is the most nonspacing marks a name carries in a row, the bound UTS #39
// (Unicode Security Mechanisms, revision 34) gives in section 5.4 item 2 and section 3.3, so that
// no letter carries a stack of marks drawn over the lines around the name (#669).
const nameMaxStackedMarks = 4

// namePunctuation is what a name takes beside its letters, marks and joiners, anywhere in it: the
// space, the apostrophe and the typographic apostrophe ’ (U+2019), which iPhone and iPad Smart
// Punctuation types inside a word, the hyphen, the katakana middle dot ・ (U+30FB) between the
// parts of a foreign name in katakana, the middle dot · (U+00B7) of Catalan l·l, the Tibetan tsheg
// ་ (U+0F0B) between syllables, and the Hebrew geresh ׳ (U+05F3) of a foreign name in Hebrew
// (#669). The space is the literal one rather than any white space: tabs, newlines and other
// control characters have no place in a name and would otherwise let a value span multiple lines.
const namePunctuation = " '\u2019-\u30FB\u00B7\u0F0B\u05F3"

var (
	// usernameShape is a letter, then 1 to 23 letters, digits or underscores.
	usernameShape = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{1,23}$`)
	// websiteShape is an optional http or https scheme, a host of dot-separated labels ending in
	// two or more letters, and an optional path.
	websiteShape = regexp.MustCompile(`^(https?://)?(www\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(/\S*)?$`)
)

// breaksOrReordersLine reports a character a single-line value refuses: a control character
// (Cc), such as a tab or a line break; a line or paragraph separator (Zl, Zp), which UAX #14
// makes a mandatory break and browsers honour; or one of the nine bidi embedding, override and
// isolate characters, U+202A to U+202E and U+2066 to U+2069, with which "\u202Enimda" displays
// as "admin" wherever the value is shown. The other format characters stay accepted: the
// zero-width joiner and non-joiner build emoji sequences and write some scripts, and the
// left-to-right and right-to-left marks fix the order a typed name shows in.
func breaksOrReordersLine(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Zl, unicode.Zp) ||
		(r >= '\u202A' && r <= '\u202E') || (r >= '\u2066' && r <= '\u2069')
}

// isNameMark reports a mark a name is written with: a nonspacing or a spacing mark (Mn, Mc), such
// as a vowel sign, a virama, a point or an accent. An enclosing mark (Me) is none, since no name
// is written with one and it draws a circle or a box over its neighbours.
func isNameMark(r rune) bool {
	return unicode.In(r, unicode.Mn, unicode.Mc)
}

// nameIsWellFormed reports whether name has a letter and is made of nothing but letters, the
// marks written on them, namePunctuation and the two joiners, each where it goes. A mark follows
// a letter or another mark, so it is never alone, first, or after a space or a punctuation
// character, where it would draw on whatever stands before the name. The zero-width non-joiner
// (U+200C), which Persian writes between two letters that must not join, and the zero-width
// joiner (U+200D), which Sinhala writes after a virama to ask for a conjunct, follow a letter or
// a mark and precede a letter, and no joiner goes anywhere else. Every other format character,
// the left-to-right and right-to-left marks among them, is refused (#669).
func nameIsWellFormed(name string) bool {
	runes := []rune(name)
	hasLetter := false
	for i, r := range runes {
		afterLetterOrMark := i > 0 && (unicode.IsLetter(runes[i-1]) || isNameMark(runes[i-1]))
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case isNameMark(r):
			if !afterLetterOrMark {
				return false
			}
		case r == '\u200C' || r == '\u200D':
			if !afterLetterOrMark || i+1 == len(runes) || !unicode.IsLetter(runes[i+1]) {
				return false
			}
		case strings.ContainsRune(namePunctuation, r):
		default:
			return false
		}
	}
	return hasLetter
}

// nameStacksMarks reports a name with more than nameMaxStackedMarks nonspacing marks in a row, or
// the same nonspacing mark twice in a row, the two rules of UTS #39 section 5.4 item 2. They are
// counted on the name decomposed (NFD), every composed letter back into its letter and marks, so
// they bound what is drawn on one letter whatever form it was typed in: à followed by four more
// marks is five, and é followed by another U+0301 is a repeat. Spacing marks sit beside their
// letter rather than over the lines around it, so they are not counted; the 48 bounds limit them.
func nameStacksMarks(name string) bool {
	inRow := 0
	var previous rune
	for _, r := range norm.NFD.String(name) {
		if !unicode.Is(unicode.Mn, r) {
			inRow = 0
		} else {
			inRow++
			if inRow > nameMaxStackedMarks || (inRow > 1 && r == previous) {
				return true
			}
		}
		previous = r
	}
	return false
}

// ParseGender reads a profile's gender as a profile PUT submits it: the word GET returns
// ("female", "male", "other"), so a client can write back what it read, or the digit the admin
// console's forms post ("0", "1", "2"). A word is matched exactly, so "Male" names no gender; a
// digit is read as an integer, as it always was. The caller stores the result's String, the word,
// whichever spelling arrived (#443).
func ParseGender(value string) (gender.Gender, bool) {
	if i, err := strconv.Atoi(value); err == nil && gender.IsValid(i) {
		return gender.Gender(i), true
	}
	for _, g := range []gender.Gender{gender.Female, gender.Male, gender.Other} {
		if value == g.String() {
			return g, true
		}
	}
	return 0, false
}

// NormalizeName is the one spelling a name is checked and stored in: trimmed of the white space
// around it, then in Unicode Normalization Form C, so a decomposed José is stored, and answered,
// as the composed one. Every write of a name passes it through here before ValidateName, so what
// is checked is exactly what is stored: a `<` followed by U+0338 is checked as the ≮ it composes
// to, and the bounds count the stored form (#669 decision 2).
func NormalizeName(name string) string {
	return norm.NFC.String(strings.TrimSpace(name))
}

// ValidateName checks a name field against the shared name rule: 1 to 48
// characters, well formed (nameIsWellFormed) and stacking no marks beyond the
// bound (nameStacksMarks). invalidNameCode is the i18n error code returned on
// failure (one of ErrCodeProfileGivenNameInvalid, ErrCodeProfileMiddleNameInvalid,
// or ErrCodeProfileFamilyNameInvalid). Caller picks the right code so that
// the localized message names the field correctly.
//
// An empty name is accepted: all three name fields are optional.
//
// i18n surface: A | C — the admin API's user create and profile update, and the
// account's own profile update.
func (val *ProfileValidator) ValidateName(name string, invalidNameCode string) error {
	if len(name) == 0 {
		return nil
	}

	// The first 48 counts code points, and the columns hold 64 UTF-16 code units on SQL Server,
	// so a name of letters beyond the Basic Multilingual Plane, two units each, could pass it and
	// overflow there, a database error in place of this refusal. Bounded again in TextLength's
	// units, the ones every text bound uses, which no engine's column can overflow.
	if utf8.RuneCountInString(name) > nameMaxLength || !nameIsWellFormed(name) ||
		nameStacksMarks(name) || inputvalidation.TextLength(name) > nameMaxLength {
		return i18n.NewLocalizedError(invalidNameCode, nil)
	}
	return nil
}

func (val *ProfileValidator) ValidateProfile(ctx context.Context, input *ValidateProfileInput) error {

	// i18n surface: C — admin/account API.
	if len(input.Username) > 0 {
		user, err := val.database.GetUserBySubject(ctx, nil, input.Subject)
		if err != nil {
			return err
		}
		// An unresolvable subject is not a validation problem the caller can show
		// to a user: it means the request carried a stale or forged subject.
		// Surface it as an error rather than dereferencing nil below.
		if user == nil {
			return errs.New("subject not found: " + input.Subject)
		}

		// Username uniqueness is best-effort, and deliberately so. This is a
		// read-then-write check with nothing to serialize it, so two concurrent
		// profile updates can both pass and end up with the same username.
		//
		// There is no unique index to lean on. username is optional and every user
		// is created with "" (UserCreator.CreateUser does not set it; a username is
		// only ever assigned later, here), so a plain unique index would permit
		// exactly one such row and break the second registration. Excluding the
		// empty value needs a partial index, which MySQL does not support, so
		// enforcing this in the schema would mean a different mechanism per engine.
		//
		// Tolerable because username is not an authentication key: sign-in resolves
		// the account by email (authflow.PasswordSubmission), this is the only caller of
		// GetUserByUsername, and the one place the value escapes is the OIDC
		// preferred_username claim, which the spec tells relying parties not to
		// assume is unique.
		userByUsername, err := val.database.GetUserByUsername(ctx, nil, input.Username)
		if err != nil {
			return err
		}

		if userByUsername != nil && userByUsername.Subject != user.Subject {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileUsernameTaken, nil)
		}

		if !usernameShape.MatchString(input.Username) {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileUsernameInvalid, nil)
		}
	}

	if err := val.ValidateName(input.GivenName, i18n.ErrCodeProfileGivenNameInvalid); err != nil {
		return err
	}

	if err := val.ValidateName(input.MiddleName, i18n.ErrCodeProfileMiddleNameInvalid); err != nil {
		return err
	}

	if err := val.ValidateName(input.FamilyName, i18n.ErrCodeProfileFamilyNameInvalid); err != nil {
		return err
	}

	// The nickname is the OIDC nickname claim, a casual name that may or may not be the
	// given name's: "Amazing Grace", "Dr. G", "Jean-Luc". So it is free text rather than
	// a username's shape, whose claim is preferred_username, and which the username field
	// fills (#632 item 4). Free text still refuses what no field a person types takes: a
	// bound, here the name fields' own, in the UTF-16 code units every text bound measures
	// in; the control characters that would put a line break in a single-line value; and
	// the angle brackets decision 3 of #275 refuses rather than strips, since nothing
	// sanitizes and an accepted nickname is stored exactly as it was sent. The control
	// characters are breaksOrReordersLine's, which adds the line and paragraph separators
	// and the bidi embeddings, overrides and isolates to the C0 and C1 controls.
	if input.Nickname != "" {
		if inputvalidation.TextLength(input.Nickname) > nameMaxLength {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileNicknameTooLong, map[string]any{"max": nameMaxLength})
		}

		if strings.ContainsFunc(input.Nickname, breaksOrReordersLine) {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileNicknameInvalid, nil)
		}

		if err := ValidateNoAngleBrackets(input.Nickname, i18n.ErrCodeProfileNicknameAngleBrackets); err != nil {
			return err
		}
	}

	if len(input.Website) > 0 {
		if !websiteShape.MatchString(input.Website) {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileWebsiteInvalid, nil)
		}
	}

	if inputvalidation.TextLength(input.Website) > 96 {
		return i18n.NewLocalizedError(i18n.ErrCodeProfileWebsiteTooLong, map[string]any{"max": 96})
	}

	if len(input.Gender) > 0 {
		if _, ok := ParseGender(input.Gender); !ok {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileGenderInvalid, nil)
		}
	}

	if len(input.DateOfBirth) > 0 {
		layout := "2006-01-02"
		parsedTime, err := time.Parse(layout, input.DateOfBirth)
		if err != nil {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileDobInvalidFormat, nil)
		}
		// Compare dates only, not times. The parsed birth date is midnight UTC, so
		// "today" is built from UTC components too: taking them from local time while
		// labelling the result UTC made a birth date equal to the current UTC date
		// look future-dated on any server behind UTC.
		//
		// A one-day tolerance on top of that, because the date arrives with no
		// timezone and the server cannot know the user's. Offsets run from UTC-12 to
		// UTC+14, so the user's local date is at most one day ahead of the UTC date
		// and at most one day behind it. Anchoring strictly to UTC fixed the
		// behind-UTC direction and broke the ahead-of-UTC one: a user in UTC+14
		// entering their own local date would be told it is in the future.
		//
		// So the rule is "reject only what cannot be today anywhere". One day ahead
		// of UTC is somebody's today and is accepted; two days ahead is nobody's and
		// is not. For a date of birth that costs nothing, since the check exists to
		// catch obvious nonsense rather than to police the boundary by an hour.
		now := time.Now().UTC()
		todayUTC := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		latestDateThatCouldBeToday := todayUTC.AddDate(0, 0, 1)
		if parsedTime.After(latestDateThatCouldBeToday) {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileDobInFuture, nil)
		}
	}

	// The zone and its country name are one value: together they are the row of the zone picker
	// the profile page reopens on, and a zone ID alone does not name a row, since one zone can be
	// listed under several countries. A pair naming no row makes the page reopen on the blank
	// option, and the next save of that page erases the user's zone. So a zone requires the name
	// of a country it is listed under, compared exactly, and no zone requires no name (#432).
	if input.ZoneInfo != "" {
		rows := timezones.ByZone(input.ZoneInfo)
		if !slices.ContainsFunc(rows, func(z timezones.Zone) bool { return z.CountryName == input.ZoneInfoCountryName }) {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileZoneInfoInvalid, nil)
		}
	} else if input.ZoneInfoCountryName != "" {
		return i18n.NewLocalizedError(i18n.ErrCodeProfileZoneInfoInvalid, nil)
	}

	if len(input.Locale) > 0 {
		if _, found := locales.ByID(input.Locale); !found {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileLocaleInvalid, nil)
		}
	}

	// The page language is Automatic, "", or exactly the tag of a catalog this server has loaded,
	// built in or an operator's: every value accepted then changes something, where a tag with no
	// catalog would be stored and do nothing (#631 decision 3). Left out of the request, nil, it is
	// not checked, because the save leaves the stored value as it is.
	if input.PageLanguage != nil && *input.PageLanguage != "" && !i18n.IsCatalogTag(*input.PageLanguage) {
		return i18n.NewLocalizedError(i18n.ErrCodeProfilePageLanguageInvalid, nil)
	}

	return nil
}

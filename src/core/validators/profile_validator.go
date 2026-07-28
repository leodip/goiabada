package validators

import (
	"regexp"
	"strconv"
	"time"

	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/timezones"
	"github.com/pkg/errors"
)

type ProfileValidator struct {
	database data.Database
}

func NewProfileValidator(database data.Database) *ProfileValidator {
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
	Subject             string
}

var (
	// nameShape allows Unicode letters, spaces, apostrophes and hyphens, 2 to 48
	// characters. Note the literal space rather than \s: tabs, newlines and other
	// control characters have no place in a name and would otherwise let a value
	// span multiple lines.
	nameShape = regexp.MustCompile(`^[\p{L} '-]{2,48}$`)
	// nameHasLetter requires at least one letter, so a value made up entirely of
	// spaces, apostrophes or hyphens is rejected.
	nameHasLetter = regexp.MustCompile(`\p{L}`)
)

// ValidateName checks a name field against the shared name pattern.
// invalidNameCode is the i18n error code returned on failure (one of
// ErrCodeProfileGivenNameInvalid, ErrCodeProfileMiddleNameInvalid, or
// ErrCodeProfileFamilyNameInvalid). Caller picks the right code so that
// the localized message names the field correctly.
//
// An empty name is accepted: all three name fields are optional.
//
// i18n surface: A | C — admin user CRUD, account self-service, registration.
func (val *ProfileValidator) ValidateName(name string, invalidNameCode string) error {
	if len(name) == 0 {
		return nil
	}

	if !nameShape.MatchString(name) || !nameHasLetter.MatchString(name) {
		return i18n.NewLocalizedError(invalidNameCode, nil)
	}
	return nil
}

func (val *ProfileValidator) ValidateProfile(input *ValidateProfileInput) error {

	// i18n surface: C — admin/account API.
	if len(input.Username) > 0 {
		user, err := val.database.GetUserBySubject(nil, input.Subject)
		if err != nil {
			return err
		}
		// An unresolvable subject is not a validation problem the caller can show
		// to a user: it means the request carried a stale or forged subject.
		// Surface it as an error rather than dereferencing nil below.
		if user == nil {
			return errors.WithStack(errors.New("subject not found: " + input.Subject))
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
		// the account by email (HandleAuthPwdPost), this is the only caller of
		// GetUserByUsername, and the one place the value escapes is the OIDC
		// preferred_username claim, which the spec tells relying parties not to
		// assume is unique.
		userByUsername, err := val.database.GetUserByUsername(nil, input.Username)
		if err != nil {
			return err
		}

		if userByUsername != nil && userByUsername.Subject != user.Subject {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileUsernameTaken, nil)
		}

		pattern := "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}

		if !regex.MatchString(input.Username) {
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

	pattern := "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(input.Nickname) > 0 {
		if !regex.MatchString(input.Nickname) {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileNicknameInvalid, nil)
		}
	}

	pattern = `^(https?://)?(www\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(/\S*)?$`
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(input.Website) > 0 {
		if !regex.MatchString(input.Website) {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileWebsiteInvalid, nil)
		}
	}

	if len(input.Website) > 96 {
		return i18n.NewLocalizedError(i18n.ErrCodeProfileWebsiteTooLong, map[string]any{"max": 96})
	}

	if len(input.Gender) > 0 {
		i, err := strconv.Atoi(input.Gender)
		if err != nil {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileGenderInvalid, nil)
		}
		if !enums.IsGenderValid(i) {
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

	if len(input.ZoneInfo) > 0 {
		timeZones := timezones.Get()
		found := false
		for _, tz := range timeZones {
			if tz.Zone == input.ZoneInfo {
				found = true
				break
			}
		}
		if !found {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileZoneInfoInvalid, nil)
		}
	}

	if len(input.Locale) > 0 {
		locales := locales.Get()
		found := false
		for _, loc := range locales {
			if loc.Id == input.Locale {
				found = true
				break
			}
		}
		if !found {
			return i18n.NewLocalizedError(i18n.ErrCodeProfileLocaleInvalid, nil)
		}
	}

	return nil
}

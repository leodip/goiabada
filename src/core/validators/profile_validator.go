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

// ValidateName checks a name field against the shared name pattern.
// invalidNameCode is the i18n error code returned on failure (one of
// ErrCodeProfileGivenNameInvalid, ErrCodeProfileMiddleNameInvalid, or
// ErrCodeProfileFamilyNameInvalid). Caller picks the right code so that
// the localized message names the field correctly.
//
// i18n surface: A | C — admin user CRUD, account self-service, registration.
func (val *ProfileValidator) ValidateName(name string, invalidNameCode string) error {
	pattern := `^[\p{L}\s'-]{2,48}$`
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(name) > 0 {
		if !regex.MatchString(name) {
			return i18n.NewLocalizedError(invalidNameCode, nil)
		}
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
		// Compare dates only, not times, to avoid timezone issues
		now := time.Now()
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		if parsedTime.After(today) {
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

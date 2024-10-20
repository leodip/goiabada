package validators

import (
	"context"
	"regexp"
	"strconv"
	"time"

	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
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

func (val *ProfileValidator) ValidateName(ctx context.Context, name string, nameField string) error {
	pattern := `^[\p{L}\s'-]{2,48}$`
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(name) > 0 {
		if !regex.MatchString(name) {
			return customerrors.NewErrorDetail("", "Please enter a valid "+nameField+". It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}
	return nil
}

func (val *ProfileValidator) ValidateProfile(ctx context.Context, input *ValidateProfileInput) error {

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
			return customerrors.NewErrorDetail("", "Sorry, this username is already taken.")
		}

		pattern := "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}

		if !regex.MatchString(input.Username) {
			return customerrors.NewErrorDetail("", "Usernames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.")
		}
	}

	err := val.ValidateName(ctx, input.GivenName, "given name")
	if err != nil {
		return err
	}

	err = val.ValidateName(ctx, input.MiddleName, "middle name")
	if err != nil {
		return err
	}

	err = val.ValidateName(ctx, input.FamilyName, "family name")
	if err != nil {
		return err
	}

	pattern := "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(input.Nickname) > 0 {
		if !regex.MatchString(input.Nickname) {
			return customerrors.NewErrorDetail("", "Nicknames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.")
		}
	}

	pattern = `^(https?://)?(www\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(/\S*)?$`
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(input.Website) > 0 {
		if !regex.MatchString(input.Website) {
			return customerrors.NewErrorDetail("", "Please enter a valid website URL.")
		}
	}

	if len(input.Website) > 96 {
		return customerrors.NewErrorDetail("", "Please ensure the website URL is no longer than 96 characters.")
	}

	if len(input.Gender) > 0 {
		i, err := strconv.Atoi(input.Gender)
		if err != nil {
			return customerrors.NewErrorDetail("", "Gender is invalid.")
		}
		if !enums.IsGenderValid(i) {
			return customerrors.NewErrorDetail("", "Gender is invalid.")
		}
	}

	if len(input.DateOfBirth) > 0 {
		layout := "2006-01-02"
		parsedTime, err := time.Parse(layout, input.DateOfBirth)
		if err != nil {
			return customerrors.NewErrorDetail("", "The date of birth is invalid. Please use the format YYYY-MM-DD.")
		}
		if parsedTime.After(time.Now()) {
			return customerrors.NewErrorDetail("", "The date of birth can't be in the future.")
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
			return customerrors.NewErrorDetail("", "The zone info is invalid.")
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
			return customerrors.NewErrorDetail("", "The locale is invalid.")
		}
	}

	return nil
}

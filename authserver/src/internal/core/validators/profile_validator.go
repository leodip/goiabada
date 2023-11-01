package core

import (
	"context"
	"regexp"
	"strconv"
	"time"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

type ProfileValidator struct {
	database *data.Database
}

func NewProfileValidator(database *data.Database) *ProfileValidator {
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

func (val *ProfileValidator) ValidateProfile(ctx context.Context, input *ValidateProfileInput) error {

	if len(input.Username) > 0 {
		user, err := val.database.GetUserBySubject(input.Subject)
		if err != nil {
			return err
		}

		userByUsername, err := val.database.GetUserByUsername(input.Username)
		if err != nil {
			return err
		}

		if userByUsername != nil && userByUsername.Subject != user.Subject {
			return customerrors.NewValidationError("", "Sorry, this username is already taken.")
		}

		pattern := "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}

		if !regex.MatchString(input.Username) {
			return customerrors.NewValidationError("", "Usernames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.")
		}
	}

	pattern := `^[\p{L}\s'-]{2,48}$`
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(input.GivenName) > 0 {
		if !regex.MatchString(input.GivenName) {
			return customerrors.NewValidationError("", "Please enter a valid given name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}

	if len(input.MiddleName) > 0 {
		if !regex.MatchString(input.MiddleName) {
			return customerrors.NewValidationError("", "Please enter a valid middle name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}

	if len(input.FamilyName) > 0 {
		if !regex.MatchString(input.FamilyName) {
			return customerrors.NewValidationError("", "Please enter a valid family name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}

	pattern = "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(input.Nickname) > 0 {
		if !regex.MatchString(input.Nickname) {
			return customerrors.NewValidationError("", "Nicknames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.")
		}
	}

	pattern = `^(https?://)?(www\.)?([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})(/\S*)?$`
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(input.Website) > 0 {
		if !regex.MatchString(input.Website) {
			return customerrors.NewValidationError("", "Please enter a valid website URL.")
		}
	}

	if len(input.Website) > 96 {
		return customerrors.NewValidationError("", "Please ensure the website URL is no longer than 96 characters.")
	}

	if len(input.Gender) > 0 {
		i, err := strconv.Atoi(input.Gender)
		if err != nil {
			return customerrors.NewValidationError("", "Gender is invalid.")
		}
		if !enums.IsGenderValid(i) {
			return customerrors.NewValidationError("", "Gender is invalid.")
		}
	}

	if len(input.DateOfBirth) > 0 {
		layout := "2006-01-02"
		parsedTime, err := time.Parse(layout, input.DateOfBirth)
		if err != nil {
			return customerrors.NewValidationError("", "The date of birth is invalid. Please use the format YYYY-MM-DD.")
		}
		if parsedTime.After(time.Now()) {
			return customerrors.NewValidationError("", "The date of birth can't be in the future.")
		}
	}

	if len(input.ZoneInfo) > 0 {
		timeZones := lib.GetTimeZones()
		found := false
		for _, tz := range timeZones {
			if tz.Zone == input.ZoneInfo {
				found = true
				break
			}
		}
		if !found {
			return customerrors.NewValidationError("", "The zone info is invalid.")
		}
	}

	if len(input.Locale) > 0 {
		locales := lib.GetLocales()
		found := false
		for _, loc := range locales {
			if loc.Id == input.Locale {
				found = true
				break
			}
		}
		if !found {
			return customerrors.NewValidationError("", "The locale is invalid.")
		}
	}

	return nil
}

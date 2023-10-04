package core

import (
	"context"
	"regexp"
	"strconv"
	"time"

	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

type ProfileValidator struct {
	database core.Database
}

func NewProfileValidator(database core.Database) *ProfileValidator {
	return &ProfileValidator{
		database: database,
	}
}

func (val *ProfileValidator) ValidateProfile(ctx context.Context, accountProfile *dtos.AccountProfile) error {

	if len(accountProfile.Username) == 0 {
		return customerrors.NewValidationError("", "Please provide a username.")
	}

	user, err := val.database.GetUserBySubject(accountProfile.Subject)
	if err != nil {
		return err
	}

	userByUsername, err := val.database.GetUserByUsername(accountProfile.Username)
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

	if !regex.MatchString(accountProfile.Username) {
		return customerrors.NewValidationError("", "Usernames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.")
	}

	pattern = `^[\p{L}\s'-]{2,48}$`
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(accountProfile.GivenName) > 0 {
		if !regex.MatchString(accountProfile.GivenName) {
			return customerrors.NewValidationError("", "Please enter a valid given name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}

	if len(accountProfile.MiddleName) > 0 {
		if !regex.MatchString(accountProfile.MiddleName) {
			return customerrors.NewValidationError("", "Please enter a valid middle name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}

	if len(accountProfile.FamilyName) > 0 {
		if !regex.MatchString(accountProfile.FamilyName) {
			return customerrors.NewValidationError("", "Please enter a valid family name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}

	pattern = "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(accountProfile.Nickname) > 0 {
		if !regex.MatchString(accountProfile.Nickname) {
			return customerrors.NewValidationError("", "Nicknames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.")
		}
	}

	pattern = `^(https?://)?(www\.)?([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})(/\S*)?$`
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(accountProfile.Website) > 0 {
		if !regex.MatchString(accountProfile.Website) {
			return customerrors.NewValidationError("", "Please enter a valid website URL.")
		}
	}

	if len(accountProfile.Website) > 48 {
		return customerrors.NewValidationError("", "Please ensure the website URL is no longer than 48 characters.")
	}

	if len(accountProfile.Gender) > 0 {
		i, err := strconv.Atoi(accountProfile.Gender)
		if err != nil {
			return customerrors.NewValidationError("", "Gender is invalid.")
		}
		if !enums.IsGenderValid(i) {
			return customerrors.NewValidationError("", "Gender is invalid.")
		}
	}

	if len(accountProfile.DateOfBirth) > 0 {
		layout := "2006-01-02"
		parsedTime, err := time.Parse(layout, accountProfile.DateOfBirth)
		if err != nil {
			return customerrors.NewValidationError("", "The date of birth is invalid. Please use the format YYYY-MM-DD.")
		}
		if parsedTime.After(time.Now()) {
			return customerrors.NewValidationError("", "The date of birth can't be in the future.")
		}
	}

	if len(accountProfile.ZoneInfo) > 0 {
		timeZones := lib.GetTimeZones()
		found := false
		for _, tz := range timeZones {
			if tz.Zone == accountProfile.ZoneInfo {
				found = true
				break
			}
		}
		if !found {
			return customerrors.NewValidationError("", "The zone info is invalid.")
		}
	}

	if len(accountProfile.Locale) > 0 {
		locales := lib.GetLocales()
		found := false
		for _, loc := range locales {
			if loc.Id == accountProfile.Locale {
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

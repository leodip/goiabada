package core

import (
	"context"
	"regexp"
	"strconv"
	"time"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
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

func (val *ProfileValidator) ValidateProfile(ctx context.Context, userProfile *dtos.UserProfile) error {

	if len(userProfile.Username) > 0 {
		user, err := val.database.GetUserBySubject(userProfile.Subject)
		if err != nil {
			return err
		}

		userByUsername, err := val.database.GetUserByUsername(userProfile.Username)
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

		if !regex.MatchString(userProfile.Username) {
			return customerrors.NewValidationError("", "Usernames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.")
		}
	}

	pattern := `^[\p{L}\s'-]{2,48}$`
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(userProfile.GivenName) > 0 {
		if !regex.MatchString(userProfile.GivenName) {
			return customerrors.NewValidationError("", "Please enter a valid given name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}

	if len(userProfile.MiddleName) > 0 {
		if !regex.MatchString(userProfile.MiddleName) {
			return customerrors.NewValidationError("", "Please enter a valid middle name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}

	if len(userProfile.FamilyName) > 0 {
		if !regex.MatchString(userProfile.FamilyName) {
			return customerrors.NewValidationError("", "Please enter a valid family name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.")
		}
	}

	pattern = "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(userProfile.Nickname) > 0 {
		if !regex.MatchString(userProfile.Nickname) {
			return customerrors.NewValidationError("", "Nicknames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.")
		}
	}

	pattern = `^(https?://)?(www\.)?([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})(/\S*)?$`
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if len(userProfile.Website) > 0 {
		if !regex.MatchString(userProfile.Website) {
			return customerrors.NewValidationError("", "Please enter a valid website URL.")
		}
	}

	if len(userProfile.Website) > 96 {
		return customerrors.NewValidationError("", "Please ensure the website URL is no longer than 96 characters.")
	}

	if len(userProfile.Gender) > 0 {
		i, err := strconv.Atoi(userProfile.Gender)
		if err != nil {
			return customerrors.NewValidationError("", "Gender is invalid.")
		}
		if !enums.IsGenderValid(i) {
			return customerrors.NewValidationError("", "Gender is invalid.")
		}
	}

	if len(userProfile.DateOfBirth) > 0 {
		layout := "2006-01-02"
		parsedTime, err := time.Parse(layout, userProfile.DateOfBirth)
		if err != nil {
			return customerrors.NewValidationError("", "The date of birth is invalid. Please use the format YYYY-MM-DD.")
		}
		if parsedTime.After(time.Now()) {
			return customerrors.NewValidationError("", "The date of birth can't be in the future.")
		}
	}

	if len(userProfile.ZoneInfo) > 0 {
		timeZones := lib.GetTimeZones()
		found := false
		for _, tz := range timeZones {
			if tz.Zone == userProfile.ZoneInfo {
				found = true
				break
			}
		}
		if !found {
			return customerrors.NewValidationError("", "The zone info is invalid.")
		}
	}

	if len(userProfile.Locale) > 0 {
		locales := lib.GetLocales()
		found := false
		for _, loc := range locales {
			if loc.Id == userProfile.Locale {
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

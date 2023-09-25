package core

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"
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

	requestId := middleware.GetReqID(ctx)

	if len(accountProfile.Username) == 0 {
		return customerrors.NewAppError(nil, "", "Please provide a username.", http.StatusOK)
	}

	user, err := val.database.GetUserBySubject(accountProfile.Subject)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}

	userByUsername, err := val.database.GetUserByUsername(accountProfile.Username)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}

	if userByUsername != nil && userByUsername.Subject != user.Subject {
		return customerrors.NewAppError(nil, "", "Sorry, this username is already taken.", http.StatusOK)
	}

	pattern := "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}

	if !regex.MatchString(accountProfile.Username) {
		return customerrors.NewAppError(nil, "", "Usernames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.", http.StatusOK)
	}

	pattern = `^[\p{L}\s'-]{2,48}$`
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}

	if len(accountProfile.GivenName) > 0 {
		if !regex.MatchString(accountProfile.GivenName) {
			return customerrors.NewAppError(nil, "", "Please enter a valid given name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.", http.StatusOK)
		}
	}

	if len(accountProfile.MiddleName) > 0 {
		if !regex.MatchString(accountProfile.MiddleName) {
			return customerrors.NewAppError(nil, "", "Please enter a valid middle name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.", http.StatusOK)
		}
	}

	if len(accountProfile.FamilyName) > 0 {
		if !regex.MatchString(accountProfile.FamilyName) {
			return customerrors.NewAppError(nil, "", "Please enter a valid family name. It should contain only letters, spaces, hyphens, and apostrophes and be between 2 and 48 characters in length.", http.StatusOK)
		}
	}

	pattern = "^[a-zA-Z][a-zA-Z0-9_]{1,23}$"
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}

	if len(accountProfile.Nickname) > 0 {
		if !regex.MatchString(accountProfile.Nickname) {
			return customerrors.NewAppError(nil, "", "Nicknames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.", http.StatusOK)
		}
	}

	pattern = `^(https?://)?(www\.)?([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})(/\S*)?$`
	regex, err = regexp.Compile(pattern)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}

	if len(accountProfile.Website) > 0 {
		if !regex.MatchString(accountProfile.Website) {
			return customerrors.NewAppError(nil, "", "Please enter a valid website URL.", http.StatusOK)
		}
	}

	if len(accountProfile.Website) > 48 {
		return customerrors.NewAppError(nil, "", "Please ensure the website URL is no longer than 48 characters.", http.StatusOK)
	}

	if len(accountProfile.Gender) > 0 {
		i, err := strconv.Atoi(accountProfile.Gender)
		if err != nil {
			return customerrors.NewAppError(nil, "", "Gender is invalid.", http.StatusOK)
		}
		if !enums.IsGenderValid(i) {
			return customerrors.NewAppError(nil, "", "Gender is invalid.", http.StatusOK)
		}
	}

	if len(accountProfile.DateOfBirth) > 0 {
		layout := "2006-01-02"
		parsedTime, err := time.Parse(layout, accountProfile.DateOfBirth)
		if err != nil {
			return customerrors.NewAppError(nil, "", "The date of birth is invalid. Please use the format YYYY-MM-DD.", http.StatusOK)
		}
		if parsedTime.After(time.Now()) {
			return customerrors.NewAppError(nil, "", "The date of birth can't be in the future.", http.StatusOK)
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
			return customerrors.NewAppError(nil, "", "The zone info is invalid.", http.StatusOK)
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
			return customerrors.NewAppError(nil, "", "The locale is invalid.", http.StatusOK)
		}
	}

	return nil
}

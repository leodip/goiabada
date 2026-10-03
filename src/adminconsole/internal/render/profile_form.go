package render

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/gender"
)

// ParseProfileForm builds the profile update from the form the account profile page and the admin
// user profile page both post. The time-zone select's value is the country name and the zone
// joined by "___"; a value that is not exactly those two halves can only come from a hand-edited
// request, and is answered with an error, which both pages render as a 500 (#440).
func ParseProfileForm(r *http.Request) (*api.UpdateUserProfileRequest, error) {
	zoneInfoValue := r.FormValue("zoneInfo")
	zoneInfoCountryName := ""
	zoneInfo := ""

	if zoneInfoValue != "" {
		zoneInfoParts := strings.Split(zoneInfoValue, "___")
		if len(zoneInfoParts) != 2 {
			return nil, errs.New("invalid zoneInfo")
		}
		zoneInfoCountryName = zoneInfoParts[0]
		zoneInfo = zoneInfoParts[1]
	}

	return &api.UpdateUserProfileRequest{
		Username:            strings.TrimSpace(r.FormValue("username")),
		GivenName:           strings.TrimSpace(r.FormValue("givenName")),
		MiddleName:          strings.TrimSpace(r.FormValue("middleName")),
		FamilyName:          strings.TrimSpace(r.FormValue("familyName")),
		Nickname:            strings.TrimSpace(r.FormValue("nickname")),
		Website:             strings.TrimSpace(r.FormValue("website")),
		Gender:              r.FormValue("gender"),
		DateOfBirth:         strings.TrimSpace(r.FormValue("dateOfBirth")),
		ZoneInfoCountryName: zoneInfoCountryName,
		ZoneInfo:            zoneInfo,
		Locale:              r.FormValue("locale"),
	}, nil
}

// EchoProfileForm puts the submitted values onto the user the page is rendered again with when
// the API refuses them, so nothing the user typed is lost. A gender or date of birth that does
// not parse keeps the stored value, since that is what was refused.
func EchoProfileForm(user *api.UserResponse, request *api.UpdateUserProfileRequest) {
	user.Username = request.Username
	user.GivenName = request.GivenName
	user.MiddleName = request.MiddleName
	user.FamilyName = request.FamilyName
	user.Nickname = request.Nickname
	user.Website = request.Website
	user.ZoneInfoCountryName = request.ZoneInfoCountryName
	user.ZoneInfo = request.ZoneInfo
	user.Locale = request.Locale

	if len(request.Gender) > 0 {
		if i, err := strconv.Atoi(request.Gender); err == nil {
			user.Gender = gender.Gender(i).String()
		}
	} else {
		user.Gender = ""
	}

	if len(request.DateOfBirth) > 0 {
		if parsed, err := time.Parse("2006-01-02", request.DateOfBirth); err == nil {
			user.BirthDate = &parsed
		}
	} else {
		user.BirthDate = nil
	}
}

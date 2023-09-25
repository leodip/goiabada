package dtos

import (
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

type AccountProfile struct {
	Username        string
	GivenName       string
	MiddleName      string
	FamilyName      string
	Nickname        string
	Website         string
	Gender          string
	DateOfBirth     string
	ZoneInfoCountry string
	ZoneInfo        string
	Locale          string
	Subject         string
}

func AccountProfileFromUser(user *entities.User) *AccountProfile {

	if user == nil {
		return nil
	}

	var tz *lib.Zone
	if len(user.ZoneInfo) > 0 {
		tz = lib.GetTimeZoneByZoneInfo(user.ZoneInfo)
	}

	profile := &AccountProfile{
		Username:    user.Username,
		GivenName:   user.GivenName,
		MiddleName:  user.MiddleName,
		FamilyName:  user.FamilyName,
		Nickname:    user.Nickname,
		Website:     user.Website,
		Gender:      user.Gender,
		DateOfBirth: user.GetDateOfBirthFormatted(),
		ZoneInfo:    user.ZoneInfo,
		Locale:      user.Locale,
		Subject:     user.Subject.String(),
	}

	if tz != nil {
		profile.ZoneInfoCountry = tz.CountryCode
	}

	return profile
}

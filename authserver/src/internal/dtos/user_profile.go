package dtos

import (
	"strconv"
	"time"

	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
)

type UserProfile struct {
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

func AssignProfileToUser(user *entities.User, profile *UserProfile) {
	user.Username = profile.Username
	user.GivenName = profile.GivenName
	user.MiddleName = profile.MiddleName
	user.FamilyName = profile.FamilyName
	user.Nickname = profile.Nickname
	user.Website = profile.Website

	if len(profile.Gender) > 0 {
		i, err := strconv.Atoi(profile.Gender)
		if err == nil {
			user.Gender = enums.Gender(i).String()
		}
	} else {
		user.Gender = ""
	}

	if len(profile.DateOfBirth) > 0 {
		layout := "2006-01-02"
		parsedTime, err := time.Parse(layout, profile.DateOfBirth)
		if err == nil {
			user.BirthDate = &parsedTime
		}
	} else {
		user.BirthDate = nil
	}

	user.ZoneInfoCountryName = profile.ZoneInfoCountryName
	user.ZoneInfo = profile.ZoneInfo
	user.Locale = profile.Locale
}

func UserProfileFromUser(user *entities.User) *UserProfile {

	if user == nil {
		return nil
	}

	profile := &UserProfile{
		Username:            user.Username,
		GivenName:           user.GivenName,
		MiddleName:          user.MiddleName,
		FamilyName:          user.FamilyName,
		Nickname:            user.Nickname,
		Website:             user.Website,
		Gender:              user.Gender,
		DateOfBirth:         user.GetDateOfBirthFormatted(),
		ZoneInfoCountryName: user.ZoneInfoCountryName,
		ZoneInfo:            user.ZoneInfo,
		Locale:              user.Locale,
		Subject:             user.Subject.String(),
	}

	return profile
}

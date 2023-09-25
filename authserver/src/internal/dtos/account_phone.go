package dtos

import (
	"strings"

	"github.com/leodip/goiabada/internal/entities"
)

type AccountPhone struct {
	PhoneNumberCountry  string
	PhoneNumber         string
	PhoneNumberVerified bool
}

func AccountPhoneFromUser(user *entities.User) *AccountPhone {

	if user == nil {
		return nil
	}

	phoneNumberCountry := ""
	phoneNumber := ""

	if len(user.PhoneNumber) > 0 {
		parts := strings.Split(user.PhoneNumber, " ")
		if len(parts) == 2 {
			phoneNumberCountry = parts[0]
			phoneNumber = parts[1]
		}
	}

	return &AccountPhone{
		PhoneNumberCountry:  phoneNumberCountry,
		PhoneNumber:         phoneNumber,
		PhoneNumberVerified: user.PhoneNumberVerified,
	}
}

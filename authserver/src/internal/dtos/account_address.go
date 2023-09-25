package dtos

import (
	"github.com/leodip/goiabada/internal/entities"
)

type AccountAddress struct {
	AddressLine1      string
	AddressLine2      string
	AddressLocality   string
	AddressRegion     string
	AddressPostalCode string
	AddressCountry    string
}

func AccountAddressFromUser(user *entities.User) *AccountAddress {

	if user == nil {
		return nil
	}

	return &AccountAddress{
		AddressLine1:      user.AddressLine1,
		AddressLine2:      user.AddressLine2,
		AddressLocality:   user.AddressLocality,
		AddressRegion:     user.AddressRegion,
		AddressPostalCode: user.AddressPostalCode,
		AddressCountry:    user.AddressCountry,
	}
}

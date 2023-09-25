package dtos

import (
	"github.com/leodip/goiabada/internal/entities"
)

type AccountEmail struct {
	Email             string
	EmailVerified     bool
	EmailConfirmation string
	Subject           string
}

func AccountEmailFromUser(user *entities.User) *AccountEmail {

	if user == nil {
		return nil
	}

	return &AccountEmail{
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Subject:       user.Subject.String(),
	}
}

package dtos

import (
	"github.com/leodip/goiabada/internal/entities"
)

type UserEmail struct {
	Email             string
	EmailConfirmation string
	EmailVerified     bool
	Subject           string
}

func AssignEmailToUser(user *entities.User, email *UserEmail) {
	user.Email = email.Email
	user.EmailVerified = email.EmailVerified
}

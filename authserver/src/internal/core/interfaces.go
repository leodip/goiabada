package core

import (
	"github.com/leodip/goiabada/internal/entities"
)

type Database interface {
	GetClientByClientIdentifier(clientIdentifier string) (*entities.Client, error)
	GetResourceByResourceIdentifier(resourceIdentifier string) (*entities.Resource, error)
	GetResourcePermissions(resourceId uint) ([]entities.Permission, error)
	GetUserByUsername(username string) (*entities.User, error)
	GetUserSessionBySessionIdentifier(sessionIdentifier string) (*entities.UserSession, error)
	GetSettings() (*entities.Settings, error)
	CreateCode(code *entities.Code) (*entities.Code, error)
	UpdateUser(user *entities.User) (*entities.User, error)
	GetUserConsent(userID uint, clientID uint) (*entities.UserConsent, error)
	SaveUserConsent(userConsent *entities.UserConsent) (*entities.UserConsent, error)
	GetSigningKey() (*entities.KeyPair, error)
	GetUserBySubject(subject string) (*entities.User, error)
	GetUserByEmail(email string) (*entities.User, error)
	GetCode(code string, used bool) (*entities.Code, error)
	GetUserById(id uint) (*entities.User, error)
}

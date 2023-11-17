package core

import (
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type UserCreator struct {
	database *data.Database
}

func NewUserCreator(database *data.Database) *UserCreator {
	return &UserCreator{
		database: database,
	}
}

type CreateUserInput struct {
	Email         string
	EmailVerified bool
	PasswordHash  string
	GivenName     string
	MiddleName    string
	FamilyName    string
}

func (uc *UserCreator) CreateUser(ctx context.Context, input *CreateUserInput) (*entities.User, error) {

	user := &entities.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		GivenName:     input.GivenName,
		MiddleName:    input.MiddleName,
		FamilyName:    input.FamilyName,
		PasswordHash:  input.PasswordHash,
	}

	authServerResource, err := uc.database.GetResourceByResourceIdentifier(constants.AuthServerResourceIdentifier)
	if err != nil {
		return nil, err
	}

	permissions, err := uc.database.GetPermissionsByResourceId(authServerResource.Id)
	if err != nil {
		return nil, err
	}

	var accountPermission *entities.Permission
	for idx, permission := range permissions {
		if permission.PermissionIdentifier == constants.ManageAccountPermissionIdentifier {
			accountPermission = &permissions[idx]
			break
		}
	}

	if accountPermission == nil {
		return nil, errors.New("unable to find the account permission")
	}

	user.Permissions = []entities.Permission{*accountPermission}

	user, err = uc.database.SaveUser(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

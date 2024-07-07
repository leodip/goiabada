package users

import (
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/models"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type UserCreator struct {
	database data.Database
}

func NewUserCreator(database data.Database) *UserCreator {
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

func (uc *UserCreator) CreateUser(ctx context.Context, input *CreateUserInput) (*models.User, error) {

	user := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		GivenName:     input.GivenName,
		MiddleName:    input.MiddleName,
		FamilyName:    input.FamilyName,
		PasswordHash:  input.PasswordHash,
	}

	authServerResource, err := uc.database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	if err != nil {
		return nil, err
	}

	permissions, err := uc.database.GetPermissionsByResourceId(nil, authServerResource.Id)
	if err != nil {
		return nil, err
	}

	var accountPermission *models.Permission
	for idx, permission := range permissions {
		if permission.PermissionIdentifier == constants.ManageAccountPermissionIdentifier {
			accountPermission = &permissions[idx]
			break
		}
	}

	if accountPermission == nil {
		return nil, errors.WithStack(errors.New("unable to find the account permission"))
	}

	user.Permissions = []models.Permission{*accountPermission}

	tx, err := uc.database.BeginTransaction()
	if err != nil {
		return nil, err
	}
	defer uc.database.RollbackTransaction(tx)

	err = uc.database.CreateUser(tx, user)
	if err != nil {
		return nil, err
	}

	for _, permission := range user.Permissions {
		err = uc.database.CreateUserPermission(tx, &models.UserPermission{
			UserId:       user.Id,
			PermissionId: permission.Id,
		})
		if err != nil {
			return nil, err
		}
	}

	err = uc.database.CommitTransaction(tx)
	if err != nil {
		return nil, err
	}

	return user, nil
}

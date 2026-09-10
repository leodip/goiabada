package user

import (
	"database/sql"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/uuidutil"
	"github.com/pkg/errors"
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

func (uc *UserCreator) CreateUser(input *CreateUserInput) (*models.User, error) {

	user := &models.User{
		Subject:       uuidutil.New(),
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

	// The user row and its account permission land in one transaction, opened through
	// RunInTransaction so a deadlock reruns the body (#301). The body is safe to rerun: the id
	// CreateUser assigns onto user is reassigned by the next attempt before the permission
	// insert reads it.
	err = uc.database.RunInTransaction(func(tx *sql.Tx) error {
		if err := uc.database.CreateUser(tx, user); err != nil {
			return err
		}

		for _, permission := range user.Permissions {
			err := uc.database.CreateUserPermission(tx, &models.UserPermission{
				UserId:       user.Id,
				PermissionId: permission.Id,
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

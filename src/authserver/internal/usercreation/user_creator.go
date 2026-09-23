// Package usercreation creates a user account: the user row and the account-management permission
// every user is given, written together in one transaction. Registration, activation and the admin
// API's create go through UserCreator rather than writing the two rows themselves; the first-run
// seed writes its administrator inside its own transaction, in internal/bootstrap.
package usercreation

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
)

// userCreatorDatabase is what user creation needs: the user row and the default permission it is
// given, in one transaction.
type userCreatorDatabase interface {
	CreateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
	CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *models.UserPermission) error
	GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]models.Permission, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*models.Resource, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

type UserCreator struct {
	database userCreatorDatabase
}

func NewUserCreator(database userCreatorDatabase) *UserCreator {
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
		Subject:       uuidutil.New(),
		Enabled:       true,
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		GivenName:     input.GivenName,
		MiddleName:    input.MiddleName,
		FamilyName:    input.FamilyName,
		PasswordHash:  input.PasswordHash,
	}

	authServerResource, err := uc.database.GetResourceByResourceIdentifier(ctx, nil, constants.AuthServerResourceIdentifier)
	if err != nil {
		return nil, err
	}
	// The seed creates this resource and nothing deletes it through the product, but a lookup
	// answers (nil, nil) for a row that is not there, and the id below dereferenced it (#425).
	if authServerResource == nil {
		return nil, errs.Errorf("unable to find the %v resource", constants.AuthServerResourceIdentifier)
	}

	permissions, err := uc.database.GetPermissionsByResourceId(ctx, nil, authServerResource.Id)
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
		return nil, errs.New("unable to find the account permission")
	}

	user.Permissions = []models.Permission{*accountPermission}

	// The user row and its account permission land in one transaction, opened through
	// RunInTransaction so a deadlock reruns the body (#301). The body is safe to rerun: the id
	// CreateUser assigns onto user is reassigned by the next attempt before the permission
	// insert reads it.
	err = uc.database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if createUserErr := uc.database.CreateUser(ctx, tx, user); createUserErr != nil {
			return createUserErr
		}

		for _, permission := range user.Permissions {
			createUserPermissionErr := uc.database.CreateUserPermission(ctx, tx, &models.UserPermission{
				UserId:       user.Id,
				PermissionId: permission.Id,
			})
			if createUserPermissionErr != nil {
				return createUserPermissionErr
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

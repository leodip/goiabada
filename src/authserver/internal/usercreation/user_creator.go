// Package usercreation creates a user account: the user row and the account-management permission
// every user is given, written together in one transaction. Registration, activation and the admin
// API's create go through Creator rather than writing the two rows themselves; the first-run
// seed writes its administrator inside its own transaction, in internal/bootstrap.
package usercreation

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/uuid"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// userCreatorDatabase is what user creation needs: the user row and the default permission it is
// given, in one transaction.
type userCreatorDatabase interface {
	CreateUser(ctx context.Context, tx *sql.Tx, user *record.User) error
	CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *record.UserPermission) error
	GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]record.Permission, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*record.Resource, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

type Creator struct {
	database userCreatorDatabase
}

func New(database userCreatorDatabase) *Creator {
	return &Creator{
		database: database,
	}
}

type Input struct {
	Email         string
	EmailVerified bool
	PasswordHash  string
	GivenName     string
	MiddleName    string
	FamilyName    string
}

func (uc *Creator) CreateUser(ctx context.Context, input *Input) (*record.User, error) {

	user, err := uc.newUser(ctx, nil, input)
	if err != nil {
		return nil, err
	}

	// The user row and its account permission land in one transaction, opened through
	// RunInTransaction so a deadlock reruns the body (#301). The body is safe to rerun: the id
	// CreateUser assigns onto user is reassigned by the next attempt before the permission
	// insert reads it.
	err = uc.database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return uc.insertUser(ctx, tx, user)
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

// CreateUserInTransaction is CreateUser on the caller's transaction, for a caller whose request
// writes other rows beside the account and must commit or roll back all of them together:
// activation, which consumes the pending registration with the account it creates (#207). Every
// read and write runs on tx, which is required, since a nil one would commit the account on its
// own. The caller's RunInTransaction body may rerun it after a deadlock: each call builds a fresh
// user.
func (uc *Creator) CreateUserInTransaction(ctx context.Context, tx *sql.Tx, input *Input) (*record.User, error) {

	if tx == nil {
		return nil, errs.New("creating a user in the caller's transaction requires a transaction")
	}

	user, err := uc.newUser(ctx, tx, input)
	if err != nil {
		return nil, err
	}

	if err := uc.insertUser(ctx, tx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// newUser builds the user the input describes, given the account-management permission every user
// is given, read on tx.
func (uc *Creator) newUser(ctx context.Context, tx *sql.Tx, input *Input) (*record.User, error) {

	user := &record.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		GivenName:     input.GivenName,
		MiddleName:    input.MiddleName,
		FamilyName:    input.FamilyName,
		PasswordHash:  input.PasswordHash,
	}

	authServerResource, err := uc.database.GetResourceByResourceIdentifier(ctx, tx, builtin.AuthServerResourceIdentifier)
	if err != nil {
		return nil, err
	}
	// The seed creates this resource and nothing deletes it through the product, but a lookup
	// answers (nil, nil) for a row that is not there, and the id below dereferenced it (#425).
	if authServerResource == nil {
		return nil, errs.Errorf("unable to find the %v resource", builtin.AuthServerResourceIdentifier)
	}

	permissions, err := uc.database.GetPermissionsByResourceId(ctx, tx, authServerResource.Id)
	if err != nil {
		return nil, err
	}

	var accountPermission *record.Permission
	for idx, permission := range permissions {
		if permission.PermissionIdentifier == builtin.ManageAccountPermissionIdentifier {
			accountPermission = &permissions[idx]
			break
		}
	}

	if accountPermission == nil {
		return nil, errs.New("unable to find the account permission")
	}

	user.Permissions = []record.Permission{*accountPermission}

	return user, nil
}

// insertUser writes the user row and then its permissions on tx, each permission naming the id the
// user insert assigned.
func (uc *Creator) insertUser(ctx context.Context, tx *sql.Tx, user *record.User) error {

	if err := uc.database.CreateUser(ctx, tx, user); err != nil {
		return err
	}

	for _, permission := range user.Permissions {
		err := uc.database.CreateUserPermission(ctx, tx, &record.UserPermission{
			UserId:       user.Id,
			PermissionId: permission.Id,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

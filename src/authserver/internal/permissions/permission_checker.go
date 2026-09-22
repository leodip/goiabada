package permissions

import (
	"context"
	"database/sql"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/core/errs"
)

// permissionCheckerDatabase is what the permission check needs: the user's own grants and the
// ones their groups carry.
type permissionCheckerDatabase interface {
	GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]models.Permission, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*models.Resource, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GroupsLoadPermissions(ctx context.Context, tx *sql.Tx, groups []models.Group) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *models.User) error
	UserLoadPermissions(ctx context.Context, tx *sql.Tx, user *models.User) error
}

type PermissionChecker struct {
	database permissionCheckerDatabase
}

func NewPermissionChecker(database permissionCheckerDatabase) *PermissionChecker {
	return &PermissionChecker{
		database: database,
	}
}

func (pc *PermissionChecker) UserHasScopePermission(ctx context.Context, userId int64, scope string) (bool, error) {
	user, err := pc.database.GetUserById(ctx, nil, userId)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}

	err = pc.database.UserLoadPermissions(ctx, nil, user)
	if err != nil {
		return false, err
	}

	err = pc.database.UserLoadGroups(ctx, nil, user)
	if err != nil {
		return false, err
	}

	err = pc.database.GroupsLoadPermissions(ctx, nil, user.Groups)
	if err != nil {
		return false, err
	}

	parts := strings.Split(scope, ":")
	if len(parts) != 2 {
		return false, errs.New("invalid scope format: " + scope + ". expected format: resource_identifier:permission_identifier")
	}
	resourceIdentifier := parts[0]
	permissionIdentifier := parts[1]

	resource, err := pc.database.GetResourceByResourceIdentifier(ctx, nil, resourceIdentifier)
	if err != nil {
		return false, err
	}
	if resource == nil {
		return false, err
	}

	permissions, err := pc.database.GetPermissionsByResourceId(ctx, nil, resource.Id)
	if err != nil {
		return false, err
	}

	var perm *models.Permission
	for idx, p := range permissions {
		if p.PermissionIdentifier == permissionIdentifier {
			perm = &permissions[idx]
			break

		}
	}

	if perm == nil {
		return false, err
	}

	userHasPermission := false
	for _, userPerm := range user.Permissions {
		if userPerm.Id == perm.Id {
			userHasPermission = true
			break
		}
	}

	if userHasPermission {
		return true, nil
	}

	groupHasPermission := false
	for _, group := range user.Groups {
		for _, groupPerm := range group.Permissions {
			if groupPerm.Id == perm.Id {
				groupHasPermission = true
				break
			}
		}
	}

	if groupHasPermission {
		return true, nil
	}

	return false, nil
}

func (pc *PermissionChecker) FilterOutScopesWhereUserIsNotAuthorized(ctx context.Context, scope string, user *models.User) (string, error) {

	if user == nil {
		return "", errs.New("user is nil")
	}

	newScope := ""

	// filter
	scopes := strings.Split(scope, " ")
	for _, scopeStr := range scopes {

		if scopeStr == "" {
			continue
		}

		if oidc.IsIdTokenScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			newScope += scopeStr + " "
			continue
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			return "", errs.New("invalid scope format: " + scopeStr)
		} else {

			userHasPermission, err := pc.UserHasScopePermission(ctx, user.Id, scopeStr)
			if err != nil {
				return "", err
			}

			if userHasPermission {
				newScope += scopeStr + " "
			}
		}
	}

	return strings.TrimSpace(newScope), nil
}

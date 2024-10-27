package user

import (
	"strings"

	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oidc"
	"github.com/pkg/errors"
)

type PermissionChecker struct {
	database data.Database
}

func NewPermissionChecker(database data.Database) *PermissionChecker {
	return &PermissionChecker{
		database: database,
	}
}

func (pc *PermissionChecker) UserHasScopePermission(userId int64, scope string) (bool, error) {
	user, err := pc.database.GetUserById(nil, userId)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}

	err = pc.database.UserLoadPermissions(nil, user)
	if err != nil {
		return false, err
	}

	err = pc.database.UserLoadGroups(nil, user)
	if err != nil {
		return false, err
	}

	err = pc.database.GroupsLoadPermissions(nil, user.Groups)
	if err != nil {
		return false, err
	}

	parts := strings.Split(scope, ":")
	if len(parts) != 2 {
		return false, errors.WithStack(errors.New("invalid scope format: " + scope + ". expected format: resource_identifier:permission_identifier"))
	}
	resourceIdentifier := parts[0]
	permissionIdentifier := parts[1]

	resource, err := pc.database.GetResourceByResourceIdentifier(nil, resourceIdentifier)
	if err != nil {
		return false, err
	}
	if resource == nil {
		return false, err
	}

	permissions, err := pc.database.GetPermissionsByResourceId(nil, resource.Id)
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

func (pc *PermissionChecker) FilterOutScopesWhereUserIsNotAuthorized(scope string, user *models.User) (string, error) {

	if user == nil {
		return "", errors.WithStack(errors.New("user is nil"))
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
			return "", errors.WithStack(errors.New("invalid scope format: " + scopeStr))
		} else {

			userHasPermission, err := pc.UserHasScopePermission(user.Id, scopeStr)
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

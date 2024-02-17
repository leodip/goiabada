package core

import (
	"strings"

	"github.com/leodip/goiabada/internal/datav2"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

type PermissionChecker struct {
	database datav2.Database
}

func NewPermissionChecker(database datav2.Database) *PermissionChecker {
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

	parts := strings.Split(scope, ":")
	if len(parts) != 2 {
		return false, errors.New("invalid scope format: " + scope + ". expected format: resource_identifier:permission_identifier")
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

	var perm *entitiesv2.Permission
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

package core

import (
	"strings"

	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/pkg/errors"
)

type PermissionChecker struct {
	database *data.Database
}

func NewPermissionChecker(database *data.Database) *PermissionChecker {
	return &PermissionChecker{
		database: database,
	}
}

func (pc *PermissionChecker) UserHasScopePermission(userId uint, scope string) (bool, error) {
	user, err := pc.database.GetUserById(userId)
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

	resource, err := pc.database.GetResourceByResourceIdentifier(resourceIdentifier)
	if err != nil {
		return false, err
	}
	if resource == nil {
		return false, err
	}

	permissions, err := pc.database.GetResourcePermissions(resource.Id)
	if err != nil {
		return false, err
	}

	var perm *entities.Permission
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

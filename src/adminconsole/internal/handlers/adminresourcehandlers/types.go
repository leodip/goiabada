package adminresourcehandlers

import (
	"github.com/leodip/goiabada/core/api"
)

type GroupInfo struct {
	Id              int64
	GroupIdentifier string
	Description     string
	HasPermission   bool
}

type GroupsWithPermissionPageResult struct {
	Page     int
	PageSize int
	Total    int
	Groups   []GroupInfo
}

type UsersWithPermissionPageResult struct {
	Page     int
	PageSize int
	Total    int
	Users    []api.UserResponse
}

type Permission struct {
	Id          int64  `json:"id"`
	Identifier  string `json:"permissionIdentifier"`
	Description string `json:"description"`
}

type SavePermissionsInput struct {
	Permissions []Permission `json:"permissions"`
	ResourceId  int64        `json:"resourceId"`
	// ExpectedPermissions is the list as the page loaded it, passed through unchanged so the auth
	// server can refuse a save from an outdated page (#428).
	ExpectedPermissions []Permission `json:"expectedPermissions"`
}

type SavePermissionsResult struct {
	Success bool
	Error   string
}

type ValidatePermissionResult struct {
	Valid bool
	Error string
}

type UserResult struct {
	Id            int64
	Subject       string
	Username      string
	Email         string
	GivenName     string
	MiddleName    string
	FamilyName    string
	HasPermission bool
}

type SearchResult struct {
	Users []UserResult
}

// permissionIdsOf is the ids of the grants a handler read, sent as the save's loaded set when it
// grants or revokes one permission from that read: the auth server refuses the save with 409 when
// the stored grants changed in between, rather than let the whole set it writes undo that change.
// Never nil, so a user or group read with no grants sends [] and not the null the save refuses
// (#428).
func permissionIdsOf(permissions []api.PermissionResponse) []int64 {
	ids := make([]int64, 0, len(permissions))
	for _, p := range permissions {
		ids = append(ids, p.Id)
	}
	return ids
}

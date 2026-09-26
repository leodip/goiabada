package admingrouphandlers

import "github.com/leodip/goiabada/core/api"

type UserResult struct {
	Id           int64
	Subject      string
	Username     string
	Email        string
	GivenName    string
	MiddleName   string
	FamilyName   string
	AddedToGroup bool
}

type SearchResult struct {
	Users []UserResult
}

type PageResult struct {
	Page     int
	PageSize int
	Total    int
	Users    []api.UserResponse
}

type PermissionsPostInput struct {
	GroupId                int64   `json:"groupId"`
	AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
	// ExpectedPermissionIds is the set as the page loaded it, passed through unchanged so the auth
	// server can refuse a save from an outdated page (#428).
	ExpectedPermissionIds []int64 `json:"expectedPermissionIds"`
}

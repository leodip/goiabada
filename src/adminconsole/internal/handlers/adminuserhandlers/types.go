package adminuserhandlers

import "github.com/leodip/goiabada/core/api"

type Address struct {
	AddressLine1      string
	AddressLine2      string
	AddressLocality   string
	AddressRegion     string
	AddressPostalCode string
	AddressCountry    string
}

type GroupsPostInput struct {
	AssignedGroupsIds []int64 `json:"assignedGroupsIds"`
	// ExpectedGroupIds is the set as the page loaded it, passed through unchanged so the auth
	// server can refuse a save from an outdated page (#428).
	ExpectedGroupIds []int64 `json:"expectedGroupIds"`
}

type PermissionsPostInput struct {
	AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
	// ExpectedPermissionIds is the set as the page loaded it, passed through unchanged so the auth
	// server can refuse a save from an outdated page (#428).
	ExpectedPermissionIds []int64 `json:"expectedPermissionIds"`
}

type PageResult struct {
	Users    []api.UserResponse
	Total    int
	Query    string
	Page     int
	PageSize int
}

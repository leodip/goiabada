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
}

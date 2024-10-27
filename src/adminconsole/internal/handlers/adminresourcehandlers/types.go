package adminresourcehandlers

import (
	"github.com/leodip/goiabada/core/models"
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
	Users    []models.User
}

type Permission struct {
	Id          int64  `json:"id"`
	Identifier  string `json:"permissionIdentifier"`
	Description string `json:"description"`
}

type SavePermissionsInput struct {
	Permissions []Permission `json:"permissions"`
	ResourceId  int64        `json:"resourceId"`
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

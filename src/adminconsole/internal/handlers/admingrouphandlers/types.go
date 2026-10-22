package admingrouphandlers

import (
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

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

// grantedPermission is a permission a group holds, as the group's permissions tab lists it: the
// permission's id, which the save sends, and its scope, resource:permission, which the row shows.
type grantedPermission struct {
	Id    int64
	Scope string
}

// groupErrorFields maps the refusals a group's settings can meet to the field each is about: the
// identifier the API requires, validates and finds in use, and the description it bounds.
var groupErrorFields = map[string]string{
	i18n.ErrCodeGroupIdentifierRequired:  "groupIdentifier",
	i18n.ErrCodeGroupIdentifierInUse:     "groupIdentifier",
	i18n.ErrCodeIdentifierInvalidFormat:  "groupIdentifier",
	i18n.ErrCodeIdentifierTooShort:       "groupIdentifier",
	i18n.ErrCodeIdentifierTooLong:        "groupIdentifier",
	i18n.ErrCodeGroupDescriptionTooLong:  "description",
	i18n.ErrCodeDescriptionAngleBrackets: "description",
}

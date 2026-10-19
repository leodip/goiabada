package adminresourcehandlers

import (
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
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

// ValidatePermissionResult answers whether a permission the page adds or edits may be saved, and,
// when it may not, why and which of its two fields, permissionIdentifier or description, the page
// marks.
type ValidatePermissionResult struct {
	Valid bool
	Error string
	Field string
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

// permissionEntry is a permission as a resource's permissions tab draws it: the id the save sends
// back, the identifier and description, and whether it is one of the authserver resource's
// built-in permissions, which the tab draws without Edit or Remove.
type permissionEntry struct {
	Id          int64
	Identifier  string
	Description string
	BuiltIn     bool
}

// resourceErrorFields maps the refusals a resource's settings can meet to the field each is about:
// the identifier the API requires, validates and finds in use by a resource or a client, or fixed on
// the system resource, and the description it bounds.
var resourceErrorFields = map[string]string{
	i18n.ErrCodeResourceIdentifierRequired:         "resourceIdentifier",
	i18n.ErrCodeResourceIdentifierInUse:            "resourceIdentifier",
	i18n.ErrCodeResourceIdentifierNamesClient:      "resourceIdentifier",
	i18n.ErrCodeResourceSystemLevelIdentifierFixed: "resourceIdentifier",
	i18n.ErrCodeIdentifierInvalidFormat:            "resourceIdentifier",
	i18n.ErrCodeIdentifierTooShort:                 "resourceIdentifier",
	i18n.ErrCodeIdentifierTooLong:                  "resourceIdentifier",
	i18n.ErrCodeResourceDescriptionTooLong:         "description",
	i18n.ErrCodeDescriptionAngleBrackets:           "description",
}

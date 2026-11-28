package adminresourcehandlers

import (
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

type GroupInfo struct {
	ID              int64
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
	ID          int64  `json:"id"`
	Identifier  string `json:"permissionIdentifier"`
	Description string `json:"description"`
}

type SavePermissionsInput struct {
	Permissions []Permission `json:"permissions"`
	ResourceID  int64        `json:"resourceId"`
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

// UserResult is one user the user search found, as the grant-permission script reads it. Each field
// declares the key the script reads, so a field is respelled without moving its key (#482 decision 7).
// FullName is the name the script draws, written by core/personname; the three names it is written
// from stay under their keys for a page left open across an upgrade (#662 decision 2).
type UserResult struct {
	ID            int64  `json:"Id"`
	Subject       string `json:"Subject"`
	Username      string `json:"Username"`
	Email         string `json:"Email"`
	GivenName     string `json:"GivenName"`
	MiddleName    string `json:"MiddleName"`
	FamilyName    string `json:"FamilyName"`
	FullName      string `json:"FullName"`
	HasPermission bool   `json:"HasPermission"`
}

type SearchResult struct {
	Users []UserResult
}

// permissionIDsOf is the ids of the grants a handler read, sent as the save's loaded set when it
// grants or revokes one permission from that read: the auth server refuses the save with 409 when
// the stored grants changed in between, rather than let the whole set it writes undo that change.
// Never nil, so a user or group read with no grants sends [] and not the null the save refuses
// (#428).
func permissionIDsOf(permissions []api.PermissionResponse) []int64 {
	ids := make([]int64, 0, len(permissions))
	for _, p := range permissions {
		ids = append(ids, p.ID)
	}
	return ids
}

// permissionEntry is a permission as a resource's permissions tab draws it: the id the save sends
// back, the identifier and description, and whether it is one of the authserver resource's
// built-in permissions, which the tab draws without Edit or Remove.
type permissionEntry struct {
	ID          int64
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

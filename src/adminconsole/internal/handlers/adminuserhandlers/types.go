package adminuserhandlers

import (
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

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

// userNewErrorFields maps the refusals creating a user can meet to the field each is about: the
// email the API requires, validates and finds in use, the three names, and the password it requires
// when no setup email is sent and holds to the password policy.
var userNewErrorFields = map[string]string{
	i18n.ErrCodeUserEmailRequired:           "email",
	i18n.ErrCodeEmailRequired:               "email",
	i18n.ErrCodeEmailInvalidFormat:          "email",
	i18n.ErrCodeEmailTooLong:                "email",
	"EMAIL_TOO_LONG":                        "email",
	"EMAIL_ALREADY_EXISTS":                  "email",
	i18n.ErrCodeProfileGivenNameInvalid:     "givenName",
	i18n.ErrCodeProfileMiddleNameInvalid:    "middleName",
	i18n.ErrCodeProfileFamilyNameInvalid:    "familyName",
	i18n.ErrCodeUserPasswordRequired:        "password",
	i18n.ErrCodePasswordTooShort:            "password",
	i18n.ErrCodePasswordTooLong:             "password",
	i18n.ErrCodePasswordLowercaseRequired:   "password",
	i18n.ErrCodePasswordUppercaseRequired:   "password",
	i18n.ErrCodePasswordNumberRequired:      "password",
	i18n.ErrCodePasswordSpecialCharRequired: "password",
	i18n.ErrCodePasswordTooCommon:           "password",
	i18n.ErrCodePasswordTooCloseToAccount:   "password",
}

// groupMembership is a group a user belongs to, as the user's groups tab lists it: the group's id,
// which the save sends, and its identifier, which the row shows.
type groupMembership struct {
	Id              int64
	GroupIdentifier string
}

// grantedPermission is a permission a user holds, as the user's permissions tab lists it: the
// permission's id, which the save sends, and its scope, resource:permission, which the row shows.
type grantedPermission struct {
	Id    int64
	Scope string
}

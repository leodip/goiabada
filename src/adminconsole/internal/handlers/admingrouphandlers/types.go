package admingrouphandlers

import (
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// UserResult is one user the member search found, as the add-members script reads it. Each field
// declares the key the script reads, so a field is respelled without moving its key (#482 decision 7).
// FullName is the name the script draws, written by core/personname; the three names it is written
// from stay under their keys for a page left open across an upgrade (#662 decision 2).
type UserResult struct {
	ID           int64  `json:"Id"`
	Subject      string `json:"Subject"`
	Username     string `json:"Username"`
	Email        string `json:"Email"`
	GivenName    string `json:"GivenName"`
	MiddleName   string `json:"MiddleName"`
	FamilyName   string `json:"FamilyName"`
	FullName     string `json:"FullName"`
	AddedToGroup bool   `json:"AddedToGroup"`
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
	GroupID                int64   `json:"groupId"`
	AssignedPermissionsIDs []int64 `json:"assignedPermissionsIds"`
	// ExpectedPermissionIDs is the set as the page loaded it, passed through unchanged so the auth
	// server can refuse a save from an outdated page (#428).
	ExpectedPermissionIDs []int64 `json:"expectedPermissionIds"`
}

// grantedPermission is a permission a group holds, as the group's permissions tab lists it: the
// permission's id, which the save sends, and its scope, resource:permission, which the row shows.
type grantedPermission struct {
	ID    int64
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

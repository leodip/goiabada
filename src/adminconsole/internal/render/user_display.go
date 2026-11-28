package render

import (
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/personname"
)

// UserFullName is the display name of the three name parts the user response carries, as
// core/personname writes it.
//
// It lives here rather than on api.UserResponse because the API enforces nothing about a full
// name: it is three fields of the same response written for display, and the rule that writes
// them is core/personname's alone, which the auth server's name claim and emails also use, so a
// user reads the same in a token, an email and the console (#350, #662 decision 2).
func UserFullName(user *api.UserResponse) string {
	if user == nil {
		return ""
	}

	return personname.FullName(user.GivenName, user.MiddleName, user.FamilyName)
}

// SessionOwnerFullName is UserFullName over the owner projection the client sessions endpoint
// returns.
func SessionOwnerFullName(owner *api.SessionOwnerResponse) string {
	if owner == nil {
		return ""
	}

	return personname.FullName(owner.GivenName, owner.MiddleName, owner.FamilyName)
}

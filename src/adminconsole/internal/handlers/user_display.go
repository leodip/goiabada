package handlers

import (
	"strings"

	"github.com/leodip/goiabada/core/api"
)

// UserFullName assembles the display name from the three name parts the user response carries.
//
// It lives here rather than on api.UserResponse because the API enforces nothing about a full
// name: it is three fields of the same response joined for display, and putting it on the wire
// type would make it a third implementation beside models.User.GetFullName and the one in
// core/handlerhelpers that already says it mimics that method (#350).
func UserFullName(user *api.UserResponse) string {
	if user == nil {
		return ""
	}

	return fullName(user.GivenName, user.MiddleName, user.FamilyName)
}

// SessionOwnerFullName is UserFullName over the owner projection the client sessions endpoint
// returns. The two delegate to one join rather than spelling it out twice, because the comment
// above is about there being three implementations of this already and a fourth would be the
// one that quietly disagrees about a user with no middle name (#373).
func SessionOwnerFullName(owner *api.SessionOwnerResponse) string {
	if owner == nil {
		return ""
	}

	return fullName(owner.GivenName, owner.MiddleName, owner.FamilyName)
}

func fullName(givenName, middleName, familyName string) string {
	parts := make([]string, 0, 3)
	for _, part := range []string{givenName, middleName, familyName} {
		if len(part) > 0 {
			parts = append(parts, part)
		}
	}

	return strings.TrimSpace(strings.Join(parts, " "))
}

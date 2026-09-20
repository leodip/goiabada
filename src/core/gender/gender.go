// Package gender holds the gender vocabulary the OIDC "gender" claim is written from: the three
// values a profile may carry, the bound that says which integers name one, and the wire strings
// they serialize as. It is a fourth shared reference vocabulary beside core/countries,
// core/locales and core/timezones, and it is in core for the same reason those are: the auth
// server validates and stores a gender, the admin console renders and re-renders one, and both
// name the same three strings.
//
// It is its own package rather than a corner of a core/enums, because a package named for a Go
// construct is what invites the next unrelated enumeration in beside it, which is how core/enums
// came to hold six auth-server-only types before #385 took them to the domains that own them.
package gender

// Gender is the index a profile form submits and a token claim is rendered from. The zero value is
// GenderFemale rather than "unset": a user with no gender recorded carries the empty string, which
// is what String returns for anything outside the range below.
type Gender int

const (
	GenderFemale Gender = iota
	GenderMale
	GenderOther
)

// String returns the wire value, or "" for a Gender outside the declared range.
//
// Total rather than panicking on the slice index, because the value is converted from a
// caller-supplied integer at four production sites and only one of them range-checks first: the
// two admin console profile forms convert inside the callback that runs exactly when the API
// rejected the submitted value, so gender=3 answered 500 instead of re-rendering the form with its
// validation message. "" is already what every one of those sites writes for no gender, so the
// out-of-range answer is the one they were reaching for (#385).
func (g Gender) String() string {
	if g < GenderFemale || g > GenderOther {
		return ""
	}
	return []string{"female", "male", "other"}[g]
}

// IsGenderValid reports whether i names one of the three genders. It is the type's own bound and
// the only statement of which integers are legal, which is why a caller that has an int rather
// than a Gender asks here instead of comparing against GenderOther itself.
func IsGenderValid(i int) bool {
	return i >= 0 && i <= int(GenderOther)
}

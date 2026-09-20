package models

import "github.com/leodip/goiabada/core/errs"

// PasswordPolicy is the strength rule new passwords are held to, carried on
// settings.password_policy. It is here rather than in core because only the auth server checks a
// password, and rather than in accountvalidation, which applies it, because Settings scans the
// column straight into a typed field and internal/data imports nothing above models (#385).
type PasswordPolicy int

const (
	PasswordPolicyNone   PasswordPolicy = iota // at least 1 char
	PasswordPolicyLow                          // at least 6 chars
	PasswordPolicyMedium                       // at least 8 chars. Must contain: 1 uppercase, 1 lowercase and 1 number
	PasswordPolicyHigh                         // at least 10 chars. Must contain: 1 uppercase, 1 lowercase, 1 number and 1 special character/symbol
)

// String returns the wire value, or "" for a PasswordPolicy outside the declared range, rather
// than panicking on the slice index. Reachable here through the column: Settings scans
// password_policy into this type with no range check, so a value outside 0..3 in the database
// would have taken the settings page down. Nothing the application writes produces one (#385).
func (p PasswordPolicy) String() string {
	if p < PasswordPolicyNone || p > PasswordPolicyHigh {
		return ""
	}
	return []string{"none", "low", "medium", "high"}[p]
}

func PasswordPolicyFromString(s string) (PasswordPolicy, error) {
	switch s {
	case PasswordPolicyNone.String():
		return PasswordPolicyNone, nil
	case PasswordPolicyLow.String():
		return PasswordPolicyLow, nil
	case PasswordPolicyMedium.String():
		return PasswordPolicyMedium, nil
	case PasswordPolicyHigh.String():
		return PasswordPolicyHigh, nil
	}
	return PasswordPolicyNone, errs.New("invalid password policy " + s)
}

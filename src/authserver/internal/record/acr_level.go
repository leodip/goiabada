package record

import "github.com/leodip/goiabada/core/errs"

// ACRLevel is the authentication context class the ceremony reached, carried on Client's
// default_acr_level column and on user_sessions.acr_level.
//
// It is here rather than in core because only the auth server authenticates: the admin console
// names no ACR value in production. It is in record rather than in ceremony, where the rest of the
// ceremony vocabulary lives, because Client.DefaultACRLevel is typed with it and record imports
// nothing above itself (#385).
type ACRLevel string

const (
	ACRLevel1          ACRLevel = "urn:goiabada:level1"
	ACRLevel2Optional  ACRLevel = "urn:goiabada:level2_optional"
	ACRLevel2Mandatory ACRLevel = "urn:goiabada:level2_mandatory"
)

// String returns the acr value verbatim, including one this server does not recognize.
//
// Deliberately not made total the way the six integer enums in this change were: ACRLevel is
// string-backed, so there is no range to be outside of, and collapsing an unrecognized value to
// the empty string would change what a token carries. OIDC Core defines acr as a case-sensitive
// string whose meaning can be deployment-specific, and Priority already answers 0 for anything
// outside the three levels, which is how comparison stays safe without discarding the value
// (#385).
func (acrl ACRLevel) String() string {
	return string(acrl)
}

func ACRLevelFromString(s string) (ACRLevel, error) {
	switch s {
	case ACRLevel1.String():
		return ACRLevel1, nil
	case ACRLevel2Optional.String():
		return ACRLevel2Optional, nil
	case ACRLevel2Mandatory.String():
		return ACRLevel2Mandatory, nil
	}
	return "", errs.New("invalid ACR level " + s)
}

// acrPriority defines the security strength ordering of ACR levels.
// Higher values indicate stronger authentication requirements.
// This is the single source of truth for ACR level comparison.
var acrPriority = map[ACRLevel]int{
	ACRLevel1:          1, // Password only (single factor)
	ACRLevel2Optional:  2, // Password + OTP if user has OTP enabled
	ACRLevel2Mandatory: 3, // Password + OTP required (user must enroll)
}

// Priority returns the numeric priority of an ACR level.
// Higher values indicate stronger authentication.
// Returns 0 for unknown ACR levels.
func (acr ACRLevel) Priority() int {
	return acrPriority[acr]
}

// IsHigherThan returns true if this ACR level represents stronger
// authentication than the other ACR level.
func (acr ACRLevel) IsHigherThan(other ACRLevel) bool {
	return acr.Priority() > other.Priority()
}

// ACRMax returns the ACR level with higher security strength.
// If either level is unknown (priority 0), returns the known one.
// If both are unknown, returns the first argument.
func ACRMax(a, b ACRLevel) ACRLevel {
	if a.Priority() >= b.Priority() {
		return a
	}
	return b
}

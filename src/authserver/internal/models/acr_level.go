package models

import "github.com/leodip/goiabada/core/errs"

// AcrLevel is the authentication context class the ceremony reached, carried on Client's
// default_acr_level column and on user_sessions.acr_level.
//
// It is here rather than in core because only the auth server authenticates: the admin console
// names no ACR value in production. It is in models rather than in ceremony, where the rest of the
// ceremony vocabulary lives, because internal/data names it -- database_seeder.go writes a client
// with AcrLevel2Optional -- and data imports nothing above models (#385).
type AcrLevel string

const (
	AcrLevel1          AcrLevel = "urn:goiabada:level1"
	AcrLevel2Optional  AcrLevel = "urn:goiabada:level2_optional"
	AcrLevel2Mandatory AcrLevel = "urn:goiabada:level2_mandatory"
)

// String returns the acr value verbatim, including one this server does not recognize.
//
// Deliberately not made total the way the six integer enums in this change were: AcrLevel is
// string-backed, so there is no range to be outside of, and collapsing an unrecognized value to
// the empty string would change what a token carries. OIDC Core defines acr as a case-sensitive
// string whose meaning can be deployment-specific, and Priority already answers 0 for anything
// outside the three levels, which is how comparison stays safe without discarding the value
// (#385).
func (acrl AcrLevel) String() string {
	return string(acrl)
}

func AcrLevelFromString(s string) (AcrLevel, error) {
	switch s {
	case AcrLevel1.String():
		return AcrLevel1, nil
	case AcrLevel2Optional.String():
		return AcrLevel2Optional, nil
	case AcrLevel2Mandatory.String():
		return AcrLevel2Mandatory, nil
	}
	return "", errs.New("invalid ACR level " + s)
}

// acrPriority defines the security strength ordering of ACR levels.
// Higher values indicate stronger authentication requirements.
// This is the single source of truth for ACR level comparison.
var acrPriority = map[AcrLevel]int{
	AcrLevel1:          1, // Password only (single factor)
	AcrLevel2Optional:  2, // Password + OTP if user has OTP enabled
	AcrLevel2Mandatory: 3, // Password + OTP required (user must enroll)
}

// Priority returns the numeric priority of an ACR level.
// Higher values indicate stronger authentication.
// Returns 0 for unknown ACR levels.
func (acr AcrLevel) Priority() int {
	return acrPriority[acr]
}

// IsHigherThan returns true if this ACR level represents stronger
// authentication than the other ACR level.
func (acr AcrLevel) IsHigherThan(other AcrLevel) bool {
	return acr.Priority() > other.Priority()
}

// IsHigherOrEqualTo returns true if this ACR level represents
// authentication that is at least as strong as the other ACR level.
func (acr AcrLevel) IsHigherOrEqualTo(other AcrLevel) bool {
	return acr.Priority() >= other.Priority()
}

// Max returns the ACR level with higher security strength.
// If either level is unknown (priority 0), returns the known one.
// If both are unknown, returns the first argument.
func AcrMax(a, b AcrLevel) AcrLevel {
	if a.Priority() >= b.Priority() {
		return a
	}
	return b
}

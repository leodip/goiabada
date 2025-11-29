package enums

import "github.com/pkg/errors"

type TokenType int

const (
	TokenTypeId TokenType = iota
	TokenTypeBearer
	TokenTypeRefresh
)

func (tt TokenType) String() string {
	return []string{"ID", "Bearer", "Refresh"}[tt]
}

type AcrLevel string

const (
	AcrLevel1          AcrLevel = "urn:goiabada:level1"
	AcrLevel2Optional  AcrLevel = "urn:goiabada:level2_optional"
	AcrLevel2Mandatory AcrLevel = "urn:goiabada:level2_mandatory"
)

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
	return "", errors.WithStack(errors.New("invalid ACR level " + s))
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

type AuthMethod int

const (
	AuthMethodPassword AuthMethod = iota
	AuthMethodOTP
)

func (am AuthMethod) String() string {
	return []string{"pwd", "otp"}[am]
}

type Gender int

const (
	GenderFemale Gender = iota
	GenderMale
	GenderOther
)

func (g Gender) String() string {
	return []string{"female", "male", "other"}[g]
}

func IsGenderValid(i int) bool {
	return i >= 0 && i <= int(GenderOther)
}

type PasswordPolicy int

const (
	PasswordPolicyNone   PasswordPolicy = iota // at least 1 char
	PasswordPolicyLow                          // at least 6 chars
	PasswordPolicyMedium                       // at least 8 chars. Must contain: 1 uppercase, 1 lowercase and 1 number
	PasswordPolicyHigh                         // at least 10 chars. Must contain: 1 uppercase, 1 lowercase, 1 number and 1 special character/symbol
)

func (p PasswordPolicy) String() string {
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
	return PasswordPolicyNone, errors.WithStack(errors.New("invalid password policy " + s))
}

type KeyState int

const (
	KeyStateCurrent KeyState = iota
	KeyStatePrevious
	KeyStateNext
)

func (ks KeyState) String() string {
	return []string{"current", "previous", "next"}[ks]
}

func KeyStateFromString(s string) (KeyState, error) {
	switch s {
	case KeyStateCurrent.String():
		return KeyStateCurrent, nil
	case KeyStatePrevious.String():
		return KeyStatePrevious, nil
	case KeyStateNext.String():
		return KeyStateNext, nil
	}
	return KeyStateCurrent, errors.WithStack(errors.New("invalid key state " + s))
}

type SMTPEncryption int

const (
	SMTPEncryptionNone SMTPEncryption = iota
	SMTPEncryptionSSLTLS
	SMTPEncryptionSTARTTLS
)

func (se SMTPEncryption) String() string {
	return []string{"none", "ssltls", "starttls"}[se]
}

func SMTPEncryptionFromString(s string) (SMTPEncryption, error) {
	// Treat empty string as "none" for backward compatibility
	if s == "" {
		return SMTPEncryptionNone, nil
	}
	switch s {
	case SMTPEncryptionNone.String():
		return SMTPEncryptionNone, nil
	case SMTPEncryptionSSLTLS.String():
		return SMTPEncryptionSSLTLS, nil
	case SMTPEncryptionSTARTTLS.String():
		return SMTPEncryptionSTARTTLS, nil
	}
	return SMTPEncryptionNone, errors.WithStack(errors.New("invalid SMTP encryption " + s))
}

type ThreeStateSetting int

const (
	ThreeStateSettingOn ThreeStateSetting = iota
	ThreeStateSettingOff
	ThreeStateSettingDefault
)

func (tss ThreeStateSetting) String() string {
	return []string{"on", "off", "default"}[tss]
}

func ThreeStateSettingFromString(s string) (ThreeStateSetting, error) {
	switch s {
	case ThreeStateSettingOn.String():
		return ThreeStateSettingOn, nil
	case ThreeStateSettingOff.String():
		return ThreeStateSettingOff, nil
	case ThreeStateSettingDefault.String():
		return ThreeStateSettingDefault, nil
	}
	return ThreeStateSettingOn, errors.WithStack(errors.New("invalid three state setting " + s))
}

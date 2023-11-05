package enums

import "errors"

type contextKey int

const (
	ContextKeyRequestId contextKey = iota
)

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
	AcrLevel1 AcrLevel = "urn:goiabada:pwd"                // password
	AcrLevel2 AcrLevel = "urn:goiabada:pwd:otp_ifpossible" // password + otp if enabled
	AcrLevel3 AcrLevel = "urn:goiabada:pwd:otp_mandatory"  // password + mandatory otp
)

func (acrl AcrLevel) String() string {
	return string(acrl)
}

func AcrLevelFromString(s string) (AcrLevel, error) {
	switch s {
	case AcrLevel1.String():
		return AcrLevel1, nil
	case AcrLevel2.String():
		return AcrLevel2, nil
	case AcrLevel3.String():
		return AcrLevel3, nil
	}
	return "", errors.New("invalid ACR level " + s)
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
	return PasswordPolicyNone, errors.New("invalid password policy " + s)
}

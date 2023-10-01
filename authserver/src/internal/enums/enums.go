package enums

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

type AcrLevel int

const (
	AcrLevel0 AcrLevel = iota // session cookie
	AcrLevel1                 // password
	AcrLevel2                 // password + otp if enabled
	AcrLevel3                 // password + mandatory otp
)

func (acrl AcrLevel) String() string {
	return []string{"0", "1", "2", "3"}[acrl]
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

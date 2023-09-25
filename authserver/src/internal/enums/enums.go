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
	AcrLevel0 AcrLevel = iota
	AcrLevel1
	AcrLevel2
)

func (acrl AcrLevel) String() string {
	return []string{"0", "1", "2"}[acrl]
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
	return i >= 0 && i < int(GenderOther)
}

package oidc

// AuthMethod is one authentication method in the amr claim's vocabulary (OIDC Core 1.0 section 2).
// Two places produce one: the ceremony's accumulator, AuthContext.AuthMethods, and the password
// grant, which mints its tokens with pwd. It is here rather than in ceremony because #385's reason
// for putting it there, that the ceremony was the one collector, stopped holding when the password
// grant began naming it, and issuance should not import the ceremony for a claim value (#437).
type AuthMethod int

const (
	AuthMethodPassword AuthMethod = iota
	AuthMethodOTP
)

// String returns the amr value, or "" for an AuthMethod outside the declared range, rather than
// panicking on the slice index. Not reachable from any int conversion today -- both call sites
// name a constant -- but the guard goes on the type so a value read back from a session row cannot
// step on it (#385).
func (am AuthMethod) String() string {
	if am < AuthMethodPassword || am > AuthMethodOTP {
		return ""
	}
	return []string{"pwd", "otp"}[am]
}

package ceremony

// AuthMethod is one factor a ceremony completed, rendered into the amr claim. It is here beside
// AuthContext.AuthMethods, the space-separated accumulator that is the only thing in the tree that
// collects one, and out of core because the admin console authenticates nobody (#385).
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

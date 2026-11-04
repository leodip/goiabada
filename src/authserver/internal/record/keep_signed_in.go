package record

// KeepSignedIn is the "Keep users signed in after the browser closes" setting, carried on
// settings.keep_signed_in as its lower-case wire value, which is also the admin API's keepSignedIn
// (#743 decision 4). It decides whether the auth server's signed-in cookie outlives the browser.
type KeepSignedIn string

const (
	// KeepSignedInAlways keeps every user signed in after the browser closes.
	KeepSignedInAlways KeepSignedIn = "always"
	// KeepSignedInAsk lets each user choose on the password page. It is the default, seeded on a new
	// deployment and written by migration 000081 on an upgraded one (#743 decision 3).
	KeepSignedInAsk KeepSignedIn = "ask"
	// KeepSignedInNever ends every user's signed-in cookie with the browser.
	KeepSignedInNever KeepSignedIn = "never"
)

// IsValid reports whether k is one of the three modes.
func (k KeepSignedIn) IsValid() bool {
	switch k {
	case KeepSignedInAlways, KeepSignedInAsk, KeepSignedInNever:
		return true
	}
	return false
}

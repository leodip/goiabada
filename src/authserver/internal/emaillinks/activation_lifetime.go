package emaillinks

import "time"

// ActivationCodeLifetime bounds how long an activation code stays usable after registration
// issues it.
//
// Consulted on the activation link's FIRST hop only, where the emailed code arrives. The two
// steps after the redirect, the form and its POST, are bounded by the marker's own window
// instead, which starts when the code was validated, so someone clicking at 4:59 still has five
// minutes to choose a password. That is the same rule the reset flow states in
// isForgotPasswordCodeExpired (#112 decision 7).
const ActivationCodeLifetime = 5 * time.Minute

// PreRegistrationLifetime is how long a pending registration can complete after its link was
// sent: the code's lifetime, within which the link can be followed, then the marker's fresh
// window, within which the password form it leads to can be submitted. Past it the registration
// is dead (#207 decision 6).
//
// The sum of the two constants rather than a number of its own, so a change to either moves it,
// and so nothing that replaces or sweeps a dead row can disagree with the activation about which
// rows can still complete.
const PreRegistrationLifetime = ActivationCodeLifetime + linkMarkerLifetime

// PreRegistrationDeadBefore is the one definition of a dead pending registration: one whose code
// was issued before the instant it returns can no longer complete, and every reader treats it as
// absent (#207 decision 6). A row issued exactly at it is still live, as a code or a marker
// expiring exactly now still is.
func PreRegistrationDeadBefore(now time.Time) time.Time {
	return now.Add(-PreRegistrationLifetime)
}

// IsPreRegistrationDead reports whether a pending registration whose code was issued at
// codeIssuedAt is dead at now, by PreRegistrationDeadBefore. A row with no issued-at reads as the
// zero time and so as dead, which is what it is: its code was never usable, as the activation's
// own expiry check fails closed on it.
func IsPreRegistrationDead(codeIssuedAt time.Time, now time.Time) bool {
	return codeIssuedAt.Before(PreRegistrationDeadBefore(now))
}

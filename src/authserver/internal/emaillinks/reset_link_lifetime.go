package emaillinks

import "time"

// ResetLinkLifetime bounds how long a password reset code stays usable after forgot password
// issues it for an account that has a password.
//
// Here rather than beside the reset that reads it, since the admin API's preview of the password
// reset link email says how long the link lasts too (#818 decision 11), and the two must not drift.
const ResetLinkLifetime = 5 * time.Minute

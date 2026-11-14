package emaillinks

import "time"

// SetupLinkLifetime bounds how long the link of a new user's setup email stays usable: the reset
// code it carries, while the account has no password. The new user reads it when they read mail,
// not within minutes. Five minutes left them a link dead before they saw it, and nothing to recover
// with, since Forgot password? sends nothing to an unverified address and nothing sends the setup
// link again (#542). Until a password is set, a leaked link has no password to replace.
//
// Here rather than beside the reset that reads it, since the admin API sends the email and says
// how long the link lasts (#818 decision 4), and the two must not drift.
const SetupLinkLifetime = 24 * time.Hour

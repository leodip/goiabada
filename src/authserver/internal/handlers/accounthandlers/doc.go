// Package accounthandlers serves the account pages a visitor reaches without a session: the
// self-registration page and the activation link it emails when the settings require a verified
// address, and the forgot-password page and the reset link it emails. The two emailed links share
// one shape (a first hop that validates the code and marks the session, then a clean hop that reads
// the marker alone) and one refusal rule: every refusal renders one page and is audited with its
// reason. All are browser pages the auth server renders; the account self-service API a signed-in
// user calls is apihandlers'.
package accounthandlers

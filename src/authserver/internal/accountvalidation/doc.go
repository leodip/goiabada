// Package accountvalidation holds the rules a user's account fields are held to: email, password,
// profile, address and phone, and the angle-bracket refusal, beside the App name's rule, which the
// general settings save and the first start share. Each validator returns a localized error a
// handler can show as it stands, and reads nothing from the request: the caller passes what the
// rule needs, the password policy included. The protocol's own request validation is in
// protocolvalidation.
package accountvalidation

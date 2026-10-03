// Package handlers serves the auth server's browser and protocol endpoints: the sign-in ceremony
// from /auth/authorize through the password, OTP, consent and issue steps, the token, userinfo,
// JWKS and discovery endpoints, dynamic client registration, RP-initiated logout, and the public
// pages and files beside them. The admin and account APIs are apihandlers', and the account pages a
// visitor reaches without a session are accounthandlers'; neither imports this package.
//
// A handler is handed one writer, PageRenderer or JSONWriter, so an endpoint a client parses as
// JSON cannot answer an HTML page (#435). Every ceremony step after /auth/authorize first checks
// that the request names the sign-in the browser holds and that the sign-in is in a state the step
// accepts (#246, #437). A credential is read from the form body alone, never from the URL query
// (#202), and a failed authorization request from a browser with no session is not redirected to
// the client until a password has been verified (#213). Each handler names the database operations
// it calls in an unexported port beside it (#386).
package handlers

// Package accounthandlers serves the account pages a signed-in user manages their own account on,
// under /account: profile, email and its verification, address, phone, picture, password, OTP,
// consents and sessions, and the sign-out. Each page reads and writes through the auth server's
// account API with the user's own token, which carries the authserver:manage-account permission
// the routes require; nothing here reaches another user's account.
//
// A handler answers a page or JSON, never both, and passes an account API failure to render's
// classifiers. HttpHelper is declared here rather than imported from the parent handlers package,
// and each handler names the API methods it calls in an unexported port beside it (#386, #440).
package accounthandlers

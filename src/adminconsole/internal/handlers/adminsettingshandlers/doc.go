// Package adminsettingshandlers serves the admin pages for the auth server's settings, under
// /admin/settings: general, sessions, tokens, email and its test message, UI theme, signing keys
// and their rotation and revocation, and the audit log switches and viewer. Every page reads and
// writes through the auth server's admin API with the administrator's token, which carries the
// authserver:manage permission the routes require.
//
// A handler answers a page or JSON, never both, and passes an admin API failure to render's
// classifiers. A save that changes what the public settings report invalidates the console's
// cached copy through SettingsInvalidator, so the next page renders with the new values rather
// than waiting out the cache. HttpHelper is declared here rather than imported from the parent
// handlers package, and each handler names the API methods it calls in an unexported port beside
// it (#386, #440).
package adminsettingshandlers

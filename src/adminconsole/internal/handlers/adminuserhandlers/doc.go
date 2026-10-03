// Package adminuserhandlers serves the admin pages for users, under /admin/users: the list, a new
// user, and each user's details, profile, email, phone, address, picture, authentication,
// attributes, groups, permissions, consents, sessions and deletion. Every page reads and writes
// through the auth server's admin API with the administrator's token, which carries the
// authserver:manage permission the routes require.
//
// A handler answers a page or JSON, never both, and passes an admin API failure to render's
// classifiers. A save keeps the page and search of the user list it was reached from in the URL it
// returns to, so the list reopens where the administrator left it (#426). The groups and
// permissions saves send the list as the page loaded it, so the API refuses it when another save
// got there first (#428). HttpHelper is declared here rather than imported from the parent handlers
// package, and each handler names the API methods it calls in an unexported port beside it (#386,
// #440).
package adminuserhandlers

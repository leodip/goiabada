// Package handlers serves the admin console's pages that belong to no area: the home page, the
// sign-in's callback, the session-ended and unauthorized pages, the 404 page, the health check, and
// the permissions lookup the permission pickers call. The pages of each area are in the child
// packages, accounthandlers and the five admin<area>handlers, and a child imports nothing of this
// package: each declares its own writer port, so it compiles against nothing above it (#440).
//
// The rules every handler here and below keeps are the module's: a handler answers a page or JSON,
// never both, and an admin API failure reaches render's classifiers rather than being answered by
// the handler itself (#279). Each handler names the admin API methods it calls in an unexported
// port beside it, so a test fake missing one fails to compile (#386).
package handlers

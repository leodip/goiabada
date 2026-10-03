// Package adminresourcehandlers serves the admin pages for resources and the permissions they
// declare, under /admin/resources: the list, a new resource, and each resource's settings,
// permissions, the users and groups holding one of them, and deletion. Every page reads and writes
// through the auth server's admin API with the administrator's token, which carries the
// authserver:manage permission the routes require.
//
// A handler answers a page or JSON, never both, and passes an admin API failure to render's
// classifiers. An identifier is checked here with the same rule the auth server applies,
// core/inputvalidation's, named through IdentifierValidator, so a page refuses what the API would.
// The permissions save sends the list as the page loaded it, so the API refuses it when another
// save got there first (#428). HttpHelper is declared here rather than imported from the parent
// handlers package, and each handler names the API methods it calls in an unexported port beside
// it (#386, #440).
package adminresourcehandlers

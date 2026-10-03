// Package admingrouphandlers serves the admin pages for groups, under /admin/groups: the list, a
// new group, and each group's settings, attributes, members, permissions and deletion. Every page
// reads and writes through the auth server's admin API with the administrator's token, which
// carries the authserver:manage permission the routes require.
//
// A handler answers a page or JSON, never both, and passes an admin API failure to render's
// classifiers. The permissions save sends the list as the page loaded it, so the API refuses it
// when another save got there first (#428). HttpHelper is declared here rather than imported from
// the parent handlers package, and each handler names the API methods it calls in an unexported
// port beside it (#386, #440).
package admingrouphandlers

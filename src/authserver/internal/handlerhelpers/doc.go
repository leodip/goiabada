// Package handlerhelpers renders this application's pages and writes its protocol endpoints' JSON
// answers: the template parse, the bind map every page reads, the 404 and 500 pages, the RFC 6749
// JSON error writer, and the two request-parameter readers logout and the CSRF middleware share.
//
// This renderer is one of two. The admin console has its own copy in
// adminconsole/internal/handlerhelpers, and about 238 of the lines here are the same in both.
//
// The duplication is deliberate and is what owning a renderer costs. The single copy this
// replaced lived in core and hid two things only one binary ever reached: the loggedInUser and
// isAdmin page data, which no auth server template binds, and a template FuncMap of which this
// application calls four entries out of twenty-two. Passing either in as a parameter would have
// left one shared package behaving differently for its two callers, which is the shape #385
// exists to remove. Drift between the two copies is the accepted price; a change worth making in
// one is worth reading the other for (#385).
package handlerhelpers

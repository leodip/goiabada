// Package handlerhelpers renders this application's pages: the template parse, the bind map every
// page reads, the 404 and 500 pages, and the JSON writers the AJAX handlers answer with.
//
// It belongs to the admin console rather than to the shared kernel because half of what it does is
// this console's alone. The bind map carries loggedInUser and isAdmin, read off the browser
// session's ID token, and no auth server template binds either; the template FuncMap has
// twenty-two entries where that server's templates call four, five of the rest being predicates
// over this console's own URL paths. The auth server has its own copy in
// authserver/internal/handlerhelpers, and the roughly 238 lines the two share can drift: that is
// what owning a renderer costs, and it is cheaper than one package behaving two ways for its two
// callers (#385).
package handlerhelpers

// Package render renders the admin console's pages and answers its AJAX handlers. A Renderer,
// built by New over the template file system, parses a page with its layout and this console's
// template functions, binds the data every page reads, the signed-in administrator's loggedInUser
// and isAdmin among it, renders the 404 and 500 pages, and writes JSON. HandleAPIError,
// HandleAPIErrorWithCallback and HandleAPIErrorJSON turn an admin API failure into one of those
// answers, and JSONNotFound, JSONBadRequestBody and JSONConflict answer the console's own refusals.
//
// A few helpers here render nothing: the display-name join, the session and consent rows, and
// ParseProfileForm and EchoProfileForm. They live here because the pages that render them are in
// more than one handler package, the account pages and the admin user pages, and a child handler
// package takes them from here rather than from its parent or a sibling (#440).
//
// The auth server has its own render package, and much of the two is the same code. Each
// application owns its renderer because the shared one put this console's page data and template
// functions into a binary that never used them; a change worth making in one copy is worth reading
// the other for (#385).
package render

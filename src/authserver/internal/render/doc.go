// Package render renders the auth server's pages and writes its protocol endpoints' JSON answers.
// A Renderer, built by New over the template file system, parses a page with its layout and the
// four template functions this application calls, binds the data every page reads, renders the 404
// and 500 pages, and writes the RFC 6749 section 5.2 JSON error and any other JSON body.
//
// Two helpers here render nothing: QueryOrFormValue and LookupQueryOrFormValue, which read a
// parameter from the URL query and then from the form body. They live here because RP-initiated
// logout and the CSRF middleware's logout exemption must read id_token_hint the same way, and one
// implementation is what keeps the two readings from drifting (#109).
//
// The admin console has its own render package, and much of the two is the same code. Each
// application owns its renderer because the shared one put admin page data and template functions
// into a binary that never used them; a change worth making in one copy is worth reading the
// other for (#385).
package render

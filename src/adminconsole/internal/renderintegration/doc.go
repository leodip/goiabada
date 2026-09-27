// Package renderintegration executes the admin console's pages through the real renderer: the
// production HttpHelper over the embedded template FS, its funcmap and the full layout, in pt-BR,
// with the runtime data types the handlers bind. It is the regression guard for the class of bug
// where a template references a field its data does not carry (the phone dropdown reading .Alpha2
// off a DTO that lacked it, which answered 500 in production and was invisible to handler tests,
// whose RenderTemplate is a mock handed a bind map), and for everything else only HTML can show:
// escaping of attacker-chosen values, the list a page sends back with a save, localized dates.
//
// Every render asserts that <html lang> carries the active locale and that no raw catalog key
// leaks into visible HTML. The suite covers every page family: the account self-service pages
// (phone, address, profile, OTP, sessions, consents, the logout form); admin clients (list,
// redirect URIs, web origins, permissions, sessions); users (list and paginator, details, delete,
// permissions, groups, sessions, consents, profile); groups and resources; settings (the audit
// log viewer, signing keys); and the layout, the menu label and the index, 404 and sign-in error
// pages.
//
// It exports nothing and nothing imports it; the name says it is a suite rather than a helper,
// which is what a -test suffix, as in handlertest, marks. The integration tier drives the auth
// server alone, so this is the only place the console's pages are rendered end to end (#431).
package renderintegration

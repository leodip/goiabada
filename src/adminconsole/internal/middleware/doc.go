// Package middleware is the admin console's own request middleware, mounted by internal/server:
// JWT, whose SessionHandler validates the administrator's stored tokens on every request, refreshes
// them when due and puts them on the context through reqctx, and whose RequiresScope sends a
// browser without the scope a route needs to sign in or to the unauthorized page; SettingsCache,
// which puts the auth server's public settings on the context; and LocaleFromJWT, which refines the
// page locale from the ID token's claim. The middleware both processes mount is in core/httpmw.
//
// Every token is checked by oauthclient's parser, which decides the issuer and audience itself, so
// nothing here compares an issuer of its own, and nothing from a refresh is stored before the
// parser has accepted it (#427).
package middleware

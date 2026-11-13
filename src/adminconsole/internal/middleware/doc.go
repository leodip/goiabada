// Package middleware is the admin console's own request middleware, mounted by internal/server:
// JWT, whose SessionHandler validates the administrator's stored tokens on every request, refreshes
// them when due and puts them on the context through reqctx, and whose RequiresScope sends a
// browser without the scope a route needs to sign in or to the unauthorized page, or answers a page
// script's request whose sign-in has ended with the session-ended JSON; SettingsCache,
// which puts the auth server's public settings on the context; and PageLanguage, which draws a
// signed-in user's pages in the page language their session holds a copy of; and SafeMode, which
// puts on the context whether the request is in safe mode, by its console session or its URL. The
// middleware both
// processes mount is in core/httpmw.
//
// Every token is checked by oauthclient's parser, which decides the issuer and audience itself, so
// nothing here compares an issuer of its own, and nothing from a refresh is stored before the
// parser has accepted it (#427).
package middleware

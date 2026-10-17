package handlers

import (
	"context"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging"
)

// checkRedirectURIEmittable is the last-resort assertion in front of every place this package
// writes a client's redirect URI somewhere a user agent will follow it: a Location header, the
// action of the auto-submitting form_post form, or the fragment the implicit flow delivers tokens
// in. It answers nil when urlmatch.IsAbsoluteRedirectURI accepts the value and an error when it does
// not.
//
// # Why this exists when nothing can reach it
//
// It is unreachable by construction, and that is the point rather than an argument against it. The
// authorization endpoint applies the same predicate to the requested URI before matching it, the
// admin API and dynamic registration apply it at intake, and the logout endpoint applies it before
// building its redirect, so a value arriving here has already been through a gate. What this turns
// into a property tests can enforce is that EVERY emission is downstream of one: a later refactor
// that moves a gate, adds a fifth way to reach an emitter, or reorders a handler is caught by a unit
// test in this package rather than by an incident report. A comment saying the same thing would only
// claim it (#122).
//
// The two code and token emitters return this error and their callers answer 500, so an undelivered
// authorization code simply expires and implicit tokens are never handed over. The error redirect
// has somewhere better to go and treats a non-nil answer as a signal rather than a failure: it falls
// through to the refusal interstitial (#108), which tells the user where the client wanted to send them.
//
// # What the log line carries, and what it must not
//
// The site, and never the URI. A value that reaches here is by definition one that no gate approved,
// which makes it unbounded caller-controlled input written into the server's log, the class #159
// closed. An operator reading this line knows the emitter is being fed something it must not emit;
// the offending value is on the client's page in the admin console, which is a bounded lookup rather
// than an unbounded write.
func checkRedirectURIEmittable(ctx context.Context, site string, redirectURI string) error {
	if urlmatch.IsAbsoluteRedirectURI(redirectURI) {
		return nil
	}

	slog.ErrorContext(ctx, "refusing to emit an authorization response to a redirect URI that is not an absolute URI, so a gate upstream of this emitter was bypassed",
		"site", site)

	return errs.New("refusing to emit an authorization response to a redirect URI that is not an absolute URI, at " + site)
}

// warnInsecureHTTPRedirect writes the record #590 asks for when an authorization response is about
// to travel to a redirect URI that is plain http off the loopback interface, which
// urlmatch.IsInsecureHTTPRedirectURI decides: the same rule the admin API and dynamic registration
// refuse at intake, so the URIs this warns about are exactly those intake would no longer accept.
// Such a URI still reaches /auth/issue by design, either stored before intake began refusing the
// shape, so a running integration survives an upgrade, or seeded for the admin console's own client
// from a plain-http GOIABADA_ADMINCONSOLE_BASEURL, which no intake check reads. Nothing else tells
// anyone that the code or the tokens it carries are leaving in the clear.
//
// slog.Warn and not Error, because the emission is correct: the URI is registered, the gates
// passed it, and an auth server whose error log carries expected events has no error log left.
//
// The record carries the site, the client's identifier and the URI, so an operator knows which of
// a client's redirect URIs to replace. Neither is a value the request chose: the identifier names
// the client the ceremony was issued to, minted by dynamic registration or validated by the admin
// API, and the URI is one the authorization endpoint matched against that client's registrations,
// at most record.RedirectURIMaxBytes. Both still go through logging.FieldForLog, which bounds and
// escapes them, as the token endpoint writes its client_identifier.
//
// The remedy differs for the admin console's client, because the console sends whatever
// GOIABADA_ADMINCONSOLE_BASEURL says: removing its http URIs before the console is served over
// https locks every administrator out, and intake refuses to add them back.
//
// Called immediately before the emitters, never after: the record names a response the handler
// is in the act of issuing, and a refusal or a failure upstream of the call sites never reaches
// it.
func warnInsecureHTTPRedirect(ctx context.Context, site, clientIdentifier, redirectURI string) {
	if !urlmatch.IsInsecureHTTPRedirectURI(redirectURI) {
		return
	}

	remedy := "add the https redirect URI the client will send on the client's page in the admin console, " +
		"move the client to it, and only then remove the http one, which cannot be added back once removed"
	if clientIdentifier == builtin.AdminConsoleClientIdentifier {
		remedy = "this is the admin console's own client: add the console's https base URL and that URL followed by " +
			"/auth/callback on this client's page, then serve the console over https with " +
			"GOIABADA_ADMINCONSOLE_BASEURL set to that URL, and only then remove the http URIs; " +
			"removed first, the console cannot sign in and they cannot be added back"
	}

	slog.WarnContext(ctx, "an authorization response is going to a redirect URI that uses plain http off the loopback interface, so the code or the tokens it carries travel to the client unencrypted",
		"site", site,
		"client_identifier", logging.FieldForLog(clientIdentifier),
		"redirect_uri", logging.FieldForLog(redirectURI),
		"remedy", remedy)
}

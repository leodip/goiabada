package handlers

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/leodip/goiabada/authserver/internal/urlmatch"
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

// insecureHTTPRedirectURI reports whether raw is an http URI on a host other than the loopback
// interface: the shape RFC 9700 section 2.6 forbids as a redirect URI, with the loopback half of
// the exception RFC 8252 section 7.3 keeps open for native and MCP clients, which urlmatch's
// IsLoopbackHost answers here.
//
// A value that does not parse answers false, and so does every non-http scheme, because this is
// a warning's predicate and not a gate: what is refused belongs to checkRedirectURIEmittable and
// the intake gates upstream of it, and this only decides which emissions are worth a line in the
// log. A hostless http URI answers true on its own, so a caller that ever skips its gate still
// warns. The scheme is folded to lower case by the parse, so HTTP and http are the same rule.
func insecureHTTPRedirectURI(raw string) bool {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" {
		return false
	}
	return !urlmatch.IsLoopbackHost(parsed.Host)
}

// warnInsecureHTTPRedirect writes the record #590 asks for when an authorization response is about
// to travel to a redirect URI that is plain http off the loopback interface. A URI stored before
// intake began refusing the shape keeps working at /auth/authorize by design, so a running
// integration survives an upgrade, and until that row is re-registered over https nothing tells
// anyone that the code or the tokens it carries are leaving in the clear.
//
// slog.Warn and not Error, because the emission is correct: the URI is registered, the gates
// passed it, and an auth server whose error log carries expected events has no error log left.
//
// The site and the client's identifier, and never the URI, for the same reason
// checkRedirectURIEmittable's log line refuses it: a redirect URI is caller-chosen input, so
// writing it here is an unbounded write into the server's log, the class #159 closed. The
// identifier is as caller-chosen as the URI, a dynamic registration names its own, so it goes
// through logging.FieldForLog like the token endpoint's client_identifier does. An operator
// reading this line finds the offending row on the client's page in the admin console, which is
// a bounded lookup rather than an unbounded write.
//
// Called immediately before the emitters, never after: the record names a response the handler
// is in the act of issuing, and a refusal or a failure upstream of the call sites never reaches
// it.
func warnInsecureHTTPRedirect(ctx context.Context, site, clientIdentifier, redirectURI string) {
	if !insecureHTTPRedirectURI(redirectURI) {
		return
	}

	slog.WarnContext(ctx, "an authorization response is going to a redirect URI that uses plain http off the loopback interface, so the code or the tokens it carries travel to the client unencrypted",
		"site", site,
		"client_identifier", logging.FieldForLog(clientIdentifier),
		"remedy", "the URI was stored before plain http began being refused at intake and still receives responses by design; re-register it over https, or remove it on the client's page in the admin console")
}

package handlers

import (
	"log/slog"

	"github.com/leodip/goiabada/core/urlutil"
	"github.com/pkg/errors"
)

// checkRedirectURIEmittable is the last-resort assertion in front of every place this package
// writes a client's redirect URI somewhere a user agent will follow it: a Location header, the
// action of the auto-submitting form_post form, or the fragment the implicit flow delivers tokens
// in. It answers nil when urlutil.IsAbsoluteRedirectURI accepts the value and an error when it does
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
// through to the interstitial #108 built, which tells the user where the client wanted to send them.
//
// # What the log line carries, and what it must not
//
// The site, and never the URI. A value that reaches here is by definition one that no gate approved,
// which makes it unbounded caller-controlled input written into the server's log, the class #159
// closed. An operator reading this line knows the emitter is being fed something it must not emit;
// the offending value is on the client's page in the admin console, which is a bounded lookup rather
// than an unbounded write.
func checkRedirectURIEmittable(site string, redirectURI string) error {
	if urlutil.IsAbsoluteRedirectURI(redirectURI) {
		return nil
	}

	slog.Error("refusing to emit an authorization response to a redirect URI that is not an absolute URI, so a gate upstream of this emitter was bypassed",
		"site", site)

	return errors.WithStack(errors.New("refusing to emit an authorization response to a redirect URI that is not an absolute URI, at " + site))
}

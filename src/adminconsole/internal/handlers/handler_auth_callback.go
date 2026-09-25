package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// signInHandshakeKeys are the values RedirToAuthorize parks in the session for the callback to
// check and then delete. Every one is required: a sign-in missing any of them was not started by
// this console's authorize redirect, or has lost what it needs to finish.
var signInHandshakeKeys = []string{
	constants.SessionKeyState,
	constants.SessionKeyCodeVerifier,
	constants.SessionKeyRedirectURI,
	constants.SessionKeyNonce,
	constants.SessionKeyRedirectBack,
	constants.SessionKeyRequestedScope,
}

// signInRefusal is one of the pages a refused sign-in answers with. The page carries catalog keys
// rather than text, and the template translates them.
type signInRefusal struct {
	status     int
	titleKey   string
	messageKey string
}

// The five refusals (#427 decisions 6, 10 and 11). The 400s are what came from the browser's
// session or request, and say what the administrator can do about it; the 500s are what the auth
// server answered, which someone must fix, and point at the log. The two 500s that concern the
// tokens share one message on purpose: those are the refusals an attacker is likeliest to be
// reading, and naming the check that stopped them would tell them which one to work on.
var (
	refusalSession = signInRefusal{http.StatusBadRequest,
		"adminconsole.sign_in_error.session.title", "adminconsole.sign_in_error.session.body"}
	refusalNoSession = signInRefusal{http.StatusBadRequest,
		"adminconsole.sign_in_error.session.title", "adminconsole.sign_in_error.no_session.body"}
	refusalExchange = signInRefusal{http.StatusInternalServerError,
		"adminconsole.sign_in_error.failed.title", "adminconsole.sign_in_error.exchange.body"}
	refusalUnverified = signInRefusal{http.StatusInternalServerError,
		"adminconsole.sign_in_error.failed.title", "adminconsole.sign_in_error.unverified.body"}
)

// HandleAuthCallbackPost completes the admin console's sign-in: the authorization response comes
// back here, form-posted, and the session that sent the browser away is checked against it.
//
// The order is the whole design (#427 decision 5). Everything refusable from the session and the
// request alone is refused before the code is exchanged, because the exchange spends the code: a
// session missing its redirect-back value used to be noticed only once the code was burned, and
// one missing its nonce skipped the nonce check altogether and signed the administrator in. Then
// the exchange, then the ID token's checks, and only then is anything written. Every refusal
// leaves the session exactly as it was.
func HandleAuthCallbackPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	tokenParser TokenParser,
	tokenExchanger TokenExchanger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		handshake := make(map[string]string, len(signInHandshakeKeys))
		for _, key := range signInHandshakeKeys {
			value, readErr := handshakeValue(sess.Values, key)
			if readErr != nil {
				// A session the store had to make up on this request -- no cookie, a cookie that
				// did not decode, or a row that is gone -- is a browser that did not bring the
				// sign-in's session back, which has causes the administrator can act on and an
				// operator can fix: a sign-in left too long, blocked cookies, or a console on
				// another site than the auth server with a cookie policy that keeps it off a
				// cross-site form post (#408). A session that came back but does not hold the
				// handshake is the ordinary stale case (#427 decision 11).
				if sess.IsNew {
					refuseSignIn(httpHelper, w, r, refusalNoSession, readErr)
				} else {
					refuseSignIn(httpHelper, w, r, refusalSession, readErr)
				}
				return
			}
			handshake[key] = value
		}

		// r.PostFormValue rather than r.FormValue here and for code, error and error_description
		// below. auth_helper.go asks the authorization endpoint for response_mode=form_post
		// precisely so all four arrive in a request body, on success and on failure alike, and this
		// route is registered POST-only, so chi answers a GET with 405 before this handler runs.
		// r.Form would have merged the URL query behind that body, which meant
		// POST /auth/callback?code=... was accepted and undid the exact leak form_post was chosen
		// to prevent: an authorization code in the request target reaches the browser's history,
		// the Referer of anything the page loads, and the access log of every proxy in front of the
		// deployment. This path is also CSRF-exempt, so a cross-origin POST does reach it (#202).
		if r.PostFormValue("state") != handshake[constants.SessionKeyState] {
			refuseSignIn(httpHelper, w, r, refusalSession,
				errs.New("the posted state is not the one this session sent"))
			return
		}

		code := r.PostFormValue("code")
		if len(strings.TrimSpace(code)) == 0 {
			// Read only once the state has matched, so what is shown is the answer to this
			// session's own request. Both are the auth server's words passed through the
			// browser, so they are conformed to RFC 6749's error_description characters and bound
			// before they reach the log, and html/template escapes them on the page.
			errorCode := customerrors.ConformErrorDescription(r.PostFormValue("error"))
			errorDescription := customerrors.ConformErrorDescription(r.PostFormValue("error_description"))
			if errorCode != "" {
				refuseSignInByAuthServer(httpHelper, w, r, errorCode, errorDescription)
				return
			}
			refuseSignIn(httpHelper, w, r, refusalSession,
				errs.New("the callback carries neither a code nor an error"))
			return
		}

		// GetEffectiveBaseURL is the one derivation routes.go also uses: the internal base URL,
		// trimmed, when one is configured. Deriving it here by hand tested the trimmed value and
		// then used the untrimmed one (#427 decision 8).
		baseUrl := config.GetAuthServer().GetEffectiveBaseURL()

		// Debug: one record on every administrator sign-in, tracing a request through the
		// code exchange. Decision 5 reserves Info for lifecycle and configuration, and this
		// is neither: an operator reading the log to see what the console is doing does not
		// need a line per sign-in, and the one reader who does is debugging the exchange
		// against a base URL they suspect (#320).
		slog.DebugContext(r.Context(), "exchanging the code for tokens", "base_url", baseUrl)

		// The admin console is always the client the seeder provisions, so the identifier
		// is the constant and only the secret is per deployment (#285).
		clientID := coreconstants.AdminConsoleClientIdentifier
		clientSecret := config.GetAdminConsole().OAuthClientSecret

		// The browser may be gone; the auth server is not. authorization_code is single use,
		// so the server has already burned the code by the time it answers, and abandoning
		// the read loses the only copy of what it issued. WithoutCancel keeps the request's
		// values, so request_id still reaches every record below, and drops only its
		// cancellation; context.Background() would drop the request id with it. The deadline
		// is what bounds this instead.
		//
		// The detachment covers this one call and stops there. Validating the tokens and
		// writing the session below stay on the browser's own request deliberately: finishing
		// a sign-in for a browser that has gone leaves a row holding an administrator's tokens
		// under a cookie that can never be delivered, and the burned code buys nothing either
		// way. So a browser that leaves here still has to sign in again -- what the detachment
		// prevents is the exchange being abandoned in flight, not the sign-in failing. The
		// refresh in internal/middleware carries its detached context further than this, because
		// there a session already exists and holds the token being replaced (#338).
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), oauthclient.TokenExchangeTimeout)
		defer cancel()

		tokenResponse, err := tokenExchanger.ExchangeCodeForTokens(ctx, code,
			handshake[constants.SessionKeyRedirectURI], clientID, clientSecret,
			handshake[constants.SessionKeyCodeVerifier], baseUrl+"/auth/token")
		if err != nil {
			refuseSignIn(httpHelper, w, r, refusalExchange, errs.Wrap(err, "unable to exchange the code for tokens"))
			return
		}

		// OIDC Core 3.1.3.7: the ID token's signature, issuer, exact audience and expiry, and
		// step 11's nonce, which this console always sends; plus the ID token and access token
		// both being there at all. All of it is decided in oauthclient, once.
		jwtInfo, err := tokenParser.DecodeAndValidateSignInResponse(r.Context(), tokenResponse,
			handshake[constants.SessionKeyNonce])
		if err != nil {
			refuseSignIn(httpHelper, w, r, refusalUnverified, errs.Wrap(err, "unable to accept the token response"))
			return
		}

		// The console never decodes its access token, so what it grants and when it lapses are
		// recorded here, from the response: the grant is the response's scope, or the requested
		// scope when it names none (RFC 6749 section 3.3), and the expiry is expires_in turned
		// into a clock time on receipt (#427 decisions 12, 15 and 16).
		stored := jwtInfo.TokenResponse
		stored.Scope = oauthclient.EffectiveScope(stored.Scope, handshake[constants.SessionKeyRequestedScope])
		sess.Values[constants.SessionKeyJwt] = stored
		sess.Values[constants.SessionKeyJwtExpiresAt] = oauthclient.ExpiresAt(&stored, time.Now())
		for _, key := range signInHandshakeKeys {
			delete(sess.Values, key)
		}
		// The identifier rotates here, and this is the admin console's one privilege
		// transition: the lines above turn a session that was holding nothing but handshake
		// values into one holding an administrator's access, id and refresh tokens.
		//
		// A cookie store is structurally immune to session fixation, because the cookie IS
		// the state and an attacker's planted copy stays the attacker's own stale state. A
		// server-side store is not: a planted identifier names a row that this sign-in then
		// fills in, so without rotation whoever planted it holds a session carrying the
		// administrator's tokens. No identifier that existed before authentication may name
		// the session authentication produces, and this is the site that owes that here
		// (#266).
		//
		// Regenerate writes the contents under a fresh identifier, deletes the old row and
		// only then sets the cookie, so any failure leaves the administrator without a
		// session rather than leaving the planted identifier live.
		//
		// Save is the fallback because the parameter is sessionstore.Store, which has no
		// rotation method: a store that cannot rotate must still be able to sign an
		// administrator in.
		if regenerator, ok := httpSession.(sessionstore.Regenerator); ok {
			err = regenerator.Regenerate(w, r, sess)
		} else {
			err = httpSession.Save(r, w, sess)
		}
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// The base URL plus path the console itself stored in its server-side session.
		http.Redirect(w, r, handshake[constants.SessionKeyRedirectBack], http.StatusFound)
	}
}

// handshakeValue reads one of the values RedirToAuthorize parked, refusing one that is absent,
// not a string, or empty. The assertion is checked because the session is a map of anything, and
// an unchecked one panicked on a value some other writer left there.
func handshakeValue(values map[string]any, key string) (string, error) {
	raw, present := values[key]
	if !present {
		return "", errs.Errorf("the session holds no %s", key)
	}
	value, ok := raw.(string)
	if !ok {
		return "", errs.Errorf("the session's %s is a %T rather than a string", key, raw)
	}
	if value == "" {
		return "", errs.Errorf("the session's %s is empty", key)
	}
	return value, nil
}

// refuseSignInByAuthServer answers the error the auth server posted back instead of a code: a
// 400, since it is the answer to the browser's own request, showing the auth server's
// description, or its error code when it sent none. Both arrive conformed.
func refuseSignInByAuthServer(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request,
	errorCode, errorDescription string) {

	refusal := signInRefusal{http.StatusBadRequest,
		"adminconsole.sign_in_error.refused.title", "adminconsole.sign_in_error.refused.body_code"}
	if errorDescription != "" {
		refusal.messageKey = "adminconsole.sign_in_error.refused.body_description"
	}
	renderSignInRefusal(httpHelper, w, r, refusal, errorCode, errorDescription,
		errs.Errorf("the auth server refused the sign-in with %s: %s", errorCode, errorDescription))
}

// refuseSignIn logs a refused sign-in and renders its page.
func refuseSignIn(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, refusal signInRefusal, cause error) {
	renderSignInRefusal(httpHelper, w, r, refusal, "", "", cause)
}

// renderSignInRefusal is shaped like the auth server's rejectAuthStateMismatch. A 400 is a stale
// tab, a second sign-in or the auth server's own refusal, logged at Warn so that nobody watching
// Error lines is paged by a Back button; a 500 is an exchange or a token the console could not
// accept, which someone must fix, logged at Error with a stack. The log names the exact cause
// every time; the page never shows a token, the code, a claim or an internal address (#427
// decisions 6 and 10).
func renderSignInRefusal(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request,
	refusal signInRefusal, errorCode, errorDescription string, cause error) {

	serverFault := refusal.status == http.StatusInternalServerError
	if serverFault {
		slog.ErrorContext(r.Context(), "unable to complete the sign-in", "error", errs.WithStack(cause))
	} else {
		slog.WarnContext(r.Context(), "sign-in refused", "error", cause)
	}

	bind := map[string]interface{}{
		"titleKey":    refusal.titleKey,
		"messageKey":  refusal.messageKey,
		"code":        errorCode,
		"description": errorDescription,
		"serverFault": serverFault,
		"requestId":   middleware.GetReqID(r.Context()),
		"_httpStatus": refusal.status,
	}
	if err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/sign_in_error.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

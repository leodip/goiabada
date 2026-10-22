package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

// signInHandshakeKeys are the values RedirToAuthorize seals into the handshake cookie for the
// callback to check. Every one is required: a sign-in missing any of them was not started by this
// console's authorize redirect, or has lost what it needs to finish.
var signInHandshakeKeys = []string{
	sessionkeys.State,
	sessionkeys.CodeVerifier,
	sessionkeys.RedirectURI,
	sessionkeys.Nonce,
	sessionkeys.RedirectBack,
	sessionkeys.RequestedScope,
}

// signInRefusal is one of the pages a refused sign-in answers with. The page carries catalog keys
// rather than text, and the template translates them.
type signInRefusal struct {
	status     int
	titleKey   string
	messageKey string
}

// The six refusals (#427 decisions 6, 10 and 11; the sixth #632 item 3). The 400s are what came
// from the browser's handshake or request, and say what the administrator can do about it; the
// 500s are what the auth server answered, which someone must fix, and point at the log. The two
// 500s that concern the tokens share one message on purpose: those are the refusals an attacker is
// likeliest to be reading, and naming the check that stopped them would tell them which one to
// work on. The 405 is the one a browser that reaches the callback by GET gets, which carries no
// authorization response at all.
var (
	refusalSession = signInRefusal{http.StatusBadRequest,
		"adminconsole.sign_in_error.session.title", "adminconsole.sign_in_error.session.body"}
	refusalNoSession = signInRefusal{http.StatusBadRequest,
		"adminconsole.sign_in_error.session.title", "adminconsole.sign_in_error.no_session.body"}
	refusalExchange = signInRefusal{http.StatusInternalServerError,
		"adminconsole.sign_in_error.failed.title", "adminconsole.sign_in_error.exchange.body"}
	refusalUnverified = signInRefusal{http.StatusInternalServerError,
		"adminconsole.sign_in_error.failed.title", "adminconsole.sign_in_error.unverified.body"}
	refusalWrongMethod = signInRefusal{http.StatusMethodNotAllowed,
		"adminconsole.sign_in_error.session.title", "adminconsole.sign_in_error.wrong_method.body"}
)

// callbackSessionStore is what the callback calls on the browser session store. Regenerate is
// in it, so a store that cannot rotate does not compile here, where it used to fall back to a
// plain save that left the pre-sign-in identifier naming the administrator's tokens (#431). The
// other three open the handshake cookie RedirToAuthorize set and remove it (#620).
type callbackSessionStore interface {
	Get(r *http.Request, name string) (*sessionstore.Session, error)
	Regenerate(w http.ResponseWriter, r *http.Request, session *sessionstore.Session) error
	CookieName(logicalName string) string
	OpenCookieValues(name, value string) (map[string]string, error)
	DeletionCookie(name string) *http.Cookie
}

// codeExchanger is the callback's one call to the token endpoint: redeem this code. The token
// URL, the client identifier and the secret are the exchanger's, given to it once when it was
// built, so the callback reads no configuration (#441).
type codeExchanger interface {
	ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (*oauth.TokenResponse, error)
}

// HandleAuthCallbackPost completes the admin console's sign-in: the authorization response comes
// back here, form-posted, and the handshake that sent the browser away is checked against it.
//
// The order is the whole design (#427 decision 5). Everything refusable from the handshake and the
// request alone is refused before the code is exchanged, because the exchange spends the code: a
// session missing its redirect-back value used to be noticed only once the code was burned, and
// one missing its nonce skipped the nonce check altogether and signed the administrator in. Then
// the exchange, then the ID token's checks, and only then is anything written. Every refusal
// leaves the session exactly as it was.
//
// The handshake arrives in its own sealed cookie rather than in the session, so the session row
// this handler writes is the console's first, created when there is a signed-in administrator to
// store in it (#620). The answer removes that cookie when it is spent: when it does not open or
// does not hold every value, since it would only be refused again, and once the posted state has
// matched it, whatever follows, since a handshake is good for one callback. A posted state that is
// absent or another leaves it, because the browser holds one handshake cookie and a second sign-in
// overwrites the first's: the callback of the sign-in it overwrote is refused for the mismatch, and
// the cookie is the newer sign-in's, which would still finish. A request that did not bring it is
// not answered with a removal either, because this route is CSRF-exempt and a cross-site post never
// carries the Lax cookie, so a removal there would let any other site end a sign-in in flight.
func HandleAuthCallbackPost(
	httpHelper HttpHelper,
	httpSession callbackSessionStore,
	tokenParser TokenParser,
	exchanger codeExchanger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handshakeCookieName := httpSession.CookieName(oauthclient.SignInHandshakeCookie)
		handshakeCookie, noCookieErr := r.Cookie(handshakeCookieName)
		removeHandshake := func() { http.SetCookie(w, httpSession.DeletionCookie(handshakeCookieName)) }

		// A browser that did not bring the sign-in's handshake back -- no cookie, or one that
		// did not open -- has causes the administrator can act on and an operator can fix: a
		// sign-in left too long, blocked cookies, a key rotated away mid sign-in, or a console
		// on another site than the auth server with a cookie policy that keeps it off a
		// cross-site form post (#408).
		if noCookieErr != nil {
			refuseSignIn(httpHelper, w, r, refusalNoSession,
				errs.Errorf("the browser brought no %s cookie", handshakeCookieName))
			return
		}
		handshake, err := httpSession.OpenCookieValues(oauthclient.SignInHandshakeCookie, handshakeCookie.Value)
		if err != nil {
			removeHandshake()
			refuseSignIn(httpHelper, w, r, refusalNoSession, errs.Wrap(err, "the sign-in handshake cookie did not open"))
			return
		}
		for _, key := range signInHandshakeKeys {
			if handshake[key] == "" {
				// A handshake that came back but does not hold every value is the ordinary
				// stale case (#427 decision 11).
				removeHandshake()
				refuseSignIn(httpHelper, w, r, refusalSession, errs.Errorf("the handshake holds no %s", key))
				return
			}
		}

		// r.PostFormValue rather than r.FormValue here and for code, error and error_description
		// below. auth_helper.go asks the authorization endpoint for response_mode=form_post
		// precisely so all four arrive in a request body, on success and on failure alike, and
		// only the POST reaches this handler: a browser that arrives by GET is answered by
		// HandleAuthCallbackGet's error page, before any of the four are read (#632 item 3).
		// r.Form would have merged the URL query behind that body, which meant
		// POST /auth/callback?code=... was accepted and undid the exact leak form_post was chosen
		// to prevent: an authorization code in the request target reaches the browser's history,
		// the Referer of anything the page loads, and the access log of every proxy in front of the
		// deployment. This path is also CSRF-exempt, so a cross-origin POST does reach it (#202).
		if r.PostFormValue("state") != handshake[sessionkeys.State] {
			refuseSignIn(httpHelper, w, r, refusalSession,
				errs.New("the posted state is not the one this sign-in sent"))
			return
		}
		removeHandshake()

		// Read once the state has matched, so a session that cannot be read spends the handshake
		// too, and still before the code is.
		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		code := r.PostFormValue("code")
		if len(strings.TrimSpace(code)) == 0 {
			// Read only once the state has matched, so what is shown is the answer to this
			// sign-in's own request. Both are the auth server's words passed through the
			// browser, so they are conformed to RFC 6749's error_description characters and bound
			// before they reach the log, and html/template escapes them on the page.
			errorCode := oauth.ConformErrorDescription(r.PostFormValue("error"))
			errorDescription := oauth.ConformErrorDescription(r.PostFormValue("error_description"))
			if errorCode != "" {
				refuseSignInByAuthServer(httpHelper, w, r, errorCode, errorDescription)
				return
			}
			refuseSignIn(httpHelper, w, r, refusalSession,
				errs.New("the callback carries neither a code nor an error"))
			return
		}

		// The token client owns the exchange's detachment from the browser and its deadline,
		// because the code is spent whether or not anyone reads the answer. Everything after it
		// stays on the browser's own request deliberately: finishing a sign-in for a browser that
		// has gone leaves a row holding an administrator's tokens under a cookie that can never be
		// delivered, and the burned code buys nothing either way. So a browser that leaves here
		// still has to sign in again -- what the detachment prevents is the exchange being
		// abandoned in flight, not the sign-in failing (#338, #441).
		tokenResponse, err := exchanger.ExchangeCode(r.Context(), code,
			handshake[sessionkeys.RedirectURI], handshake[sessionkeys.CodeVerifier])
		if err != nil {
			refuseSignIn(httpHelper, w, r, refusalExchange, errs.Wrap(err, "unable to exchange the code for tokens"))
			return
		}

		// OIDC Core 3.1.3.7: the ID token's signature, issuer, exact audience and expiry, and
		// step 11's nonce, which this console always sends; plus the ID token and access token
		// both being there at all. All of it is decided in oauthclient, once.
		jwtInfo, err := tokenParser.DecodeAndValidateSignInResponse(r.Context(), tokenResponse,
			handshake[sessionkeys.Nonce])
		if err != nil {
			refuseSignIn(httpHelper, w, r, refusalUnverified, errs.Wrap(err, "unable to accept the token response"))
			return
		}

		// The console never decodes its access token, so what it grants and when it lapses are
		// recorded here, from the response: the grant is the response's scope, or the requested
		// scope when it names none (RFC 6749 section 3.3), and the expiry is expires_in turned
		// into a clock time on receipt (#427 decisions 12, 15 and 16).
		stored := jwtInfo.TokenResponse
		stored.Scope = oauthclient.EffectiveScope(stored.Scope, handshake[sessionkeys.RequestedScope])
		sess.Values[sessionkeys.JWT] = stored
		sess.Values[sessionkeys.JWTExpiresAt] = oauthclient.ExpiresAt(&stored, time.Now())
		// A session written before #620 can still hold a handshake of its own, which nothing
		// reads any more and which is not carried into the signed-in session.
		for _, key := range signInHandshakeKeys {
			delete(sess.Values, key)
		}
		// The identifier rotates here, and this is the admin console's one privilege
		// transition: the lines above turn a session that was holding nothing, usually one the
		// store made up on this request, into one holding an administrator's access, id and
		// refresh tokens.
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
		if err = httpSession.Regenerate(w, r, sess); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// The base URL plus path the console itself sealed into the handshake. It arrives in a
		// cookie, but one the AEAD has just authenticated under the console's own session keys,
		// so no browser can choose it.
		//nolint:gosec // G710: the console's base URL and path, sealed by this console and opened above
		http.Redirect(w, r, handshake[sessionkeys.RedirectBack], http.StatusFound)
	}
}

// HandleAuthCallbackGet answers a browser that reaches the callback by GET: a bookmark, the
// history, a pasted address. Nothing a person opens on their own carries an authorization
// response -- the callback is where the auth server form_posts one -- so the route used to answer
// with chi's bare 405, an empty body that left a blank page with nothing to do next (#632 item 3).
// The sign-in error page is drawn instead, at the same honest status and with the same Allow
// header: the method is still wrong, only the body no longer is. No session is read and nothing is
// logged beyond the refusal itself, because there is no sign-in here to say anything about.
func HandleAuthCallbackGet(httpHelper HttpHelper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", http.MethodPost)
		refuseSignIn(httpHelper, w, r, refusalWrongMethod,
			errs.New("the callback was reached by GET, which carries no authorization response"))
	}
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

// renderSignInRefusal is shaped like the auth server's requireAuthState. A 400 is a stale
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

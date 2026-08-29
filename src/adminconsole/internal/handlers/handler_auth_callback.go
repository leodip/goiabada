package handlers

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/pkg/errors"
)

func HandleAuthCallbackPost(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	tokenParser TokenParser,
	tokenExchanger TokenExchanger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if sess.Values[constants.SessionKeyState] == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting state in the session, but it was nil")))
			return
		}

		stateFromSess := sess.Values[constants.SessionKeyState].(string)

		// r.PostFormValue rather than r.FormValue here and for code, error and error_description
		// below. auth_helper.go asks the authorization endpoint for response_mode=form_post
		// precisely so all four arrive in a request body, on success and on failure alike, and this
		// route is registered POST-only, so chi answers a GET with 405 before this handler runs.
		// r.Form would have merged the URL query behind that body, which meant
		// POST /auth/callback?code=... was accepted and undid the exact leak form_post was chosen
		// to prevent: an authorization code in the request target reaches the browser's history,
		// the Referer of anything the page loads, and the access log of every proxy in front of the
		// deployment. This path is also CSRF-exempt, so a cross-origin POST does reach it (#202).
		state := r.PostFormValue("state")
		if stateFromSess != state {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("state from session is different from state posted")))
			return
		}

		if sess.Values[constants.SessionKeyCodeVerifier] == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting code verifier in the session, but it was nil")))
			return
		}
		codeVerifier := sess.Values[constants.SessionKeyCodeVerifier].(string)

		if sess.Values[constants.SessionKeyRedirectURI] == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting redirect URI in the session, but it was nil")))
			return
		}

		redirectURI := sess.Values[constants.SessionKeyRedirectURI].(string)

		code := r.PostFormValue("code")
		if len(strings.TrimSpace(code)) == 0 {
			error := r.PostFormValue("error")
			errorDescription := r.PostFormValue("error_description")
			if len(error) > 0 {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(error+" - "+errorDescription)))
			} else {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting code, but it was empty")))
			}
			return
		}

		baseUrl := config.GetAuthServer().BaseURL
		if len(strings.TrimSpace(config.GetAuthServer().InternalBaseURL)) > 0 {
			baseUrl = config.GetAuthServer().InternalBaseURL
		}

		slog.Info("Exchanging code for tokens. baseUrl: " + baseUrl)

		// The admin console is always the client the seeder provisions, so the identifier
		// is the constant and only the secret is per deployment (#285).
		clientID := constants.AdminConsoleClientIdentifier
		clientSecret := config.GetAdminConsole().OAuthClientSecret

		tokenResponse, err := tokenExchanger.ExchangeCodeForTokens(code, redirectURI, clientID,
			clientSecret, codeVerifier, baseUrl+"/auth/token")
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.Wrap(err, "could not exchange code for tokens"))
			return
		}

		jwtInfo, err := tokenParser.DecodeAndValidateTokenResponse(tokenResponse)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.Wrap(err, "error parsing token response"))
			return
		}

		if sess.Values[constants.SessionKeyNonce] != nil {
			nonce := sess.Values[constants.SessionKeyNonce].(string)
			if !jwtInfo.IdToken.IsNonceValid(nonce) {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("nonce from session is different from the one in id token")))
				return
			}
		}

		if sess.Values[constants.SessionKeyRedirectBack] == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting referrer but it was nil")))
			return
		}
		redirectBack := sess.Values[constants.SessionKeyRedirectBack].(string)

		sess.Values[constants.SessionKeyJwt] = *tokenResponse
		delete(sess.Values, constants.SessionKeyState)
		delete(sess.Values, constants.SessionKeyNonce)
		delete(sess.Values, constants.SessionKeyRedirectURI)
		delete(sess.Values, constants.SessionKeyCodeVerifier)
		delete(sess.Values, constants.SessionKeyRedirectBack)
		// The identifier rotates here, and this is the admin console's one privilege
		// transition: the line above turns a session that was holding nothing but handshake
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
		// Save is the fallback because the parameter is sessions.Store, which has no
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

		// redirect
		http.Redirect(w, r, redirectBack, http.StatusFound)
	}
}

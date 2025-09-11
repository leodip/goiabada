package handlers

import (
    "log/slog"
    "net/http"
    "strings"

    "github.com/gorilla/sessions"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/pkg/errors"
)

func HandleAuthCallbackPost(
    httpHelper HttpHelper,
    httpSession sessions.Store,
    tokenParser TokenParser,
    tokenExchanger TokenExchanger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        sess, err := httpSession.Get(r, constants.SessionName)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

		if sess.Values[constants.SessionKeyState] == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting state in the session, but it was nil")))
			return
		}

		stateFromSess := sess.Values[constants.SessionKeyState].(string)
		state := r.FormValue("state")
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

		code := r.FormValue("code")
		if len(strings.TrimSpace(code)) == 0 {
			error := r.FormValue("error")
			errorDescription := r.FormValue("error_description")
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

        // Use configured confidential client credentials
        clientID := config.GetAdminConsole().OAuthClientID
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
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// redirect
		http.Redirect(w, r, redirectBack, http.StatusFound)
	}
}

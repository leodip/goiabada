package handlers

import (
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/validators"
	"github.com/pkg/errors"
)

func HandleAuthCallbackPost(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	tokenParser TokenParser,
	tokenIssuer TokenIssuer,
	tokenValidator TokenValidator,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
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
		if len(code) == 0 {
			error := r.FormValue("error")
			errorDescription := r.FormValue("error_description")
			if len(error) > 0 {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(error+" - "+errorDescription)))
			} else {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting code, but it was empty")))
			}
			return
		}

		codeHash, err := lib.HashString(code)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		codeEntity, err := database.GetCodeByCodeHash(nil, codeHash, false)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if codeEntity == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting code, but it was nil")))
			return
		}

		err = database.CodeLoadClient(nil, codeEntity)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		client, err := database.GetClientByClientIdentifier(nil, codeEntity.Client.ClientIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting to have a client but it was nil")))
			return
		}
		clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		input := validators.ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			Code:         code,
			RedirectURI:  redirectURI,
			CodeVerifier: codeVerifier,
			ClientId:     client.ClientIdentifier,
			ClientSecret: clientSecretDecrypted,
		}

		validateResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		tokenResponse, err := tokenIssuer.GenerateTokenResponseForAuthCode(r.Context(), validateResult.CodeEntity)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		validateResult.CodeEntity.Used = true
		err = database.UpdateCode(nil, validateResult.CodeEntity)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		jwtInfo, err := tokenParser.DecodeAndValidateTokenResponse(r.Context(), tokenResponse)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.Wrap(err, "error parsing token response"))
			return
		}
		if jwtInfo.AccessToken != nil && !jwtInfo.AccessToken.SignatureIsValid {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("signature of access token is invalid")))
			return
		}
		if jwtInfo.IdToken != nil && !jwtInfo.IdToken.SignatureIsValid {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("signature of id token is invalid")))
			return
		}
		if jwtInfo.RefreshToken != nil && !jwtInfo.RefreshToken.SignatureIsValid {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("signature of refresh token is invalid")))
			return
		}

		if sess.Values[constants.SessionKeyNonce] != nil {
			nonce := sess.Values[constants.SessionKeyNonce].(string)
			if !jwtInfo.IdToken.IsNonceValid(nonce) {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("nonce from session is different from the one in id token")))
				return
			}
		}

		if sess.Values[constants.SessionKeyReferrer] == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting referrer but it was nil")))
			return
		}
		referrer := sess.Values[constants.SessionKeyReferrer].(string)

		sess.Values[constants.SessionKeyJwt] = *tokenResponse
		delete(sess.Values, constants.SessionKeyState)
		delete(sess.Values, constants.SessionKeyNonce)
		delete(sess.Values, constants.SessionKeyRedirectURI)
		delete(sess.Values, constants.SessionKeyCodeVerifier)
		delete(sess.Values, constants.SessionKeyReferrer)
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// redirect
		http.Redirect(w, r, referrer, http.StatusFound)
	}
}

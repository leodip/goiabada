package server

import (
	"net/http"

	"github.com/leodip/goiabada/internal/constants"
	core_token "github.com/leodip/goiabada/internal/core/token"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
)

func (s *Server) handleAuthCallbackPost(tokenIssuer tokenIssuer, tokenValidator tokenValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*entities.Settings)
		sess, err := s.sessionStore.Get(r, constants.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if sess.Values[constants.SessionKeyState] == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting state in the session, but it was nil")))
			return
		}

		stateFromSess := sess.Values[constants.SessionKeyState].(string)
		state := r.FormValue("state")
		if stateFromSess != state {
			s.internalServerError(w, r, errors.WithStack(errors.New("state from session is different from state posted")))
			return
		}

		if sess.Values[constants.SessionKeyCodeVerifier] == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting code verifier in the session, but it was nil")))
			return
		}
		codeVerifier := sess.Values[constants.SessionKeyCodeVerifier].(string)

		if sess.Values[constants.SessionKeyRedirectURI] == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting redirect URI in the session, but it was nil")))
			return
		}

		redirectURI := sess.Values[constants.SessionKeyRedirectURI].(string)

		code := r.FormValue("code")
		if len(code) == 0 {
			error := r.FormValue("error")
			errorDescription := r.FormValue("error_description")
			if len(error) > 0 {
				s.internalServerError(w, r, errors.WithStack(errors.New(error+" - "+errorDescription)))
			} else {
				s.internalServerError(w, r, errors.WithStack(errors.New("expecting code, but it was empty")))
			}
			return
		}

		codeHash, err := lib.HashString(code)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		codeEntity, err := s.database.GetCodeByCodeHash(nil, codeHash, false)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if codeEntity == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting code, but it was nil")))
			return
		}

		err = s.database.CodeLoadClient(nil, codeEntity)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		client, err := s.database.GetClientByClientIdentifier(nil, codeEntity.Client.ClientIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting to have a client but it was nil")))
			return
		}
		clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		input := core_validators.ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			Code:         code,
			RedirectURI:  redirectURI,
			CodeVerifier: codeVerifier,
			ClientId:     client.ClientIdentifier,
			ClientSecret: clientSecretDecrypted,
		}

		validateResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		tokenResponse, err := tokenIssuer.GenerateTokenResponseForAuthCode(r.Context(),
			&core_token.GenerateTokenResponseForAuthCodeInput{
				Code: validateResult.CodeEntity,
			})
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		validateResult.CodeEntity.Used = true
		err = s.database.UpdateCode(nil, validateResult.CodeEntity)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		jwtInfo, err := s.tokenParser.DecodeAndValidateTokenResponse(r.Context(), tokenResponse)
		if err != nil {
			s.internalServerError(w, r, errors.Wrap(err, "error parsing token response"))
			return
		}
		if jwtInfo.AccessToken != nil && !jwtInfo.AccessToken.SignatureIsValid {
			s.internalServerError(w, r, errors.WithStack(errors.New("signature of access token is invalid")))
			return
		}
		if jwtInfo.IdToken != nil && !jwtInfo.IdToken.SignatureIsValid {
			s.internalServerError(w, r, errors.WithStack(errors.New("signature of id token is invalid")))
			return
		}
		if jwtInfo.RefreshToken != nil && !jwtInfo.RefreshToken.SignatureIsValid {
			s.internalServerError(w, r, errors.WithStack(errors.New("signature of refresh token is invalid")))
			return
		}

		if sess.Values[constants.SessionKeyNonce] != nil {
			nonce := sess.Values[constants.SessionKeyNonce].(string)
			if !jwtInfo.IdToken.IsNonceValid(nonce) {
				s.internalServerError(w, r, errors.WithStack(errors.New("nonce from session is different from the one in id token")))
				return
			}
		}

		if sess.Values[constants.SessionKeyReferrer] == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting referrer but it was nil")))
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
			s.internalServerError(w, r, err)
			return
		}

		// redirect
		http.Redirect(w, r, referrer, http.StatusFound)
	}
}

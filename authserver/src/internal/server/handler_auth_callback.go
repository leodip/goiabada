package server

import (
	"net/http"

	"github.com/leodip/goiabada/internal/common"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
)

func (s *Server) handleAuthCallbackPost(tokenIssuer tokenIssuer, tokenValidator tokenValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if sess.Values[common.SessionKeyState] == nil {
			s.internalServerError(w, r, errors.New("expecting state in the session, but it was nil"))
			return
		}

		stateFromSess := sess.Values[common.SessionKeyState].(string)
		state := r.FormValue("state")
		if stateFromSess != state {
			s.internalServerError(w, r, errors.New("state from session is different from state posted"))
			return
		}

		if sess.Values[common.SessionKeyCodeVerifier] == nil {
			s.internalServerError(w, r, errors.New("expecting code verifier in the session, but it was nil"))
			return
		}
		codeVerifier := sess.Values[common.SessionKeyCodeVerifier].(string)

		if sess.Values[common.SessionKeyRedirectURI] == nil {
			s.internalServerError(w, r, errors.New("expecting redirect URI in the session, but it was nil"))
			return
		}

		redirectURI := sess.Values[common.SessionKeyRedirectURI].(string)

		code := r.FormValue("code")
		if len(code) == 0 {
			error := r.FormValue("error")
			errorDescription := r.FormValue("error_description")
			if len(error) > 0 {
				s.internalServerError(w, r, errors.New(error+" - "+errorDescription))
			} else {
				s.internalServerError(w, r, errors.New("expecting code, but it was empty"))
			}
			return
		}

		codeHash, err := lib.HashString(code)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		codeEntity, err := s.database.GetCode(codeHash, false)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if codeEntity == nil {
			s.internalServerError(w, r, errors.New("expecting code, but it was nil"))
			return
		}

		client, err := s.database.GetClientByClientIdentifier(codeEntity.Client.ClientIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.New("expecting to have a client but it was nil"))
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

		validateTokenRequestResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		keyPair, err := s.database.GetCurrentSigningKey()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		validateTokenResponse, err := tokenIssuer.GenerateTokenForAuthCode(r.Context(),
			validateTokenRequestResult.CodeEntity, keyPair, lib.GetBaseUrl())
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		validateTokenRequestResult.CodeEntity.Used = true
		_, err = s.database.SaveCode(validateTokenRequestResult.CodeEntity)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		jwtInfo, err := tokenValidator.ParseTokenResponse(r.Context(), validateTokenResponse)
		if err != nil {
			s.internalServerError(w, r, errors.Wrap(err, "error parsing token response"))
			return
		}
		if jwtInfo.AccessToken != nil && !jwtInfo.AccessToken.SignatureIsValid {
			s.internalServerError(w, r, errors.New("signature of access token is invalid"))
			return
		}
		if jwtInfo.IdToken != nil && !jwtInfo.IdToken.SignatureIsValid {
			s.internalServerError(w, r, errors.New("signature of id token is invalid"))
			return
		}
		if jwtInfo.RefreshToken != nil && !jwtInfo.RefreshToken.SignatureIsValid {
			s.internalServerError(w, r, errors.New("signature of refresh token is invalid"))
			return
		}

		if sess.Values[common.SessionKeyNonce] != nil {
			nonce := sess.Values[common.SessionKeyNonce].(string)
			if !jwtInfo.IdToken.IsNonceValid(nonce) {
				s.internalServerError(w, r, errors.New("nonce from session is different from the one in id token"))
				return
			}
		}

		if sess.Values[common.SessionKeyReferrer] == nil {
			s.internalServerError(w, r, errors.New("expecting referrer but it was nil"))
			return
		}
		referrer := sess.Values[common.SessionKeyReferrer].(string)

		sess.Values[common.SessionKeyJwt] = *validateTokenResponse
		delete(sess.Values, common.SessionKeyState)
		delete(sess.Values, common.SessionKeyNonce)
		delete(sess.Values, common.SessionKeyRedirectURI)
		delete(sess.Values, common.SessionKeyCodeVerifier)
		delete(sess.Values, common.SessionKeyReferrer)
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// redirect
		http.Redirect(w, r, referrer, http.StatusFound)
	}
}

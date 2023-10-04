package server

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/internal/common"
	core_token "github.com/leodip/goiabada/internal/core/token"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
)

func (s *Server) handleAuthCallbackGet(tokenIssuer tokenIssuer, tokenValidator tokenValidator) http.HandlerFunc {
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
		state := r.URL.Query().Get("state")
		if stateFromSess != state {
			s.internalServerError(w, r, errors.New("state from session is different from state in querystring"))
			return
		}

		if sess.Values[common.SessionKeyCodeVerifier] == nil {
			s.internalServerError(w, r, errors.New("expecting code verifier in the session, but it was nil"))
			return
		}
		codeVerifier := sess.Values[common.SessionKeyCodeVerifier].(string)

		if sess.Values[common.SessionKeyRedirectUri] == nil {
			s.internalServerError(w, r, errors.New("expecting redirect URI in the session, but it was nil"))
			return
		}

		redirectUri := sess.Values[common.SessionKeyRedirectUri].(string)

		code := r.FormValue("code")
		if len(code) == 0 {
			s.internalServerError(w, r, errors.New("expecting code, but it was empty"))
			return
		}

		codeEntity, err := s.database.GetCode(code, false)
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

		input := core_token.TokenRequestInput{
			GrantType:    "authorization_code",
			Code:         code,
			RedirectUri:  redirectUri,
			CodeVerifier: codeVerifier,
			ClientId:     client.ClientIdentifier,
			ClientSecret: clientSecretDecrypted,
		}

		tokenRequestResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		keyPair, err := s.database.GetSigningKey()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		tokenResponse, err := tokenIssuer.GenerateTokenForAuthCode(r.Context(), tokenRequestResult.CodeEntity, keyPair)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		tokenRequestResult.CodeEntity.Used = true
		_, err = s.database.UpdateCode(tokenRequestResult.CodeEntity)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		jwtInfo, err := tokenValidator.ValidateJwtSignature(r.Context(), tokenResponse)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if sess.Values[common.SessionKeyNonce] != nil {
			nonce := sess.Values[common.SessionKeyNonce].(string)
			if !jwtInfo.IsIdTokenNonceValid(nonce) {
				s.internalServerError(w, r, errors.New("nonce from session is different from the one in id token"))
				return
			}
		}

		if sess.Values[common.SessionKeyReferrer] == nil {
			s.internalServerError(w, r, errors.New("expecting referrer but it was nil"))
			return
		}
		referrer := sess.Values[common.SessionKeyReferrer].(string)

		sess.Values[common.SessionKeyJwt] = *tokenResponse
		delete(sess.Values, common.SessionKeyState)
		delete(sess.Values, common.SessionKeyNonce)
		delete(sess.Values, common.SessionKeyRedirectUri)
		delete(sess.Values, common.SessionKeyCodeVerifier)
		delete(sess.Values, common.SessionKeyReferrer)
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// redirect
		url := viper.GetString("BaseUrl") + referrer
		http.Redirect(w, r, url, http.StatusFound)
	}
}

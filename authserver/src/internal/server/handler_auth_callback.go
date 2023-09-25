package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
)

func (s *Server) handleAuthCallback(tokenValidator tokenValidator) http.HandlerFunc {
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

		tokenUrl := viper.GetString("BaseUrl") + "/auth/token"

		formData := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {codeEntity.Client.ClientIdentifier},
			"client_secret": {clientSecretDecrypted},
			"code":          {code},
			"code_verifier": {codeVerifier},
			"redirect_uri":  {redirectUri},
		}

		formDataString := formData.Encode()
		requestBody := strings.NewReader(formDataString)
		request, err := http.NewRequest("POST", tokenUrl, requestBody)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient := &http.Client{Transport: tr}
		resp, err := httpClient.Do(request)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		defer resp.Body.Close()

		jsonBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		jsonStr := string(jsonBytes)

		var tokenResponse dtos.TokenResponse
		if err := json.Unmarshal([]byte(jsonStr), &tokenResponse); err != nil {
			s.internalServerError(w, r, err)
			return
		}
		_, err = tokenValidator.ValidateJwtSignature(r.Context(), &tokenResponse)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if sess.Values[common.SessionKeyReferrer] == nil {
			s.internalServerError(w, r, errors.New("expecting referrer but it was nil"))
			return
		}
		referrer := sess.Values[common.SessionKeyReferrer].(string)

		sess.Values[common.SessionKeyJwt] = jsonStr
		delete(sess.Values, common.SessionKeyState)
		delete(sess.Values, common.SessionKeyNonce)
		delete(sess.Values, common.SessionKeyRedirectUri)
		delete(sess.Values, common.SessionKeyCodeVerifier)
		delete(sess.Values, common.SessionKeyReferrer)
		sess.Save(r, w)

		// redirect
		url := viper.GetString("BaseUrl") + referrer
		http.Redirect(w, r, url, http.StatusFound)
	}
}

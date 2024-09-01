package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleAuthCallbackPost(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	database data.Database,
	tokenParser TokenParser,
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

		codeHash, err := hashutil.HashString(code)
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
		clientSecretDecrypted, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		tokenResponse, err := exchangeCodeForTokens(code, redirectURI, client.ClientIdentifier,
			clientSecretDecrypted, codeVerifier, config.GetAuthServer().BaseURL+"/auth/token")
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.Wrap(err, "could not exchange code for tokens"))
			return
		}

		jwtInfo, err := tokenParser.DecodeAndValidateTokenResponse(r.Context(), tokenResponse)
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
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// redirect
		http.Redirect(w, r, redirectBack, http.StatusFound)
	}
}

func exchangeCodeForTokens(
	code,
	redirectURI,
	clientId,
	clientSecret,
	codeVerifier,
	tokenEndpoint string,
) (*oauth.TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret) // Add client secret to form data
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error response from server: %s", body)
	}

	var tokenResponse oauth.TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %v", err)
	}

	return &tokenResponse, nil
}

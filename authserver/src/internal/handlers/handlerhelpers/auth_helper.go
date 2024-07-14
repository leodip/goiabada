package handlerhelpers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/security"
)

type AuthHelper struct {
	sessionStore sessions.Store
}

func NewAuthHelper(sessionStore sessions.Store) *AuthHelper {
	return &AuthHelper{
		sessionStore: sessionStore,
	}
}

func (s *AuthHelper) GetLoggedInSubject(r *http.Request) string {
	var jwtInfo security.JwtInfo
	if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
		var ok bool
		jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(security.JwtInfo)
		if !ok {
			stackBytes := debug.Stack()
			slog.Error("unable to cast jwtInfo\n" + string(stackBytes))
			return ""
		}
		if jwtInfo.IdToken != nil {
			sub := jwtInfo.IdToken.GetStringClaim("sub")
			return sub
		}
	}
	return ""
}

func (s *AuthHelper) GetAuthContext(r *http.Request) (*security.AuthContext, error) {
	sess, err := s.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return nil, err
	}
	jsonData, ok := sess.Values[constants.SessionKeyAuthContext].(string)
	if !ok {
		return nil, customerrors.ErrNoAuthContext
	}

	var authContext security.AuthContext
	err = json.Unmarshal([]byte(jsonData), &authContext)
	if err != nil {
		return nil, err
	}
	return &authContext, nil
}

func (s *AuthHelper) SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *security.AuthContext) error {

	sess, err := s.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(authContext)
	if err != nil {
		return err
	}
	sess.Values[constants.SessionKeyAuthContext] = string(jsonData)
	err = sess.Save(r, w)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthHelper) ClearAuthContext(w http.ResponseWriter, r *http.Request) error {

	sess, err := s.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return err
	}
	delete(sess.Values, constants.SessionKeyAuthContext)
	err = sess.Save(r, w)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthHelper) RedirToAuthorize(w http.ResponseWriter, r *http.Request, clientIdentifier string, referrer string) error {
	sess, err := s.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return err
	}

	redirectURI := lib.GetBaseUrl() + "/auth/callback"
	codeVerifier := lib.GenerateSecureRandomString(120)
	codeChallenge := lib.GeneratePKCECodeChallenge(codeVerifier)
	state := lib.GenerateSecureRandomString(16)
	nonce := lib.GenerateSecureRandomString(16)

	sess.Values[constants.SessionKeyState] = state
	sess.Values[constants.SessionKeyNonce] = nonce
	sess.Values[constants.SessionKeyCodeVerifier] = codeVerifier
	sess.Values[constants.SessionKeyRedirectURI] = redirectURI
	sess.Values[constants.SessionKeyReferrer] = referrer
	err = sess.Save(r, w)
	if err != nil {
		return err
	}

	values := url.Values{}
	values.Add("client_id", clientIdentifier)
	values.Add("redirect_uri", redirectURI)
	values.Add("response_mode", "form_post")
	values.Add("response_type", "code")
	values.Add("code_challenge_method", "S256")
	values.Add("code_challenge", codeChallenge)
	values.Add("state", state)
	nonceHash, err := lib.HashString(nonce)
	if err != nil {
		return err
	}
	values.Add("nonce", nonceHash)
	values.Add("scope", fmt.Sprintf("openid %v:%v %v:%v",
		constants.AuthServerResourceIdentifier, constants.ManageAccountPermissionIdentifier,
		constants.AuthServerResourceIdentifier, constants.AdminWebsitePermissionIdentifier))
	values.Add("acr_values", "2") // pwd + optional otp (if enabled)

	destUrl := fmt.Sprintf("%v/auth/authorize?%v", lib.GetBaseUrl(), values.Encode())

	http.Redirect(w, r, destUrl, http.StatusFound)

	return nil
}

func (s *AuthHelper) IsAuthorizedToAccessResource(jwtInfo security.JwtInfo, scopesAnyOf []string) bool {
	if jwtInfo.AccessToken != nil && jwtInfo.AccessToken.SignatureIsValid {
		acrLevel := jwtInfo.AccessToken.GetAcrLevel()
		if acrLevel != nil &&
			(*acrLevel == enums.AcrLevel2 || *acrLevel == enums.AcrLevel3) {
			for _, scope := range scopesAnyOf {
				if jwtInfo.AccessToken.HasScope(scope) {
					return true
				}
			}
		}
	}
	return false
}

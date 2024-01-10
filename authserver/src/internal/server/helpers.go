package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"log/slog"

	"slices"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
)

func (s *Server) renderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) error {

	buf, err := s.renderTemplateToBuffer(r, layoutName, templateName, data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	if data != nil && data["_httpStatus"] != nil {
		httpStatus, ok := data["_httpStatus"].(int)
		if !ok {
			return errors.New("unable to cast _httpStatus to int")
		}
		w.WriteHeader(httpStatus)
	}

	buf.WriteTo(w)
	return nil
}

func (s *Server) includeLeftPanelImage(templateName string) bool {
	templates := []string{
		"/auth_pwd.html",
		"/auth_otp.html",
		"/auth_otp_enrollment.html",
		"/forgot_password.html",
		"/reset_password.html",
		"/consent.html",
		"/account_register.html",
		"/account_register_activation.html",
		"/account_register_activation_result.html",
		"/logout_consent.html",
	}

	return slices.Contains(templates, templateName)
}

func (s *Server) getLoggedInSubject(r *http.Request) string {
	var jwtInfo dtos.JwtInfo
	if r.Context().Value(common.ContextKeyJwtInfo) != nil {
		var ok bool
		jwtInfo, ok = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		if !ok {
			slog.Error("unable to cast jwtInfo to dtos.JwtInfo")
			return ""
		}
		if jwtInfo.IdToken != nil {
			sub := jwtInfo.IdToken.GetStringClaim("sub")
			return sub
		}
	}
	return ""
}

func (s *Server) renderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) (*bytes.Buffer, error) {

	settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
	data["appName"] = settings.AppName
	data["uiTheme"] = settings.UITheme
	data["urlPath"] = r.URL.Path
	data["goiabadaVersion"] = constants.Version + " (" + constants.BuildDate + ")"

	var jwtInfo dtos.JwtInfo
	if r.Context().Value(common.ContextKeyJwtInfo) != nil {
		var ok bool
		jwtInfo, ok = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		if !ok {
			return nil, errors.New("unable to cast jwtInfo to dtos.JwtInfo")
		}
		if jwtInfo.IdToken != nil && jwtInfo.IdToken.SignatureIsValid && jwtInfo.IdToken.Claims["sub"] != nil {
			sub := jwtInfo.IdToken.Claims["sub"].(string)
			user, err := s.database.GetUserBySubject(sub)
			if err != nil {
				return nil, err
			}
			if user != nil {
				data["loggedInUser"] = user
			}
		}
		if jwtInfo.AccessToken != nil && jwtInfo.AccessToken.SignatureIsValid &&
			jwtInfo.AccessToken.HasScope(constants.AuthServerResourceIdentifier+":"+constants.AdminWebsitePermissionIdentifier) {
			data["isAdmin"] = true
		}
	}

	if s.includeLeftPanelImage(templateName) {
		leftPanelImage, err := s.getRandomStaticFile("images/left-panel")
		if err != nil {
			return nil, errors.Wrap(err, "unable to get random static file")
		}
		data["leftPanelImage"] = leftPanelImage
	}

	name := filepath.Base(layoutName)

	if strings.HasPrefix(templateName, "/") {
		templateName = templateName[1:]
	}
	if strings.HasPrefix(layoutName, "/") {
		layoutName = layoutName[1:]
	}

	templateFiles := []string{
		layoutName,
		templateName,
	}

	files, err := fs.ReadDir(s.templateFS, "partials")
	if err != nil {
		return nil, errors.Wrap(err, "unable to read the partials dir")
	}

	for _, file := range files {
		templateFiles = append(templateFiles, "partials/"+file.Name())
	}

	templ, err := template.New(name).Funcs(templateFuncMap).ParseFS(s.templateFS, templateFiles...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to render template")
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, data)
	if err != nil {
		return nil, errors.Wrap(err, "unable to execute template")
	}
	return &buf, nil
}

func (s *Server) internalServerError(w http.ResponseWriter, r *http.Request, err error) {

	requestId := middleware.GetReqID(r.Context())
	slog.Error(err.Error(), "request-id", requestId)

	w.WriteHeader(http.StatusInternalServerError)

	// render the error in the UI
	err = s.renderTemplate(w, r, "/layouts/no_menu_layout.html", "/error.html", map[string]interface{}{
		"requestId": requestId,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("unable to render the error page: %v", err.Error()), http.StatusInternalServerError)
	}
}

func (s *Server) jsonError(w http.ResponseWriter, r *http.Request, err error) {

	w.Header().Set("Content-Type", "application/json")

	requestId := middleware.GetReqID(r.Context())

	errorStr := ""
	errorDescriptionStr := ""

	valError, ok := err.(*customerrors.ValidationError)
	if ok {
		// validation error
		w.WriteHeader(http.StatusBadRequest)
		errorStr = valError.Code
		errorDescriptionStr = valError.Description
	} else {
		// any other error
		w.WriteHeader(http.StatusInternalServerError)
		slog.Error(err.Error(), "request-id", requestId)
		errorStr = "server_error"
		errorDescriptionStr = fmt.Sprintf("An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: %v", requestId)
	}

	values := map[string]string{
		"error":             errorStr,
		"error_description": errorDescriptionStr,
	}
	json.NewEncoder(w).Encode(values)
}

func (s *Server) getAuthContext(r *http.Request) (*dtos.AuthContext, error) {

	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		return nil, err
	}
	jsonData, ok := sess.Values[common.SessionKeyAuthContext].(string)
	if !ok {
		return nil, customerrors.ErrNoAuthContext
	}

	var authContext dtos.AuthContext
	err = json.Unmarshal([]byte(jsonData), &authContext)
	if err != nil {
		return nil, err
	}
	return &authContext, nil
}

func (s *Server) saveAuthContext(w http.ResponseWriter, r *http.Request, authContext *dtos.AuthContext) error {

	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(authContext)
	if err != nil {
		return err
	}
	sess.Values[common.SessionKeyAuthContext] = string(jsonData)
	err = sess.Save(r, w)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) clearAuthContext(w http.ResponseWriter, r *http.Request) error {

	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		return err
	}
	delete(sess.Values, common.SessionKeyAuthContext)
	err = sess.Save(r, w)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) isAuthorizedToAccessResource(jwtInfo dtos.JwtInfo, scopesAnyOf []string) bool {
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

func (s *Server) redirToAuthorize(w http.ResponseWriter, r *http.Request, clientIdentifier string, referrer string) {
	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		s.internalServerError(w, r, err)
		return
	}

	redirectURI := lib.GetBaseUrl() + "/auth/callback"
	codeVerifier := lib.GenerateSecureRandomString(120)
	codeChallenge := lib.GeneratePKCECodeChallenge(codeVerifier)
	state := lib.GenerateSecureRandomString(16)
	nonce := lib.GenerateSecureRandomString(16)

	sess.Values[common.SessionKeyState] = state
	sess.Values[common.SessionKeyNonce] = nonce
	sess.Values[common.SessionKeyCodeVerifier] = codeVerifier
	sess.Values[common.SessionKeyRedirectURI] = redirectURI
	sess.Values[common.SessionKeyReferrer] = referrer
	err = sess.Save(r, w)
	if err != nil {
		s.internalServerError(w, r, err)
		return
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
		s.internalServerError(w, r, err)
		return
	}
	values.Add("nonce", nonceHash)
	values.Add("scope", fmt.Sprintf("openid %v:%v %v:%v",
		constants.AuthServerResourceIdentifier, constants.ManageAccountPermissionIdentifier,
		constants.AuthServerResourceIdentifier, constants.AdminWebsitePermissionIdentifier))
	values.Add("acr_values", "2") // pwd + optional otp (if enabled)

	destUrl := fmt.Sprintf("%v/auth/authorize?%v", lib.GetBaseUrl(), values.Encode())

	http.Redirect(w, r, destUrl, http.StatusFound)
}

func (s *Server) startNewUserSession(w http.ResponseWriter, r *http.Request,
	userId uint, clientId uint, authMethods string, acrLevel string) (*entities.UserSession, error) {

	utcNow := time.Now().UTC()

	ipWithoutPort, _, _ := net.SplitHostPort(r.RemoteAddr)
	if len(ipWithoutPort) == 0 {
		ipWithoutPort = r.RemoteAddr
	}

	userSession := &entities.UserSession{
		SessionIdentifier: uuid.New().String(),
		Started:           utcNow,
		LastAccessed:      utcNow,
		IpAddress:         ipWithoutPort,
		AuthMethods:       authMethods,
		AcrLevel:          acrLevel,
		AuthTime:          utcNow,
		UserId:            userId,
		DeviceName:        lib.GetDeviceName(r),
		DeviceType:        lib.GetDeviceType(r),
		DeviceOS:          lib.GetDeviceOS(r),
	}

	userSession.Clients = append(userSession.Clients, entities.UserSessionClient{
		Started:      utcNow,
		LastAccessed: utcNow,
		ClientId:     clientId,
	})

	userSession, err := s.database.CreateUserSession(userSession)
	if err != nil {
		return nil, err
	}

	allUserSessions, err := s.database.GetUserSessionsByUserId(userId)
	if err != nil {
		return nil, err
	}

	// delete other sessions from this same device & ip
	for _, us := range allUserSessions {
		if us.SessionIdentifier != userSession.SessionIdentifier &&
			us.DeviceName == userSession.DeviceName &&
			us.DeviceType == userSession.DeviceType &&
			us.DeviceOS == userSession.DeviceOS &&
			us.IpAddress == ipWithoutPort {
			err = s.database.DeleteUserSession(us.Id)
			if err != nil {
				return nil, err
			}
		}
	}

	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get the session")
	}

	sess.Values[common.SessionKeySessionIdentifier] = userSession.SessionIdentifier
	err = sess.Save(r, w)
	if err != nil {
		return nil, err
	}

	lib.LogAudit(constants.AuditStartedNewUserSesson, map[string]interface{}{
		"userId":   userId,
		"clientId": clientId,
	})

	return userSession, nil
}

func (s *Server) bumpUserSession(w http.ResponseWriter, r *http.Request, sessionIdentifier string, clientId uint) (*entities.UserSession, error) {

	userSession, err := s.database.GetUserSessionBySessionIdentifier(sessionIdentifier)
	if err != nil {
		return nil, err
	}

	if userSession != nil {

		utcNow := time.Now().UTC()
		userSession.LastAccessed = utcNow

		// concatenate any new IP address
		ipWithoutPort, _, _ := net.SplitHostPort(r.RemoteAddr)
		if len(ipWithoutPort) == 0 {
			ipWithoutPort = r.RemoteAddr
		}

		if !strings.Contains(userSession.IpAddress, ipWithoutPort) {
			userSession.IpAddress = fmt.Sprintf("%v,%v", userSession.IpAddress, ipWithoutPort)
		}

		// append client if not already present
		clientFound := false
		for _, c := range userSession.Clients {
			if c.ClientId == clientId {
				clientFound = true
				break
			}
		}
		if !clientFound {
			userSession.Clients = append(userSession.Clients, entities.UserSessionClient{
				Started:      utcNow,
				LastAccessed: utcNow,
				ClientId:     clientId,
			})
		} else {
			// update last accessed
			for i, c := range userSession.Clients {
				if c.ClientId == clientId {
					userSession.Clients[i].LastAccessed = utcNow
					break
				}
			}
		}

		userSession, err = s.database.UpdateUserSession(userSession)
		if err != nil {
			return nil, err
		}

		lib.LogAudit(constants.AuditBumpedUserSession, map[string]interface{}{
			"userId":   userSession.UserId,
			"clientId": clientId,
		})

		return userSession, nil
	}

	return nil, errors.New("Unexpected: can't bump user session because user session is nil")
}

func (s *Server) getRandomStaticFile(path string) (string, error) {
	files, err := fs.ReadDir(s.staticFS, path)
	if err != nil {
		return "", err
	}

	if len(files) == 0 {
		return "", fmt.Errorf("dir %v in static fs is empty, can't select a random file", path)
	}

	randomIndex := rand.Intn(len(files))
	randomFile := files[randomIndex]

	filename := randomFile.Name()
	return filepath.Join("/static", path, filename), nil
}

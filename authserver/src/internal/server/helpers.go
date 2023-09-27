package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"
)

func (s *Server) renderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) error {

	buf, err := s.renderTemplateToBuffer(r, layoutName, templateName, data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	buf.WriteTo(w)
	return nil
}

func (s *Server) includeLeftPanelImage(templateName string) bool {
	templates := []string{
		"/auth_pwd.html",
		"/auth_otp.html",
		"/forgot_password.html",
		"/reset_password.html",
		"/register.html",
	}

	return slices.Contains(templates, templateName)
}

func (s *Server) renderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) (*bytes.Buffer, error) {
	templateDir := viper.GetString("TemplateDir")

	settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
	data["appName"] = settings.AppName

	if s.includeLeftPanelImage(templateName) {
		leftPanelImage, err := lib.GetRandomStaticFile("/images/left-panel")
		if err != nil {
			return nil, customerrors.NewAppError(err, "", "unable to get random static file", http.StatusInternalServerError)
		}
		data["leftPanelImage"] = leftPanelImage
	}

	name := filepath.Base(templateDir + layoutName)

	templateFiles := []string{
		templateDir + layoutName,
		templateDir + templateName,
	}

	files, err := os.ReadDir(templateDir + "/partials/")
	if err != nil {
		return nil, customerrors.NewAppError(err, "", "unable to read the partials dir", http.StatusInternalServerError)
	}

	for _, file := range files {
		templateFiles = append(templateFiles, templateDir+"/partials/"+file.Name())
	}

	templ, err := template.New(name).Funcs(template.FuncMap{}).ParseFiles(templateFiles...)
	if err != nil {
		return nil, customerrors.NewAppError(err, "", "unable to render template", http.StatusInternalServerError)
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, data)
	if err != nil {
		return nil, customerrors.NewAppError(err, "", "unable to execute template", http.StatusInternalServerError)
	}
	return &buf, nil
}

func (s *Server) internalServerError(w http.ResponseWriter, r *http.Request, err error) {

	requestId := middleware.GetReqID(r.Context())
	slog.Error(err.Error(), "request-id", requestId)

	// render the error in the UI
	err = s.renderTemplate(w, r, "/layouts/layout.html", "/auth_error.html", map[string]interface{}{
		"error": fmt.Sprintf("Something went wrong on the server. For additional information, refer to the server logs. Request Id: %v", requestId),
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("unable to render the error page: %v", err.Error()), http.StatusInternalServerError)
	}
}

func (s *Server) jsonError(w http.ResponseWriter, r *http.Request, err error) {

	requestId := middleware.GetReqID(r.Context())

	errorStr := ""
	errorDescriptionStr := ""

	appError, ok := err.(*customerrors.AppError)
	if ok {
		w.WriteHeader(appError.StatusCode)

		if appError.StatusCode == http.StatusInternalServerError {
			// HTTP 500
			slog.Error(err.Error(), "request-id", requestId)
			errorStr = "server_error"
			errorDescriptionStr = fmt.Sprintf("An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: %v", requestId)
		} else {
			errorStr = appError.Code
			errorDescriptionStr = appError.Description
		}

	} else {
		// HTTP 500
		slog.Error(err.Error(), "request-id", requestId)
		errorStr = "server_error"
		errorDescriptionStr = fmt.Sprintf("An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: %v", requestId)
	}

	values := map[string]string{
		"error":             errorStr,
		"error_description": errorDescriptionStr,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(values)
}

func (s *Server) getAuthContext(r *http.Request) (*dtos.AuthContext, error) {

	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		return nil, err
	}
	jsonData, ok := sess.Values[common.SessionKeyAuthContext].(string)
	if !ok {
		return nil, customerrors.NewAppError(nil, "", "unable to find auth context in session", http.StatusInternalServerError)
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
	sess.Save(r, w)

	return nil
}

func (s *Server) clearAuthContext(w http.ResponseWriter, r *http.Request) error {

	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		return err
	}
	delete(sess.Values, common.SessionKeyAuthContext)
	sess.Save(r, w)

	return nil
}

func (s *Server) redirToAuthorize(w http.ResponseWriter, r *http.Request, clientId string, referrer string) {
	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		s.internalServerError(w, r, err)
		return
	}

	redirectUri := viper.GetString("BaseUrl") + "/auth/callback"
	codeVerifier := lib.GenerateSecureRandomString(120)
	codeChallenge := lib.GeneratePKCECodeChallenge(codeVerifier)
	state := lib.GenerateSecureRandomString(16)
	nonce := lib.GenerateSecureRandomString(16)

	sess.Values[common.SessionKeyState] = state
	sess.Values[common.SessionKeyNonce] = nonce
	sess.Values[common.SessionKeyCodeVerifier] = codeVerifier
	sess.Values[common.SessionKeyRedirectUri] = redirectUri
	sess.Values[common.SessionKeyReferrer] = referrer
	sess.Save(r, w)

	http.Redirect(w, r,
		fmt.Sprintf("%v/auth/authorize?client_id=%v&redirect_uri=%v&response_type=code&code_challenge_method=S256&code_challenge=%v&state=%v&nonce=%v",
			viper.GetString("BaseUrl"), clientId, redirectUri, codeChallenge, state, nonce),
		http.StatusFound)
}

package server

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/core"
	core_authorize "github.com/leodip/goiabada/internal/core/authorize"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/spf13/viper"
)

func (s *Server) buildScopeInfoArray(scope string, consent *entities.UserConsent) []dtos.ScopeInfo {
	scopeInfoArr := []dtos.ScopeInfo{}

	if len(scope) == 0 {
		return scopeInfoArr
	}

	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		if scope == "roles" {
			scopeInfoArr = append(scopeInfoArr, dtos.ScopeInfo{
				Scope:            scope,
				Description:      "Access to your user's assigned roles",
				AlreadyConsented: consent != nil && strings.Contains(consent.Scope, scope),
			})
		} else if core.IsOIDCScope(scope) {
			scopeInfoArr = append(scopeInfoArr, dtos.ScopeInfo{
				Scope:            scope,
				Description:      core.GetOIDCScopeDescription(scope),
				AlreadyConsented: consent != nil && strings.Contains(consent.Scope, scope),
			})
		} else {
			// resource-permission
			parts := strings.Split(scope, ":")
			scopeInfoArr = append(scopeInfoArr, dtos.ScopeInfo{
				Scope:            scope,
				Description:      fmt.Sprintf("Permission %v on resource %v", parts[1], parts[0]),
				AlreadyConsented: consent != nil && strings.Contains(consent.Scope, scope),
			})
		}
	}
	return scopeInfoArr
}

func (s *Server) handleConsentGet(codeIssuer codeIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())
		authContext, err := s.getAuthContext(r)
		if err != nil {
			s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
			return
		}

		if authContext == nil || !authContext.AuthCompleted {
			s.renderAuthorizeError(w, r, customerrors.NewAppError(nil, "", "authContext is missing or has an unexpected state", http.StatusInternalServerError))
			return
		}

		client, err := s.database.GetClientByClientIdentifier(authContext.ClientId)
		if err != nil {
			s.renderAuthorizeError(w, r, customerrors.NewAppError(nil, "", "authContext is missing or has an unexpected state", http.StatusInternalServerError))
			return
		}
		if client == nil {
			s.renderAuthorizeError(w, r, customerrors.NewAppError(nil, "", "expecting client but it was null", http.StatusInternalServerError))
			return
		}

		user, err := s.database.GetUserById(authContext.UserId)
		if err != nil {
			s.renderAuthorizeError(w, r, err)
			return
		}
		if user == nil {
			s.renderAuthorizeError(w, r, customerrors.NewAppError(nil, "", "expecting user but it was null", http.StatusInternalServerError))
			return
		}

		if !client.ConsentRequired {

			createCodeInput := &core_authorize.CreateCodeInput{
				AuthContext: *authContext,
				UserId:      user.ID,
				AcrLevel:    authContext.AcrLevel,
				AuthMethods: authContext.AuthMethods,
			}
			code, err := codeIssuer.CreateAuthCode(r.Context(), createCodeInput)
			if err != nil {
				s.renderAuthorizeError(w, r, err)
				return
			}

			err = s.clearAuthContext(w, r)
			if err != nil {
				s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
				return
			}
			s.issueAuthCode(w, r, code)
			return

		} else {

			consent, err := s.database.GetUserConsent(user.ID, client.ID)
			if err != nil {
				s.renderAuthorizeError(w, r, err)
				return
			}

			scopeInfoArr := s.buildScopeInfoArray(authContext.Scope, consent)

			allScopesAlreadyConsented := true
			for _, scopeInfo := range scopeInfoArr {
				allScopesAlreadyConsented = allScopesAlreadyConsented && scopeInfo.AlreadyConsented
			}

			if allScopesAlreadyConsented {
				createCodeInput := &core_authorize.CreateCodeInput{
					AuthContext: *authContext,
					UserId:      user.ID,
					AcrLevel:    authContext.AcrLevel,
					AuthMethods: authContext.AuthMethods,
				}
				code, err := codeIssuer.CreateAuthCode(r.Context(), createCodeInput)
				if err != nil {
					s.renderAuthorizeError(w, r, err)
					return
				}

				err = s.clearAuthContext(w, r)
				if err != nil {
					s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
					return
				}
				s.issueAuthCode(w, r, code)
				return
			} else {
				bind := map[string]interface{}{
					"csrfField":         csrf.TemplateField(r),
					"clientIdentifier":  client.ClientIdentifier,
					"clientDescription": client.Description,
					"scopes":            scopeInfoArr,
				}

				err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/consent.html", bind)
				if err != nil {
					s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
					return
				}
			}
		}
	}
}

func (s *Server) handleConsentPost(codeIssuer codeIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())
		authContext, err := s.getAuthContext(r)
		if err != nil {
			s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
			return
		}

		btn := r.FormValue("btnSubmit")
		if len(btn) == 0 {
			btn = r.FormValue("btnCancel")
		}

		if btn == "submit" {

			consented := ""
			for key := range r.Form {
				if strings.HasPrefix(key, "consent") {
					consented = consented + " " + key
				}
			}
			consented = strings.TrimSpace(consented)

			if len(consented) == 0 {
				s.redirToClientWithError(w, r, "access_denied", "The user did not provide consent", authContext.ResponseMode,
					authContext.RedirectUri, authContext.State)
			} else {

				client, err := s.database.GetClientByClientIdentifier(authContext.ClientId)
				if err != nil {
					s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
					return
				}
				if client == nil {
					s.renderAuthorizeError(w, r, customerrors.NewAppError(nil, "", "expecting client but it was null", http.StatusInternalServerError))
					return
				}

				user, err := s.database.GetUserById(authContext.UserId)
				if err != nil {
					s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
					return
				}
				if user == nil {
					s.renderAuthorizeError(w, r, customerrors.NewAppError(nil, "", "expecting user but it was null", http.StatusInternalServerError))
					return
				}

				consent, err := s.database.GetUserConsent(user.ID, client.ID)
				if err != nil {
					s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
					return
				}

				scopeInfoArr := s.buildScopeInfoArray(authContext.Scope, consent)

				if consent == nil {
					consent = &entities.UserConsent{
						UserID:   user.ID,
						ClientID: client.ID,
					}
				} else {
					consent.Scope = ""
				}

				for idx, scope := range scopeInfoArr {
					if strings.Contains(consented, fmt.Sprintf("consent%v", idx)) {
						consent.Scope = consent.Scope + " " + scope.Scope
					}
				}
				consent.Scope = strings.TrimSpace(consent.Scope)

				consent, err = s.database.SaveUserConsent(consent)
				if err != nil {
					s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
					return
				}
				authContext.ConsentedScope = consent.Scope

				createCodeInput := &core_authorize.CreateCodeInput{
					AuthContext: *authContext,
					UserId:      user.ID,
					AcrLevel:    authContext.AcrLevel,
					AuthMethods: authContext.AuthMethods,
				}
				code, err := codeIssuer.CreateAuthCode(r.Context(), createCodeInput)
				if err != nil {
					s.renderAuthorizeError(w, r, err)
					return
				}

				err = s.clearAuthContext(w, r)
				if err != nil {
					s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
					return
				}
				s.issueAuthCode(w, r, code)
				return
			}

		} else if btn == "cancel" {
			s.redirToClientWithError(w, r, "access_denied", "The user did not provide consent", authContext.ResponseMode,
				authContext.RedirectUri, authContext.State)
		}
	}
}

func (s *Server) issueAuthCode(w http.ResponseWriter, r *http.Request, code *entities.Code) error {

	responseMode := r.URL.Query().Get("response_mode")
	if responseMode == "" {
		responseMode = "query"
	}

	if responseMode == "fragment" {
		values := url.Values{}
		values.Add("code", code.Code)
		values.Add("state", code.State)
		http.Redirect(w, r, code.RedirectUri+"#"+values.Encode(), http.StatusFound)
		return nil
	}
	if responseMode == "form_post" {
		m := make(map[string]string)
		m["redirectUri"] = code.RedirectUri
		m["code"] = code.Code
		if len(strings.TrimSpace(code.State)) > 0 {
			m["state"] = code.State
		}

		templateDir := viper.GetString("TemplateDir")
		t, _ := template.ParseFiles(templateDir + "/form_post")
		err := t.Execute(w, m)
		if err != nil {
			return customerrors.NewAppError(err, "", "unable to execute template", http.StatusInternalServerError)
		}
		return nil
	}

	// default to query
	redirUrl, _ := url.ParseRequestURI(code.RedirectUri)
	values := redirUrl.Query()
	values.Add("code", code.Code)
	values.Add("state", code.State)
	redirUrl.RawQuery = values.Encode()
	http.Redirect(w, r, redirUrl.String(), http.StatusFound)
	return nil
}

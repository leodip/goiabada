package server

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/core"
	core_authorize "github.com/leodip/goiabada/internal/core/authorize"
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

func (s *Server) filterOutScopesWhereUserIsNotAuthorized(scope string, user *entities.User) (string, error) {
	newScope := ""

	// remove double spaces
	space := regexp.MustCompile(`\s+`)
	scope = space.ReplaceAllString(scope, " ")

	// filter
	scopes := strings.Split(scope, " ")
	for _, scopeStr := range scopes {

		if core.IsOIDCScope(scopeStr) || scopeStr == "roles" {
			newScope += scopeStr + " "
			continue
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) == 2 {
			res, err := s.database.GetResourceByResourceIdentifier(parts[0])
			if err != nil {
				return "", err
			}
			if res == nil {
				continue
			}

			userHasPermission := false
			for _, perm := range user.Permissions {
				if perm.ResourceId == res.Id && perm.PermissionIdentifier == parts[1] {
					userHasPermission = true
					break
				}
			}

			if userHasPermission {
				newScope += scopeStr + " "
			}
		}
	}

	return strings.TrimSpace(newScope), nil
}

func (s *Server) handleConsentGet(codeIssuer codeIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := s.getAuthContext(r)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if authContext == nil || !authContext.AuthCompleted {
			s.internalServerError(w, r, errors.New("authContext is missing or has an unexpected state"))
			return
		}

		user, err := s.database.GetUserById(authContext.UserId)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if user == nil {
			s.internalServerError(w, r, err)
			return
		}

		authContext.Scope, err = s.filterOutScopesWhereUserIsNotAuthorized(authContext.Scope, user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		err = s.saveAuthContext(w, r, authContext)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		client, err := s.database.GetClientByClientIdentifier(authContext.ClientId)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(common.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(common.ContextKeySessionIdentifier).(string)
		}

		if !client.ConsentRequired {

			createCodeInput := &core_authorize.CreateCodeInput{
				AuthContext:       *authContext,
				SessionIdentifier: sessionIdentifier,
			}
			code, err := codeIssuer.CreateAuthCode(r.Context(), createCodeInput)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			err = s.clearAuthContext(w, r)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			err = s.issueAuthCode(w, r, code, authContext.ResponseMode)
			if err != nil {
				s.internalServerError(w, r, err)
			}
			return

		} else {

			consent, err := s.database.GetUserConsent(user.Id, client.Id)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			scopeInfoArr := s.buildScopeInfoArray(authContext.Scope, consent)

			allScopesAlreadyConsented := true
			for _, scopeInfo := range scopeInfoArr {
				allScopesAlreadyConsented = allScopesAlreadyConsented && scopeInfo.AlreadyConsented
			}

			if allScopesAlreadyConsented {
				createCodeInput := &core_authorize.CreateCodeInput{
					AuthContext:       *authContext,
					SessionIdentifier: sessionIdentifier,
				}
				code, err := codeIssuer.CreateAuthCode(r.Context(), createCodeInput)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}

				err = s.clearAuthContext(w, r)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				err = s.issueAuthCode(w, r, code, authContext.ResponseMode)
				if err != nil {
					s.internalServerError(w, r, err)
				}
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
					s.internalServerError(w, r, err)
					return
				}
			}
		}
	}
}

func (s *Server) handleConsentPost(codeIssuer codeIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := s.getAuthContext(r)
		if err != nil {
			s.internalServerError(w, r, err)
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
					authContext.RedirectURI, authContext.State)
			} else {

				client, err := s.database.GetClientByClientIdentifier(authContext.ClientId)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				if client == nil {
					s.internalServerError(w, r, err)
					return
				}

				user, err := s.database.GetUserById(authContext.UserId)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				if user == nil {
					s.internalServerError(w, r, err)
					return
				}

				consent, err := s.database.GetUserConsent(user.Id, client.Id)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}

				scopeInfoArr := s.buildScopeInfoArray(authContext.Scope, consent)

				if consent == nil {
					consent = &entities.UserConsent{
						UserId:    user.Id,
						ClientId:  client.Id,
						GrantedAt: time.Now().UTC(),
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
					s.internalServerError(w, r, err)
					return
				}
				authContext.ConsentedScope = consent.Scope

				sessionIdentifier := ""
				if r.Context().Value(common.ContextKeySessionIdentifier) != nil {
					sessionIdentifier = r.Context().Value(common.ContextKeySessionIdentifier).(string)
				}

				createCodeInput := &core_authorize.CreateCodeInput{
					AuthContext:       *authContext,
					SessionIdentifier: sessionIdentifier,
				}
				code, err := codeIssuer.CreateAuthCode(r.Context(), createCodeInput)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}

				err = s.clearAuthContext(w, r)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				err = s.issueAuthCode(w, r, code, authContext.ResponseMode)
				if err != nil {
					s.internalServerError(w, r, err)
				}
				return
			}

		} else if btn == "cancel" {
			s.redirToClientWithError(w, r, "access_denied", "The user did not provide consent", authContext.ResponseMode,
				authContext.RedirectURI, authContext.State)
		}
	}
}

func (s *Server) issueAuthCode(w http.ResponseWriter, r *http.Request, code *entities.Code, responseMode string) error {

	if responseMode == "" {
		responseMode = "query"
	}

	if responseMode == "fragment" {
		values := url.Values{}
		values.Add("code", code.Code)
		values.Add("state", code.State)
		http.Redirect(w, r, code.RedirectURI+"#"+values.Encode(), http.StatusFound)
		return nil
	}
	if responseMode == "form_post" {
		m := make(map[string]interface{})
		m["redirectURI"] = code.RedirectURI
		m["code"] = code.Code
		if len(strings.TrimSpace(code.State)) > 0 {
			m["state"] = code.State
		}

		templateDir := viper.GetString("TemplateDir")
		t, err := template.ParseFiles(templateDir + "/form_post.html")
		if err != nil {
			return errors.Wrap(err, "unable to parse template")
		}
		err = t.Execute(w, m)
		if err != nil {
			return errors.Wrap(err, "unable to execute template")
		}
		return nil
	}

	// default to query
	redirUrl, _ := url.ParseRequestURI(code.RedirectURI)
	values := redirUrl.Query()
	values.Add("code", code.Code)
	values.Add("state", code.State)
	redirUrl.RawQuery = values.Encode()
	http.Redirect(w, r, redirUrl.String(), http.StatusFound)
	return nil
}

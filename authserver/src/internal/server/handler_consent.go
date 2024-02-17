package server

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/core"
	core_authorize "github.com/leodip/goiabada/internal/core/authorize"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) buildScopeInfoArray(scope string, consent *entitiesv2.UserConsent) []dtos.ScopeInfo {
	scopeInfoArr := []dtos.ScopeInfo{}

	if len(scope) == 0 {
		return scopeInfoArr
	}

	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		if core.IsIdTokenScope(scope) {
			scopeInfoArr = append(scopeInfoArr, dtos.ScopeInfo{
				Scope:            scope,
				Description:      core.GetIdTokenScopeDescription(scope),
				AlreadyConsented: consent != nil && consent.HasScope(scope),
			})
		} else {
			// resource-permission
			parts := strings.Split(scope, ":")
			scopeInfoArr = append(scopeInfoArr, dtos.ScopeInfo{
				Scope:            scope,
				Description:      fmt.Sprintf("Permission %v on resource %v", parts[1], parts[0]),
				AlreadyConsented: consent != nil && consent.HasScope(scope),
			})
		}
	}
	return scopeInfoArr
}

func (s *Server) filterOutScopesWhereUserIsNotAuthorized(scope string, user *entitiesv2.User,
	permissionChecker *core.PermissionChecker) (string, error) {

	newScope := ""

	// filter
	scopes := strings.Split(scope, " ")
	for _, scopeStr := range scopes {

		if core.IsIdTokenScope(scopeStr) {
			newScope += scopeStr + " "
			continue
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			return "", errors.New("invalid scope format: " + scopeStr)
		} else {

			userHasPermission, err := permissionChecker.UserHasScopePermission(user.Id, scopeStr)
			if err != nil {
				return "", err
			}

			if userHasPermission {
				newScope += scopeStr + " "
			}
		}
	}

	return strings.TrimSpace(newScope), nil
}

func (s *Server) handleConsentGet(codeIssuer codeIssuer, permissionChecker *core.PermissionChecker) http.HandlerFunc {
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

		user, err := s.databasev2.GetUserById(nil, authContext.UserId)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if user == nil {
			s.internalServerError(w, r, err)
			return
		}

		if !user.Enabled {
			lib.LogAudit(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})

			s.redirToClientWithError(w, r, "access_denied", "The user is not enabled", authContext.ResponseMode,
				authContext.RedirectURI, authContext.State)
			return
		}

		newScope, err := s.filterOutScopesWhereUserIsNotAuthorized(authContext.Scope, user, permissionChecker)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		authContext.SetScope(newScope)
		if len(authContext.Scope) == 0 {
			s.redirToClientWithError(w, r, "access_denied", "The user is not authorized to access any of the requested scopes", authContext.ResponseMode,
				authContext.RedirectURI, authContext.State)
			return
		}
		err = s.saveAuthContext(w, r, authContext)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		client, err := s.databasev2.GetClientByClientIdentifier(nil, authContext.ClientId)
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

		// if the client requested an offline refresh token, consent is mandatory
		if client.ConsentRequired || authContext.HasScope("offline_access") {

			consent, err := s.databasev2.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			scopeInfoArr := s.buildScopeInfoArray(authContext.Scope, consent)

			scopesFullyConsented := true
			for _, scopeInfo := range scopeInfoArr {
				scopesFullyConsented = scopesFullyConsented && scopeInfo.AlreadyConsented
			}

			if !scopesFullyConsented || authContext.HasScope("offline_access") {
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
				return
			}
		}

		// create and issue auth code
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
	}
}

func (s *Server) handleConsentPost(codeIssuer codeIssuer) http.HandlerFunc {
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

				client, err := s.databasev2.GetClientByClientIdentifier(nil, authContext.ClientId)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				if client == nil {
					s.internalServerError(w, r, err)
					return
				}

				user, err := s.databasev2.GetUserById(nil, authContext.UserId)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				if user == nil {
					s.internalServerError(w, r, err)
					return
				}

				consent, err := s.databasev2.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}

				scopeInfoArr := s.buildScopeInfoArray(authContext.Scope, consent)

				if consent == nil {
					consent = &entitiesv2.UserConsent{
						UserId:    user.Id,
						ClientId:  client.Id,
						GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
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

				if consent.Id > 0 {
					err = s.databasev2.UpdateUserConsent(nil, consent)
					if err != nil {
						s.internalServerError(w, r, err)
						return
					}
				} else {
					err = s.databasev2.CreateUserConsent(nil, consent)
					if err != nil {
						s.internalServerError(w, r, err)
						return
					}
				}
				authContext.ConsentedScope = consent.Scope

				lib.LogAudit(constants.AuditSavedConsent, map[string]interface{}{
					"userId":   consent.UserId,
					"clientId": consent.ClientId,
				})

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

func (s *Server) issueAuthCode(w http.ResponseWriter, r *http.Request, code *entitiesv2.Code, responseMode string) error {

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

		t, err := template.ParseFS(s.templateFS, "form_post.html")
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

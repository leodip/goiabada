package handlers

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/oidc"
	"github.com/leodip/goiabada/internal/security"
)

type ScopeInfo struct {
	Scope            string
	Description      string
	AlreadyConsented bool
}

func buildScopeInfoArray(scope string, consent *models.UserConsent) []ScopeInfo {
	scopeInfoArr := []ScopeInfo{}

	if len(scope) == 0 {
		return scopeInfoArr
	}

	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		if oidc.IsIdTokenScope(scope) {
			scopeInfoArr = append(scopeInfoArr, ScopeInfo{
				Scope:            scope,
				Description:      oidc.GetIdTokenScopeDescription(scope),
				AlreadyConsented: consent != nil && consent.HasScope(scope),
			})
		} else {
			// resource-permission
			parts := strings.Split(scope, ":")
			scopeInfoArr = append(scopeInfoArr, ScopeInfo{
				Scope:            scope,
				Description:      fmt.Sprintf("Permission %v on resource %v", parts[1], parts[0]),
				AlreadyConsented: consent != nil && consent.HasScope(scope),
			})
		}
	}
	return scopeInfoArr
}

func filterOutScopesWhereUserIsNotAuthorized(scope string, user *models.User,
	permissionChecker *security.PermissionChecker) (string, error) {

	newScope := ""

	// filter
	scopes := strings.Split(scope, " ")
	for _, scopeStr := range scopes {

		if oidc.IsIdTokenScope(scopeStr) {
			newScope += scopeStr + " "
			continue
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			return "", errors.WithStack(errors.New("invalid scope format: " + scopeStr))
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

func HandleConsentGet(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	templateFS fs.FS,
	codeIssuer CodeIssuer,
	permissionChecker *security.PermissionChecker,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if authContext == nil || !authContext.AuthCompleted {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext is missing or has an unexpected state")))
			return
		}

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if !user.Enabled {
			lib.LogAudit(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})

			redirToClientWithError(w, r, templateFS, "access_denied", "The user is not enabled", authContext.ResponseMode,
				authContext.RedirectURI, authContext.State)
			return
		}

		newScope, err := filterOutScopesWhereUserIsNotAuthorized(authContext.Scope, user, permissionChecker)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		authContext.SetScope(newScope)
		if len(authContext.Scope) == 0 {
			redirToClientWithError(w, r, templateFS, "access_denied", "The user is not authorized to access any of the requested scopes", authContext.ResponseMode,
				authContext.RedirectURI, authContext.State)
			return
		}
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		// if the client requested an offline refresh token, consent is mandatory
		if client.ConsentRequired || authContext.HasScope("offline_access") {

			consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			scopeInfoArr := buildScopeInfoArray(authContext.Scope, consent)

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

				err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/consent.html", bind)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				return
			}
		}

		// create and issue auth code
		createCodeInput := &security.CreateCodeInput{
			AuthContext:       *authContext,
			SessionIdentifier: sessionIdentifier,
		}
		code, err := codeIssuer.CreateAuthCode(r.Context(), createCodeInput)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = authHelper.ClearAuthContext(w, r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		err = issueAuthCode(w, r, templateFS, code, authContext.ResponseMode)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}

func HandleConsentPost(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	templateFS fs.FS,
	codeIssuer CodeIssuer,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if authContext == nil || !authContext.AuthCompleted {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext is missing or has an unexpected state")))
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
				redirToClientWithError(w, r, templateFS, "access_denied", "The user did not provide consent", authContext.ResponseMode,
					authContext.RedirectURI, authContext.State)
			} else {

				client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				if client == nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				user, err := database.GetUserById(nil, authContext.UserId)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				if user == nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				scopeInfoArr := buildScopeInfoArray(authContext.Scope, consent)

				if consent == nil {
					consent = &models.UserConsent{
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
					err = database.UpdateUserConsent(nil, consent)
					if err != nil {
						httpHelper.InternalServerError(w, r, err)
						return
					}
				} else {
					err = database.CreateUserConsent(nil, consent)
					if err != nil {
						httpHelper.InternalServerError(w, r, err)
						return
					}
				}
				authContext.ConsentedScope = consent.Scope

				lib.LogAudit(constants.AuditSavedConsent, map[string]interface{}{
					"userId":   consent.UserId,
					"clientId": consent.ClientId,
				})

				sessionIdentifier := ""
				if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
					sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
				}

				createCodeInput := &security.CreateCodeInput{
					AuthContext:       *authContext,
					SessionIdentifier: sessionIdentifier,
				}
				code, err := codeIssuer.CreateAuthCode(r.Context(), createCodeInput)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				err = authHelper.ClearAuthContext(w, r)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				err = issueAuthCode(w, r, templateFS, code, authContext.ResponseMode)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
				}
				return
			}

		} else if btn == "cancel" {
			redirToClientWithError(w, r, templateFS, "access_denied", "The user did not provide consent", authContext.ResponseMode,
				authContext.RedirectURI, authContext.State)
		}
	}
}

func issueAuthCode(w http.ResponseWriter, r *http.Request, templateFS fs.FS, code *models.Code, responseMode string) error {

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

		t, err := template.ParseFS(templateFS, "form_post.html")
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

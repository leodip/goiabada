package handlers

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
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
		if oidc.IsIdTokenScope(scope) || oidc.IsOfflineAccessScope(scope) {
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

func HandleConsentGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		requiredState := oauth.AuthStateRequiresConsent
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("client not found")))
			return
		}

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

		// Show consent screen if:
		// - Not all scopes are fully consented, OR
		// - offline_access is requested (always re-confirm refresh token grant), OR
		// - prompt=consent was explicitly requested (force consent UI)
		if !scopesFullyConsented || authContext.HasScope(oidc.OfflineAccessScope) || authContext.HasPromptValue("consent") {
			bind := map[string]interface{}{
				"csrfField":         csrf.TemplateField(r),
				"clientIdentifier":  client.ClientIdentifier,
				"clientDescription": client.Description,
				"scopes":            scopeInfoArr,
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/consent.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		} else {
			// consent is done, ready to issue code
			authContext.AuthState = oauth.AuthStateReadyToIssueCode
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/issue", http.StatusFound)
		}
	}
}

func HandleConsentPost(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	database data.Database,
	templateFS fs.FS,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		requiredState := oauth.AuthStateRequiresConsent
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
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
				err = redirToClientWithError(w, r, templateFS, "access_denied", "The user did not provide consent", authContext.ResponseMode,
					authContext.RedirectURI, authContext.State, authContext.ResponseType)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
				}

				err = authHelper.ClearAuthContext(w, r)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
			} else {

				client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				if client == nil {
					httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("client not found")))
					return
				}

				user, err := database.GetUserById(nil, authContext.UserId)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				if user == nil {
					httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
					return
				}

				consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				if consent == nil {
					consent = &models.UserConsent{
						UserId:    user.Id,
						ClientId:  client.Id,
						GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
					}
				} else {
					consent.Scope = ""
				}

				scopeInfoArr := buildScopeInfoArray(authContext.Scope, consent)

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

				auditLogger.Log(constants.AuditSavedConsent, map[string]interface{}{
					"userId":    consent.UserId,
					"clientId":  consent.ClientId,
					"consentId": consent.Id,
				})

				// consent is done, ready to issue code
				authContext.AuthState = oauth.AuthStateReadyToIssueCode
				err = authHelper.SaveAuthContext(w, r, authContext)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/issue", http.StatusFound)
			}
		} else {

			err = redirToClientWithError(w, r, templateFS, "access_denied", "The user did not provide consent", authContext.ResponseMode,
				authContext.RedirectURI, authContext.State, authContext.ResponseType)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}

			err = authHelper.ClearAuthContext(w, r)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}
	}
}

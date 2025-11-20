package handlers

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAuthorizeGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	templateFS fs.FS,
	authorizeValidator AuthorizeValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())

		authContext := oauth.AuthContext{
			AuthState:                     oauth.AuthStateInitial,
			ClientId:                      r.URL.Query().Get("client_id"),
			RedirectURI:                   r.URL.Query().Get("redirect_uri"),
			ResponseType:                  r.URL.Query().Get("response_type"),
			CodeChallengeMethod:           r.URL.Query().Get("code_challenge_method"),
			CodeChallenge:                 r.URL.Query().Get("code_challenge"),
			ResponseMode:                  r.URL.Query().Get("response_mode"),
			MaxAge:                        r.URL.Query().Get("max_age"),
			AcrValuesFromAuthorizeRequest: r.URL.Query().Get("acr_values"),
			State:                         r.URL.Query().Get("state"),
			Nonce:                         r.URL.Query().Get("nonce"),
			UserAgent:                     r.UserAgent(),
			IpAddress:                     r.RemoteAddr,
		}
		authContext.SetScope(r.URL.Query().Get("scope"))

		err := authHelper.SaveAuthContext(w, r, &authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		renderErrorUi := func(message string) {
			bind := map[string]interface{}{
				"title": "Unable to authorize",
				"error": message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		err = authorizeValidator.ValidateClientAndRedirectURI(&validators.ValidateClientAndRedirectURIInput{
			RequestId:   requestId,
			ClientId:    authContext.ClientId,
			RedirectURI: authContext.RedirectURI,
		})

		if err != nil {
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				renderErrorUi(valError.GetDescription())
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		redirToClientWithError := func(validationError *customerrors.ErrorDetail) {
			err := redirToClientWithError(w, r, templateFS, validationError.GetCode(), validationError.GetDescription(),
				r.URL.Query().Get("response_mode"), r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("state"))
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}

			err = authHelper.ClearAuthContext(w, r)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		err = authorizeValidator.ValidateRequest(&validators.ValidateRequestInput{
			ResponseType:        authContext.ResponseType,
			CodeChallengeMethod: authContext.CodeChallengeMethod,
			CodeChallenge:       authContext.CodeChallenge,
			ResponseMode:        authContext.ResponseMode,
		})

		if err != nil {
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				redirToClientWithError(valError)
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		err = authorizeValidator.ValidateScopes(authContext.Scope)

		if err != nil {
			valError, ok := err.(*customerrors.ErrorDetail)
			if ok {
				redirToClientWithError(valError)
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.UserSessionLoadUser(nil, userSession)
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
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId))))
			return
		}

		hasValidUserSession := userSessionManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
		if hasValidUserSession {

			// is the account still enabled?

			if !userSession.User.Enabled {

				// the user account has been disabled
				// we should log this event and return an error to the client
				auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
					"userId": userSession.UserId,
				})

				redirToClientWithError(customerrors.NewErrorDetailWithHttpStatusCode("access_denied", "The user account is disabled.", http.StatusBadRequest))
				return
			}

			// if the user has a valid session, that means they already completed level1 auth
			// so we can send them to level1 completed handler, where further checks will be made

			authContext.UserId = userSession.UserId
			authContext.AcrLevel = userSession.AcrLevel
			authContext.AuthMethods = userSession.AuthMethods
			authContext.AuthState = oauth.AuthStateLevel1ExistingSession
			err = authHelper.SaveAuthContext(w, r, &authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1completed", http.StatusFound)
			return
		}

		// no valid session, requires level 1 auth
		authContext.AuthState = oauth.AuthStateRequiresLevel1
		err = authHelper.SaveAuthContext(w, r, &authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1", http.StatusFound)
	}
}

func redirToClientWithError(w http.ResponseWriter, r *http.Request, templateFS fs.FS, code string,
	description string, responseMode string, redirectURI string, state string) error {

	if responseMode == "fragment" {
		values := url.Values{}
		values.Add("error", code)
		values.Add("error_description", description)
		if len(strings.TrimSpace(state)) > 0 {
			values.Add("state", state)
		}
		http.Redirect(w, r, redirectURI+"#"+values.Encode(), http.StatusFound)
		return nil
	}

	if responseMode == "form_post" {
		m := make(map[string]interface{})
		m["redirectURI"] = redirectURI
		m["error"] = code
		m["error_description"] = description
		if len(strings.TrimSpace(state)) > 0 {
			m["state"] = state
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
	redirUrl, _ := url.ParseRequestURI(redirectURI)
	values := redirUrl.Query()
	values.Add("error", code)
	values.Add("error_description", description)
	if len(strings.TrimSpace(state)) > 0 {
		values.Add("state", state)
	}
	redirUrl.RawQuery = values.Encode()

	http.Redirect(w, r, redirUrl.String(), http.StatusFound)
	return nil
}

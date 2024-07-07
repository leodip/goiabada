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
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/security"
	"github.com/leodip/goiabada/internal/validators"
)

func HandleAuthorizeGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	userSessionHelper UserSessionHelper,
	database data.Database,
	templateFS fs.FS,
	authorizeValidator AuthorizeValidator,
	loginManager LoginManager,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())

		authContext := security.AuthContext{
			ClientId:            r.URL.Query().Get("client_id"),
			RedirectURI:         r.URL.Query().Get("redirect_uri"),
			ResponseType:        r.URL.Query().Get("response_type"),
			CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
			CodeChallenge:       r.URL.Query().Get("code_challenge"),
			ResponseMode:        r.URL.Query().Get("response_mode"),
			MaxAge:              r.URL.Query().Get("max_age"),
			RequestedAcrValues:  r.URL.Query().Get("acr_values"),
			State:               r.URL.Query().Get("state"),
			Nonce:               r.URL.Query().Get("nonce"),
			UserAgent:           r.UserAgent(),
			IpAddress:           r.RemoteAddr,
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

		err = authorizeValidator.ValidateClientAndRedirectURI(r.Context(), &validators.ValidateClientAndRedirectURIInput{
			RequestId:   requestId,
			ClientId:    authContext.ClientId,
			RedirectURI: authContext.RedirectURI,
		})

		if err != nil {
			valError, ok := err.(*customerrors.ValidationError)
			if ok {
				renderErrorUi(valError.Description)
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		redirToClientWithError := func(validationError *customerrors.ValidationError) {
			err := redirToClientWithError(w, r, templateFS, validationError.Code, validationError.Description,
				r.URL.Query().Get("response_mode"), r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("state"))
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		err = authorizeValidator.ValidateRequest(r.Context(), &validators.ValidateRequestInput{
			ResponseType:        authContext.ResponseType,
			CodeChallengeMethod: authContext.CodeChallengeMethod,
			CodeChallenge:       authContext.CodeChallenge,
			ResponseMode:        authContext.ResponseMode,
		})

		if err != nil {
			valError, ok := err.(*customerrors.ValidationError)
			if ok {
				redirToClientWithError(valError)
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		err = authorizeValidator.ValidateScopes(r.Context(), authContext.Scope)

		if err != nil {
			valError, ok := err.(*customerrors.ValidationError)
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

		requestedAcrValues := authContext.ParseRequestedAcrValues()
		targetAcrLevel := client.DefaultAcrLevel

		hasValidUserSession := loginManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
		if hasValidUserSession {
			// valid user session

			if !userSession.User.Enabled {

				lib.LogAudit(constants.AuditUserDisabled, map[string]interface{}{
					"userId": userSession.UserId,
				})

				redirToClientWithError(&customerrors.ValidationError{
					Code:        "access_denied",
					Description: "The user account is disabled.",
				})
				return
			}

			if len(requestedAcrValues) > 0 {
				targetAcrLevel = requestedAcrValues[0]
			}

			mustPerformOTPAuth := loginManager.MustPerformOTPAuth(r.Context(), client, userSession, targetAcrLevel)
			if mustPerformOTPAuth {
				authContext.UserId = userSession.User.Id
				err = authHelper.SaveAuthContext(w, r, &authContext)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, lib.GetBaseUrl()+"/auth/otp", http.StatusFound)
				return
			}

		} else {
			// no valid session
			err = authHelper.SaveAuthContext(w, r, &authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, lib.GetBaseUrl()+"/auth/pwd", http.StatusFound)
			return
		}

		// no further authentication is needed

		authContext.UserId = userSession.User.Id
		err = authContext.SetAcrLevel(targetAcrLevel, userSession)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		authContext.AuthMethods = userSession.AuthMethods
		authContext.AuthTime = userSession.AuthTime
		authContext.AuthCompleted = true

		// bump session
		_, err = userSessionHelper.BumpUserSession(r, sessionIdentifier, client.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// save auth context
		err = authHelper.SaveAuthContext(w, r, &authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// redirect to consent
		http.Redirect(w, r, lib.GetBaseUrl()+"/auth/consent", http.StatusFound)
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

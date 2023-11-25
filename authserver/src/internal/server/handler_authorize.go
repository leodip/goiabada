package server

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
)

func (s *Server) handleAuthorizeGet(authorizeValidator authorizeValidator,
	codeIssuer codeIssuer, loginManager loginManager) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())

		authContext := dtos.AuthContext{
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

		err := s.saveAuthContext(w, r, &authContext)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		renderErrorUi := func(message string) {
			bind := map[string]interface{}{
				"title": "Unable to authorize",
				"error": message,
			}

			err := s.renderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		err = authorizeValidator.ValidateClientAndRedirectURI(r.Context(), &core_validators.ValidateClientAndRedirectURIInput{
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
				s.internalServerError(w, r, err)
				return
			}
		}

		redirToClientWithError := func(validationError *customerrors.ValidationError) {
			err := s.redirToClientWithError(w, r, validationError.Code, validationError.Description,
				r.URL.Query().Get("response_mode"), r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("state"))
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		err = authorizeValidator.ValidateRequest(r.Context(), &core_validators.ValidateRequestInput{
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
				s.internalServerError(w, r, err)
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
				s.internalServerError(w, r, err)
				return
			}
		}

		sessionIdentifier := ""
		if r.Context().Value(common.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(common.ContextKeySessionIdentifier).(string)
		}

		userSession, err := s.database.GetUserSessionBySessionIdentifier(sessionIdentifier)
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
			s.internalServerError(w, r, errors.New("client not found"))
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
				err = s.saveAuthContext(w, r, &authContext)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, lib.GetBaseUrl()+"/auth/otp", http.StatusFound)
				return
			}

		} else {
			// no valid session
			err = s.saveAuthContext(w, r, &authContext)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, lib.GetBaseUrl()+"/auth/pwd", http.StatusFound)
			return
		}

		// no further authentication is needed

		authContext.UserId = userSession.User.Id
		err = authContext.SetAcrLevel(targetAcrLevel, userSession)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		authContext.AuthMethods = userSession.AuthMethods
		authContext.AuthTime = userSession.AuthTime
		authContext.AuthCompleted = true

		// bump session
		_, err = s.bumpUserSession(w, r, sessionIdentifier, client.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// save auth context
		err = s.saveAuthContext(w, r, &authContext)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// redirect to consent
		http.Redirect(w, r, lib.GetBaseUrl()+"/auth/consent", http.StatusFound)
	}
}

func (s *Server) redirToClientWithError(w http.ResponseWriter, r *http.Request, code string,
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

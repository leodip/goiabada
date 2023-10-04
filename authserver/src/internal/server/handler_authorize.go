package server

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/internal/common"
	core_authorize "github.com/leodip/goiabada/internal/core/authorize"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/spf13/viper"
)

func (s *Server) handleAuthorizeGet(authorizeValidator authorizeValidator,
	codeIssuer codeIssuer, loginManager loginManager) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())

		authContext := dtos.AuthContext{
			ClientId:            r.URL.Query().Get("client_id"),
			RedirectUri:         r.URL.Query().Get("redirect_uri"),
			ResponseType:        r.URL.Query().Get("response_type"),
			CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
			CodeChallenge:       r.URL.Query().Get("code_challenge"),
			ResponseMode:        r.URL.Query().Get("response_mode"),
			Scope:               r.URL.Query().Get("scope"),
			MaxAge:              r.URL.Query().Get("max_age"),
			RequestedAcrValues:  r.URL.Query().Get("acr_values"),
			State:               r.URL.Query().Get("state"),
			Nonce:               r.URL.Query().Get("nonce"),
			UserAgent:           r.UserAgent(),
			IpAddress:           r.RemoteAddr,
		}

		err := s.saveAuthContext(w, r, &authContext)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		renderErrorUi := func(message string) {
			bind := map[string]interface{}{
				"error": message,
			}

			err := s.renderTemplate(w, r, "/layouts/layout.html", "/auth_error.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		err = authorizeValidator.ValidateClientAndRedirectUri(r.Context(), &core_authorize.ValidateClientAndRedirectUriInput{
			RequestId:   requestId,
			ClientId:    authContext.ClientId,
			RedirectUri: authContext.RedirectUri,
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

		err = authorizeValidator.ValidateRequest(r.Context(), &core_authorize.ValidateRequestInput{
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

		err = authorizeValidator.ValidateScopes(r.Context(), authContext.Scope, nil)

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

		hasValidUserSession := loginManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
		if hasValidUserSession {
			// valid user session

			mustPerformPasswordAuth := loginManager.MustPerformPasswordAuth(r.Context(), userSession,
				authContext.ParseRequestedAcrValues())
			if mustPerformPasswordAuth {
				authContext.UserId = userSession.User.ID
				err = s.saveAuthContext(w, r, &authContext)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/auth/pwd", http.StatusFound)
				return
			}

			mustPerformOTPAuth := loginManager.MustPerformOTPAuth(r.Context(), userSession,
				authContext.ParseRequestedAcrValues())
			if mustPerformOTPAuth {
				authContext.UserId = userSession.User.ID
				err = s.saveAuthContext(w, r, &authContext)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/auth/otp", http.StatusFound)
				return
			}

		} else {
			// no valid session
			err = s.saveAuthContext(w, r, &authContext)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/auth/pwd", http.StatusFound)
			return
		}

		// no further authentication is needed

		authContext.UserId = userSession.User.ID
		authContext.AcrLevel = codeIssuer.GetUserSessionAcrLevel(r.Context(), userSession).String()
		authContext.AuthMethods = userSession.AuthMethods
		authContext.AuthCompleted = true

		// bump session
		_, err = s.bumpUserSession(w, r, sessionIdentifier, authContext.RequestedAcrValues)
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
		http.Redirect(w, r, "/auth/consent", http.StatusFound)
	}
}

func (s *Server) bumpUserSession(w http.ResponseWriter, r *http.Request, sessionIdentifier string, requestedAcrValues string) (*entities.UserSession, error) {

	userSession, err := s.database.GetUserSessionBySessionIdentifier(sessionIdentifier)
	if err != nil {
		return nil, err
	}

	if userSession != nil {

		userSession.LastAccessed = time.Now().UTC()
		userSession.RequestedAcrValues = requestedAcrValues

		// concatenate any new IP address
		ipWithoutPort, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !strings.Contains(userSession.IpAddress, ipWithoutPort) {
			userSession.IpAddress = fmt.Sprintf("%v,%v", userSession.IpAddress, ipWithoutPort)
		}

		userSession, err = s.database.UpdateUserSession(userSession)
		if err != nil {
			return nil, err
		}

		return userSession, nil
	}

	return nil, errors.New("Unexpected: can't bump user session because user session is nil")
}

func (s *Server) redirToClientWithError(w http.ResponseWriter, r *http.Request, code string,
	description string, responseMode string, redirectUri string, state string) error {

	if responseMode == "fragment" {
		values := url.Values{}
		values.Add("error", code)
		values.Add("error_description", description)
		if len(strings.TrimSpace(state)) > 0 {
			values.Add("state", state)
		}
		http.Redirect(w, r, redirectUri+"#"+values.Encode(), http.StatusFound)
		return nil
	}

	if responseMode == "form_post" {
		m := make(map[string]interface{})
		m["redirectUri"] = redirectUri
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
	redirUrl, _ := url.ParseRequestURI(redirectUri)
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

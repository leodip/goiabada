package server

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

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
		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if sess.Values[common.SessionKeySessionIdentifier] != nil {
			sessionIdentifier = sess.Values[common.SessionKeySessionIdentifier].(string)
		}

		authContext := dtos.AuthContext{
			ClientId:            r.URL.Query().Get("client_id"),
			RedirectUri:         r.URL.Query().Get("redirect_uri"),
			ResponseType:        r.URL.Query().Get("response_type"),
			CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
			CodeChallenge:       r.URL.Query().Get("code_challenge"),
			ResponseMode:        r.URL.Query().Get("response_mode"),
			Scope:               r.URL.Query().Get("scope"),
			MaxAge:              r.URL.Query().Get("max_age"),
			AcrValues:           r.URL.Query().Get("acr_values"),
			State:               r.URL.Query().Get("state"),
			Nonce:               r.URL.Query().Get("nonce"),
			UserAgent:           r.UserAgent(),
			IpAddress:           r.RemoteAddr,
			SessionIdentifier:   sessionIdentifier,
		}

		err = s.saveAuthContext(w, r, &authContext)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		err = authorizeValidator.ValidateClientAndRedirectUri(r.Context(), &core_authorize.ValidateClientAndRedirectUriInput{
			RequestId:   requestId,
			ClientId:    authContext.ClientId,
			RedirectUri: authContext.RedirectUri,
		})
		if err != nil {
			s.renderAuthorizeError(w, r, err)
			return
		}

		err = authorizeValidator.ValidateRequest(r.Context(), &core_authorize.ValidateRequestInput{
			ResponseType:        authContext.ResponseType,
			CodeChallengeMethod: authContext.CodeChallengeMethod,
			CodeChallenge:       authContext.CodeChallenge,
			ResponseMode:        authContext.ResponseMode,
		})
		if err != nil {
			s.renderAuthorizeError(w, r, err)
			return
		}

		err = authorizeValidator.ValidateScopes(r.Context(), authContext.Scope, nil)
		if err != nil {
			s.renderAuthorizeError(w, r, err)
			return
		}

		userSession, err := s.database.GetUserSessionBySessionIdentifier(authContext.SessionIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		hasValidUserSession := loginManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
		if hasValidUserSession {
			// valid user session

			performFirstLevelAuth := loginManager.PerformFirstLevelAuth(r.Context(), userSession, authContext.ParseRequestedAcrValues())
			if performFirstLevelAuth {
				authContext.Username = userSession.User.Username
				err = s.saveAuthContext(w, r, &authContext)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/auth/pwd", http.StatusFound)
				return
			}

			performSecondLevelAuth := loginManager.PerformSecondLevelAuth(r.Context(), userSession, authContext.ParseRequestedAcrValues())
			if performSecondLevelAuth {
				authContext.Username = userSession.User.Username
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

		// bump last accessed timestamp
		_, err = s.bumpUserSession(w, r, sessionIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// redirect to consent
		authContext.Username = userSession.User.Username
		authContext.AcrLevel = codeIssuer.GetUserSessionAcrLevel(r.Context(), userSession).String()
		authContext.AuthMethods = userSession.AuthMethods
		authContext.AuthCompleted = true
		err = s.saveAuthContext(w, r, &authContext)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, "/auth/consent", http.StatusFound)
	}
}

func (s *Server) bumpUserSession(w http.ResponseWriter, r *http.Request, sessionIdentifier string) (*entities.UserSession, error) {

	userSession, err := s.database.GetUserSessionBySessionIdentifier(sessionIdentifier)
	if err != nil {
		return nil, err
	}

	if userSession != nil {

		userSession.LastAccessed = time.Now().UTC()

		// concatenate any new IP address
		ipAddress := r.RemoteAddr
		if !strings.Contains(userSession.IpAddress, ipAddress) {
			userSession.IpAddress = fmt.Sprintf("%v,%v", userSession.IpAddress, ipAddress)
		}

		userSession, err = s.database.UpdateUserSession(userSession)
		if err != nil {
			return nil, err
		}

		return userSession, nil
	}

	return nil, customerrors.NewAppError(nil, "", "Unexpected: can't bump user session because user session is nil", http.StatusInternalServerError)
}

func (s *Server) renderAuthorizeError(w http.ResponseWriter, r *http.Request, err error) {

	if appError, ok := err.(*customerrors.AppError); ok {

		if appError.StatusCode == http.StatusInternalServerError {
			s.internalServerError(w, r, appError)
			return
		}

		if appError.UseRedirectUri {
			// render the error using the client's redirect uri
			err := s.redirToClientWithError(w, r, appError.Code, appError.Description, r.URL.Query().Get("response_mode"),
				r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("state"))
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		} else {
			// render the error in the UI
			err = s.renderTemplate(w, r, "/layouts/layout.html", "/auth_error.html", map[string]interface{}{
				"error": appError.Description,
			})
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}
	} else {
		s.internalServerError(w, r, err)
		return
	}
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
		m := make(map[string]string)
		m["redirectUri"] = redirectUri
		m["error"] = code
		m["error_description"] = description
		if len(strings.TrimSpace(state)) > 0 {
			m["state"] = state
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

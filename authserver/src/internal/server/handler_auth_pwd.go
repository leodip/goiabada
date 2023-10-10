package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAuthPwdGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		_, err := s.getAuthContext(r)
		if err != nil {
			if errors.Is(err, customerrors.ErrNoAuthContext) {
				http.Redirect(w, r, lib.GetBaseUrl()+"/account/profile", http.StatusFound)
			} else {
				s.internalServerError(w, r, err)
			}
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(common.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(common.ContextKeySessionIdentifier).(string)
		}

		// try to get email from session
		email := ""
		if len(sessionIdentifier) > 0 {
			userSession, err := s.database.GetUserSessionBySessionIdentifier(sessionIdentifier)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			if userSession != nil {
				email = userSession.User.Email
			}
		}

		bind := map[string]interface{}{
			"error":     nil,
			"csrfField": csrf.TemplateField(r),
		}
		if len(email) > 0 {
			bind["email"] = email
		}

		err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/auth_pwd.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAuthPwdPost(authorizeValidator authorizeValidator, loginManager loginManager) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		authContext, err := s.getAuthContext(r)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":     message,
				"email":     email,
				"csrfField": csrf.TemplateField(r),
			}

			err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/auth_pwd.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if len(strings.TrimSpace(email)) == 0 {
			renderError("Email is required.")
			return
		}

		if len(strings.TrimSpace(password)) == 0 {
			renderError("Password is required.")
			return
		}

		user, err := s.database.GetUserByEmail(email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		authFailedMessage := "Authentication failed. Please check your credentials and try again."
		if user == nil {
			renderError(authFailedMessage)
			return
		}

		if !lib.VerifyPasswordHash(user.PasswordHash, password) {
			renderError(authFailedMessage)
			return
		}

		// from this point the user is considered authenticated with pwd

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

			mustPerformOTPAuth := loginManager.MustPerformOTPAuth(r.Context(), userSession,
				authContext.ParseRequestedAcrValues())
			if mustPerformOTPAuth {
				authContext.UserId = user.ID
				err = s.saveAuthContext(w, r, authContext)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, lib.GetBaseUrl()+"/auth/otp", http.StatusFound)
				return
			}

		} else {
			// no valid session

			// optional: the system will offer if enabled for the user
			optional2fa := user.OTPEnabled

			// mandatory: if client requested level 3 in acr_values, we'll force a step 2
			requestedAcrValues := authContext.ParseRequestedAcrValues()
			mandatory2fa := len(requestedAcrValues) == 1 && requestedAcrValues[0] == enums.AcrLevel3

			if optional2fa || mandatory2fa {
				authContext.UserId = user.ID
				err = s.saveAuthContext(w, r, authContext)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, lib.GetBaseUrl()+"/auth/otp", http.StatusFound)
				return
			}
		}

		// user is fully authenticated

		// start new session

		_, err = s.startNewUserSession(w, r, user.ID, enums.AuthMethodPassword.String(), authContext.RequestedAcrValues)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// redirect to consent
		authContext.UserId = user.ID
		authContext.AcrLevel = enums.AcrLevel1.String()
		authContext.AuthMethods = enums.AuthMethodPassword.String()
		authContext.AuthTime = time.Now().UTC()
		authContext.AuthCompleted = true
		err = s.saveAuthContext(w, r, authContext)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, lib.GetBaseUrl()+"/auth/consent", http.StatusFound)
	}
}

package server

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
)

func (s *Server) handleAuthPwdGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		_, err := s.getAuthContext(r)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// try to get email from session
		email := ""
		if sess.Values[common.SessionKeySessionIdentifier] != nil {
			sessionIdentifier, ok := sess.Values[common.SessionKeySessionIdentifier].(string)
			if ok {
				userSession, err := s.database.GetUserSessionBySessionIdentifier(sessionIdentifier)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				if userSession != nil {
					email = userSession.User.Email
				}
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

		// check scopes again (with the user instance)
		err = authorizeValidator.ValidateScopes(r.Context(), authContext.Scope, user)
		if err != nil {
			valError, ok := err.(*customerrors.ValidationError)
			if ok {
				renderError(valError.Description)
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if sess.Values[common.SessionKeySessionIdentifier] != nil {
			sessionIdentifier = sess.Values[common.SessionKeySessionIdentifier].(string)
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
				http.Redirect(w, r, "/auth/otp", http.StatusFound)
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
				http.Redirect(w, r, "/auth/otp", http.StatusFound)
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
		authContext.AuthCompleted = true
		err = s.saveAuthContext(w, r, authContext)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, "/auth/consent", http.StatusFound)
	}
}

func (s *Server) startNewUserSession(w http.ResponseWriter, r *http.Request,
	userId uint, authMethodsStr string, requestedAcrValues string) (*entities.UserSession, error) {

	utcNow := time.Now().UTC()

	ipWithoutPort, _, _ := net.SplitHostPort(r.RemoteAddr)

	userSession := &entities.UserSession{
		SessionIdentifier:  uuid.New().String(),
		Started:            utcNow,
		LastAccessed:       utcNow,
		IpAddress:          ipWithoutPort,
		AuthMethods:        authMethodsStr,
		RequestedAcrValues: requestedAcrValues,
		UserID:             userId,
		DeviceName:         lib.GetDeviceName(r),
		DeviceType:         lib.GetDeviceType(r),
		DeviceOS:           lib.GetDeviceOS(r),
	}
	userSession, err := s.database.CreateUserSession(userSession)
	if err != nil {
		return nil, err
	}

	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get the session")
	}

	sess.Values[common.SessionKeySessionIdentifier] = userSession.SessionIdentifier
	err = sess.Save(r, w)
	if err != nil {
		return nil, err
	}

	return userSession, nil
}

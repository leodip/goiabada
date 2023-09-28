package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAuthPwdGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())
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
			s.renderAuthorizeError(w, r, customerrors.NewInternalServerError(err, requestId))
			return
		}
	}
}

func (s *Server) renderPwdPostError(w http.ResponseWriter, r *http.Request, err error) {

	if appError, ok := err.(*customerrors.AppError); ok {

		if appError.StatusCode == http.StatusInternalServerError {
			s.internalServerError(w, r, appError)
			return
		}

		err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/auth_pwd.html", map[string]interface{}{
			"error":     appError.Description,
			"email":     r.FormValue("email"),
			"csrfField": csrf.TemplateField(r),
		})
		if err != nil {
			s.internalServerError(w, r, err)
		}

	} else {
		s.internalServerError(w, r, err)
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

		if len(strings.TrimSpace(email)) == 0 {
			s.renderPwdPostError(w, r, customerrors.NewAppError(nil, "", "Email is required.", http.StatusOK))
			return
		}

		if len(strings.TrimSpace(password)) == 0 {
			s.renderPwdPostError(w, r, customerrors.NewAppError(nil, "", "Password is required.", http.StatusOK))
			return
		}

		user, err := s.database.GetUserByEmail(email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		authFailedMessage := "Authentication failed. Please check your credentials and try again."
		if user == nil {
			s.renderPwdPostError(w, r, customerrors.NewAppError(nil, "", authFailedMessage, http.StatusOK))
			return
		}

		if !lib.VerifyPasswordHash(user.PasswordHash, password) {
			s.renderPwdPostError(w, r, customerrors.NewAppError(nil, "", authFailedMessage, http.StatusOK))
			return
		}

		// from this point the user is considered authenticated with pwd

		// check scopes again (with the user instance)
		err = authorizeValidator.ValidateScopes(r.Context(), authContext.Scope, user)
		if err != nil {
			s.renderPwdPostError(w, r, err)
			return
		}

		userSession, err := s.database.GetUserSessionBySessionIdentifier(authContext.SessionIdentifier)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		hasValidUserSession := loginManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
		if hasValidUserSession {

			performSecondLevelAuth := loginManager.PerformSecondLevelAuth(r.Context(), userSession, authContext.ParseRequestedAcrValues())
			if performSecondLevelAuth {
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

			settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

			// optional: the system will offer if available in both server settings and user settings
			optional2fa := (settings.AcrLevel2IncludeOTP && user.AcrLevel2IncludeOTP)

			// mandatory: if client requested level 2 in acr_levels, we'll force a step 2
			requestedAcrValues := authContext.ParseRequestedAcrValues()
			mandatory2fa := len(requestedAcrValues) == 1 && requestedAcrValues[0] == enums.AcrLevel2

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

		_, err = s.startNewUserSession(w, r, user.ID, enums.AuthMethodPassword.String())
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
	userId uint, authMethodsStr string) (*entities.UserSession, error) {

	utcNow := time.Now().UTC()

	userSession := &entities.UserSession{
		SessionIdentifier: uuid.New().String(),
		Started:           utcNow,
		LastAccessed:      utcNow,
		IpAddress:         r.RemoteAddr,
		AuthMethods:       authMethodsStr,
		UserID:            userId,
		DeviceName:        lib.GetDeviceName(r),
		DeviceType:        lib.GetDeviceType(r),
		DeviceOS:          lib.GetDeviceOS(r),
	}
	userSession, err := s.database.CreateUserSession(userSession)
	if err != nil {
		return nil, err
	}

	sess, err := s.sessionStore.Get(r, common.SessionName)
	if err != nil {
		return nil, customerrors.NewAppError(err, "", "unable to get the session", http.StatusInternalServerError)
	}

	sess.Values[common.SessionKeySessionIdentifier] = userSession.SessionIdentifier
	sess.Save(r, w)

	return userSession, nil
}

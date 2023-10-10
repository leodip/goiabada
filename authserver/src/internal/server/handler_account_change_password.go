package server

import (
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAccountChangePasswordGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessAccountPages(jwtInfo) {
			s.redirToAuthorize(w, r, "account-management", lib.GetBaseUrl()+r.RequestURI, "openid")
			return
		}

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := s.renderTemplate(w, r, "/layouts/account_layout.html", "/account_change_password.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

	}
}

func (s *Server) handleAccountChangePasswordPost(passwordValidator passwordValidator) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessAccountPages(jwtInfo) {
			s.redirToAuthorize(w, r, "account-management", lib.GetBaseUrl()+r.RequestURI, "openid")
			return
		}

		currentPassword := r.FormValue("currentPassword")
		newPassword := r.FormValue("newPassword")
		newPasswordConfirmation := r.FormValue("newPasswordConfirmation")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/account_layout.html", "/account_change_password.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if len(strings.TrimSpace(currentPassword)) == 0 {
			renderError("Current password is required.")
			return
		}

		sub, err := jwtInfo.IdTokenClaims.GetSubject()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user, err := s.database.GetUserBySubject(sub)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if !lib.VerifyPasswordHash(user.PasswordHash, currentPassword) {
			renderError("Authentication failed. Check your current password and try again.")
			return
		}

		if len(strings.TrimSpace(newPassword)) == 0 {
			renderError("New password is required.")
			return
		}

		if newPassword != newPasswordConfirmation {
			renderError("The new password confirmation does not match the password.")
			return
		}

		err = passwordValidator.ValidatePassword(r.Context(), newPassword)
		if err != nil {
			renderError(err.Error())
			return
		}

		passwordHash, err := lib.HashPassword(newPassword)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user.PasswordHash = passwordHash
		user.ForgotPasswordCodeEncrypted = nil
		user.ForgotPasswordCodeIssuedAt = nil
		_, err = s.database.UpdateUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"passwordChangedSuccessfully": true,
			"csrfField":                   csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/account_layout.html", "/account_change_password.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

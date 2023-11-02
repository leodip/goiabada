package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	core_senders "github.com/leodip/goiabada/internal/core/senders"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserNewGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		bind := map[string]interface{}{
			"smtpEnabled":     settings.SMTPEnabled,
			"setPasswordType": "now",
			"page":            r.URL.Query().Get("page"),
			"query":           r.URL.Query().Get("query"),
			"csrfField":       csrf.TemplateField(r),
		}

		err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_new.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserNewPost(profileValidator profileValidator, emailValidator emailValidator,
	passwordValidator passwordValidator, inputSanitizer inputSanitizer, emailSender emailSender) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":           message,
				"smtpEnabled":     settings.SMTPEnabled,
				"setPasswordType": r.FormValue("setPasswordType"),
				"page":            r.URL.Query().Get("page"),
				"query":           r.URL.Query().Get("query"),
				"email":           r.FormValue("email"),
				"emailVerified":   r.FormValue("emailVerified") == "on",
				"givenName":       r.FormValue("givenName"),
				"middleName":      r.FormValue("middleName"),
				"familyName":      r.FormValue("familyName"),
				"csrfField":       csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_new.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))

		if len(email) == 0 {
			renderError("The email address cannot be empty.")
			return
		}

		err := emailValidator.ValidateEmailAddress(r.Context(), email)
		if err != nil {
			renderError(err.Error())
			return
		}

		if len(email) > 60 {
			renderError("The email address cannot exceed a maximum length of 60 characters.")
			return
		}

		existingUser, err := s.database.GetUserByEmail(email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if existingUser != nil {
			renderError("The email address is already in use.")
			return
		}

		err = profileValidator.ValidateName(r.Context(), r.FormValue("givenName"), "given name")
		if err != nil {
			renderError(err.Error())
			return
		}

		err = profileValidator.ValidateName(r.Context(), r.FormValue("middleName"), "middle name")
		if err != nil {
			renderError(err.Error())
			return
		}

		err = profileValidator.ValidateName(r.Context(), r.FormValue("familyName"), "family name")
		if err != nil {
			renderError(err.Error())
			return
		}

		setPasswordType := r.FormValue("setPasswordType")
		password := ""
		passwordHash := ""
		if (settings.SMTPEnabled && setPasswordType == "now") || !settings.SMTPEnabled {
			formPassword := r.FormValue("password")
			err := passwordValidator.ValidatePassword(r.Context(), formPassword)
			if err != nil {
				renderError(err.Error())
				return
			}
			password = formPassword
		}

		if len(password) > 0 {
			passwordHash, err = lib.HashPassword(password)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		accountPermission, err := s.getAccountPermission()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		user := &entities.User{
			Subject:       uuid.New(),
			Enabled:       true,
			Email:         email,
			EmailVerified: r.FormValue("emailVerified") == "on",
			GivenName:     r.FormValue("givenName"),
			MiddleName:    r.FormValue("middleName"),
			FamilyName:    r.FormValue("familyName"),
			PasswordHash:  passwordHash,
			Permissions:   []entities.Permission{*accountPermission},
		}

		user, err = s.database.CreateUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if settings.SMTPEnabled && setPasswordType == "email" {
			verificationCode := lib.GenerateSecureRandomString(32)
			verificationCodeEncrypted, err := lib.EncryptText(verificationCode, settings.AESEncryptionKey)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			user.ForgotPasswordCodeEncrypted = verificationCodeEncrypted
			utcNow := time.Now().UTC()
			user.ForgotPasswordCodeIssuedAt = &utcNow
			user, err := s.database.UpdateUser(user)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			name := user.GetFullName()
			if len(name) == 0 {
				name = user.Email
			}

			bind := map[string]interface{}{
				"name": name,
				"link": lib.GetBaseUrl() + "/reset-password?email=" + user.Email + "&code=" + verificationCode,
			}
			buf, err := s.renderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_newuser_set_password.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			input := &core_senders.SendEmailInput{
				To:       user.Email,
				Subject:  settings.AppName + " - create a password for your new account",
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), input)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		sess.AddFlash("true", "userCreated")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/details?page=%v&query=%v", lib.GetBaseUrl(), user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}

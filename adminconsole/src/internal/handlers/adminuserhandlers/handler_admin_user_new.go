package adminuserhandlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/audit"
	"github.com/leodip/goiabada/adminconsole/internal/communication"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/data"
	"github.com/leodip/goiabada/adminconsole/internal/encryption"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/hashutil"
	"github.com/leodip/goiabada/adminconsole/internal/models"
	"github.com/leodip/goiabada/adminconsole/internal/stringutil"
	"github.com/leodip/goiabada/adminconsole/internal/users"
)

func HandleAdminUserNewGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		bind := map[string]interface{}{
			"smtpEnabled":     settings.SMTPEnabled,
			"setPasswordType": "now",
			"page":            r.URL.Query().Get("page"),
			"query":           r.URL.Query().Get("query"),
			"csrfField":       csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserNewPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	userCreator handlers.UserCreator,
	profileValidator handlers.ProfileValidator,
	emailValidator handlers.EmailValidator,
	passwordValidator handlers.PasswordValidator,
	inputSanitizer handlers.InputSanitizer,
	emailSender handlers.EmailSender,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

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

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_new.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
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

		existingUser, err := database.GetUserByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
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
			passwordHash, err = hashutil.HashPassword(password)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		user, err := userCreator.CreateUser(r.Context(), &users.CreateUserInput{
			Email:         email,
			EmailVerified: r.FormValue("emailVerified") == "on",
			PasswordHash:  passwordHash,
			GivenName:     inputSanitizer.Sanitize(r.FormValue("givenName")),
			MiddleName:    inputSanitizer.Sanitize(r.FormValue("middleName")),
			FamilyName:    inputSanitizer.Sanitize(r.FormValue("familyName")),
		})
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		audit.Log(constants.AuditCreatedUser, map[string]interface{}{
			"email":        user.Email,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		if settings.SMTPEnabled && setPasswordType == "email" {
			verificationCode := stringutil.GenerateSecureRandomString(32)
			verificationCodeEncrypted, err := encryption.EncryptText(verificationCode, settings.AESEncryptionKey)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			user.ForgotPasswordCodeEncrypted = verificationCodeEncrypted
			utcNow := time.Now().UTC()
			user.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: utcNow, Valid: true}
			err = database.UpdateUser(nil, user)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			name := user.GetFullName()
			if len(name) == 0 {
				name = user.Email
			}

			bind := map[string]interface{}{
				"name": name,
				"link": config.AdminConsoleBaseUrl + "/reset-password?email=" + user.Email + "&code=" + verificationCode,
			}
			buf, err := httpHelper.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_newuser_set_password.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			input := &communication.SendEmailInput{
				To:       user.Email,
				Subject:  settings.AppName + " - create a password for your new account",
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), input)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.AddFlash("true", "userCreated")
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/details?page=%v&query=%v", config.AdminConsoleBaseUrl, user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}

package handlers

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/communication"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
)

func HandleForgotPasswordGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"error":     nil,
			"csrfField": csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

	}
}

func HandleForgotPasswordPost(
	httpHelper HttpHelper,
	database data.Database,
	emailSender EmailSender,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		email := r.FormValue("email")
		email = strings.ToLower(email)

		if len(email) == 0 || strings.Count(email, "@") != 1 {

			bind := map[string]interface{}{
				"error":     "Please enter a valid email address.",
				"csrfField": csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		user, err := database.GetUserByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user != nil {

			settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

			verificationCode := lib.GenerateSecureRandomString(32)
			verificationCodeEncrypted, err := lib.EncryptText(verificationCode, settings.AESEncryptionKey)
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

			bind := map[string]interface{}{
				"name": user.GetFullName(),
				"link": lib.GetBaseUrl() + "/reset-password?email=" + user.Email + "&code=" + verificationCode,
			}
			buf, err := httpHelper.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_forgot_password.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			input := &communication.SendEmailInput{
				To:       user.Email,
				Subject:  "Password reset",
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), input)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"linkSent":  true,
			"csrfField": csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

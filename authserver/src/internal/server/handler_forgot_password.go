package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	core_senders "github.com/leodip/goiabada/internal/core/senders"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleForgotPasswordGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"error":     nil,
			"csrfField": csrf.TemplateField(r),
		}

		err := s.renderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

	}
}

func (s *Server) handleForgotPasswordPost(emailSender emailSender) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		email := r.FormValue("email")
		email = strings.ToLower(email)

		if len(email) == 0 || strings.Count(email, "@") != 1 {

			bind := map[string]interface{}{
				"error":     "Please enter a valid email address.",
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			return
		}

		user, err := s.database.GetUserByEmail(email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if user != nil {

			if len(user.ForgotPasswordCodeEncrypted) > 0 && user.ForgotPasswordCodeIssuedAt != nil {
				const waitTime = 90 * time.Second
				remainingTime := int(user.ForgotPasswordCodeIssuedAt.Add(waitTime).Sub(time.Now().UTC()).Seconds())
				if remainingTime > 0 {
					bind := map[string]interface{}{
						"error":     fmt.Sprintf("A request to send a password reset link was made recently. Please wait for %v seconds before requesting another one", remainingTime),
						"csrfField": csrf.TemplateField(r),
					}

					err := s.renderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
					if err != nil {
						s.internalServerError(w, r, err)
						return
					}
					return
				}
			}

			settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

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

			bind := map[string]interface{}{
				"name": user.GetFullName(),
				"link": lib.GetBaseUrl() + "/reset-password?email=" + user.Email + "&code=" + verificationCode,
			}
			buf, err := s.renderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_forgot_password.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			input := &core_senders.SendEmailInput{
				To:       user.Email,
				Subject:  "Password reset",
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), input)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"linkSent":  true,
			"csrfField": csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

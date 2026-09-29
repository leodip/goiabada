package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/stringutil"
)

func HandleForgotPasswordGet(
	pageRenderer PageRenderer,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"error": nil,
		}

		err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

	}
}

// forgotPasswordDatabase is what the forgot password page needs: the user it stamps with a reset
// code.
type forgotPasswordDatabase interface {
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*models.User, error)
	UpdateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
}

func HandleForgotPasswordPost(
	pageRenderer PageRenderer,
	database forgotPasswordDatabase,
	emailSender EmailSender,
	dataCipher *encryption.DataCipher,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		email := r.FormValue("email")
		email = strings.ToLower(email)

		if len(email) == 0 || strings.Count(email, "@") != 1 {

			// i18n surface: A — browser-flow form rerender.
			bind := map[string]interface{}{
				"error": i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil).Localize(r.Context()),
			}

			err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
			return
		}

		user, err := database.GetUserByEmail(r.Context(), nil, email)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if user != nil {

			verificationCode := stringutil.GenerateSecurityRandomString(32)
			verificationCodeEncrypted, resetEmailErr := dataCipher.Encrypt(verificationCode)
			if resetEmailErr != nil {
				pageRenderer.InternalServerError(w, r, resetEmailErr)
				return
			}

			// The hash is how the reset link finds this row again, since the link carries
			// the code and no email address (#112). The encryption above stays: it is what
			// proves a submitted code matches, where the hash only locates the row.
			verificationCodeHash := hashutil.HashString(verificationCode)

			user.ForgotPasswordCodeEncrypted = verificationCodeEncrypted
			user.ForgotPasswordCodeHash = verificationCodeHash
			utcNow := time.Now().UTC()
			user.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: utcNow, Valid: true}
			resetEmailErr = database.UpdateUser(r.Context(), nil, user)
			if resetEmailErr != nil {
				pageRenderer.InternalServerError(w, r, resetEmailErr)
				return
			}

			bind := map[string]interface{}{
				"name": user.FullName(),
				"link": emaillinks.ResetPasswordLink(baseURL, verificationCode),
			}
			emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, user.Locale, "en"))
			buf, resetEmailErr := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_forgot_password.html", bind)
			if resetEmailErr != nil {
				pageRenderer.InternalServerError(w, r, resetEmailErr)
				return
			}

			input := &emaildelivery.SendEmailInput{
				To:       user.Email,
				Subject:  i18n.T(emailReq.Context(), "email.forgot_password.subject"),
				HtmlBody: buf.String(),
			}
			settings, ok := reqctx.SettingsFrom(r.Context())
			if !ok {
				pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
				return
			}
			resetEmailErr = emailSender.SendEmail(r.Context(), emaildelivery.SMTPConfigFromSettings(settings), input)
			if resetEmailErr != nil {
				pageRenderer.InternalServerError(w, r, resetEmailErr)
				return
			}
		}

		bind := map[string]interface{}{
			"linkSent": true,
		}

		err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
	}
}

package accounthandlers

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAccountEmailGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		bind := map[string]interface{}{
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"email":             user.Email,
			"emailVerified":     user.EmailVerified,
			"emailConfirmation": "",
			"smtpEnabled":       settings.SMTPEnabled,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountEmailSendVerificationPost(
	httpHelper handlers.HttpHelper,
	database data.Database,
	emailSender handlers.EmailSender,
) http.HandlerFunc {

	type sendVerificationResult struct {
		EmailVerified         bool
		EmailVerificationSent bool
		EmailDestination      string
		TooManyRequests       bool
		WaitInSeconds         int
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := sendVerificationResult{}

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SMTPEnabled {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("SMTP is not enabled")))
			return
		}

		if len(user.EmailVerificationCodeEncrypted) > 0 && user.EmailVerificationCodeIssuedAt.Valid {
			const waitTime = 60 * time.Second
			remainingTime := int(user.EmailVerificationCodeIssuedAt.Time.Add(waitTime).Sub(time.Now().UTC()).Seconds())
			if remainingTime > 0 {
				result.TooManyRequests = true
				result.WaitInSeconds = remainingTime
				httpHelper.EncodeJson(w, r, result)
				return
			}
		}

		if user.EmailVerified {
			result.EmailVerified = true
			httpHelper.EncodeJson(w, r, result)
			return
		}

		verificationCode := stringutil.GenerateSecureRandomString(32)
		emailVerificationCodeEncrypted, err := encryption.EncryptText(verificationCode, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		user.EmailVerificationCodeEncrypted = emailVerificationCodeEncrypted
		utcNow := time.Now().UTC()
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: utcNow, Valid: true}
		err = database.UpdateUser(nil, user)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"name": user.GetFullName(),
			"link": config.Get().BaseURL + "/account/email-verify?code=" + verificationCode,
		}
		buf, err := httpHelper.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_verification.html", bind)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		input := &communication.SendEmailInput{
			To:       user.Email,
			Subject:  "Email verification",
			HtmlBody: buf.String(),
		}
		err = emailSender.SendEmail(r.Context(), input)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		result.EmailVerificationSent = true
		result.EmailDestination = user.Email
		httpHelper.EncodeJson(w, r, result)
	}
}

func HandleAccountEmailVerifyGet(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		code := r.URL.Query().Get("code")
		if len(code) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting code to verify the email, but it's empty")))
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		emailVerificationCode, err := encryption.DecryptText(user.EmailVerificationCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("unable to decrypt email verification code")))
			return
		}

		if emailVerificationCode != code || user.EmailVerificationCodeIssuedAt.Time.Add(5*time.Minute).Before(time.Now().UTC()) {
			bind := map[string]interface{}{}

			err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email_verification.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		user.EmailVerified = true
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Valid: false}
		err = database.UpdateUser(nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditVerifiedEmail, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.Get().BaseURL+"/account/email", http.StatusFound)
	}
}

func HandleAccountEmailPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	emailValidator handlers.EmailValidator,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		input := &validators.ValidateEmailInput{
			Email:             strings.ToLower(strings.TrimSpace(r.FormValue("email"))),
			EmailConfirmation: strings.ToLower(strings.TrimSpace(r.FormValue("emailConfirmation"))),
			Subject:           sub,
		}

		err = emailValidator.ValidateEmailUpdate(input)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {

				bind := map[string]interface{}{
					"user":              user,
					"email":             input.Email,
					"emailVerified":     user.EmailVerified,
					"emailConfirmation": input.EmailConfirmation,
					"csrfField":         csrf.TemplateField(r),
					"error":             valError.GetDescription(),
				}

				err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
				}
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		if input.Email != user.Email {
			user.Email = inputSanitizer.Sanitize(input.Email)
			user.EmailVerified = false
			user.EmailVerificationCodeEncrypted = nil
			user.EmailVerificationCodeIssuedAt = sql.NullTime{Valid: false}

			err = database.UpdateUser(nil, user)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			sess, err := httpSession.Get(r, constants.SessionName)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			sess.AddFlash("true", "savedSuccessfully")
			err = sess.Save(r, w)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditUpdatedUserEmail, map[string]interface{}{
				"userId":       user.Id,
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})
		}

		http.Redirect(w, r, config.Get().BaseURL+"/account/email", http.StatusFound)
	}
}

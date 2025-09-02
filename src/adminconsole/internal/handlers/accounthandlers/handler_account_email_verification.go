package accounthandlers

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/pkg/errors"
)

func HandleAccountEmailVerificationGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		loggedInSubject := authHelper.GetLoggedInSubject(r)
		if strings.TrimSpace(loggedInSubject) == "" {
			http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/unauthorized", http.StatusFound)
			return
		}
		user, err := database.GetUserBySubject(nil, loggedInSubject)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SMTPEnabled {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("SMTP is not enabled")))
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"email":             user.Email,
			"emailVerified":     user.EmailVerified,
			"smtpEnabled":       settings.SMTPEnabled,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email_verification.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountEmailSendVerificationPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	emailSender handlers.EmailSender,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		result := EmailSendVerificationResult{}

		loggedInSubject := authHelper.GetLoggedInSubject(r)
		if strings.TrimSpace(loggedInSubject) == "" {
			http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/unauthorized", http.StatusFound)
			return
		}

		user, err := database.GetUserBySubject(nil, loggedInSubject)
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

		verificationCode := strings.ToUpper(stringutil.GenerateRandomLetterString(3)) + stringutil.GenerateRandomNumberString(3)
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
			"name":             user.GetFullName(),
			"link":             config.GetAdminConsole().BaseURL + "/account/email-verification",
			"verificationCode": verificationCode,
		}
		buf, err := httpHelper.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_verification.html", bind)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		input := &communication.SendEmailInput{
			To:       user.Email,
			Subject:  "Email verification - code " + verificationCode,
			HtmlBody: buf.String(),
		}
		err = emailSender.SendEmail(r.Context(), input)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditSentEmailVerificationMessage, map[string]interface{}{
			"userId":           user.Id,
			"emailDestination": user.Email,
			"loggedInUser":     authHelper.GetLoggedInSubject(r),
		})

		result.EmailVerificationSent = true
		result.EmailDestination = user.Email
		httpHelper.EncodeJson(w, r, result)
	}
}

func HandleAccountEmailVerificationPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		loggedInSubject := authHelper.GetLoggedInSubject(r)
		if strings.TrimSpace(loggedInSubject) == "" {
			http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/unauthorized", http.StatusFound)
			return
		}

		user, err := database.GetUserBySubject(nil, loggedInSubject)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user.EmailVerified {
			http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/email-verification", http.StatusFound)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SMTPEnabled {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("SMTP is not enabled")))
			return
		}

		verificationCode := strings.TrimSpace(r.FormValue("verificationCode"))
		storedVerificationCode, err := encryption.DecryptText(user.EmailVerificationCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			slog.Error("unable to decrypt email verification code")
		}

		if !strings.EqualFold(storedVerificationCode, verificationCode) ||
			user.EmailVerificationCodeIssuedAt.Time.Add(5*time.Minute).Before(time.Now().UTC()) {
			settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

			bind := map[string]interface{}{
				"savedSuccessfully": false,
				"email":             user.Email,
				"emailVerified":     user.EmailVerified,
				"smtpEnabled":       settings.SMTPEnabled,
				"csrfField":         csrf.TemplateField(r),
				"error":             "Invalid or expired verification code",
			}

			auditLogger.Log(constants.AuditFailedEmailVerificationCode, map[string]interface{}{
				"userId":       user.Id,
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})

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

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditVerifiedEmail, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/email-verification", http.StatusFound)
	}
}
